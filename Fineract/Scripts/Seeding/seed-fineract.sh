#!/usr/bin/env bash
# seed-fineract.sh — Populate a fresh Fineract instance with minimal sample data.
# Creates: 1 sub-office, 1 staff member, 2 clients, 1 loan product, 1 savings product.
#
# Usage:
#   chmod +x seed-fineract.sh
#   ./seed-fineract.sh
#
# Prerequisites: curl, jq
# Assumes Fineract is running at https://localhost:8443 with default credentials.

set -euo pipefail

# ---------- Configuration ----------
BASE_URL="${FINERACT_URL:-https://localhost:8443/fineract-provider/api/v1}"
HEALTH_URL="${FINERACT_HEALTH_URL:-https://localhost:8443/fineract-provider/actuator/health}"
TENANT="${FINERACT_TENANT:-default}"
USER="${FINERACT_USER:-mifos}"
PASS="${FINERACT_PASS:-password}"
CURL_TIMEOUT="${FINERACT_CURL_TIMEOUT:-20}"       # seconds, per request
HEALTH_TIMEOUT="${FINERACT_HEALTH_TIMEOUT:-180}"  # seconds, total wait for startup

AUTH="Authorization: Basic $(printf '%s' "${USER}:${PASS}" | base64)"
TENANT_HDR="Fineract-Platform-TenantId: ${TENANT}"
CONTENT="Content-Type: application/json"

TODAY=$(date +"%d %B %Y")        # e.g. "29 July 2026"
RUN_SUFFIX=$(date +"%Y%m%d-%H%M%S")  # makes named resources unique per run

LOG_FILE="${FINERACT_SEED_LOG:-./seed-fineract-$(date +%Y%m%d-%H%M%S).log}"

# ---------- Logging ----------
# All log_* functions write to both stdout/stderr AND the log file.
_log() {
  local level=$1; shift
  local ts
  ts=$(date +"%Y-%m-%d %H:%M:%S")
  printf '[%s] [%s] %s\n' "$ts" "$level" "$*" | tee -a "$LOG_FILE" >&2
}
log_info()  { _log "INFO"  "$@"; }
log_warn()  { _log "WARN"  "$@"; }
log_error() { _log "ERROR" "$@"; }
log_debug() {
  if [ "${FINERACT_SEED_DEBUG:-0}" = "1" ]; then
    _log "DEBUG" "$@"
  else
    printf '[%s] [DEBUG] %s\n' "$(date +"%Y-%m-%d %H:%M:%S")" "$*" >> "$LOG_FILE"
  fi
}

# Catch-all: any command that fails and isn't explicitly handled gets logged
# with the exact line number and command, instead of the script dying silently.
on_error() {
  local exit_code=$1 line_no=$2 command=$3
  log_error "Unexpected failure (exit ${exit_code}) at line ${line_no}: ${command}"
  log_error "Full log written to: ${LOG_FILE}"
  exit "$exit_code"
}
trap 'on_error $? $LINENO "$BASH_COMMAND"' ERR

# ---------- Helpers ----------

# wait_for_health: polls the actuator health endpoint until it reports UP,
# or gives up after HEALTH_TIMEOUT seconds. Prevents racing container startup
# / Liquibase migrations on a fresh instance.
wait_for_health() {
  log_info "Waiting for Fineract to report healthy at ${HEALTH_URL} (timeout ${HEALTH_TIMEOUT}s)..."
  local waited=0
  local interval=5
  while [ "$waited" -lt "$HEALTH_TIMEOUT" ]; do
    local status
    status=$(curl -sk --max-time 5 -o /dev/null -w '%{http_code}' "$HEALTH_URL" 2>>"$LOG_FILE" || echo "000")
    if [ "$status" = "200" ]; then
      local body
      body=$(curl -sk --max-time 5 "$HEALTH_URL" 2>>"$LOG_FILE" || echo "")
      if echo "$body" | jq -e '.status == "UP"' >/dev/null 2>&1; then
        log_info "Fineract is healthy."
        return 0
      fi
    fi
    log_debug "Health check attempt: HTTP ${status}, not ready yet. Waiting ${interval}s..."
    sleep "$interval"
    waited=$((waited + interval))
  done
  log_error "Fineract did not become healthy within ${HEALTH_TIMEOUT}s. Check container logs:"
  log_error "  docker compose logs fineract-manager --tail=100"
  exit 1
}

# call: makes an HTTP request and returns ONLY the response body on stdout.
# HTTP status is captured separately and stashed in LAST_HTTP_STATUS.
# Distinguishes network/timeout failures (curl exit code) from HTTP-level errors.
LAST_HTTP_STATUS=""
HTTP_STATUS_FILE=$(mktemp)
call() {
  local method=$1 endpoint=$2 body="${3:-}"
  local url="${BASE_URL}${endpoint}"
  local http_status response_body
  local tmp_body
  tmp_body=$(mktemp)

  log_debug "-> ${method} ${endpoint}"

  set +e
  if [ -n "$body" ]; then
    http_status=$(curl -sk --max-time "$CURL_TIMEOUT" -X "$method" "$url" \
      -H "$AUTH" -H "$TENANT_HDR" -H "$CONTENT" \
      -d "$body" \
      -o "$tmp_body" -w '%{http_code}' 2>>"$LOG_FILE")
  else
    http_status=$(curl -sk --max-time "$CURL_TIMEOUT" -X "$method" "$url" \
      -H "$AUTH" -H "$TENANT_HDR" -H "$CONTENT" \
      -o "$tmp_body" -w '%{http_code}' 2>>"$LOG_FILE")
  fi
  local curl_exit=$?
  set -e

  if [ "$curl_exit" -ne 0 ]; then
    rm -f "$tmp_body"
    log_error "curl failed (exit ${curl_exit}) calling ${method} ${endpoint} — connection/timeout issue, not an HTTP error."
    log_error "Check: is Fineract up? Is the URL correct (${BASE_URL})? See curl exit codes: man curl"
    exit 1
  fi

  response_body=$(cat "$tmp_body")
  rm -f "$tmp_body"

  # Write status to a file so it survives the subshell boundary
  echo "$http_status" > "$HTTP_STATUS_FILE"
  log_debug "<- ${method} ${endpoint} : HTTP ${http_status}"

  echo "$response_body"
}

# check_error: validates a response before the caller tries to use it.
# Exits with a clear message on empty body, invalid JSON, or non-2xx status —
# instead of silently dying inside a masked jq/pipefail failure.
check_error() {
  local response=$1 step=$2
  LAST_HTTP_STATUS=$(cat "$HTTP_STATUS_FILE" 2>/dev/null || echo "")

  if [ -z "$response" ]; then
    log_error "Step '${step}' failed: empty response body (HTTP ${LAST_HTTP_STATUS})"
    exit 1
  fi

  if ! echo "$response" | jq -e . >/dev/null 2>&1; then
    log_error "Step '${step}' failed: response is not valid JSON (HTTP ${LAST_HTTP_STATUS})"
    log_error "Raw response: ${response}"
    exit 1
  fi

  case "$LAST_HTTP_STATUS" in
    2??) : ;; # 2xx is fine
    *)
      log_error "Step '${step}' failed with HTTP ${LAST_HTTP_STATUS}:"
      echo "$response" | jq . 2>>"$LOG_FILE" | tee -a "$LOG_FILE" >&2
      exit 1
      ;;
  esac
}

extract_id() {
  echo "$1" | jq -r '.resourceId // .clientId // .savingsId // .loanProductId // .resourceId // empty'
}

log_info "=== Fineract Seed Script ==="
log_info "Target:  $BASE_URL"
log_info "Tenant:  $TENANT"
log_info "Date:    $TODAY"
log_info "Run tag: $RUN_SUFFIX (appended to resource names for idempotency)"
log_info "Log file: $LOG_FILE"
log_info ""

# ---------- 0. Wait for Fineract to be ready ----------
wait_for_health

# ---------- 1. Create a sub-office ----------
OFFICE_NAME="Branch Office ${RUN_SUFFIX}"
log_info "1. Creating sub-office '${OFFICE_NAME}'..."
OFFICE_RESP=$(call POST "/offices" "$(cat <<EOF
{
  "name": "${OFFICE_NAME}",
  "dateFormat": "dd MMMM yyyy",
  "locale": "en",
  "openingDate": "$TODAY",
  "parentId": 1
}
EOF
)")
check_error "$OFFICE_RESP" "Create office"
OFFICE_ID=$(extract_id "$OFFICE_RESP")
log_info "   Office ID: $OFFICE_ID"

# ---------- 2. Create a staff member ----------
log_info "2. Creating staff member..."
STAFF_RESP=$(call POST "/staff" "$(cat <<EOF
{
  "officeId": $OFFICE_ID,
  "firstname": "Jane",
  "lastname": "Doe",
  "isLoanOfficer": true,
  "locale": "en",
  "dateFormat": "dd MMMM yyyy",
  "joiningDate": "$TODAY"
}
EOF
)")
check_error "$STAFF_RESP" "Create staff"
STAFF_ID=$(extract_id "$STAFF_RESP")
log_info "   Staff ID: $STAFF_ID"

# ---------- 3. Create clients ----------
create_client() {
  local firstname=$1 lastname=$2
  local resp
  resp=$(call POST "/clients" "$(cat <<EOF
{
  "officeId": $OFFICE_ID,
  "legalFormId": 1,
  "firstname": "$firstname",
  "lastname": "$lastname",
  "active": true,
  "activationDate": "$TODAY",
  "dateFormat": "dd MMMM yyyy",
  "locale": "en",
  "staffId": $STAFF_ID
}
EOF
)")
  check_error "$resp" "Create client $firstname $lastname"
  extract_id "$resp"
}

log_info "3. Creating clients..."
CLIENT1_ID=$(create_client "Alice" "Smith")
log_info "   Client 1 (Alice Smith) ID: $CLIENT1_ID"
CLIENT2_ID=$(create_client "Bob" "Jones")
log_info "   Client 2 (Bob Jones) ID: $CLIENT2_ID"

# ---------- 4. Create a loan product ----------
LOAN_PRODUCT_NAME="Standard Personal Loan ${RUN_SUFFIX}"
LOAN_PRODUCT_SHORT="S${RUN_SUFFIX: -3}"  # shortName has tight length limits in Fineract
log_info "4. Creating loan product '${LOAN_PRODUCT_NAME}'..."
LOAN_PRODUCT_RESP=$(call POST "/loanproducts" "$(cat <<EOF
{
  "name": "${LOAN_PRODUCT_NAME}",
  "shortName": "${LOAN_PRODUCT_SHORT}",
  "currencyCode": "USD",
  "locale": "en_GB",
  "dateFormat": "dd MMMM yyyy",
  "digitsAfterDecimal": 2,
  "inMultiplesOf": 0,
  "principal": 10000,
  "minPrincipal": 1000,
  "maxPrincipal": 100000,
  "numberOfRepayments": 12,
  "repaymentEvery": 1,
  "repaymentFrequencyType": 2,
  "interestRatePerPeriod": 1.5,
  "interestRateFrequencyType": 2,
  "amortizationType": 1,
  "interestType": 0,
  "interestCalculationPeriodType": 1,
  "transactionProcessingStrategyCode": "mifos-standard-strategy",
  "accountingRule": 1,
  "isInterestRecalculationEnabled": false,
  "daysInYearType": 365,
  "daysInMonthType": 30,
  "loanScheduleType": "CUMULATIVE",
  "loanScheduleProcessingType": "HORIZONTAL"
}
EOF
)")
check_error "$LOAN_PRODUCT_RESP" "Create loan product"
LOAN_PRODUCT_ID=$(extract_id "$LOAN_PRODUCT_RESP")
log_info "   Loan Product ID: $LOAN_PRODUCT_ID"

# ---------- 5. Create a savings product ----------
SAVINGS_PRODUCT_NAME="Basic Savings Account ${RUN_SUFFIX}"
SAVINGS_PRODUCT_SHORT="B${RUN_SUFFIX: -3}"
log_info "5. Creating savings product '${SAVINGS_PRODUCT_NAME}'..."
SAVINGS_PRODUCT_RESP=$(call POST "/savingsproducts" "$(cat <<EOF
{
  "name": "${SAVINGS_PRODUCT_NAME}",
  "shortName": "${SAVINGS_PRODUCT_SHORT}",
  "description": "A basic savings account with daily interest calculation",
  "currencyCode": "USD",
  "locale": "en_GB",
  "digitsAfterDecimal": 4,
  "inMultiplesOf": 0,
  "nominalAnnualInterestRate": 5.0,
  "interestCompoundingPeriodType": 4,
  "interestPostingPeriodType": 4,
  "interestCalculationType": 1,
  "interestCalculationDaysInYearType": 365,
  "accountingRule": 1,
  "lockinPeriodFrequency": 0,
  "lockinPeriodFrequencyType": 0,
  "withdrawalFeeForTransfers": true,
  "allowOverdraft": false,
  "enforceMinRequiredBalance": false,
  "lienAllowed": false,
  "withHoldTax": false
}
EOF
)")
check_error "$SAVINGS_PRODUCT_RESP" "Create savings product"
SAVINGS_PRODUCT_ID=$(extract_id "$SAVINGS_PRODUCT_RESP")
log_info "   Savings Product ID: $SAVINGS_PRODUCT_ID"

# ---------- Summary ----------
log_info ""
log_info "=== Seed Complete ==="
log_info "  Office:          $OFFICE_ID ($OFFICE_NAME, parent of Head Office)"
log_info "  Staff:           $STAFF_ID (Jane Doe, loan officer)"
log_info "  Client 1:        $CLIENT1_ID (Alice Smith)"
log_info "  Client 2:        $CLIENT2_ID (Bob Jones)"
log_info "  Loan Product:    $LOAN_PRODUCT_ID ($LOAN_PRODUCT_NAME)"
log_info "  Savings Product: $SAVINGS_PRODUCT_ID ($SAVINGS_PRODUCT_NAME)"
log_info ""
log_info "Full log written to: $LOG_FILE"
log_info "All IDs above can be used in subsequent API calls."
log_info "Example — get client details:"
log_info "  curl -sk -H '$AUTH' -H '$TENANT_HDR' $BASE_URL/clients/$CLIENT1_ID"