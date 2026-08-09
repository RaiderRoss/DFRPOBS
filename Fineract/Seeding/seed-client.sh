set -euo pipefail

BASE_URL="${FINERACT_URL:-https://localhost:8443/fineract-provider/api/v1}"
HEALTH_URL="${FINERACT_HEALTH_URL:-https://localhost:8443/fineract-provider/actuator/health}"
TENANT="${FINERACT_TENANT:-default}"
USER="${FINERACT_USER:-mifos}"
PASS="${FINERACT_PASS:-password}"
CURL_TIMEOUT="${FINERACT_CURL_TIMEOUT:-20}"       
HEALTH_TIMEOUT="${FINERACT_HEALTH_TIMEOUT:-180}" 

AUTH="Authorization: Basic $(printf '%s' "${USER}:${PASS}" | base64)"
TENANT_HDR="Fineract-Platform-TenantId: ${TENANT}"
CONTENT="Content-Type: application/json"

TODAY=$(date +"%d %B %Y")        # e.g. "29 July 2026"
RUN_SUFFIX=$(date +"%Y%m%d-%H%M%S")  # makes named resources unique per run

LOG_FILE="${FINERACT_SEED_LOG:-./seed-fineract-$(date +%Y%m%d-%H%M%S).log}"

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

on_error() {
  local exit_code=$1 line_no=$2 command=$3
  log_error "Unexpected failure (exit ${exit_code}) at line ${line_no}: ${command}"
  log_error "Full log written to: ${LOG_FILE}"
  exit "$exit_code"
}
trap 'on_error $? $LINENO "$BASH_COMMAND"' ERR


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

  echo "$http_status" > "$HTTP_STATUS_FILE"
  log_debug "<- ${method} ${endpoint} : HTTP ${http_status}"

  echo "$response_body"
}

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

wait_for_health

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

log_info "Creating client..."
CLIENT1_ID=$(create_client "Tim" "Marsh")
log_info "   Client 1 (Alice Smith) ID: $CLIENT1_ID"

log_info ""
log_info "=== Seed Complete ==="
log_info "  Client 1:        $CLIENT1_ID (Alice Smith)"
log_info ""
log_info "Full log written to: $LOG_FILE"
log_info "All IDs above can be used in subsequent API calls."
log_info "Example — get client details:"
log_info "  curl -sk -H '$AUTH' -H '$TENANT_HDR' $BASE_URL/clients/$CLIENT1_ID"