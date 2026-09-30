#!/usr/bin/env bash
#
# Submits one source's evidence from a captured window to the DFRaaS Evidence Repository.
#
# One EvidenceItem references one artifact, so a window that captured the firewall, the
# IDS, the bank and the tunnel's login is five items from five registered sources — not one
# upload carrying five files. --source picks which one goes; the window supplies the rest.
#
# The coverage window is the same for all of them, because they observed one scenario over
# one period. Only the artifact, the digest and the registered source differ.
#
# The digest is sent as a *claim*. The repository recomputes it from the bytes that
# arrive, compares the two, and stores only its own value; a mismatch is a 422 and
# nothing is preserved. That comparison is the only part of the trip from this machine
# to the repository that can be verified rather than trusted, which is why this script
# re-checks the file locally first: a log that changed since capture should be caught
# here, as a local finding, rather than looking like a transport failure at the far end.
#
# groundtruth.json is deliberately not sent. Labels known before the packets were sent
# are research metadata, not evidence, and the repository has nowhere truthful to put
# them.
#
#   ./submit-evidence.sh --dry-run                    # show exactly what would be sent
#   ./submit-evidence.sh                              # firewall log of the latest window
#   ./submit-evidence.sh --source ids                 # the IDS evidence for that window
#   ./submit-evidence.sh --source banking-audit       # the bank's audit trail for it
#   ./submit-evidence.sh --source auth                # who opened the tunnel it arrived in
#   ./submit-evidence.sh --run 20260906204848 --source ids
#   ./submit-evidence.sh --list                       # what is available to send
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# Configuration. Every value can be set in pde.conf (which the console sources)
# or exported before running.
# ---------------------------------------------------------------------------
OUTDIR="${OUTDIR:-$SCRIPT_DIR/output}"
URL="${DFRAAS_URL:-http://localhost:8080}"
AUTH="${DFRAAS_AUTH:-admin:admin}"

# Each PDE source registers separately. They are different collectors observing
# different things, so they get different keys and types at the repository — and a
# reader asking "where did this come from" gets an answer more useful than "the testbed".
FW_SOURCE_KEY="${DFRAAS_SOURCE_KEY:-pde-sim-ufw-01}"
FW_DISPLAY_NAME="${DFRAAS_DISPLAY_NAME:-PDE testbed firewall (ufw)}"
FW_SOURCE_TYPE="${DFRAAS_SOURCE_TYPE:-FIREWALL}"

IDS_SOURCE_KEY="${DFRAAS_IDS_SOURCE_KEY:-pde-sim-slips-01}"
IDS_DISPLAY_NAME="${DFRAAS_IDS_DISPLAY_NAME:-PDE testbed IDS (Slips)}"
IDS_SOURCE_TYPE="${DFRAAS_IDS_SOURCE_TYPE:-IDS}"

# The bank is two collectors, so two sources: its event stream says what happened, its
# audit trail says who did it. DB_AUDIT is the type EvidenceSource's own documentation
# uses as its example; the repository takes any SCREAMING_SNAKE_CASE type without a
# migration.
BANK_EVENTS_SOURCE_KEY="${DFRAAS_BANK_EVENTS_SOURCE_KEY:-pde-sim-fineract-events-01}"
BANK_EVENTS_DISPLAY_NAME="${DFRAAS_BANK_EVENTS_DISPLAY_NAME:-PDE testbed bank event stream (Fineract)}"
BANK_EVENTS_SOURCE_TYPE="${DFRAAS_BANK_EVENTS_SOURCE_TYPE:-BANKING_EVENTS}"

BANK_AUDIT_SOURCE_KEY="${DFRAAS_BANK_AUDIT_SOURCE_KEY:-pde-sim-fineract-audit-01}"
BANK_AUDIT_DISPLAY_NAME="${DFRAAS_BANK_AUDIT_DISPLAY_NAME:-PDE testbed bank audit trail (Fineract)}"
BANK_AUDIT_SOURCE_TYPE="${DFRAAS_BANK_AUDIT_SOURCE_TYPE:-DB_AUDIT}"

# The remote-access source: sshd on the research VM. It is the only source that attributes a
# session to a person rather than to an address or a login — see Auth/README.md, including
# what IAP means for the address it records.
AUTH_SOURCE_KEY="${DFRAAS_AUTH_SOURCE_KEY:-pde-sim-sshd-01}"
AUTH_DISPLAY_NAME="${DFRAAS_AUTH_DISPLAY_NAME:-PDE testbed remote access (sshd)}"
AUTH_SOURCE_TYPE="${DFRAAS_AUTH_SOURCE_TYPE:-AUTH_LOG}"

RUN=""
SOURCE="firewall"
DRY_RUN=0
LIST=0
WORK_GROUP=""

log()  { printf '  %s\n' "$*" >&2; }
fail() { printf '  error: %s\n' "$*" >&2; exit 1; }

usage() {
	sed -n '2,22p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'
	cat <<-EOF

	Options:
	  --source NAME          which source's evidence to send:
	                         firewall | ids | banking-events | banking-audit | auth
	                                                          (default $SOURCE)
	  --list                 show the windows and what each holds, then exit
	  --run ID               window to submit from, e.g. 20260906204848 (default: latest)
	  --outdir DIR           where captures live                     (default $OUTDIR)
	  --url URL              repository base URL                     (default $URL)
	  --source-key KEY       override the registered source key for --source
	  --auth USER:PASS       HTTP Basic credentials                  (default admin:admin)
	  --register-with UUID   register the source first, under this work group
	  --dry-run              print the request and exit; sends nothing

	The source must be registered before its first upload. Registration is where
	classification is decided, so it takes a work group id and is a deliberate act —
	--register-with is the convenience form of it, not an automatic one:

	  curl -u $AUTH $URL/api/work-groups           # find the work group id
	  ./submit-evidence.sh --source $SOURCE --register-with <uuid>   # then submit
	EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		--run) RUN="$2"; shift 2 ;;
		--source) SOURCE="$2"; shift 2 ;;
		--list) LIST=1; shift ;;
		--outdir) OUTDIR="$2"; shift 2 ;;
		--url) URL="${2%/}"; shift 2 ;;
		--source-key) SOURCE_KEY_OVERRIDE="$2"; shift 2 ;;
		--auth) AUTH="$2"; shift 2 ;;
		--register-with) WORK_GROUP="$2"; shift 2 ;;
		--dry-run) DRY_RUN=1; shift ;;
		-h|--help) usage; exit 0 ;;
		*) fail "unknown option: $1 (try --help)" ;;
	esac
done

command -v curl    >/dev/null 2>&1 || fail "curl not found on PATH"
command -v python3 >/dev/null 2>&1 || fail "python3 not found on PATH"

case "$SOURCE" in
	firewall|ids|banking-events|banking-audit|auth) ;;
	*) fail "unknown --source '$SOURCE' (firewall | ids | banking-events | banking-audit | auth)" ;;
esac

# ---------------------------------------------------------------------------
# --list: what is on disk and therefore sendable, per window per source
# ---------------------------------------------------------------------------
if [[ "$LIST" -eq 1 ]]; then
	found=0
	for dir in "$OUTDIR"/*/; do
		[[ -d "$dir" ]] || continue
		stamp=$(basename "$dir")
		[[ "$stamp" == "sessions" ]] && continue
		[[ -f "$dir/firewall_${stamp}.manifest.json" ]] || continue
		found=1
		printf '  %s\n' "$stamp" >&2
		if [[ -f "$dir/firewall_${stamp}.log" ]]; then
			printf '    %-15s %-38s %s bytes\n' firewall "firewall_${stamp}.log" \
				"$(stat -c %s "$dir/firewall_${stamp}.log")" >&2
		fi
		for pair in "ids:ids_${stamp}.alerts.log" "banking-events:banking-events_${stamp}.jsonl" \
		            "banking-audit:banking-audit_${stamp}.jsonl" "auth:auth_${stamp}.log"; do
			src="${pair%%:*}" file="${pair#*:}"
			if [[ -f "$dir/$file" ]]; then
				printf '    %-15s %-38s %s bytes\n' "$src" "$file" "$(stat -c %s "$dir/$file")" >&2
			else
				printf '    %-15s %s\n' "$src" "not captured for this window" >&2
			fi
		done
	done
	[[ "$found" -eq 1 ]] || log "no captures found in $OUTDIR"
	exit 0
fi

# ---------------------------------------------------------------------------
# Resolve the run
# ---------------------------------------------------------------------------
if [[ -z "$RUN" ]]; then
	# `|| true` is load-bearing: with `set -o pipefail`, find's non-zero exit on a
	# missing directory fails the whole assignment, and `set -e` then kills the script
	# before the explanatory message below can be printed. Silent exit 1, no reason given.
	# Each capture is a directory named for its window, holding that window's files.
	latest=$(find "$OUTDIR" -mindepth 2 -maxdepth 2 -name 'firewall_*.manifest.json' 2>/dev/null | sort | tail -1 || true)
	[[ -n "$latest" ]] || fail "no captures found in $OUTDIR — run a capture first"
	RUN=$(basename "$(dirname "$latest")")
fi

RUN_DIR="$OUTDIR/$RUN"
MANIFEST="$RUN_DIR/firewall_${RUN}.manifest.json"
GROUP="$RUN_DIR/window_${RUN}.group.json"
[[ -f "$MANIFEST" ]] || fail "no manifest for window $RUN ($MANIFEST)"

# The coverage window is a property of the capture, not of the source: both sources
# observed the same packets over the same period, so both items carry the same window
# and correlation can line them up along it. Only the artifact and its digest differ.
#
# The firewall's digest lives in its own manifest; every other source's lives in the group
# manifest, which is the record that says they all describe one window.
CONTENT_TYPE="text/plain"
case "$SOURCE" in
	firewall)
		SOURCE_KEY="${SOURCE_KEY_OVERRIDE:-$FW_SOURCE_KEY}"
		DISPLAY_NAME="$FW_DISPLAY_NAME"; SOURCE_TYPE="$FW_SOURCE_TYPE" ;;
	ids)
		SOURCE_KEY="${SOURCE_KEY_OVERRIDE:-$IDS_SOURCE_KEY}"
		DISPLAY_NAME="$IDS_DISPLAY_NAME"; SOURCE_TYPE="$IDS_SOURCE_TYPE" ;;
	banking-events)
		SOURCE_KEY="${SOURCE_KEY_OVERRIDE:-$BANK_EVENTS_SOURCE_KEY}"
		DISPLAY_NAME="$BANK_EVENTS_DISPLAY_NAME"; SOURCE_TYPE="$BANK_EVENTS_SOURCE_TYPE"
		CONTENT_TYPE="application/x-ndjson" ;;
	banking-audit)
		SOURCE_KEY="${SOURCE_KEY_OVERRIDE:-$BANK_AUDIT_SOURCE_KEY}"
		DISPLAY_NAME="$BANK_AUDIT_DISPLAY_NAME"; SOURCE_TYPE="$BANK_AUDIT_SOURCE_TYPE"
		CONTENT_TYPE="application/x-ndjson" ;;
	auth)
		SOURCE_KEY="${SOURCE_KEY_OVERRIDE:-$AUTH_SOURCE_KEY}"
		DISPLAY_NAME="$AUTH_DISPLAY_NAME"; SOURCE_TYPE="$AUTH_SOURCE_TYPE" ;;
esac
# The dedupe key: <source>_<window>, the artifact's own name without its extension.
ARTIFACT_ID="${SOURCE}_${RUN}"

if [[ "$SOURCE" == "firewall" ]]; then
	LOG_FILE="$RUN_DIR/firewall_${RUN}.log"
	read -r EVENT_START EVENT_END MANIFEST_SHA256 < <(python3 -c '
import json, sys
m = json.load(open(sys.argv[1]))
print(m["window"]["start_utc"], m["window"]["end_utc"], m["output"]["sha256"])
' "$MANIFEST") || true
else
	[[ -f "$GROUP" ]] || fail "window $RUN has no $SOURCE evidence (no $GROUP) — only the firewall was captured"
	read -r EVENT_START EVENT_END MANIFEST_SHA256 ITEM_FILE < <(python3 -c '
import json, sys
g = json.load(open(sys.argv[1]))
item = next((i for i in g["items"] if i["pde_source"] == sys.argv[2]), None)
if item is None:
    raise SystemExit("group manifest lists no %s item" % sys.argv[2])
print(g["window"]["start_utc"], g["window"]["end_utc"], item["sha256"], item["file"])
' "$GROUP" "$SOURCE") || true
	[[ -n "${ITEM_FILE:-}" ]] || fail "window $RUN has no $SOURCE evidence — it was captured without that source"
	LOG_FILE="$RUN_DIR/$ITEM_FILE"
fi

[[ -f "$LOG_FILE" ]] || fail "window $RUN has no $SOURCE evidence ($LOG_FILE)"
[[ -n "$MANIFEST_SHA256" ]] || fail "no recorded sha256 for the $SOURCE artifact — treat window $RUN as suspect"

# ---------------------------------------------------------------------------
# Local integrity check, before anything is sent
# ---------------------------------------------------------------------------
ACTUAL_SHA256=$(sha256sum "$LOG_FILE" | cut -d' ' -f1)
if [[ "$ACTUAL_SHA256" != "$MANIFEST_SHA256" ]]; then
	log "the log file no longer matches the digest recorded at capture:"
	log "  manifest    $MANIFEST_SHA256"
	log "  recomputed  $ACTUAL_SHA256"
	fail "refusing to submit the $SOURCE artifact from window $RUN — it changed after it was captured"
fi

BYTES=$(stat -c %s "$LOG_FILE")
METADATA=$(python3 -c '
import json, sys
print(json.dumps({
	"sourceKey": sys.argv[1],
	"sourceArtifactId": sys.argv[2],
	"eventStart": sys.argv[3],
	"eventEnd": sys.argv[4],
	"sourceSha256": sys.argv[5],
}))
' "$SOURCE_KEY" "$ARTIFACT_ID" "$EVENT_START" "$EVENT_END" "$MANIFEST_SHA256")

if [[ "$DRY_RUN" -eq 1 ]]; then
	log "POST $URL/api/evidence-items"
	log ""
	log "metadata part (application/json):"
	printf '%s\n' "$METADATA" | python3 -m json.tool | sed 's/^/    /' >&2
	log ""
	log "file part: $LOG_FILE (${BYTES} bytes, sha256 verified against the manifest)"
	log ""
	log "nothing was sent"
	exit 0
fi

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT
printf '%s' "$METADATA" > "$TMP_DIR/metadata.json"
# Created up front: curl writes no body file when the connection itself fails, and
# the error paths below read it.
: > "$TMP_DIR/response.json"

# ---------------------------------------------------------------------------
# Register the source, if asked and not already registered
# ---------------------------------------------------------------------------
if [[ -n "$WORK_GROUP" ]]; then
	# `|| true` rather than `|| echo "000"`: on a failed connection curl has already
	# printed 000 from -w, so appending another turns the code into "000000" and the
	# unreachable case below never matches.
	existing=$(curl -sS -u "$AUTH" -o /dev/null -w '%{http_code}' \
		"$URL/api/evidence-sources?sourceKey=$SOURCE_KEY" || true)
	existing="${existing:-000}"
	if [[ "$existing" == "200" ]]; then
		log "source $SOURCE_KEY is already registered"
	else
		python3 -c '
import json, sys
print(json.dumps({
	"sourceKey": sys.argv[1],
	"displayName": sys.argv[2],
	"workGroupId": sys.argv[3],
	"sourceType": sys.argv[4],
}))
' "$SOURCE_KEY" "$DISPLAY_NAME" "$WORK_GROUP" "$SOURCE_TYPE" > "$TMP_DIR/source.json"

		: > "$TMP_DIR/register.out"
		code=$(curl -sS -u "$AUTH" -o "$TMP_DIR/register.out" -w '%{http_code}' \
			-X POST "$URL/api/evidence-sources" \
			-H 'Content-Type: application/json' \
			--data-binary "@$TMP_DIR/source.json" || true)
		code="${code:-000}"
		case "$code" in
			201) log "registered source $SOURCE_KEY under work group $WORK_GROUP" ;;
			404) fail "no work group with id $WORK_GROUP — list them with: curl -u $AUTH $URL/api/work-groups" ;;
			*)   [[ -s "$TMP_DIR/register.out" ]] && sed 's/^/    /' "$TMP_DIR/register.out" >&2
				 fail "could not register the source (HTTP $code)" ;;
		esac
	fi
fi

# ---------------------------------------------------------------------------
# Submit
# ---------------------------------------------------------------------------
log "submitting the $SOURCE artifact from window $RUN as $ARTIFACT_ID (${BYTES} bytes) to $URL"

CODE=$(curl -sS -u "$AUTH" -o "$TMP_DIR/response.json" -w '%{http_code}' \
	-X POST "$URL/api/evidence-items" \
	-F "metadata=<$TMP_DIR/metadata.json;type=application/json" \
	-F "file=@$LOG_FILE;type=$CONTENT_TYPE" || true)
CODE="${CODE:-000}"

response_field() {
	python3 -c '
import json, sys
try:
	print(json.load(open(sys.argv[1])).get(sys.argv[2], ""))
except Exception:
	print("")
' "$TMP_DIR/response.json" "$1" 2>/dev/null
}

case "$CODE" in
	201)
		log "preserved"
		printf '    %-12s %s\n' "id" "$(response_field id)" >&2
		printf '    %-12s %s\n' "digest" "$(response_field currentHash)" >&2
		printf '    %-12s %s\n' "status" "$(response_field status)" >&2
		# The repository computed that digest from the bytes it received and re-checked
		# it against the object it stored. Matching the manifest is the point: it is what
		# makes "nothing happened to this file in transit" a verified statement.
		if [[ "$(response_field currentHash)" == "$MANIFEST_SHA256" ]]; then
			log "the repository's digest matches the one taken at capture"
		else
			log "WARNING: the repository stored a different digest than the manifest records"
		fi
		;;
	409)
		log "already preserved — this artifact was submitted before, and the repository"
		log "dedupes on (source, artifact id) so it was not stored twice"
		;;
	404)
		log "no source is registered under the key '$SOURCE_KEY'"
		log "each PDE source registers separately — register this one first:"
		log "  $0 --source $SOURCE --register-with <workGroupId>"
		exit 1
		;;
	422)
		log "the repository's integrity check failed: the bytes it received do not hash"
		log "to the digest this capture asserted. Nothing was preserved."
		[[ -s "$TMP_DIR/response.json" ]] && sed 's/^/    /' "$TMP_DIR/response.json" >&2
		exit 1
		;;
	401)
		log "authentication failed for user '${AUTH%%:*}' — set --auth or DFRAAS_AUTH"
		exit 1
		;;
	413)
		log "the artifact is larger than the repository's multipart limit"
		log "raise MAX_ARTIFACT_SIZE on the backend, or capture a shorter window"
		exit 1
		;;
	503)
		log "the repository could not reach its object store, so nothing was preserved."
		log "Safe to run again once it is back: the same capture re-derives the same"
		log "storage key and the same artifact id."
		exit 1
		;;
	000)
		log "could not reach $URL"
		log "If the repository runs on the research VM, open the admin tunnel and point at it:"
		log "  ./vm.sh tunnel up    then    DFRAAS_URL=http://localhost:18080 $0"
		log "If the backend runs on Windows and this is WSL, localhost may not route"
		log "there. Try the host address:"
		log "  DFRAAS_URL=http://\$(ip route show default | awk '{print \$3}'):8080 $0"
		exit 1
		;;
	*)
		log "unexpected response (HTTP $CODE)"
		[[ -s "$TMP_DIR/response.json" ]] && sed 's/^/    /' "$TMP_DIR/response.json" >&2
		exit 1
		;;
esac
