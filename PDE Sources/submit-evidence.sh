#!/usr/bin/env bash
#
# Submits a captured window to the DFRaaS Evidence Repository.
#
# One run becomes one EvidenceItem: the log file is the artifact, and the manifest
# supplies everything the repository needs to describe it — the coverage window the
# capture asserts, and the sha256 taken before anything else touched the file.
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
#   ./submit-evidence.sh --dry-run          # show exactly what would be sent
#   ./submit-evidence.sh                    # submit the most recent capture
#   ./submit-evidence.sh --run 20260905143000
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# Configuration. Every value can be set in pde.conf (which the console sources)
# or exported before running.
# ---------------------------------------------------------------------------
OUTDIR="${OUTDIR:-$SCRIPT_DIR/output}"
URL="${DFRAAS_URL:-http://localhost:8080}"
SOURCE_KEY="${DFRAAS_SOURCE_KEY:-pde-sim-ufw-01}"
AUTH="${DFRAAS_AUTH:-admin:admin}"
DISPLAY_NAME="${DFRAAS_DISPLAY_NAME:-PDE testbed firewall (ufw)}"
SOURCE_TYPE="${DFRAAS_SOURCE_TYPE:-FIREWALL}"

RUN=""
DRY_RUN=0
WORK_GROUP=""

log()  { printf '  %s\n' "$*" >&2; }
fail() { printf '  error: %s\n' "$*" >&2; exit 1; }

usage() {
	sed -n '2,22p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'
	cat <<-EOF

	Options:
	  --run ID               capture to submit, e.g. 20260905143000  (default: latest)
	  --outdir DIR           where captures live                     (default $OUTDIR)
	  --url URL              repository base URL                     (default $URL)
	  --source-key KEY       registered source to file under         (default $SOURCE_KEY)
	  --auth USER:PASS       HTTP Basic credentials                  (default admin:admin)
	  --register-with UUID   register the source first, under this work group
	  --dry-run              print the request and exit; sends nothing

	The source must be registered before its first upload. Registration is where
	classification is decided, so it takes a work group id and is a deliberate act —
	--register-with is the convenience form of it, not an automatic one:

	  curl -u $AUTH $URL/api/work-groups           # find the work group id
	  ./submit-evidence.sh --register-with <uuid>  # register it, then submit
	EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		--run) RUN="$2"; shift 2 ;;
		--outdir) OUTDIR="$2"; shift 2 ;;
		--url) URL="${2%/}"; shift 2 ;;
		--source-key) SOURCE_KEY="$2"; shift 2 ;;
		--auth) AUTH="$2"; shift 2 ;;
		--register-with) WORK_GROUP="$2"; shift 2 ;;
		--dry-run) DRY_RUN=1; shift ;;
		-h|--help) usage; exit 0 ;;
		*) fail "unknown option: $1 (try --help)" ;;
	esac
done

command -v curl    >/dev/null 2>&1 || fail "curl not found on PATH"
command -v python3 >/dev/null 2>&1 || fail "python3 not found on PATH"

# ---------------------------------------------------------------------------
# Resolve the run
# ---------------------------------------------------------------------------
if [[ -z "$RUN" ]]; then
	# `|| true` is load-bearing: with `set -o pipefail`, find's non-zero exit on a
	# missing directory fails the whole assignment, and `set -e` then kills the script
	# before the explanatory message below can be printed. Silent exit 1, no reason given.
	latest=$(find "$OUTDIR" -maxdepth 1 -name 'firewall_*.manifest.json' 2>/dev/null | sort | tail -1 || true)
	[[ -n "$latest" ]] || fail "no captures found in $OUTDIR — run a capture first"
	RUN=$(basename "$latest" | sed -e 's/^firewall_//' -e 's/\.manifest\.json$//')
fi

MANIFEST="$OUTDIR/firewall_${RUN}.manifest.json"
LOG_FILE="$OUTDIR/firewall_${RUN}.log"
[[ -f "$MANIFEST" ]] || fail "no manifest for run $RUN ($MANIFEST)"
[[ -f "$LOG_FILE" ]] || fail "no log file for run $RUN ($LOG_FILE)"

# The artifact id the repository dedupes on. Derived from the capture rather than
# generated here, so re-running this script for the same window is idempotent: the
# second attempt is rejected as a duplicate instead of preserving the log twice.
ARTIFACT_ID="firewall_${RUN}"

read -r EVENT_START EVENT_END MANIFEST_SHA256 < <(python3 -c '
import json, sys
m = json.load(open(sys.argv[1]))
print(m["window"]["start_utc"], m["window"]["end_utc"], m["output"]["sha256"])
' "$MANIFEST") || true

[[ -n "$MANIFEST_SHA256" ]] || fail "manifest has no sha256 — treat run $RUN as suspect"

# ---------------------------------------------------------------------------
# Local integrity check, before anything is sent
# ---------------------------------------------------------------------------
ACTUAL_SHA256=$(sha256sum "$LOG_FILE" | cut -d' ' -f1)
if [[ "$ACTUAL_SHA256" != "$MANIFEST_SHA256" ]]; then
	log "the log file no longer matches the digest recorded at capture:"
	log "  manifest    $MANIFEST_SHA256"
	log "  recomputed  $ACTUAL_SHA256"
	fail "refusing to submit run $RUN — it changed after it was captured"
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
log "submitting run $RUN as $ARTIFACT_ID (${BYTES} bytes) to $URL"

CODE=$(curl -sS -u "$AUTH" -o "$TMP_DIR/response.json" -w '%{http_code}' \
	-X POST "$URL/api/evidence-items" \
	-F "metadata=<$TMP_DIR/metadata.json;type=application/json" \
	-F "file=@$LOG_FILE;type=text/plain" || true)
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
		log "already preserved — this capture was submitted before, and the repository"
		log "dedupes on (source, artifact id) so it was not stored twice"
		;;
	404)
		log "no source is registered under the key '$SOURCE_KEY'"
		log "register it first:  $0 --register-with <workGroupId>"
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
