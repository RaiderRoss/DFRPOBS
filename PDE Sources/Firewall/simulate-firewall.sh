#!/usr/bin/env bash
#
# Ubuntu Firewall (ufw) PDE source simulator.
#
# Produces a genuine ufw log file for a controlled traffic scenario. Nothing about the
# log format is authored here: real packets cross the real INPUT chain and the kernel's
# netfilter LOG target writes the lines. What this script controls is the experiment —
# how many users, for how long, and what fraction of them behave maliciously.
#
# Requires root (it manipulates the firewall and creates a network namespace) and puts
# the host firewall back exactly as it found it on exit, including on Ctrl-C.
#
#   sudo ./simulate-firewall.sh --users 10 --duration 30 --malicious-pct 10
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
USERS=10
DURATION=30
RATE=20
MALICIOUS_PCT=10
MALICIOUS_USERS=1
ATTACK_PROFILE=port-scan
SEED=1337
OUTDIR="$SCRIPT_DIR/../output"
DRY_RUN=0
KEEP_FIREWALL=0

# Test subnet. Deliberately not a range anything else on this host uses, so extraction
# can separate simulated traffic from whatever else the firewall happens to log.
SUBNET="10.99.0.0/24"
HOST_IP="10.99.0.1"
USER_IP_BASE="10.99.0."
USER_IP_OFFSET=10          # first user is 10.99.0.11

NS="pde-fw"
VETH_HOST="veth-pde-h"
VETH_NS="veth-pde-n"

# Ports the firewall permits — ordinary application traffic.
BENIGN_PORTS="80,443,8080"
# Ports the firewall denies — the sweep an attacker runs looking for a way in.
MALICIOUS_PORTS="21,22,23,135,139,445,1433,3306,3389,5432,5900,6379,9200,27017"

# Host services kept reachable while ufw is up, so enabling a default-deny firewall
# does not cut off the dev stack or the Windows host's access to it.
PRESERVE_PORTS="22,5432,5433,8080,9000,9001,19092,8081"

UFW_LOG="/var/log/ufw.log"
KERN_LOG="/var/log/kern.log"

usage() {
	sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'
	cat <<-EOF

	Options:
	  --users N              simulated users, one source IP each   (default $USERS)
	  --duration S           capture window in seconds             (default $DURATION)
	  --rate R               connection attempts per second        (default $RATE)
	  --malicious-pct P      share of *events* that are malicious  (default $MALICIOUS_PCT)
	  --malicious-users N    how many *users* are attackers        (default $MALICIOUS_USERS)
	  --attack-profile P     attacker behaviour                    (default $ATTACK_PROFILE)
	                         port-scan|brute-force|db-probe|stealth|syn-burst|mixed
	  --seed N               makes a run reproducible              (default $SEED)
	  --outdir DIR           where the log and manifest land       (default $OUTDIR)
	  --dry-run              print the firewall changes and exit
	  --keep-firewall        skip teardown (debugging only)

	Note that --malicious-pct and --malicious-users are independent knobs. "10%" of
	events and a 10:1 user ratio are not the same statement, and a brief should say
	which one it means: 10:1 users is 9.09% of users, not 10%.
	EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		--users) USERS="$2"; shift 2 ;;
		--duration) DURATION="$2"; shift 2 ;;
		--rate) RATE="$2"; shift 2 ;;
		--malicious-pct) MALICIOUS_PCT="$2"; shift 2 ;;
		--malicious-users) MALICIOUS_USERS="$2"; shift 2 ;;
		--attack-profile) ATTACK_PROFILE="$2"; shift 2 ;;
		--seed) SEED="$2"; shift 2 ;;
		--outdir) OUTDIR="$2"; shift 2 ;;
		--dry-run) DRY_RUN=1; shift ;;
		--keep-firewall) KEEP_FIREWALL=1; shift ;;
		-h|--help) usage; exit 0 ;;
		*) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
	esac
done

log() { printf '[%(%H:%M:%S)T] %s\n' -1 "$*"; }
die() { echo "error: $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
[[ $MALICIOUS_USERS -lt $USERS ]] || die "--malicious-users must be less than --users"
command -v ufw >/dev/null || die "ufw not installed"
command -v ip >/dev/null || die "iproute2 not installed"
command -v python3 >/dev/null || die "python3 not installed"

# --dry-run is what someone runs *before* deciding to let this touch their firewall, so
# it must not itself demand root.
if [[ $DRY_RUN -eq 0 ]]; then
	[[ $EUID -eq 0 ]] || die "must run as root (firewall rules and network namespaces)"
	pgrep -x rsyslogd >/dev/null || die "rsyslogd is not running; ufw log lines would not \
reach $UFW_LOG. Start it with: systemctl start rsyslog"
fi

# The LOG target is a module on the WSL kernel and is loaded on demand, but failing here
# with a clear message beats discovering an empty log file after the run.
modprobe xt_LOG 2>/dev/null || true
modprobe nf_log_syslog 2>/dev/null || true

# Build the user list.
declare -a USER_IPS=()
for ((i = 1; i <= USERS; i++)); do
	USER_IPS+=("${USER_IP_BASE}$((USER_IP_OFFSET + i))")
done
# Attackers are drawn from the end of the list so a run's benign users keep stable
# addresses as --malicious-users changes.
declare -a MALICIOUS_IPS=()
for ((i = 0; i < MALICIOUS_USERS; i++)); do
	MALICIOUS_IPS+=("${USER_IPS[$((USERS - 1 - i))]}")
done
USERS_CSV=$(IFS=,; echo "${USER_IPS[*]}")
MALICIOUS_CSV=$(IFS=,; echo "${MALICIOUS_IPS[*]:-}")

if [[ $DRY_RUN -eq 1 ]]; then
	cat <<-EOF
	Would apply:
	  ufw --force enable
	  ufw logging full                       # unrate-limited; see note below
	  ufw allow from $SUBNET to any port <${BENIGN_PORTS}> proto tcp
	  ufw allow to any port <${PRESERVE_PORTS}> proto tcp   # keep dev stack reachable
	  (everything else from $SUBNET falls to the default DROP and is logged as BLOCK)

	  ip netns add $NS
	  veth $VETH_HOST <-> $VETH_NS, host $HOST_IP/24
	  namespace addresses: ${USER_IPS[*]}
	  attackers: ${MALICIOUS_IPS[*]:-none}

	ufw logging must be 'full' rather than the default 'low'. At low/medium/high ufw
	rate-limits its own LOG rules to 3/min, which would reduce a ${DURATION}s window to a
	handful of lines regardless of how much traffic is generated.
	EOF
	exit 0
fi

# ---------------------------------------------------------------------------
# Snapshot the firewall so the run is reversible
# ---------------------------------------------------------------------------
STATE_DIR=$(mktemp -d /tmp/pde-fw-state.XXXXXX)
ORIG_ENABLED=$(grep -E '^ENABLED=' /etc/ufw/ufw.conf | cut -d= -f2)
ORIG_LOGLEVEL=$(grep -E '^LOGLEVEL=' /etc/ufw/ufw.conf | cut -d= -f2)
cp -a /etc/ufw/user.rules "$STATE_DIR/user.rules"
cp -a /etc/ufw/user6.rules "$STATE_DIR/user6.rules"
log "firewall state saved to $STATE_DIR (was ENABLED=$ORIG_ENABLED LOGLEVEL=$ORIG_LOGLEVEL)"

restore() {
	local rc=$?
	[[ $KEEP_FIREWALL -eq 1 ]] && { echo "--keep-firewall: leaving firewall and namespace in place"; return 0; }
	echo "restoring firewall and tearing down namespace..."
	ip netns pids "$NS" 2>/dev/null | xargs -r kill 2>/dev/null || true
	ip netns del "$NS" 2>/dev/null || true
	ip link del "$VETH_HOST" 2>/dev/null || true
	cp -a "$STATE_DIR/user.rules" /etc/ufw/user.rules 2>/dev/null || true
	cp -a "$STATE_DIR/user6.rules" /etc/ufw/user6.rules 2>/dev/null || true
	ufw logging "$ORIG_LOGLEVEL" >/dev/null 2>&1 || true
	if [[ "$ORIG_ENABLED" == "no" ]]; then
		ufw --force disable >/dev/null 2>&1 || true
	else
		ufw --force enable >/dev/null 2>&1 || true
	fi
	rm -rf "$STATE_DIR"
	echo "firewall restored to ENABLED=$ORIG_ENABLED LOGLEVEL=$ORIG_LOGLEVEL"
	return $rc
}
trap restore EXIT INT TERM

# ---------------------------------------------------------------------------
# Network namespace: one address per simulated user
# ---------------------------------------------------------------------------
log "creating namespace $NS with $USERS user addresses"
ip netns del "$NS" 2>/dev/null || true
ip link del "$VETH_HOST" 2>/dev/null || true

ip netns add "$NS"
ip link add "$VETH_HOST" type veth peer name "$VETH_NS"
ip link set "$VETH_NS" netns "$NS"
ip addr add "$HOST_IP/24" dev "$VETH_HOST"
ip link set "$VETH_HOST" up
ip netns exec "$NS" ip link set lo up
for ip_addr in "${USER_IPS[@]}"; do
	ip netns exec "$NS" ip addr add "$ip_addr/24" dev "$VETH_NS"
done
ip netns exec "$NS" ip link set "$VETH_NS" up

# ---------------------------------------------------------------------------
# Firewall
# ---------------------------------------------------------------------------
log "configuring ufw (logging=full, default deny incoming)"
IFS=',' read -ra _preserve <<< "$PRESERVE_PORTS"
for p in "${_preserve[@]}"; do
	ufw allow "$p/tcp" >/dev/null
done
IFS=',' read -ra _benign <<< "$BENIGN_PORTS"
for p in "${_benign[@]}"; do
	ufw allow from "$SUBNET" to any port "$p" proto tcp >/dev/null
done
ufw logging full >/dev/null
ufw --force enable >/dev/null
log "ufw active"

# ---------------------------------------------------------------------------
# Capture window
# ---------------------------------------------------------------------------
WINDOW_START_EPOCH=$(date -u +%s)
WINDOW_START_ISO=$(date -u -d "@$WINDOW_START_EPOCH" +%Y-%m-%dT%H:%M:%SZ)
STAMP=$(date -u -d "@$WINDOW_START_EPOCH" +%Y%m%d%H%M%S)

# Byte offset rather than a timestamp filter: syslog's traditional format has neither a
# year nor sub-second precision, so it cannot reliably bound a 30-second window on its own.
SRC_LOG="$UFW_LOG"
[[ -f "$SRC_LOG" ]] || SRC_LOG="$KERN_LOG"
LOG_OFFSET=$(stat -c %s "$SRC_LOG" 2>/dev/null || echo 0)
log "capturing from $SRC_LOG at byte offset $LOG_OFFSET"

mkdir -p "$OUTDIR"
GT_JSON="$OUTDIR/firewall_${STAMP}.groundtruth.json"
OUT_LOG="$OUTDIR/firewall_${STAMP}.log"
MANIFEST="$OUTDIR/firewall_${STAMP}.manifest.json"

log "generating traffic: ${USERS} users, ${DURATION}s, ${RATE}/s, ${MALICIOUS_PCT}% malicious, profile=${ATTACK_PROFILE}"
ip netns exec "$NS" python3 "$SCRIPT_DIR/generate_traffic.py" \
	--users "$USERS_CSV" \
	--malicious-users "$MALICIOUS_CSV" \
	--target "$HOST_IP" \
	--duration "$DURATION" \
	--rate "$RATE" \
	--malicious-pct "$MALICIOUS_PCT" \
	--attack-profile "$ATTACK_PROFILE" \
	--benign-ports "$BENIGN_PORTS" \
	--malicious-ports "$MALICIOUS_PORTS" \
	--seed "$SEED" \
	--out "$GT_JSON"

WINDOW_END_ISO=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# rsyslog batches writes; without this the tail of the window is routinely missing.
log "waiting for rsyslog to flush"
sleep 3

# ---------------------------------------------------------------------------
# Extract, hash, seal
# ---------------------------------------------------------------------------
tail -c "+$((LOG_OFFSET + 1))" "$SRC_LOG" 2>/dev/null \
	| grep -F "SRC=${USER_IP_BASE}" > "$OUT_LOG" || true

LINES=$(wc -l < "$OUT_LOG")
BYTES=$(stat -c %s "$OUT_LOG")
# `|| echo 0` rather than `|| true`: grep exits 1 on zero matches and prints nothing,
# which would leave these empty and produce invalid JSON in the manifest below.
BLOCKED=$(grep -c 'UFW BLOCK' "$OUT_LOG" || echo 0)
ALLOWED=$(grep -c 'UFW ALLOW' "$OUT_LOG" || echo 0)

if [[ $LINES -eq 0 ]]; then
	echo "warning: no ufw log lines captured. Check that ufw logging is not being" >&2
	echo "         rate-limited and that $SRC_LOG is being written to." >&2
fi

# Hashed before anything else touches the file, per the SecureRS ingestion rule the
# Evidence Repository follows. This digest is what the EvidenceItem will carry.
SHA256=$(sha256sum "$OUT_LOG" | cut -d' ' -f1)
chmod 444 "$OUT_LOG"

python3 - "$MANIFEST" <<PY
import json, subprocess, sys
manifest = {
    "source": {
        "pde_source": "firewall",
        "product": "ufw",
        "version": subprocess.run(["ufw","--version"], capture_output=True, text=True)
                     .stdout.splitlines()[0].strip(),
        "kernel": subprocess.run(["uname","-r"], capture_output=True, text=True).stdout.strip(),
        "log_facility": "netfilter LOG target -> rsyslog -> ${SRC_LOG}",
        "collection_method": "real packets across the host INPUT chain; log lines are "
                            "kernel-generated and were not synthesised",
    },
    "window": {
        "start_utc": "${WINDOW_START_ISO}",
        "end_utc": "${WINDOW_END_ISO}",
        "duration_seconds": ${DURATION},
    },
    "configuration": {
        "users": ${USERS},
        "malicious_users": ${MALICIOUS_USERS},
        "malicious_event_pct": ${MALICIOUS_PCT},
        "attack_profile": "${ATTACK_PROFILE}",
        "events_per_second": ${RATE},
        "seed": ${SEED},
        "subnet": "${SUBNET}",
        "benign_ports": [int(p) for p in "${BENIGN_PORTS}".split(",")],
        "malicious_ports": [int(p) for p in "${MALICIOUS_PORTS}".split(",")],
    },
    "output": {
        "log_file": "firewall_${STAMP}.log",
        "ground_truth_file": "firewall_${STAMP}.groundtruth.json",
        "lines": ${LINES},
        "bytes": ${BYTES},
        "ufw_block_lines": ${BLOCKED},
        "ufw_allow_lines": ${ALLOWED},
        "sha256": "${SHA256}",
    },
    "caveats": [
        "syslog timestamps carry no year and no sub-second precision; the authoritative "
        "window bounds are window.start_utc/end_utc recorded by the generator",
        "lines are filtered to SRC=${USER_IP_BASE}* — unrelated host traffic logged in the "
        "same window is excluded",
        "ufw logging was set to 'full' for the run; at the default 'low' its LOG rules are "
        "rate-limited to 3/min and most of the window would be lost",
    ],
}
json.dump(manifest, open(sys.argv[1], "w"), indent=2)
PY

# Files are created by root; hand them back to whoever invoked sudo.
if [[ -n "${SUDO_USER:-}" ]]; then
	chown "$SUDO_USER" "$OUT_LOG" "$MANIFEST" "$GT_JSON" 2>/dev/null || true
fi

log "captured $LINES lines ($BLOCKED BLOCK, $ALLOWED ALLOW)"
log "sha256 $SHA256"
log "  log      $OUT_LOG"
log "  manifest $MANIFEST"
log "  truth    $GT_JSON"
