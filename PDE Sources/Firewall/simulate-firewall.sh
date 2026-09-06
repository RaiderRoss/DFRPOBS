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

# IDS correlation. When enabled, Slips sniffs the veth this script creates, so both
# sources observe the same packets over the same window.
WITH_IDS=0
IDS_READY_TIMEOUT=240
# Slips raises evidence in batches after it has seen the flows, so stopping it the
# instant the window closes reliably collects nothing. This is how long to keep it
# running past the window before collecting.
IDS_DRAIN=45

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
#
# Deliberately wide. The firewall logs a BLOCK however few ports are touched, but an
# IDS decides "vertical port scan" from the number of DISTINCT ports one source reaches
# for on one host inside a timewindow. The earlier 14-port list is thin enough to sit
# under that threshold, which would leave the IDS silent about an attack the firewall
# recorded plainly — the opposite of the correlation this is built to show.
# (slips-cli.sh's own working demo sweeps 70 ports.) None may overlap BENIGN_PORTS.
MALICIOUS_PORTS="21,22,23,25,53,110,111,135,137,139,143,161,389,445,512,513,514,873,993,995,1080,1433,1521,2049,2375,3306,3389,5060,5432,5900,6379,8443,9200,11211,27017"

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
	  --with-ids             also run Slips on the veth, so the IDS observes the
	                         same packets over the same window (adds ~2 min of
	                         startup before the window, and --ids-drain after)
	  --ids-drain S          seconds to keep Slips running past the window so it
	                         can raise evidence for it       (default $IDS_DRAIN)

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
		--with-ids) WITH_IDS=1; shift ;;
		--ids-drain) IDS_DRAIN="$2"; shift 2 ;;
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
# Used directly for verdict logging; see the note where the LOG rules are installed.
command -v iptables >/dev/null || die "iptables not installed"
command -v python3 >/dev/null || die "python3 not installed"

# --dry-run is what someone runs *before* deciding to let this touch their firewall, so
# it must not itself demand root.
if [[ $DRY_RUN -eq 0 ]]; then
	[[ $EUID -eq 0 ]] || die "must run as root (firewall rules and network namespaces)"
	pgrep -x rsyslogd >/dev/null || die "rsyslogd is not running; ufw log lines would not \
reach $UFW_LOG. Start it with: systemctl start rsyslog"
fi

IDS_LIB="$SCRIPT_DIR/../IDS/slips-lib.sh"
if [[ $WITH_IDS -eq 1 ]]; then
	[[ -f "$IDS_LIB" ]] || die "--with-ids needs $IDS_LIB"
	# shellcheck source=../IDS/slips-lib.sh
	source "$IDS_LIB"
	if [[ $DRY_RUN -eq 0 ]]; then
		slips_preflight || die "IDS preflight failed"
	fi
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

	  # Order matters, and these are applied in this order:
	  ufw allow from $SUBNET to any port <${BENIGN_PORTS}> proto tcp
	  ufw deny  from $SUBNET                                 # everything else = the attacker
	  ufw allow to any port <${PRESERVE_PORTS}> proto tcp    # keep dev stack reachable

	  PRESERVE_PORTS overlaps the attacker's port list (22, 5432), so the subnet rules
	  must come first — otherwise attacker traffic to those ports matches a permit rule
	  and is logged as allowed, mislabelling part of the dataset.

	  Then, into ufw's own chain, two unrate-limited LOG rules:
	  iptables -I ufw-user-input 1 -s $SUBNET -p tcp -m multiport --dports <${BENIGN_PORTS}> \\
	           -j LOG --log-prefix "[UFW ALLOW] "
	  iptables -I ufw-user-input 2 -s $SUBNET -p tcp -m multiport ! --dports <${BENIGN_PORTS}> \\
	           -j LOG --log-prefix "[UFW BLOCK] "

	  ufw's own 'log' keyword hardcodes -m limit --limit 3/min --limit-burst 10 with no
	  loglevel check, so it caps verdict lines at ~11 per rule per 30s no matter what
	  'logging full' says. These replace it. They are removed when ufw reloads on restore.

	  ip netns add $NS
	  veth $VETH_HOST <-> $VETH_NS, host $HOST_IP/24
	  namespace addresses: ${USER_IPS[*]}
	  attackers: ${MALICIOUS_IPS[*]:-none}

	ufw rate-limits logging in two independent places, and both would gut a ${DURATION}s window:

	  1. the AUDIT chains, limited below loglevel 'high' — lifted by 'logging full'
	  2. the per-rule 'log' keyword, limited unconditionally with no loglevel check
	     — not lifted by anything, which is why the LOG rules above are installed
	     directly instead

	Without both, a run returns roughly 11 verdict lines per rule and looks like a
	firewall that saw almost no traffic.
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
	# Slips must let go of the interface before it is deleted underneath it.
	if [[ $WITH_IDS -eq 1 ]] && declare -F slips_stop >/dev/null; then
		slips_stop
	fi
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
# IDS
#
# Started here, between creating the interface and opening the window: Slips can only
# attach to a veth that already exists, and it must be reading packets before any are
# generated. Its ~80s of module and threat-feed loading is why this cannot be deferred
# to just before the traffic — a window opened during startup is simply not observed.
#
# ufw is configured *after* this, so `logging full` is active for the window rather
# than for the couple of minutes Slips spends starting up.
# ---------------------------------------------------------------------------

# Named for the run only once the window has a timestamp; until then Slips writes to a
# scratch directory, because STAMP is deliberately taken from the window start and the
# window has not opened yet.
if [[ $WITH_IDS -eq 1 ]]; then
	SLIPS_OUT="$OUTDIR/ids-run"
	rm -rf "$SLIPS_OUT"
	log "starting Slips on $VETH_HOST (loading modules and threat-intel feeds)"
	slips_start_redis || die "could not start the Slips redis"
	slips_start "$VETH_HOST" "$SLIPS_OUT" || die "could not start Slips"
	slips_wait_ready "$IDS_READY_TIMEOUT" || die "Slips never became ready"
	log "Slips is reading $VETH_HOST"
fi

# ---------------------------------------------------------------------------
# Firewall
# ---------------------------------------------------------------------------
log "configuring ufw (logging=full, default deny incoming)"
# Rule ORDER carries the labelling, and ufw evaluates in the order rules are added.
# PRESERVE_PORTS deliberately overlaps MALICIOUS_PORTS (22 and 5432 are both a service
# this host needs reachable and a port an attacker probes). If the preserve rules came
# first they would match the simulated attacker too, and those attempts would be logged
# as permitted — silently mislabelling part of the dataset. So the test subnet's rules
# are added first and are scoped to the subnet, and the host-wide preserve rules can
# only ever match traffic from somewhere else.
IFS=',' read -ra _benign <<< "$BENIGN_PORTS"
for p in "${_benign[@]}"; do
	ufw allow from "$SUBNET" to any port "$p" proto tcp >/dev/null
done

# Everything else from the test subnet is the attacker. An explicit deny is clearer
# than relying on the default policy and, unlike the default, it is unambiguously
# attributable to this run.
ufw deny from "$SUBNET" >/dev/null

IFS=',' read -ra _preserve <<< "$PRESERVE_PORTS"
for p in "${_preserve[@]}"; do
	ufw allow "$p/tcp" >/dev/null
done
ufw logging full >/dev/null
ufw --force enable >/dev/null

# ---------------------------------------------------------------------------
# Verdict logging, installed directly rather than through ufw's `log` keyword.
#
# ufw hardcodes `-m limit --limit 3/min --limit-burst 10` onto every per-rule log,
# with no loglevel check (backend_iptables.py: `limit_args` in the rule-snippet
# builder). `ufw logging full` only lifts the limit from the AUDIT chains, which take
# their own branch. The result is that a 30s window yields ~11 verdict lines per rule —
# burst 10 plus 3/min for half a minute — however much traffic crosses the firewall,
# while the AUDIT lines beside them are complete. A dataset labelled from that is
# missing 95% of its verdicts.
#
# These rules live in ufw's own chain, use the same kernel LOG target and the same
# prefixes; the only difference is the absence of a rate limit that exists to protect
# syslog on a production host and has no place in a 30-second measurement. LOG does not
# terminate a packet's traversal, so the allow/deny rules below still decide its fate.
# ufw reloads its chains from user.rules on enable/disable, so these do not survive the
# restore in the exit trap.
# ---------------------------------------------------------------------------
iptables -I ufw-user-input 1 -s "$SUBNET" -p tcp -m multiport --dports "$BENIGN_PORTS" \
	-j LOG --log-prefix "[UFW ALLOW] " --log-level 4
iptables -I ufw-user-input 2 -s "$SUBNET" -p tcp -m multiport ! --dports "$BENIGN_PORTS" \
	-j LOG --log-prefix "[UFW BLOCK] " --log-level 4
log "ufw active (verdict logging installed without ufw's 3/min cap)"

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

# NOT named LINES. `LINES` is a bash special variable: with `checkwinsize` on — the
# default since bash 5.0, and it applies to scripts too whenever the shell has a
# terminal — bash rewrites LINES with the terminal's height after *every* external
# command. The assignment below is correct and the value is destroyed one command later,
# so the manifest silently records the height of whoever's window ran it. It only
# reproduces on a tty, which is why piped tests never caught it.
LOG_LINES=$(wc -l < "$OUT_LOG")
BYTES=$(stat -c %s "$OUT_LOG")

# `grep -c` prints "0" *and* exits 1 when nothing matches, so `|| echo 0` emits "0\n0"
# — two values where the manifest expects one, which is a JSON syntax error rather than
# a wrong number. `|| true` keeps grep's own "0" and only suppresses the exit status.
count_lines() {
	local n
	n=$(grep -c "$1" "$OUT_LOG" 2>/dev/null || true)
	printf '%s' "${n:-0}"
}
BLOCKED=$(count_lines 'UFW BLOCK')
ALLOWED=$(count_lines 'UFW ALLOW')
# At `logging full` ufw also emits an [UFW AUDIT] line for every packet it sees, from
# the ufw-before-logging chains, in addition to any verdict line. Counted separately so
# the totals reconcile: a blocked packet produces both an AUDIT and a BLOCK line.
AUDITED=$(count_lines 'UFW AUDIT')

# Every captured line carries exactly one ufw prefix, so the verdicts must account for
# all of them. This is cheap and it is what would have caught LINES being silently
# replaced by the terminal height: 11 + 33 + 1136 against a reported 17.
TALLIED=$((BLOCKED + ALLOWED + AUDITED))
if [[ $TALLIED -ne $LOG_LINES ]]; then
	echo "warning: verdict counts do not reconcile with the line count" >&2
	echo "         ${BLOCKED} BLOCK + ${ALLOWED} ALLOW + ${AUDITED} AUDIT = ${TALLIED}, but the file has ${LOG_LINES} lines." >&2
	echo "         The manifest may be wrong; treat this run as suspect." >&2
fi

if [[ $LOG_LINES -eq 0 ]]; then
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
        "lines": ${LOG_LINES},
        "bytes": ${BYTES},
        "ufw_block_lines": ${BLOCKED},
        "ufw_allow_lines": ${ALLOWED},
        "ufw_audit_lines": ${AUDITED},
        "sha256": "${SHA256}",
    },
    "caveats": [
        "syslog timestamps carry no year and no sub-second precision; the authoritative "
        "window bounds are window.start_utc/end_utc recorded by the generator",
        "lines are filtered to SRC=${USER_IP_BASE}* — unrelated host traffic logged in the "
        "same window is excluded. Both directions are kept, so the host's RST replies to "
        "refused connections appear alongside the inbound attempts",
        "ufw logging was set to 'full' for the run; at the default 'low' its LOG rules are "
        "rate-limited to 3/min and most of the window would be lost",
        "at 'full' ufw emits an [UFW AUDIT] line for every packet in addition to any "
        "verdict line, so lines exceeds the event count: a blocked attempt produces both "
        "an AUDIT and a BLOCK entry",
        "verdict logging ([UFW ALLOW] / [UFW BLOCK]) was installed as unrate-limited LOG "
        "rules in ufw's own ufw-user-input chain rather than via ufw's 'log' keyword, "
        "which hardcodes --limit 3/min --limit-burst 10 regardless of logging level and "
        "would cap a 30s window at roughly 11 verdict lines per rule. Same kernel LOG "
        "target, same prefixes, no rate limit",
        "a blocked SYN is retransmitted by the client kernel, so one blocked attempt can "
        "produce several BLOCK lines; count distinct SPT values, not lines, to recover "
        "the attempt count",
    ],
}
json.dump(manifest, open(sys.argv[1], "w"), indent=2)
PY

# ---------------------------------------------------------------------------
# IDS evidence for the same window
# ---------------------------------------------------------------------------
IDS_LOG="$OUTDIR/ids_${STAMP}.alerts.log"
GROUP_MANIFEST="$OUTDIR/window_${STAMP}.group.json"
IDS_TOTAL=0; IDS_KEPT=0; IDS_SHA=""; IDS_SEVERITIES="0 0 0 0 0"

if [[ $WITH_IDS -eq 1 ]]; then
	# Slips raises evidence in batches once it has seen the flows, so the window's
	# findings do not exist yet at this point. Draining is not politeness, it is the
	# difference between collecting the evidence and collecting an empty file.
	log "draining Slips for ${IDS_DRAIN}s so it can raise evidence for the window"
	sleep "$IDS_DRAIN"

	# Stopped before anything is read: alerts.log is being appended to while Slips
	# runs, and evidence is what this file is for — it should not be collected from a
	# moving target.
	slips_stop
	log "Slips stopped; collecting"

	# Defended rather than trusted: `read` returns non-zero on an empty herestring,
	# which under `set -e` would abort the run at the point where the evidence has been
	# collected but nothing has been written down about it.
	IDS_COUNTS=$(slips_collect "$SLIPS_OUT" "$WINDOW_START_ISO" "$WINDOW_END_ISO" "$IDS_LOG" || echo "0 0")
	read -r IDS_TOTAL IDS_KEPT <<< "$IDS_COUNTS" || true
	IDS_TOTAL=${IDS_TOTAL:-0}
	IDS_KEPT=${IDS_KEPT:-0}
	IDS_SEVERITIES=$(slips_severity_counts "$IDS_LOG")
	IDS_SHA=$(sha256sum "$IDS_LOG" | cut -d' ' -f1)
	chmod 444 "$IDS_LOG"
	log "IDS evidence: ${IDS_KEPT} of ${IDS_TOTAL} findings fall inside the window"

	# Keep Slips' full working tree per run, not just the alerts: zeek_files/conn.log
	# is the flow record behind the findings, and an investigator asking "on what basis"
	# needs it. Safe to move now that the container is stopped.
	if [[ -d "$SLIPS_OUT" ]]; then
		rm -rf "$OUTDIR/ids_${STAMP}"
		mv "$SLIPS_OUT" "$OUTDIR/ids_${STAMP}"
		SLIPS_OUT="$OUTDIR/ids_${STAMP}"
	fi

	# The group is the point of the exercise: one window, one attack, two independent
	# sources that saw it. This is the record an EvidenceGroup row would be built from.
	python3 - "$GROUP_MANIFEST" <<PY
import json, sys
crit, high, med, low, info = "${IDS_SEVERITIES}".split()
group = {
    "group_id": "${STAMP}",
    "window": {
        "start_utc": "${WINDOW_START_ISO}",
        "end_utc": "${WINDOW_END_ISO}",
        "duration_seconds": ${DURATION},
    },
    "scenario": {
        "users": ${USERS},
        "malicious_users": ${MALICIOUS_USERS},
        "malicious_event_pct": ${MALICIOUS_PCT},
        "attack_profile": "${ATTACK_PROFILE}",
        "seed": ${SEED},
        "subnet": "${SUBNET}",
    },
    "items": [
        {
            "pde_source": "firewall",
            "product": "ufw",
            "file": "firewall_${STAMP}.log",
            "sha256": "${SHA256}",
            "lines": ${LOG_LINES},
            "ufw_block_lines": ${BLOCKED},
            "ufw_allow_lines": ${ALLOWED},
            "ufw_audit_lines": ${AUDITED},
        },
        {
            "pde_source": "ids",
            "product": "slips",
            "file": "ids_${STAMP}.alerts.log",
            "sha256": "${IDS_SHA}",
            "evidence_lines": ${IDS_KEPT},
            "evidence_lines_seen_total": ${IDS_TOTAL},
            "threat_levels": {
                "critical": int(crit), "high": int(high),
                "medium": int(med), "low": int(low), "info": int(info),
            },
        },
    ],
    "correlation": (
        "Both items describe the same packets. Slips sniffed ${VETH_HOST} live while "
        "ufw logged the same traffic crossing the INPUT chain, so the two are "
        "independent accounts of one attack rather than one record split in two."
    ),
    "caveats": [
        "IDS findings are sliced to the window by the timestamp on each evidence line; "
        "Slips keeps its own 1-hour timewindows internally and its alert threshold "
        "accumulates per profile across that hour, not across this ${DURATION}s window",
        "a line whose timestamp cannot be parsed is kept rather than dropped",
    ],
}
json.dump(group, open(sys.argv[1], "w"), indent=2)
PY
fi

# Files are created by root; hand them back to whoever invoked sudo.
if [[ -n "${SUDO_USER:-}" ]]; then
	chown "$SUDO_USER" "$OUT_LOG" "$MANIFEST" "$GT_JSON" 2>/dev/null || true
	if [[ $WITH_IDS -eq 1 ]]; then
		chown "$SUDO_USER" "$IDS_LOG" "$GROUP_MANIFEST" 2>/dev/null || true
		# Slips writes its working tree as root inside the container.
		chown -R "$SUDO_USER" "$SLIPS_OUT" 2>/dev/null || true
	fi
fi

log "captured $LOG_LINES lines ($BLOCKED BLOCK, $ALLOWED ALLOW)"
log "sha256 $SHA256"
log "  log      $OUT_LOG"
log "  manifest $MANIFEST"
log "  truth    $GT_JSON"
