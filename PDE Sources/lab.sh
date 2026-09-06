#!/usr/bin/env bash
# ==============================================================
#  PDE lab lifecycle — up, down, status.
#
#  Brings up the standing infrastructure a capture is taken
#  against: the client topology, the firewall, and the IDS. All
#  three then stay running across as many windows as you like,
#  which is how a bank actually runs them, and which means the
#  IDS pays its ~50s of startup once rather than per capture.
#
#  Captures are taken by Firewall/simulate-firewall.sh, which
#  detects a running lab and uses it instead of building its own.
#
#    sudo ./lab.sh up --with-ids
#    sudo Firewall/simulate-firewall.sh          # window 1
#    sudo Firewall/simulate-firewall.sh          # window 2
#    sudo ./lab.sh down
#
#  IMPORTANT: while the lab is up your firewall is enabled with
#  test rules and full logging. `down` puts it back. `status`
#  detects a session that did not survive a reboot and offers to.
# ==============================================================
set -euo pipefail

PDE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lab-config.sh
source "$PDE_ROOT/lab-config.sh"
IDS_LIB="$PDE_ROOT/IDS/slips-lib.sh"

WITH_IDS=0
IDS_READY_TIMEOUT=240
USERS=10

log()  { printf '[%(%H:%M:%S)T] %s\n' -1 "$*"; }
die()  { echo "error: $*" >&2; exit 1; }

usage() {
	sed -n '2,22p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'
	cat <<-EOF

	Commands:
	  up [--with-ids] [--users N]   build the lab and leave it running
	  down                          restore the firewall and tear everything down
	  status                        report what is up, and detect a stale session

	EOF
}

lab_is_up() { [[ -f "$LAB_STATE" ]]; }

# Takes the namespace to look for rather than assuming the compiled-in default: the
# question is whether *this session's* namespace is alive, and a session may have
# recorded a different one. Checking the default would report a live lab on the strength
# of a namespace that has nothing to do with the recorded session.
netns_exists() {
	local ns="${1:-$NS}"
	ip netns list 2>/dev/null | awk '{print $1}' | grep -qx "$ns"
}

# ---------------------------------------------------------------------------
# up
# ---------------------------------------------------------------------------
lab_up() {
	[[ $EUID -eq 0 ]] || die "must run as root (firewall rules and network namespaces)"
	lab_is_up && die "a lab is already up — './lab.sh status', or './lab.sh down' first"
	command -v ufw >/dev/null || die "ufw not installed"
	command -v iptables >/dev/null || die "iptables not installed"
	pgrep -x rsyslogd >/dev/null || die "rsyslogd is not running; ufw lines would not reach $UFW_LOG"

	if [[ $WITH_IDS -eq 1 ]]; then
		[[ -f "$IDS_LIB" ]] || die "--with-ids needs $IDS_LIB"
		# shellcheck source=IDS/slips-lib.sh
		source "$IDS_LIB"
		slips_preflight || die "IDS preflight failed"
	fi

	modprobe xt_LOG 2>/dev/null || true
	modprobe nf_log_syslog 2>/dev/null || true

	mkdir -p "$LAB_DIR"

	# --- snapshot before touching anything -----------------------------------
	local orig_enabled orig_loglevel
	orig_enabled=$(grep -E '^ENABLED=' /etc/ufw/ufw.conf | cut -d= -f2)
	orig_loglevel=$(grep -E '^LOGLEVEL=' /etc/ufw/ufw.conf | cut -d= -f2)
	cp -a /etc/ufw/user.rules "$LAB_DIR/user.rules.bak"
	cp -a /etc/ufw/user6.rules "$LAB_DIR/user6.rules.bak"

	# Written before the changes are made, not after. If this script dies halfway
	# through the setup, `down` still has everything it needs to undo the parts that
	# did land — a state file written at the end would be missing precisely when a
	# failure made it necessary.
	local lab_stamp; lab_stamp=$(date -u +%Y%m%d%H%M%S)
	# Every value is quoted. This file is sourced, and the repo path contains a space
	# ("PDE Sources"), so an unquoted LAB_SLIPS_OUT parses as an assignment followed by
	# a command — bash then reports "Sources/output/...: No such file or directory" from
	# a file that merely looks like configuration.
	cat > "$LAB_STATE" <<-EOF
	# PDE lab session state. Written by lab.sh up; consumed by lab.sh down and by
	# simulate-firewall.sh. Deleting this by hand orphans the firewall changes.
	LAB_STAMP="$lab_stamp"
	LAB_STARTED_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	LAB_WITH_IDS="$WITH_IDS"
	LAB_USERS="$USERS"
	LAB_ORIG_ENABLED="$orig_enabled"
	LAB_ORIG_LOGLEVEL="$orig_loglevel"
	LAB_NS="$NS"
	LAB_VETH_HOST="$VETH_HOST"
	LAB_SUBNET="$SUBNET"
	LAB_HOST_IP="$HOST_IP"
	LAB_SLIPS_OUT="$PDE_ROOT/output/ids-session-$lab_stamp"
	EOF
	log "state recorded in $LAB_STATE (ufw was ENABLED=$orig_enabled LOGLEVEL=$orig_loglevel)"

	# --- topology -------------------------------------------------------------
	log "creating namespace $NS with $USERS user addresses"
	ip netns del "$NS" 2>/dev/null || true
	ip link del "$VETH_HOST" 2>/dev/null || true
	ip netns add "$NS"
	ip link add "$VETH_HOST" type veth peer name "$VETH_NS"
	ip link set "$VETH_NS" netns "$NS"
	ip addr add "$HOST_IP/24" dev "$VETH_HOST"
	ip link set "$VETH_HOST" up
	ip netns exec "$NS" ip link set lo up
	local i
	for ((i = 1; i <= USERS; i++)); do
		ip netns exec "$NS" ip addr add "${USER_IP_BASE}$((USER_IP_OFFSET + i))/24" dev "$VETH_NS"
	done
	ip netns exec "$NS" ip link set "$VETH_NS" up

	# --- IDS, before the firewall so `logging full` is not on during its startup ---
	if [[ $WITH_IDS -eq 1 ]]; then
		local slips_out="$PDE_ROOT/output/ids-session-$lab_stamp"
		mkdir -p "$slips_out"
		log "starting Slips on $VETH_HOST (loading modules and threat-intel feeds)"
		slips_start_redis || die "could not start the Slips redis"
		slips_start "$VETH_HOST" "$slips_out" || die "could not start Slips"
		slips_wait_ready "$IDS_READY_TIMEOUT" || die "Slips never became ready"
		log "Slips is reading $VETH_HOST"
	fi

	# --- firewall -------------------------------------------------------------
	# Order carries the labelling. PRESERVE_PORTS overlaps MALICIOUS_PORTS (22, 5432);
	# if the preserve rules came first they would match the simulated attacker too and
	# those attempts would be logged as permitted. Subnet rules are scoped and go
	# first, so the host-wide rules can only ever match traffic from somewhere else.
	log "configuring ufw (logging=full, default deny incoming)"
	local p
	IFS=',' read -ra _benign <<< "$BENIGN_PORTS"
	for p in "${_benign[@]}"; do
		ufw allow from "$SUBNET" to any port "$p" proto tcp >/dev/null
	done
	ufw deny from "$SUBNET" >/dev/null
	IFS=',' read -ra _preserve <<< "$PRESERVE_PORTS"
	for p in "${_preserve[@]}"; do
		ufw allow "$p/tcp" >/dev/null
	done
	ufw logging full >/dev/null
	ufw --force enable >/dev/null

	# Verdict logging installed directly: ufw hardcodes -m limit --limit 3/min
	# --limit-burst 10 onto every rule created with its `log` keyword, with no
	# loglevel check, which caps a window at ~11 verdict lines per rule however much
	# traffic crosses. Same kernel target, same prefixes, no rate limit. Removed when
	# ufw reloads on `down`.
	iptables -I ufw-user-input 1 -s "$SUBNET" -p tcp -m multiport --dports "$BENIGN_PORTS" \
		-j LOG --log-prefix "[UFW ALLOW] " --log-level 4
	iptables -I ufw-user-input 2 -s "$SUBNET" -p tcp -m multiport ! --dports "$BENIGN_PORTS" \
		-j LOG --log-prefix "[UFW BLOCK] " --log-level 4

	log "lab up"
	echo
	echo "  Your firewall is now ENABLED with test rules and LOGLEVEL=full."
	echo "  Capture windows with:  sudo Firewall/simulate-firewall.sh"
	echo "  Put it back with:      sudo ./lab.sh down"
}

# ---------------------------------------------------------------------------
# down
# ---------------------------------------------------------------------------
lab_down() {
	[[ $EUID -eq 0 ]] || die "must run as root"
	lab_is_up || die "no lab session recorded ($LAB_STATE missing)"

	# Parsed, not sourced — see lab_get. Everything below also tolerates a missing or
	# damaged value and falls back to the compiled-in default, because a half-written
	# state file must still be enough to put the firewall back.
	local LAB_WITH_IDS LAB_NS LAB_VETH_HOST LAB_ORIG_ENABLED LAB_ORIG_LOGLEVEL LAB_SLIPS_OUT
	LAB_WITH_IDS=$(lab_get LAB_WITH_IDS 0)
	LAB_NS=$(lab_get LAB_NS "$NS")
	LAB_VETH_HOST=$(lab_get LAB_VETH_HOST "$VETH_HOST")
	LAB_ORIG_ENABLED=$(lab_get LAB_ORIG_ENABLED no)
	LAB_ORIG_LOGLEVEL=$(lab_get LAB_ORIG_LOGLEVEL low)
	LAB_SLIPS_OUT=$(lab_get LAB_SLIPS_OUT "")

	if [[ "${LAB_WITH_IDS:-0}" -eq 1 && -f "$IDS_LIB" ]]; then
		# shellcheck source=IDS/slips-lib.sh
		source "$IDS_LIB"
		log "stopping Slips"
		slips_stop
	fi

	log "tearing down namespace ${LAB_NS:-$NS}"
	ip netns pids "${LAB_NS:-$NS}" 2>/dev/null | xargs -r kill 2>/dev/null || true
	ip netns del "${LAB_NS:-$NS}" 2>/dev/null || true
	ip link del "${LAB_VETH_HOST:-$VETH_HOST}" 2>/dev/null || true

	log "restoring firewall"
	cp -a "$LAB_DIR/user.rules.bak" /etc/ufw/user.rules 2>/dev/null || true
	cp -a "$LAB_DIR/user6.rules.bak" /etc/ufw/user6.rules 2>/dev/null || true
	ufw logging "${LAB_ORIG_LOGLEVEL:-low}" >/dev/null 2>&1 || true
	if [[ "${LAB_ORIG_ENABLED:-no}" == "no" ]]; then
		ufw --force disable >/dev/null 2>&1 || true
	else
		ufw --force enable >/dev/null 2>&1 || true
	fi

	if [[ -n "${SUDO_USER:-}" && -d "${LAB_SLIPS_OUT:-}" ]]; then
		chown -R "$SUDO_USER" "$LAB_SLIPS_OUT" 2>/dev/null || true
	fi

	rm -f "$LAB_STATE" "$LAB_DIR/user.rules.bak" "$LAB_DIR/user6.rules.bak"
	log "firewall restored to ENABLED=${LAB_ORIG_ENABLED:-no} LOGLEVEL=${LAB_ORIG_LOGLEVEL:-low}"
	[[ -n "${LAB_SLIPS_OUT:-}" ]] && echo "  Slips session output kept: $LAB_SLIPS_OUT"
	return 0
}

# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------
lab_status() {
	if ! lab_is_up; then
		echo "lab: down"
		local enabled; enabled=$(grep -E '^ENABLED=' /etc/ufw/ufw.conf 2>/dev/null | cut -d= -f2)
		if [[ "$enabled" == "yes" ]]; then
			echo "note: ufw is enabled, but not by a lab session — left alone."
		fi
		return 0
	fi

	local started ns
	started=$(lab_get LAB_STARTED_UTC "?")
	ns=$(lab_get LAB_NS "$NS")
	if netns_exists "$ns"; then
		echo "lab: UP since $started"
		echo "  namespace   $ns ($(lab_get LAB_USERS "?") users)"
		echo "  firewall    ufw enabled with test rules, LOGLEVEL=full"
		echo "  ids         $([[ "$(lab_get LAB_WITH_IDS 0)" -eq 1 ]] && echo "slips on $(lab_get LAB_VETH_HOST "$VETH_HOST")" || echo "not running")"
		echo "  restores to ENABLED=$(lab_get LAB_ORIG_ENABLED "?") LOGLEVEL=$(lab_get LAB_ORIG_LOGLEVEL "?")"
		return 0
	fi

	# State recorded but the namespace is gone: the session did not survive. A reboot
	# is the usual cause, and it matters because ufw.service is enabled — the firewall
	# comes back up on boot still carrying the test rules, with nothing running that
	# would put it back.
	echo "lab: STALE"
	echo "  A session was recorded at $started but its namespace is gone,"
	echo "  most likely a reboot or 'wsl --shutdown'."
	echo
	echo "  Your firewall may still be enabled with the test rules on it."
	echo "  Recover with:  sudo ./lab.sh down"
	return 2
}

# ---------------------------------------------------------------------------
cmd="${1:-}"
[[ $# -gt 0 ]] && shift
while [[ $# -gt 0 ]]; do
	case "$1" in
		--with-ids) WITH_IDS=1; shift ;;
		--users) USERS="$2"; shift 2 ;;
		*) die "unknown option '$1'" ;;
	esac
done

case "$cmd" in
	up)     lab_up ;;
	down)   lab_down ;;
	status) lab_status ;;
	-h|--help|help|"") usage ;;
	*) die "unknown command '$cmd' (try: up, down, status)" ;;
esac
