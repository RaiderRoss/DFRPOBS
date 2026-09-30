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
#
#  Two sources can live on the research VM instead (Remote/):
#    --ids-remote     the IDS is a tcpdump on the veth here; each
#                     window's packets are analysed by Slips there
#    --with-banking   the bank is Fineract there, reached from the
#                     namespace through a tunnel on HOST_IP:BANK_PORT
# ==============================================================
set -euo pipefail

PDE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lab-config.sh
source "$PDE_ROOT/lab-config.sh"
# shellcheck source=Remote/vm-lib.sh
source "$PDE_ROOT/Remote/vm-lib.sh"
IDS_LIB="$PDE_ROOT/IDS/slips-lib.sh"
BANK_SEED="${BANK_SEED:-$PDE_ROOT/Banking/seed.json}"

WITH_IDS=0
IDS_REMOTE=0
WITH_BANKING=0
IDS_READY_TIMEOUT=240
USERS=10

log()  { printf '[%(%H:%M:%S)T] %s\n' -1 "$*"; }
die()  { echo "error: $*" >&2; exit 1; }

usage() {
	sed -n '2,22p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'
	cat <<-EOF

	Commands:
	  up [--with-ids [--ids-remote]] [--with-banking] [--users N]
	                                build the lab and leave it running
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
	# Before any rule is written: a contradiction between the port lists cannot be seen in
	# the finished dataset, only in the labels disagreeing with each other.
	lab_check_port_lists || die "the port lists contradict each other; fix lab-config.sh"

	if [[ $WITH_IDS -eq 1 ]]; then
		[[ -f "$IDS_LIB" ]] || die "--with-ids needs $IDS_LIB"
		# shellcheck source=IDS/slips-lib.sh
		source "$IDS_LIB"
		if [[ $IDS_REMOTE -eq 1 ]]; then
			command -v tcpdump >/dev/null || die "--ids-remote needs tcpdump (apt install tcpdump)"
			slips_remote_preflight || die "remote IDS preflight failed"
		else
			slips_preflight || die "IDS preflight failed"
		fi
	fi
	if [[ $WITH_BANKING -eq 1 ]]; then
		[[ -r "$BANK_SEED" ]] || die "--with-banking needs a seeded bank ($BANK_SEED); see Banking/README.md"
		vm_reachable || die "--with-banking needs the research VM (status: $(vm_status || echo unknown)); ./vm.sh start"
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
	LAB_IDS_MODE="$([[ $IDS_REMOTE -eq 1 ]] && echo remote || echo local)"
	LAB_WITH_BANKING="$WITH_BANKING"
	LAB_USERS="$USERS"
	LAB_ORIG_ENABLED="$orig_enabled"
	LAB_ORIG_LOGLEVEL="$orig_loglevel"
	LAB_NS="$NS"
	LAB_VETH_HOST="$VETH_HOST"
	LAB_SUBNET="$SUBNET"
	LAB_HOST_IP="$HOST_IP"
	LAB_SLIPS_OUT="$PDE_ROOT/output/sessions/ids-$lab_stamp"
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

	# --- listener behind the alert ports --------------------------------------
	# Bound to the host address, so it can only start once the veth carries it. Recorded in
	# the state file immediately: it runs in the root namespace, so deleting the namespace
	# would not stop it, and `down` must be able to find it even if setup fails after this.
	log "starting the alert listener on $HOST_IP ports $ALERT_PORTS"
	local listener_pid
	listener_pid=$(alert_listener_start "$HOST_IP" "$LAB_DIR/alert-listener.pid" "$LAB_DIR/alert-listener.log") \
		|| die "could not start the alert listener"
	cat >> "$LAB_STATE" <<-EOF
	LAB_LISTENER_PID="$listener_pid"
	LAB_ALERT_PORTS="$ALERT_PORTS"
	EOF

	# --- IDS, before the firewall so `logging full` is not on during its startup ---
	if [[ $WITH_IDS -eq 1 && $IDS_REMOTE -eq 1 ]]; then
		# The sensor stays here, the analysis goes to the VM: tcpdump writes the veth for
		# the whole session, and each capture slices its window out and ships it.
		local slips_out="$PDE_ROOT/output/sessions/ids-$lab_stamp"
		local tcpdump_pid
		log "capturing $VETH_HOST to $slips_out/veth.pcap (analysed per window by Slips on $VM_NAME)"
		tcpdump_pid=$(pcap_capture_start "$VETH_HOST" "$slips_out/veth.pcap" "$LAB_DIR/tcpdump.log") \
			|| die "could not start the packet capture"
		cat >> "$LAB_STATE" <<-EOF
		LAB_TCPDUMP_PID="$tcpdump_pid"
		LAB_PCAP="$slips_out/veth.pcap"
		EOF
	elif [[ $WITH_IDS -eq 1 ]]; then
		local slips_out="$PDE_ROOT/output/sessions/ids-$lab_stamp"
		mkdir -p "$slips_out"
		log "starting Slips on $VETH_HOST (loading modules and threat-intel feeds)"
		slips_start_redis || die "could not start the Slips redis"
		slips_start "$VETH_HOST" "$slips_out" || die "could not start Slips"
		slips_wait_ready "$IDS_READY_TIMEOUT" || die "Slips never became ready"
		log "Slips is reading $VETH_HOST"
	fi

	# --- the bank, on the host side of the veth ------------------------------
	# Bound to HOST_IP, so it can only open once the veth carries that address. A simulated
	# user reaching https://HOST_IP:BANK_PORT crosses this host's INPUT chain — ufw logs it —
	# and the tunnel carries it on to Fineract on the VM.
	if [[ $WITH_BANKING -eq 1 ]]; then
		log "opening the bank tunnel $HOST_IP:$BANK_PORT -> $VM_NAME:8443"
		vm_bank_tunnel_start || die "could not open the bank tunnel"
		echo 'LAB_BANK_TUNNEL="1"' >> "$LAB_STATE"
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
	# Permitted as well: the guaranteed-alert profile needs its connections to complete,
	# and a denied SYN never does.
	IFS=',' read -ra _alert <<< "$ALERT_PORTS"
	for p in "${_alert[@]}"; do
		ufw allow from "$SUBNET" to any port "$p" proto tcp >/dev/null
	done
	# The bank's port is in ALLOWED_PORTS, so the verdict rules label it ALLOW whether or
	# not banking is on; permitting it always keeps the label and the rule in agreement.
	ufw allow from "$SUBNET" to any port "$BANK_PORT" proto tcp >/dev/null
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
	# ALLOWED_PORTS, not BENIGN_PORTS: the alert ports are permitted too, and the BLOCK rule
	# below is "everything else", so leaving them out would label permitted traffic BLOCK.
	iptables -I ufw-user-input 1 -s "$SUBNET" -p tcp -m multiport --dports "$ALLOWED_PORTS" \
		-j LOG --log-prefix "[UFW ALLOW] " --log-level 4
	iptables -I ufw-user-input 2 -s "$SUBNET" -p tcp -m multiport ! --dports "$ALLOWED_PORTS" \
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

	# In the root namespace, so tearing the namespace down below would not stop it.
	log "stopping the alert listener"
	alert_listener_stop "$(lab_get LAB_LISTENER_PID "")"
	rm -f "$LAB_DIR/alert-listener.pid"

	# The bank tunnel is bound to the veth's address; closed before that address goes.
	if [[ "$(lab_get LAB_BANK_TUNNEL 0)" == "1" ]] || vm_tunnel_running bank; then
		log "closing the bank tunnel"
		vm_tunnel_stop bank
	fi

	if [[ "${LAB_WITH_IDS:-0}" -eq 1 && -f "$IDS_LIB" ]]; then
		# shellcheck source=IDS/slips-lib.sh
		source "$IDS_LIB"
		if [[ "$(lab_get LAB_IDS_MODE local)" == "remote" ]]; then
			log "stopping the packet capture"
			pcap_capture_stop "$(lab_get LAB_TCPDUMP_PID "")"
		else
			log "stopping Slips"
			slips_stop
		fi
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
		if [[ "$(lab_get LAB_WITH_IDS 0)" -ne 1 ]]; then
			echo "  ids         not running"
		elif [[ "$(lab_get LAB_IDS_MODE local)" == "remote" ]]; then
			local tpid; tpid=$(lab_get LAB_TCPDUMP_PID "")
			if [[ -n "$tpid" && -d "/proc/$tpid" ]]; then
				echo "  ids         capturing $(lab_get LAB_VETH_HOST "$VETH_HOST") (pid $tpid); Slips on $VM_NAME per window"
			else
				echo "  ids         capture NOT running — windows would have no packets for Slips"
			fi
		else
			echo "  ids         slips on $(lab_get LAB_VETH_HOST "$VETH_HOST")"
		fi
		if [[ "$(lab_get LAB_WITH_BANKING 0)" -eq 1 ]]; then
			if vm_tunnel_running bank; then
				echo "  bank        tunnel $HOST_IP:$BANK_PORT -> $VM_NAME (Fineract)"
			else
				echo "  bank        tunnel DOWN — banking windows will fail; restart the lab"
			fi
		fi
		local lpid; lpid=$(lab_get LAB_LISTENER_PID "")
		if [[ -n "$lpid" && -d "/proc/$lpid" ]]; then
			echo "  listener    ports $(lab_get LAB_ALERT_PORTS "?") on $HOST_IP (pid $lpid)"
		else
			echo "  listener    not running — guaranteed-alert connections will not complete"
		fi
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
		--ids-remote) IDS_REMOTE=1; shift ;;
		--with-banking) WITH_BANKING=1; shift ;;
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
