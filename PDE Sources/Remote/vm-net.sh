#!/usr/bin/env bash
# ==============================================================
#  Runs ON the research VM, as root (sudo), not on the lab machine.
#
#  The VM's end of the SSH tunnel device, and the two things that
#  have to be true before the VM's own ufw can be the firewall
#  evidence for traffic that arrives through it.
#
#    vm-net.sh up <tunN> <vm_ip> <peer_ip> <lab_subnet> <user>
#    vm-net.sh down <tunN> <lab_subnet>
#    vm-net.sh status [tunN]
#    vm-net.sh relay-up <listen_ip> <port> <host:port>
#    vm-net.sh relay-down
#    vm-net.sh listener-up <listen_ip> <ports>     the alert-profile listener
#    vm-net.sh listener-down
#    vm-net.sh slips-up <tunN> <user> <subdir>     the IDS, live on the device
#    vm-net.sh slips-ready [timeout] | slips-outdir | slips-down
#    vm-net.sh firewall-up <lab_subnet> <allowed_ports> <tunN>
#    vm-net.sh firewall-keep          cancel the auto-revert watchdog
#    vm-net.sh firewall-down
#
#  Driven from the lab machine by Remote/tun-lib.sh. See TUNNEL.md.
#
#  Nothing here restarts sshd. A restart would drop the very
#  session that is running this script, and on a VM whose only
#  way in is IAP SSH that is not a recoverable mistake.
# ==============================================================
set -u

log() { printf '[vm-net] %s\n' "$*"; }
die() { printf '[vm-net] error: %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "must run as root (interfaces, sshd config, ufw)"

SSHD_DROPIN=/etc/ssh/sshd_config.d/60-pde-tunnel.conf
RELAY_PID=/run/pde-bank-relay.pid
FW_KEEP=/run/pde-fw-keep
FW_WATCHDOG_SECONDS="${FW_WATCHDOG_SECONDS:-600}"

# ---------------------------------------------------------------------------
# sshd: permit tunnelling
#
# A drop-in rather than an edit to sshd_config, so the change is one file that can be
# deleted, and so it is obvious to the next person that it did not come with the image.
#
# Validated with `sshd -t` BEFORE anything is reloaded, and reloaded rather than restarted.
# Reload re-reads the configuration for new connections and leaves established ones alone,
# which matters because this script is itself running down one of them.
# ---------------------------------------------------------------------------
sshd_permit_tunnel() {
	if [[ -f "$SSHD_DROPIN" ]] && grep -qE '^[[:space:]]*PermitTunnel[[:space:]]+point-to-point' "$SSHD_DROPIN"; then
		log "sshd already permits tunnelling"
		return 0
	fi

	# The drop-in only takes effect if the main config includes the directory. Ubuntu's
	# default does, but an image that predates it would accept the file and ignore it —
	# the tunnel request would then be refused with no sign of why.
	if ! grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config; then
		die "sshd_config has no Include for sshd_config.d; refusing to edit the main config"
	fi

	mkdir -p "$(dirname "$SSHD_DROPIN")"
	cat > "$SSHD_DROPIN" <<-'EOF'
	# Added by the PDE lab (Remote/vm-net.sh). Lets `ssh -w` put a layer-3 tun device on
	# this host, so the lab's simulated users reach it with their own source addresses
	# instead of arriving from a port forward's near end.
	#
	# point-to-point, not yes: `yes` would also allow ethernet (layer 2) tunnels, which
	# nothing here needs. The device itself is pre-created and owned by the lab's user, so
	# no session gains the ability to make interfaces.
	PermitTunnel point-to-point
	EOF

	if ! sshd -t 2>/tmp/pde-sshd-test.err; then
		rm -f "$SSHD_DROPIN"
		log "sshd rejected the configuration; it was removed and nothing was reloaded:"
		sed 's/^/    /' /tmp/pde-sshd-test.err >&2
		die "sshd -t failed"
	fi

	# Debian/Ubuntu call it ssh.service; be tolerant of sshd.service too rather than
	# leaving a validated config unloaded.
	if systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null; then
		log "sshd reloaded; tunnelling permitted (existing sessions untouched)"
	else
		die "could not reload sshd (the drop-in is in place but not yet active)"
	fi
}

# ---------------------------------------------------------------------------
# The device
#
# Persistent and owned by the lab's account, for the same reason as on the lab machine:
# sshd attaches the session to tun<N> as that user, and a device it does not own cannot be
# attached. This is also what keeps sshd from needing to create interfaces itself.
# ---------------------------------------------------------------------------
tun_up() {
	local num="$1" vm_ip="$2" peer_ip="$3" subnet="$4" user="$5" prefix="${6:-}"
	local dev="tun$num"

	modprobe tun 2>/dev/null || true
	[[ -c /dev/net/tun ]] || die "no /dev/net/tun on this host"

	id "$user" >/dev/null 2>&1 || die "no such user: $user"

	# Remade every time, never reused. Measured: ssh -w attaches to a device this function
	# has just created, and fails with "Tunnel forwarding failed" against one an earlier sshd
	# session already attached to. Whatever state that leaves behind is not resettable from
	# here, so the device is torn down and made again rather than adopted.
	#
	# Safe at this point in the lifecycle: the IDS that sniffs this device is started after
	# the tunnel and stopped before it, so nothing is reading it when this runs.
	ip link del "$dev" 2>/dev/null || true
	ip tuntap add dev "$dev" mode tun user "$user" || die "could not create $dev"
	log "created $dev, owned by $user"

	# With a prefix, the VM end sits in a network that contains the lab's users, the way a
	# VPN's client pool is part of a bank's internal network — and that network is what the
	# IDS takes as local (see TUN_VM_PREFIX in lab-config.sh). The peer is inside it, so the
	# route to the lab's end comes with the address.
	if [[ -n "$prefix" ]]; then
		ip addr add "$vm_ip/$prefix" dev "$dev" || die "could not address $dev"
	else
		ip addr add "$vm_ip" peer "$peer_ip" dev "$dev" || die "could not address $dev"
	fi
	ip link set "$dev" up || die "could not bring $dev up"

	# The return path. Replies to the simulated users are generated here, so without this
	# route they leave by the default gateway and never come back — the users would see
	# every connection time out while the VM's logs showed the requests arriving.
	ip route replace "$subnet" dev "$dev" || die "could not route $subnet via $dev"

	log "$dev up: $vm_ip${prefix:+/$prefix} (lab end $peer_ip), $subnet routed via $dev"
}

tun_down() {
	local num="$1" subnet="$2"
	# Declared separately, not alongside num: `local` expands every argument before it
	# assigns any, so "tun$num" here would have used the outer, unset num — which is why
	# teardown was deleting a device called "tun" and the real one survived every time.
	local dev="tun$num"
	ip route del "$subnet" dev "$dev" 2>/dev/null || true
	ip link del "$dev" 2>/dev/null || true
	log "$dev removed"
}

# ---------------------------------------------------------------------------
# The bank relay
#
# Terminates the user's connection on the tun address, on the host, so it crosses INPUT and
# ufw logs it; then carries the bytes to Fineract's published port. See lab-config.sh for
# why a Docker-published port cannot be logged directly.
# ---------------------------------------------------------------------------
relay_up() {
	local listen_ip="$1" port="$2" target="$3"
	local script; script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/bank-relay.py"
	[[ -f "$script" ]] || die "missing $script (run ./vm.sh sync)"

	if [[ -s "$RELAY_PID" ]] && kill -0 "$(cat "$RELAY_PID")" 2>/dev/null; then
		log "relay already running (pid $(cat "$RELAY_PID"))"
		return 0
	fi

	# stdin redirected as well as stdout: a background process on the far end of an SSH
	# session holds that session open until it exits if it keeps the tty.
	setsid python3 "$script" --listen "$listen_ip:$port" --target "$target" \
		--pidfile "$RELAY_PID" </dev/null >/var/log/pde-bank-relay.log 2>&1 &
	local i
	for ((i = 0; i < 50; i++)); do
		[[ -s "$RELAY_PID" ]] && { log "relay listening on $listen_ip:$port -> $target"; return 0; }
		sleep 0.1
	done
	log "the relay did not come up; its output:"
	sed 's/^/    /' /var/log/pde-bank-relay.log >&2 2>/dev/null || true
	die "relay failed to start"
}

relay_down() {
	if [[ -s "$RELAY_PID" ]]; then
		kill "$(cat "$RELAY_PID")" 2>/dev/null || true
		rm -f "$RELAY_PID"
	fi
	pkill -f bank-relay.py 2>/dev/null || true
	log "relay stopped"
}

# ---------------------------------------------------------------------------
# ufw, here rather than on the lab machine
#
# This is the one action on this VM that can end in losing access to it, so it is built to
# fail safe:
#
#   * SSH is permitted before ufw is enabled. Its rule comes AFTER the lab subnet's deny,
#     which cannot touch it: the IAP connections this VM is managed through come from
#     35.235.240.0/20, never from the lab subnet.
#   * DEFAULT_FORWARD_POLICY is set to ACCEPT. ufw's default is DROP, and Docker's traffic
#     between containers and out to the internet crosses FORWARD: leaving it at DROP takes
#     Fineract's own database connection out. The evidence is INPUT, so this costs nothing.
#   * A watchdog disables ufw again after FW_WATCHDOG_SECONDS unless `firewall-keep` has
#     said the lab still has access. A wrong rule then costs a wait, not the VM.
#
# The verdict LOG rules are the same ones the local lab used, and for the same reason: ufw's
# own `log` keyword hardcodes a rate limit that caps a window at ~11 lines per rule.
# ---------------------------------------------------------------------------
firewall_up() {
	local subnet="$1" allowed_ports="$2" num="$3"
	local dev="tun$num"   # separate: see the note in tun_down

	command -v ufw >/dev/null || die "ufw is not installed on the VM"

	# Recorded so firewall-down puts back what the VM had, not what this assumed.
	if [[ ! -f /run/pde-fw-prev ]]; then
		{
			printf 'ENABLED=%s\n' "$(grep -E '^ENABLED=' /etc/ufw/ufw.conf | cut -d= -f2)"
			printf 'LOGLEVEL=%s\n' "$(grep -E '^LOGLEVEL=' /etc/ufw/ufw.conf | cut -d= -f2)"
			printf 'FORWARD=%s\n' "$(grep -E '^DEFAULT_FORWARD_POLICY=' /etc/default/ufw | cut -d= -f2 | tr -d '"')"
		} > /run/pde-fw-prev
	fi

	rm -f "$FW_KEEP"
	# Detached, stdin closed, and started BEFORE the firewall changes so a mistake in them
	# is still covered.
	setsid bash -c "sleep $FW_WATCHDOG_SECONDS; [ -f '$FW_KEEP' ] || ufw --force disable" \
		</dev/null >/var/log/pde-fw-watchdog.log 2>&1 &
	log "watchdog armed: ufw disables itself in ${FW_WATCHDOG_SECONDS}s unless confirmed"

	# From nothing. ufw keeps its rules across sessions and matches them in the order they
	# were FIRST added, so an earlier session's rules would survive a re-run in their old
	# order whatever this function now says. Resetting makes the order below the order that
	# applies. A reset leaves ufw disabled, which cannot lock anyone out.
	ufw --force reset >/dev/null

	sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw

	# The lab subnet's rules first: its permitted ports, then a deny for everything else.
	# ORDER CARRIES THE LABELLING. The verdict LOG rules label a packet by its port alone,
	# so any rule that lets a subnet packet through on a port outside the list makes the
	# evidence say BLOCK for a connection that succeeded. Measured before this order was
	# fixed: two attacker probes to 22 reached the VM's sshd, one of them logged BLOCK.
	local p
	IFS=',' read -ra _allowed <<< "$allowed_ports"
	for p in "${_allowed[@]}"; do
		ufw allow from "$subnet" to any port "$p" proto tcp >/dev/null
	done
	ufw deny from "$subnet" >/dev/null

	# SSH for everyone else. The GCP firewall already admits 22 only from IAP, so this widens
	# nothing, and scoping it to that range here would lock the VM out if Google changed it.
	ufw allow 22/tcp >/dev/null

	# 'low', not 'full'. At 'full' ufw logs every packet this host handles — Docker's traffic
	# between Fineract, Kafka and PostgreSQL included — faster than journald can drain the
	# kernel's log buffer. Measured: journald reported "Missed ~7000 kernel messages" every
	# ~8s and "/dev/kmsg buffer overrun, some messages lost", and ~6% of the lab's own
	# attempts never reached the evidence. The lab's traffic does not need 'full': the verdict
	# LOG rules below log every packet from the subnet on the tunnel device at any level.
	ufw logging low >/dev/null
	ufw --force enable >/dev/null

	# Unrate-limited verdict logging, straight into ufw's own chain, scoped to what arrives
	# on the tunnel device so nothing else on the VM is logged into the evidence.
	iptables -C ufw-user-input -i "$dev" -s "$subnet" -p tcp -m multiport --dports "$allowed_ports" \
		-j LOG --log-prefix "[UFW ALLOW] " --log-level 4 2>/dev/null \
		|| iptables -I ufw-user-input 1 -i "$dev" -s "$subnet" -p tcp -m multiport --dports "$allowed_ports" \
			-j LOG --log-prefix "[UFW ALLOW] " --log-level 4
	iptables -C ufw-user-input -i "$dev" -s "$subnet" -p tcp -m multiport ! --dports "$allowed_ports" \
		-j LOG --log-prefix "[UFW BLOCK] " --log-level 4 2>/dev/null \
		|| iptables -I ufw-user-input 2 -i "$dev" -s "$subnet" -p tcp -m multiport ! --dports "$allowed_ports" \
			-j LOG --log-prefix "[UFW BLOCK] " --log-level 4

	log "ufw enabled, logging low, verdict rules logging every $subnet packet on $dev"
	log "CONFIRM ACCESS, then: vm-net.sh firewall-keep"
}

firewall_keep() {
	touch "$FW_KEEP"
	log "watchdog cancelled; ufw stays up"
}

firewall_down() {
	local subnet="${1:-}" dev="${2:-}"
	rm -f "$FW_KEEP"
	if [[ -r /run/pde-fw-prev ]]; then
		local enabled loglevel forward
		enabled=$(grep -E '^ENABLED='  /run/pde-fw-prev | cut -d= -f2)
		loglevel=$(grep -E '^LOGLEVEL=' /run/pde-fw-prev | cut -d= -f2)
		forward=$(grep -E '^FORWARD='  /run/pde-fw-prev | cut -d= -f2)
		[[ -n "$forward" ]] && sed -i "s/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY=\"$forward\"/" /etc/default/ufw
		ufw logging "${loglevel:-low}" >/dev/null 2>&1 || true
		if [[ "${enabled:-no}" == "no" ]]; then ufw --force disable >/dev/null 2>&1 || true
		else ufw --force enable >/dev/null 2>&1 || true; fi
		rm -f /run/pde-fw-prev
		log "ufw restored to ENABLED=${enabled:-no} LOGLEVEL=${loglevel:-low}"
	else
		ufw --force disable >/dev/null 2>&1 || true
		log "no recorded previous state; ufw disabled"
	fi
}

# ---------------------------------------------------------------------------
# The services the lab's users actually talk to, now that they arrive here
#
# Both are bound to the tunnel address, not 0.0.0.0. That is what makes a user's connection
# a local delivery that crosses INPUT — where ufw logs it — and it also means neither is
# reachable from anywhere else on the VM's network.
# ---------------------------------------------------------------------------
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." 2>/dev/null && pwd)"
LISTENER_PID=/run/pde-alert-listener.pid

_user_home() { getent passwd "$1" | cut -d: -f6; }

listener_up() {
	local ip="$1" ports="$2"
	local script="$REPO/PDE Sources/Firewall/alert_listener.py"
	[[ -f "$script" ]] || die "missing $script (run ./vm.sh sync)"
	if [[ -s "$LISTENER_PID" ]] && kill -0 "$(cat "$LISTENER_PID")" 2>/dev/null; then
		log "alert listener already running (pid $(cat "$LISTENER_PID"))"
		return 0
	fi
	rm -f "$LISTENER_PID"
	setsid python3 "$script" --host "$ip" --ports "$ports" --pidfile "$LISTENER_PID" \
		</dev/null >/var/log/pde-alert-listener.log 2>&1 &
	local i
	for ((i = 0; i < 50; i++)); do
		[[ -s "$LISTENER_PID" ]] && { log "alert listener on $ip ports $ports"; return 0; }
		sleep 0.1
	done
	log "the alert listener did not come up; its output:"
	sed 's/^/    /' /var/log/pde-alert-listener.log >&2 2>/dev/null || true
	die "alert listener failed to start"
}

listener_down() {
	[[ -s "$LISTENER_PID" ]] && { kill "$(cat "$LISTENER_PID")" 2>/dev/null || true; rm -f "$LISTENER_PID"; }
	pkill -f "Firewall/alert_listener.py" 2>/dev/null || true
	log "alert listener stopped"
}

# Slips, sniffing the tunnel device live.
#
# This is the mode the lab had before the IDS moved to the VM, and it is the better one: a
# real IDS watches an interface continuously and its per-source profile carries across
# windows, where file-mode analysis starts fresh each time and cannot accumulate.
#
# It reuses the standing redis that slips-warm.sh keeps, so it inherits the warm
# threat-intel cache rather than downloading ~45 feeds again.
slips_up() {
	local dev="$1" user="$2" subdir="$3"
	local img="${SLIPS_IMG:-stratosphereips/slips:latest}"
	local home outdir
	home="$(_user_home "$user")" || die "no home for $user"
	outdir="$home/$subdir"
	mkdir -p "$outdir"

	bash "$REPO/PDE Sources/Remote/slips-warm.sh" redis >/dev/null || die "the Slips redis is not up"

	# Slips' own configuration, unchanged. Its local network is the watched interface's own
	# network, which is why the tunnel's VM end carries a prefix (TUN_VM_PREFIX).
	docker rm -f pde-slips >/dev/null 2>&1 || true
	docker run -d --net=host --cap-add=NET_ADMIN --name pde-slips \
		-v "$outdir":/output "$img" ./slips.py -i "$dev" -o /output >/dev/null \
		|| die "could not start Slips on $dev"
	printf '%s\n' "$outdir" > /run/pde-slips-out
	log "Slips starting on $dev, output $outdir"
}

# Nothing may be generated until this returns, or the window's traffic is simply missed.
slips_ready() {
	local timeout="${1:-240}" waited=0
	while [[ $waited -lt $timeout ]]; do
		# Two markers, because they differ by Slips version and the string is the only
		# readiness signal there is. 1.1.x prints "Started Input Process"; the current image
		# prints the Zeek line instead, and waiting for the old one times out against a Slips
		# that has been reading packets for minutes.
		if docker logs pde-slips 2>&1 | grep -qE "Started Input Process|Zeek is logging all traffic on interface"; then
			log "Slips is reading packets (${waited}s)"
			return 0
		fi
		if ! docker ps --format '{{.Names}}' | grep -qx pde-slips; then
			log "Slips exited during startup; last lines:"
			docker logs pde-slips 2>&1 | tail -5 >&2
			return 1
		fi
		sleep 5; waited=$((waited + 5))
	done
	log "Slips did not report readiness within ${timeout}s"
	return 1
}

# The output directory, so the lab machine knows where to read alerts.log from.
slips_outdir() { cat /run/pde-slips-out 2>/dev/null || true; }

slips_down() {
	docker rm -f pde-slips >/dev/null 2>&1 || true
	rm -f /run/pde-slips-out
	# The standing redis is left alone: it holds the warm threat-intel cache and belongs to
	# the VM, not to this lab session.
	log "Slips stopped (the standing redis is left up)"
}

status() {
	local num="${1:-}" dev
	[[ -n "$num" ]] && dev="tun$num" || dev=""
	if [[ -n "$dev" ]]; then
		ip -brief addr show dev "$dev" 2>/dev/null || echo "$dev absent"
	fi
	printf 'sshd tunnel  %s\n' "$([[ -f $SSHD_DROPIN ]] && echo 'drop-in present' || echo 'not configured')"
	printf 'relay        %s\n' "$([[ -s $RELAY_PID ]] && kill -0 "$(cat $RELAY_PID)" 2>/dev/null \
		&& echo "running (pid $(cat $RELAY_PID))" || echo 'stopped')"
	printf 'ufw          %s\n' "$(ufw status 2>/dev/null | head -1 | sed 's/^Status: //')"
	printf 'watchdog     %s\n' "$([[ -f $FW_KEEP ]] && echo 'cancelled (ufw stays)' || echo 'armed or not running')"
}

case "${1:-}" in
	up)
		[[ $# -eq 6 || $# -eq 7 ]] || die "up <tunN> <vm_ip> <peer_ip> <lab_subnet> <user> [prefix]"
		sshd_permit_tunnel
		tun_up "$2" "$3" "$4" "$5" "$6" "${7:-}" ;;
	down)
		[[ $# -eq 3 ]] || die "down <tunN> <lab_subnet>"
		tun_down "$2" "$3" ;;
	status)        status "${2:-}" ;;
	relay-up)
		[[ $# -eq 4 ]] || die "relay-up <listen_ip> <port> <host:port>"
		relay_up "$2" "$3" "$4" ;;
	relay-down)    relay_down ;;
	listener-up)
		[[ $# -eq 3 ]] || die "listener-up <listen_ip> <ports>"
		listener_up "$2" "$3" ;;
	listener-down) listener_down ;;
	slips-up)
		[[ $# -eq 4 ]] || die "slips-up <tun_dev> <user> <subdir>"
		slips_up "$2" "$3" "$4" ;;
	slips-ready)   slips_ready "${2:-240}" ;;
	slips-outdir)  slips_outdir ;;
	slips-down)    slips_down ;;
	firewall-up)
		[[ $# -eq 4 ]] || die "firewall-up <lab_subnet> <allowed_ports> <tunN>"
		firewall_up "$2" "$3" "$4" ;;
	firewall-keep) firewall_keep ;;
	firewall-down) firewall_down ;;
	*) sed -n '2,24p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'; exit 1 ;;
esac
