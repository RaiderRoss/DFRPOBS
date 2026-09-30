#!/usr/bin/env bash
# ==============================================================
#  The SSH tunnel device — this machine's end.
#
#  Sourced, not run. lab-config.sh must be sourced first (for the
#  TUN_* and SUBNET constants) and Remote/vm-lib.sh after it, for
#  vm_ssh and the runtime directory the pidfiles live in.
#
#  What this builds, and why it is not a port forward:
#
#    namespace 10.99.0.11-.20 ─ veth ─ 10.99.0.1
#                                        │ (forwarded, not answered)
#                                   tun7 10.98.0.2
#                                        │  ssh -w, inside the IAP session
#                                   tun7 10.98.0.1  on the VM
#                                        └─ ufw INPUT ─ Slips ─ relay ─ Fineract
#
#  A -L forward would arrive at the VM from the VM's own address. The
#  whole point here is that it does not: the packets keep the source
#  addresses they left the namespace with, so the VM's firewall and
#  IDS see ten separate users and can tell the attacker from them.
#
#  Defines functions only — sourcing it has no side effects.
# ==============================================================

# The user the ssh process will run as, which is the user that has to be able to open the
# tun device. The lab runs under sudo, but gcloud's credential lives in the invoking user's
# home, so vm-lib.sh hands every gcloud call back to SUDO_USER — and with it the ssh
# beneath it. A device owned by root would then be unopenable by the very process that
# needs it, which fails with a bare "open failed" and no hint as to why.
_tun_owner() {
	if [[ $EUID -eq 0 && -n "${SUDO_USER:-}" ]]; then printf '%s' "$SUDO_USER"; else id -un; fi
}

_tun_pidfile()  { printf '%s/tunnel-tundev.pid' "$(_vm_tunnel_dir)"; }
_tun_statefile() { printf '%s/tundev.state' "$(_vm_tunnel_dir)"; }

# ---------------------------------------------------------------------------
# The local device
#
# Created PERSISTENT and owned by the ssh user, deliberately. `ssh -w` does not create
# interfaces; it opens /dev/net/tun and attaches to tun<N>, which for a non-root process
# only works if the device already exists and belongs to it.
#
# It does NOT survive usefully, though: a device an earlier sshd session attached to cannot
# be attached again, so it is deleted and remade on every bring-up rather than reused. The
# addressing and routes are cheap to rebuild; adopting the old device is what failed.
# ---------------------------------------------------------------------------
tun_local_create() {
	[[ $EUID -eq 0 ]] || { echo "tun_local_create needs root (creates an interface)" >&2; return 1; }
	local owner; owner="$(_tun_owner)"

	modprobe tun 2>/dev/null || true
	[[ -c /dev/net/tun ]] || {
		echo "no /dev/net/tun on this kernel — the WSL kernel needs TUN support for this mode" >&2
		return 1
	}

	# Remade every time, for the same reason as on the VM: a device a previous ssh session
	# attached to cannot be attached again, and adopting one is what produced "Tunnel
	# forwarding failed" on every run that reused it.
	ip link del "$TUN_DEV" 2>/dev/null || true
	ip tuntap add dev "$TUN_DEV" mode tun user "$owner" || {
		echo "could not create $TUN_DEV" >&2; return 1; }

	ip addr add "$TUN_LOCAL_IP" peer "$TUN_VM_IP" dev "$TUN_DEV" || return 1
	ip link set "$TUN_DEV" up || return 1
}

tun_local_destroy() {
	[[ $EUID -eq 0 ]] || { echo "tun_local_destroy needs root" >&2; return 1; }
	ip link del "$TUN_DEV" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Forwarding
#
# The users are in a namespace, so their packets ENTER this host on the veth and LEAVE it
# on the tun: that is forwarding, not local delivery, and it is off by default. The two
# explicit FORWARD rules are scoped to this lab's subnet and interfaces so the path works
# whatever the host's own firewall policy happens to be — including with ufw disabled,
# which is the normal state once the firewall evidence moves to the VM.
#
# The previous ip_forward value is recorded before it is changed, so `down` restores what
# the machine had rather than assuming it was off.
# ---------------------------------------------------------------------------
tun_forwarding_on() {
	[[ $EUID -eq 0 ]] || { echo "tun_forwarding_on needs root" >&2; return 1; }
	local prev; prev=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)
	printf 'PREV_IP_FORWARD=%s\n' "$prev" > "$(_tun_statefile)"
	sysctl -qw net.ipv4.ip_forward=1 || return 1

	# -C tests for the rule first: these are inserted once per lab, and a second copy
	# would survive the single -D below and quietly keep forwarding after teardown.
	iptables -C FORWARD -i "$VETH_HOST" -o "$TUN_DEV" -s "$SUBNET" -j ACCEPT 2>/dev/null \
		|| iptables -I FORWARD 1 -i "$VETH_HOST" -o "$TUN_DEV" -s "$SUBNET" -j ACCEPT
	iptables -C FORWARD -i "$TUN_DEV" -o "$VETH_HOST" -d "$SUBNET" -j ACCEPT 2>/dev/null \
		|| iptables -I FORWARD 1 -i "$TUN_DEV" -o "$VETH_HOST" -d "$SUBNET" -j ACCEPT
}

tun_forwarding_off() {
	[[ $EUID -eq 0 ]] || return 0
	iptables -D FORWARD -i "$VETH_HOST" -o "$TUN_DEV" -s "$SUBNET" -j ACCEPT 2>/dev/null || true
	iptables -D FORWARD -i "$TUN_DEV" -o "$VETH_HOST" -d "$SUBNET" -j ACCEPT 2>/dev/null || true
	local sf; sf="$(_tun_statefile)"
	if [[ -r "$sf" ]]; then
		local prev; prev=$(grep -E '^PREV_IP_FORWARD=' "$sf" | cut -d= -f2)
		[[ -n "$prev" ]] && sysctl -qw "net.ipv4.ip_forward=$prev" 2>/dev/null || true
		rm -f "$sf"
	fi
}

# The namespace's users aim at TUN_VM_IP, which is not on their own /24, so they need a
# route out. Without it every connection fails inside the namespace with "Network is
# unreachable" and nothing reaches the tunnel at all — a failure that looks like the
# tunnel being down when it is up.
tun_ns_route_add() {
	local ns="${1:-$NS}"
	ip netns exec "$ns" ip route replace "$TUN_VM_IP/32" via "$HOST_IP" dev "$VETH_NS"
}

# ---------------------------------------------------------------------------
# The ssh session that carries the device
# ---------------------------------------------------------------------------
tun_session_running() {
	local pidfile pid
	pidfile="$(_tun_pidfile)"
	[[ -s "$pidfile" ]] || return 1
	pid="$(head -1 "$pidfile")"
	# Matched against the command line, not just the PID: a pidfile left by a session that
	# did not survive a reboot may name any process by now.
	[[ -r "/proc/$pid/cmdline" ]] \
		&& [[ "$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)" == *"$VM_NAME"* ]]
}

# Brings up the ssh session and waits until the far end answers.
#
# Readiness is a ping to TUN_VM_IP rather than the presence of a process: ssh reports
# success as soon as it is connected, but the device is only usable once sshd has attached
# its end and the VM has addressed it. Pinging is the only check that covers the whole path.
tun_session_start() {
	local pidfile log spec
	pidfile="$(_tun_pidfile)"
	log="$(_vm_tunnel_dir)/tunnel-tundev.log"
	spec="${TUN_NUM}:${TUN_NUM}"
	tun_session_running && return 0
	_vm_gcloud_cmd || return 1

	# -w: the tunnel device, this end's number to the far end's. Both devices already exist.
	# ExitOnForwardFailure makes a refused tunnel request kill the session instead of
	# leaving an SSH connection up with no device behind it — the state that otherwise
	# looks like a routing problem and is really PermitTunnel being off on the VM.
	setsid "${VM_GCLOUD[@]}" compute ssh "$VM_USER@$VM_NAME" --zone "$VM_ZONE" \
		--tunnel-through-iap --quiet \
		-- -w "$spec" -o Tunnel=point-to-point -N -T \
		-o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 \
		-o LogLevel=ERROR </dev/null >"$log" 2>&1 &
	local pid=$!
	printf '%s\n%s\n' "$pid" "-w $spec" > "$pidfile"

	local i
	for ((i = 0; i < 90; i++)); do
		if ping -c1 -W1 -I "$TUN_DEV" "$TUN_VM_IP" >/dev/null 2>&1; then
			return 0
		fi
		if ! kill -0 "$pid" 2>/dev/null; then
			echo "the tunnel device session exited; its output:" >&2
			sed 's/^/    /' "$log" >&2
			# The most common cause by far, and it is invisible in ssh's own message.
			grep -qiE 'tunnel|administratively prohibited' "$log" 2>/dev/null \
				&& echo "    hint: PermitTunnel may be off on the VM — Remote/vm-net.sh up sets it" >&2
			rm -f "$pidfile"
			return 1
		fi
		sleep 1
	done
	echo "the tunnel device came up but $TUN_VM_IP never answered within 90s" >&2
	tun_session_stop
	return 1
}

tun_session_stop() {
	local pidfile pid spec
	pidfile="$(_tun_pidfile)"
	[[ -s "$pidfile" ]] || return 0
	pid="$(head -1 "$pidfile")"
	spec="$(sed -n 2p "$pidfile")"
	if tun_session_running; then
		# The whole process group: killing gcloud alone orphans the ssh beneath it, which
		# keeps the device attached.
		kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
	fi
	if [[ -n "$spec" ]]; then
		sleep 0.5
		pkill -TERM -f -- "$spec" 2>/dev/null || true
	fi
	rm -f "$pidfile"
}

# ---------------------------------------------------------------------------
# The VM's end
#
# Run through vm_ssh before the device session is opened, because sshd has to permit
# tunnelling and the VM's tun<N> has to exist before ssh can attach to it. Ordering this
# the other way round is what produces the "administratively prohibited" failure.
# ---------------------------------------------------------------------------
tun_vm_prepare() {
	vm_ssh "sudo bash \"\$HOME/$VM_REPO_DIR/PDE Sources/Remote/vm-net.sh\" up \
		'$TUN_NUM' '$TUN_VM_IP' '$TUN_LOCAL_IP' '$SUBNET' '$VM_USER' '$TUN_VM_PREFIX'" </dev/null
}

tun_vm_teardown() {
	vm_ssh "sudo bash \"\$HOME/$VM_REPO_DIR/PDE Sources/Remote/vm-net.sh\" down \
		'$TUN_NUM' '$SUBNET'" </dev/null
}

# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------
tun_up() {
	local ns="${1:-$NS}"
	tun_vm_prepare   || { echo "could not prepare the VM's end of the tunnel" >&2; return 1; }
	tun_local_create || return 1
	tun_forwarding_on || return 1
	tun_session_start || return 1
	# Checked inline rather than through lab.sh's netns_exists: this is also called from
	# vm.sh, where that function is not in scope, and a missing namespace is not an error —
	# the tunnel is usable on its own, and the lab adds the route when it builds one.
	if ip netns list 2>/dev/null | awk '{print $1}' | grep -qx "$ns"; then
		tun_ns_route_add "$ns"
	fi
	return 0
}

tun_down() {
	tun_session_stop
	tun_forwarding_off
	tun_local_destroy
	# Best effort: the VM may already be stopped, in which case its end went with it.
	tun_vm_teardown >/dev/null 2>&1 || true
}

tun_status() {
	if ip link show "$TUN_DEV" >/dev/null 2>&1; then
		echo "device      $TUN_DEV present ($TUN_LOCAL_IP -> $TUN_VM_IP)"
	else
		echo "device      $TUN_DEV absent"
	fi
	if tun_session_running; then
		echo "session     up (ssh -w through IAP to $VM_NAME)"
	else
		echo "session     down"
	fi
	if ping -c1 -W1 -I "$TUN_DEV" "$TUN_VM_IP" >/dev/null 2>&1; then
		echo "far end     $TUN_VM_IP answers"
	else
		echo "far end     $TUN_VM_IP silent"
	fi
	echo "forwarding  net.ipv4.ip_forward=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo '?')"
}
