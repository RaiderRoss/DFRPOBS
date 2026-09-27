#!/usr/bin/env bash
# ==============================================================
#  Research-VM helpers for the PDE lab.
#
#  Sourced, not run. Everything that crosses from this machine
#  to the GCP VM goes through here: gcloud, SSH over IAP, and the
#  port-forwarding tunnels. lab-config.sh must be sourced first
#  for the VM_* constants and LAB_DIR.
#
#  Defines functions only — sourcing it has no side effects.
# ==============================================================

# gcloud has to be a native Linux SDK. WSL puts the *Windows* SDK on PATH through
# interop (/mnt/c/...), and that one keeps its credentials on the Windows side, vanishes
# under sudo's reset PATH, and hands SSH to PuTTY. Remote/install-gcloud.sh puts the Linux
# SDK where this looks by default.
#
# Credentials live in the invoking user's home, not root's. The lab runs under sudo, and
# Ubuntu's sudo sets HOME to /root, where there is no login — so every gcloud call made
# from a root script is handed back to SUDO_USER rather than run as root.
_vm_user_home() {
	if [[ $EUID -eq 0 && -n "${SUDO_USER:-}" ]]; then
		getent passwd "$SUDO_USER" | cut -d: -f6
	else
		printf '%s' "$HOME"
	fi
}

vm_gcloud_bin() {
	local bin="${GCLOUD_BIN:-$(_vm_user_home)/google-cloud-sdk/bin/gcloud}"
	if [[ ! -x "$bin" ]]; then
		echo "no Linux gcloud at $bin — run Remote/install-gcloud.sh" >&2
		return 1
	fi
	case "$bin" in
		/mnt/*) echo "gcloud at $bin is the Windows SDK; install the Linux one (Remote/install-gcloud.sh)" >&2
		        return 1 ;;
	esac
	printf '%s' "$bin"
}

# Fills VM_GCLOUD with the command prefix every call runs through. An array rather than a
# function because setsid (for the tunnels) can only exec a program, not a shell function.
#
# The configuration is chosen per process with CLOUDSDK_ACTIVE_CONFIG_NAME, never by
# activating it: activation is global and persistent, and this machine's default
# configuration belongs to other work. It is set as an environment variable rather than
# as --configuration because anything after `--` goes to ssh, and a flag appended there
# would be handed to the wrong program.
_vm_gcloud_cmd() {
	local bin
	bin="$(vm_gcloud_bin)" || return 1
	if [[ $EUID -eq 0 && -n "${SUDO_USER:-}" ]]; then
		VM_GCLOUD=(sudo -u "$SUDO_USER" -H -- env "CLOUDSDK_ACTIVE_CONFIG_NAME=$VM_GCLOUD_CONFIG" "$bin")
	else
		VM_GCLOUD=(env "CLOUDSDK_ACTIVE_CONFIG_NAME=$VM_GCLOUD_CONFIG" "$bin")
	fi
}

vm_gcloud() {
	_vm_gcloud_cmd || return 1
	"${VM_GCLOUD[@]}" "$@"
}

# RUNNING, TERMINATED (which is GCP's word for stopped), STAGING... or empty when the
# question could not be asked at all.
vm_status() {
	vm_gcloud compute instances describe "$VM_NAME" --zone "$VM_ZONE" \
		--format='value(status)' 2>/dev/null
}

# Runs one shell command on the VM. stdin and stdout pass straight through and are
# binary-safe (-T: no pseudo-terminal), which is how files move in both directions:
#   vm_ssh 'cat > /tmp/x' < local        vm_ssh 'cat /tmp/x' > local
vm_ssh() {
	vm_gcloud compute ssh "$VM_USER@$VM_NAME" --zone "$VM_ZONE" --tunnel-through-iap --quiet \
		--command "$1" -- -T -o LogLevel=ERROR
}

vm_reachable() {
	[[ "$(vm_status)" == "RUNNING" ]] && vm_ssh true </dev/null >/dev/null 2>&1
}

# ---------------------------------------------------------------------------
# Tunnels
#
# One SSH connection per tunnel, carrying any number of -L forwards, running detached in
# its own process group so the whole chain — sudo, gcloud, its IAP helper, ssh — is
# stopped by one signal. The pidfile names the group.
#
#   admin  127.0.0.1:VM_LOCAL_REPO_PORT and :VM_LOCAL_FINERACT_PORT. Needs nothing local;
#          used to submit evidence and to seed the bank.
#   bank   HOST_IP:BANK_PORT, bound to the lab's veth address so simulated users reach
#          the bank through this host's firewall. Can only exist while the lab does.
# ---------------------------------------------------------------------------
# Tunnel state lives in a per-user runtime directory, not in .lab/: .lab is created by
# lab.sh as root (it holds the ufw backups) and the admin tunnel runs as the user, who
# could not write there. Keyed by the user the tunnel runs as — SUDO_USER when root starts
# one on their behalf — so root and the user see the same pidfiles. /tmp is right for it:
# the processes these name do not survive a reboot either.
_vm_tunnel_dir() {
	local u
	if [[ $EUID -eq 0 && -n "${SUDO_USER:-}" ]]; then u="$SUDO_USER"; else u="$(id -un)"; fi
	local d="/tmp/pde-tunnels-$u"
	if [[ ! -d "$d" ]]; then
		mkdir -p "$d" && chmod 700 "$d"
		[[ $EUID -eq 0 && "$u" != "root" ]] && chown "$u" "$d"
	fi
	printf '%s' "$d"
}

_vm_tunnel_pidfile() { printf '%s/tunnel-%s.pid' "$(_vm_tunnel_dir)" "$1"; }

vm_tunnel_running() {
	local pidfile pid
	pidfile="$(_vm_tunnel_pidfile "$1")"
	[[ -s "$pidfile" ]] || return 1
	pid="$(head -1 "$pidfile")"
	# Checked against the command line, not just the PID: a pidfile left by a session
	# that did not survive a reboot may name any process by now.
	[[ -r "/proc/$pid/cmdline" ]] \
		&& [[ "$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)" == *"$VM_NAME"* ]]
}

# vm_tunnel_start <name> <forward>...     forward = bind:localport:host:remoteport
vm_tunnel_start() {
	local name="$1"; shift
	local pidfile log
	pidfile="$(_vm_tunnel_pidfile "$name")"
	log="$(_vm_tunnel_dir)/tunnel-$name.log"
	vm_tunnel_running "$name" && return 0
	_vm_gcloud_cmd || return 1

	local args=() f
	for f in "$@"; do args+=(-L "$f"); done

	# ExitOnForwardFailure: a forward that cannot bind must fail the tunnel, not leave an
	# SSH session up with half its ports missing. ServerAlive*: IAP drops idle sessions,
	# and a dead tunnel should exit rather than sit there accepting nothing.
	setsid "${VM_GCLOUD[@]}" compute ssh "$VM_USER@$VM_NAME" --zone "$VM_ZONE" --tunnel-through-iap --quiet \
		-- -N -T -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 \
		-o LogLevel=ERROR "${args[@]}" </dev/null >"$log" 2>&1 &
	local pid=$!
	# Line 2 is the first forward spec, which only this tunnel's processes carry on their
	# command lines — the handle stop falls back on when the group signal misses some.
	printf '%s\n%s\n' "$pid" "$1" > "$pidfile"

	# Ready when the first forward accepts a connection. IAP plus key propagation on a
	# first run can take a while; a tunnel that dies meanwhile is reported, not waited on.
	local first="$1" host port i
	host="$(cut -d: -f1 <<< "$first")"
	port="$(cut -d: -f2 <<< "$first")"
	for ((i = 0; i < 90; i++)); do
		if (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null; then
			return 0
		fi
		if ! kill -0 "$pid" 2>/dev/null; then
			echo "the $name tunnel exited; its output:" >&2
			sed 's/^/    /' "$log" >&2
			rm -f "$pidfile"
			return 1
		fi
		sleep 1
	done
	echo "the $name tunnel did not open $host:$port within 90s" >&2
	vm_tunnel_stop "$name"
	return 1
}

vm_tunnel_stop() {
	local pidfile pid spec
	pidfile="$(_vm_tunnel_pidfile "$1")"
	[[ -s "$pidfile" ]] || return 0
	pid="$(head -1 "$pidfile")"
	spec="$(sed -n 2p "$pidfile")"
	if vm_tunnel_running "$1"; then
		# The whole process group: killing gcloud alone orphans the ssh beneath it, which
		# keeps holding the port.
		kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
	fi
	# Under sudo the command can run in a session of its own (use_pty), outside that group.
	# Whatever still carries this tunnel's forward spec is part of it.
	if [[ -n "$spec" ]]; then
		sleep 0.5
		pkill -TERM -f -- "-L $spec" 2>/dev/null || true
	fi
	rm -f "$pidfile"
}

vm_admin_tunnel_start() {
	vm_tunnel_start admin \
		"127.0.0.1:${VM_LOCAL_REPO_PORT}:localhost:8080" \
		"127.0.0.1:${VM_LOCAL_FINERACT_PORT}:localhost:8443"
}

vm_bank_tunnel_start() {
	vm_tunnel_start bank "${HOST_IP}:${BANK_PORT}:localhost:8443"
}
