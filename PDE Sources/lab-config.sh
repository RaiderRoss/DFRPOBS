#!/usr/bin/env bash
# ==============================================================
#  Shared lab constants.
#
#  Sourced by lab.sh (which builds and tears the lab down) and by
#  simulate-firewall.sh (which captures windows against it). Kept
#  in one file because the port lists interact: PRESERVE_PORTS
#  deliberately overlaps MALICIOUS_PORTS, and rule ORDER is what
#  keeps that from mislabelling the dataset. Two copies of these
#  drifting apart would reintroduce that bug silently.
#
#  Defines variables and helper functions only — sourcing it
#  has no side effects.
# ==============================================================

# Where a running lab records what it changed, so it can be undone later. Inside the
# repo rather than /tmp on purpose: `D /tmp` in tmpfiles.d means /tmp is cleared on
# boot, which would destroy the restore data at exactly the moment a crashed session
# needs it. Gitignored.
LAB_DIR="${LAB_DIR:-$PDE_ROOT/.lab}"
LAB_STATE="$LAB_DIR/state.env"

# Reads one field out of the state file by parsing it, never by sourcing it.
#
# Sourcing puts the recovery path at the mercy of the file it is trying to recover from:
# one malformed line makes `source` return non-zero, `set -e` aborts, and the firewall
# stays modified — the failure takes out the only thing that could undo it. Parsing
# cannot fail that way, and cannot execute anything either.
#
#   lab_get <KEY> [default]
lab_get() {
	local v
	v=$(grep -E "^$1=" "$LAB_STATE" 2>/dev/null | head -1 | cut -d= -f2- | sed 's/^"//; s/"$//')
	printf '%s' "${v:-${2:-}}"
}

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
# In tunnel mode the bank server answers them: a public web front (Firewall/benign_web.py)
# serving plain HTTP and HTTPS, so a benign user loads a page rather than making a bare
# connect to a closed port — which a flow-based IDS cannot tell from a scan. Together these
# must equal BENIGN_PORTS.
WEB_HTTP_PORTS="80,8080"
WEB_HTTPS_PORTS="443"

# Ports the firewall denies — the sweep an attacker runs looking for a way in.
#
# Deliberately wide. The firewall logs a BLOCK however few ports are touched, but an
# IDS decides "vertical port scan" from the number of DISTINCT ports one source reaches
# for on one host inside a timewindow — measured at around 10 for Slips. A thin list
# leaves the IDS silent about an attack the firewall recorded plainly, which is the
# opposite of the correlation this exists to demonstrate. None may overlap BENIGN_PORTS.
#
# 8443 is deliberately NOT here. It is BANK_PORT, and it is in ALLOWED_PORTS, so the verdict
# rules label it ALLOW — an attacker's probe to it was therefore recorded as permitted
# banking traffic while the ground truth called the same packet malicious. One port
# contradicting the label on both sides is worse than a slightly narrower sweep, and 34
# ports is still far above the ~10 distinct ports Slips needs to call it a vertical scan.
MALICIOUS_PORTS="21,22,23,25,53,110,111,135,137,139,143,161,389,445,512,513,514,873,993,995,1080,1433,1521,2049,2375,3306,3389,5060,5432,5900,6379,9200,11211,27017"

# Ports the guaranteed-alert profile connects to. Permitted from the subnet and answered
# by a listener on the host, so every attempt completes its handshake.
#
# Chosen against Slips' own tables, not by feel: none is in its services.csv or its
# ports_used_by_specific_orgs.csv, so an ESTABLISHED connection to one is "unknown
# destination port" evidence at HIGH (0.8), confidence 1.0, once per connection. Five at
# most: above five distinct ports Slips' vertical-scan detector can mark the source a
# port scanner, and a marked scanner has exactly this evidence suppressed. None may
# overlap BENIGN_PORTS, MALICIOUS_PORTS or PRESERVE_PORTS.
ALERT_PORTS="13337,17171,24242,28282"

# The bank, as the simulated users see it. Fineract runs on the research VM; the lab
# forwards HOST_IP:BANK_PORT to it over an IAP SSH tunnel (see Remote/vm-lib.sh), so a
# user in the namespace reaches the bank the way a customer reaches a bank's API: through
# this host's firewall, where ufw logs it on INPUT like any other permitted connection.
# That forward is what lets one actor appear in the firewall log, the IDS evidence and
# the bank's own audit trail for the same window. None may overlap the lists above.
BANK_PORT=8443

# Everything the subnet is permitted to reach, for the verdict LOG rules. The BLOCK rule
# is "everything else", so a permitted port missing from here is logged as BLOCK.
# iptables multiport accepts at most 15 ports.
ALLOWED_PORTS="$BENIGN_PORTS,$ALERT_PORTS,$BANK_PORT"

ALERT_LISTENER="$PDE_ROOT/Firewall/alert_listener.py"

# Host services kept reachable while ufw is up, so a default-deny firewall does not cut
# off the dev stack or the Windows host's access to it. Overlaps MALICIOUS_PORTS on 22
# and 5432 — see the rule ordering in lab.sh, which is what stops that overlap
# mislabelling attacker traffic as permitted.
PRESERVE_PORTS="22,5432,5433,8080,9000,9001,19092,8081"

UFW_LOG="/var/log/ufw.log"
KERN_LOG="/var/log/kern.log"

# The research VM that hosts Fineract, the Evidence Repository and Slips. The lab itself
# stays on this machine; see Remote/README.md for why the split falls where it does.
# Overridable in pde.conf.
VM_PROJECT="${VM_PROJECT:-fineract-slips-research}"
VM_NAME="${VM_NAME:-fineract-slips}"
VM_ZONE="${VM_ZONE:-africa-south1-a}"
# The account the lab uses on the VM. gcloud would otherwise log in as whatever your local
# username is — different on Windows and in WSL, different for every teammate — and each
# would land in an empty home with no checkout and no docker access. One shared account,
# with everyone's key mapped onto it, makes the VM the same place for all of them.
VM_USER="${VM_USER:-pde}"
# The VM's checkout of this repository, relative to VM_USER's home. It is updated with
# `./vm.sh sync`, which ships a bundle: the VM holds no credential for the repo.
VM_REPO_DIR="${VM_REPO_DIR:-DFRPOBS}"
# A named gcloud configuration, passed on every call and never activated, so nothing
# here can change which project the machine's default configuration points at.
VM_GCLOUD_CONFIG="${VM_GCLOUD_CONFIG:-fineract-research}"
# Where the VM's services appear on this machine while the admin tunnel is up. Not the
# services' own ports: a locally-run Evidence Repository already owns 8080. The frontend
# is deliberately absent — its CORS rule names localhost:5173 exactly, so it is browsed
# through a tunnel on its real ports (Remote/README.md), not a remapped one.
VM_LOCAL_REPO_PORT="${VM_LOCAL_REPO_PORT:-18080}"
VM_LOCAL_FINERACT_PORT="${VM_LOCAL_FINERACT_PORT:-18443}"

# ---------------------------------------------------------------------------
# The SSH tunnel device — a layer-3 hop to the VM, inside the IAP session
#
# A port forward (-L) gives the VM one source address: its own, because the forward's far
# end opens the connection locally. That is why the bank tunnel could never be the
# firewall's evidence, and why ufw had to stay on this machine.
#
# `ssh -w` instead puts a tun interface on each end and routes between them, so the
# namespace's packets arrive at the VM with the source addresses they left with. Ten users
# are ten sources there, which is what lets the VM's ufw log them on INPUT and Slips
# profile them apart. It rides the same IAP session, so it opens no new firewall hole.
#
# The far end is a DIFFERENT subnet from SUBNET on purpose. SUBNET is directly connected on
# the veth here, so an address inside it is answered by this host and never reaches the
# tunnel; the users have to aim at something this machine has to route.
TUN_NUM="${TUN_NUM:-7}"                       # ssh -w takes a number; the device is tun<N>
TUN_DEV="tun${TUN_NUM}"
TUN_LOCAL_IP="${TUN_LOCAL_IP:-10.98.0.2}"     # this machine's end of the point-to-point link
TUN_VM_IP="${TUN_VM_IP:-10.98.0.1}"           # the VM's end — and the address the users target

# The VM end's network: both ends of the tunnel AND the lab's users (10.98.0.0 - 10.99.255.255).
# A bank's remote-access VPN gives its clients addresses from a pool that is part of the
# internal network, and this models that. It is also what the IDS reads as "local": Slips,
# sniffing live, takes the local network from the interface's own address and netmask, and
# with a point-to-point /32 every user — benign or not — was "a private IP outside the used
# local network", which alone put all nine benign users over its alert threshold.
TUN_VM_PREFIX="${TUN_VM_PREFIX:-15}"

# Fineract is a Docker-published port, so packets to it are rewritten in nat/PREROUTING and
# cross FORWARD, never INPUT: the VM's ufw would not log the one connection that matters
# most. A plain TCP relay on the host terminates the connection on the tun address first —
# that crosses INPUT and is logged — then opens its own to the container. It passes bytes
# through untouched, so Fineract's TLS is still end to end from the user's point of view.
BANK_RELAY_LISTEN_IP="${BANK_RELAY_LISTEN_IP:-$TUN_VM_IP}"
BANK_RELAY_TARGET="${BANK_RELAY_TARGET:-127.0.0.1:8443}"

# Starts the accept-and-close listener behind ALERT_PORTS, detached, so it outlives the
# script that started it — lab.sh exits as soon as the lab is up.
#   alert_listener_start <host> <pidfile> <logfile>    echoes the PID
#
# The listener writes its own PID once every port is bound. That file is the readiness
# signal and the only trustworthy PID: setsid forks when it has to, and then $! names a
# process that has already exited.
alert_listener_start() {
	local host="$1" pidfile="$2" logfile="$3" i
	rm -f "$pidfile"
	setsid python3 "$ALERT_LISTENER" --host "$host" --ports "$ALERT_PORTS" \
		--pidfile "$pidfile" </dev/null >"$logfile" 2>&1 &
	for ((i = 0; i < 50; i++)); do
		if [[ -s "$pidfile" ]]; then
			cat "$pidfile"
			return 0
		fi
		sleep 0.1
	done
	echo "the alert listener did not come up; its output:" >&2
	sed 's/^/    /' "$logfile" >&2 2>/dev/null || true
	return 1
}

# Stops it. The PID is checked against the process's command line before it is
# signalled: one recorded by a session that did not survive a reboot may now name
# anything. With no usable PID it falls back to the script path, which nothing else runs.
#   alert_listener_stop [pid]
alert_listener_stop() {
	local pid="${1:-}"
	if [[ -n "$pid" && -r "/proc/$pid/cmdline" ]] \
		&& [[ "$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)" == *alert_listener.py* ]]; then
		kill "$pid" 2>/dev/null || true
		return 0
	fi
	pkill -f -- "Firewall/alert_listener.py" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Running without the research VM
#
# The bank's public web site, and optionally the bank itself, on this machine. These mirror
# what Remote/vm-net.sh does on the VM, so a window captured offline differs from a cloud one
# in where it was observed, not in what the simulated users did.
# ---------------------------------------------------------------------------
WEB_FRONT="$PDE_ROOT/Firewall/benign_web.py"
BANK_RELAY="$PDE_ROOT/Remote/bank-relay.py"
FINERACT_DIR="${FINERACT_DIR:-$(cd "$PDE_ROOT/.." && pwd)/Fineract}"
# The local bank (Banking/local-bank.sh) publishes Fineract on this machine's loopback only.
# The relay puts it on the lab's host address, where a user's call crosses INPUT and the
# firewall logs it — the same arrangement as on the VM, for the same reason.
LOCAL_BANK_TARGET="${LOCAL_BANK_TARGET:-127.0.0.1:8443}"
# Its own seed file. A seed holds one Fineract instance's database ids, so the VM's means
# nothing to a local bank and the other way round; keeping them apart lets one checkout use
# either.
LOCAL_BANK_SEED="${LOCAL_BANK_SEED:-$PDE_ROOT/Banking/seed.local.json}"

# Starts the bank's public web site on <host>, detached. Self-signed TLS, made once into
# <tlsdir>: nothing in the lab verifies it, as nothing here has a CA to verify against.
#   web_front_start <host> <pidfile> <logfile> <tlsdir>    echoes the PID
web_front_start() {
	local host="$1" pidfile="$2" logfile="$3" tlsdir="$4" i
	if [[ -n "$WEB_HTTPS_PORTS" && ! -s "$tlsdir/cert.pem" ]]; then
		mkdir -p "$tlsdir" && chmod 700 "$tlsdir"
		openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=pde-bank.lab" \
			-keyout "$tlsdir/key.pem" -out "$tlsdir/cert.pem" >/dev/null 2>&1 || {
			echo "could not create the web site's certificate (is openssl installed?)" >&2
			return 1
		}
	fi
	rm -f "$pidfile"
	setsid python3 "$WEB_FRONT" --host "$host" --http-ports "$WEB_HTTP_PORTS" \
		--https-ports "$WEB_HTTPS_PORTS" --cert "$tlsdir/cert.pem" --key "$tlsdir/key.pem" \
		--pidfile "$pidfile" </dev/null >"$logfile" 2>&1 &
	for ((i = 0; i < 50; i++)); do
		[[ -s "$pidfile" ]] && { cat "$pidfile"; return 0; }
		sleep 0.1
	done
	echo "the bank's web site did not come up; its output:" >&2
	sed 's/^/    /' "$logfile" >&2 2>/dev/null || true
	# The usual cause on a developer's machine: a service listening on every interface at one
	# of these ports — most often the Evidence Repository's backend on 8080.
	if grep -q 'cannot bind' "$logfile" 2>/dev/null; then
		echo "    hint: another service holds that port on all of this machine's addresses. Run it on" >&2
		echo "    127.0.0.1 only (the Evidence Repository: --server.address=127.0.0.1) or stop it" >&2
		echo "    while the lab runs." >&2
	fi
	return 1
}

# The bank relay, detached: accepts on <listen> (address:port) and passes the bytes to
# <target>. It parses nothing, so the user's TLS session is still with Fineract.
#   bank_relay_start <listen> <target> <pidfile> <logfile>    echoes the PID
bank_relay_start() {
	local listen="$1" target="$2" pidfile="$3" logfile="$4" i
	rm -f "$pidfile"
	setsid python3 "$BANK_RELAY" --listen "$listen" --target "$target" --pidfile "$pidfile" \
		</dev/null >"$logfile" 2>&1 &
	for ((i = 0; i < 50; i++)); do
		[[ -s "$pidfile" ]] && { cat "$pidfile"; return 0; }
		sleep 0.1
	done
	echo "the bank relay did not come up; its output:" >&2
	sed 's/^/    /' "$logfile" >&2 2>/dev/null || true
	return 1
}

# Stops a detached helper by its PID, but only while that PID still belongs to the helper:
# a PID recycled after a reboot must not take an unrelated process with it. Without a usable
# PID, falls back to the helper's script path.
#   _helper_stop <pid> <script path fragment>
_helper_stop() {
	local pid="${1:-}" name="$2"
	if [[ -n "$pid" && -r "/proc/$pid/cmdline" ]] \
		&& [[ "$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)" == *"$name"* ]]; then
		kill "$pid" 2>/dev/null || true
		return 0
	fi
	pkill -f -- "$name" 2>/dev/null || true
}
web_front_stop()  { _helper_stop "${1:-}" "Firewall/benign_web.py"; }
bank_relay_stop() { _helper_stop "${1:-}" "Remote/bank-relay.py"; }

# True while a helper started above is still running under the PID it was given.
helper_alive() {
	local pid="${1:-}" name="$2"
	[[ -n "$pid" && -r "/proc/$pid/cmdline" ]] \
		&& [[ "$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)" == *"$name"* ]]
}

# The local bank's state as Docker reports it, e.g. "Up 5 minutes (healthy)"; empty when it
# is not running. Found by the compose labels rather than a container name, so it does not
# depend on the compose project's name.
local_bank_state() {
	docker ps --filter "label=com.docker.compose.service=fineract-manager" \
		--filter "label=com.docker.compose.project.working_dir=$FINERACT_DIR" \
		--format '{{.Status}}' 2>/dev/null | head -1
}
local_bank_healthy() { [[ "$(local_bank_state)" == *"(healthy)"* ]]; }

# The port lists carry the dataset's labels, and the rules that apply them cannot detect a
# contradiction between two lists — they just produce a window in which some packet is
# labelled one thing by the firewall and the opposite by the ground truth. 8443 sat in both
# MALICIOUS_PORTS and ALLOWED_PORTS for several commits without anything noticing, so the
# invariants the comments above state are now checked before a lab is built.
#
# PRESERVE_PORTS overlapping MALICIOUS_PORTS (22, 5432) is the one intended overlap and is
# NOT flagged: those ports are both a real host service and something an attacker probes,
# and rule ORDER is what keeps it from mislabelling anything.
#
#   lab_check_port_lists    prints every problem it finds; non-zero if there were any
lab_check_port_lists() {
	local bad=0
	_ports_of() { tr ',' '\n' <<< "$1" | sed '/^$/d' | sort -u; }
	_overlap() {
		local common
		common=$(comm -12 <(_ports_of "$2") <(_ports_of "$4") | tr '\n' ' ')
		if [[ -n "${common// /}" ]]; then
			echo "port lists $1 and $3 overlap on: ${common% }" >&2
			bad=1
		fi
	}

	_overlap BENIGN_PORTS    "$BENIGN_PORTS"    MALICIOUS_PORTS "$MALICIOUS_PORTS"
	_overlap BENIGN_PORTS    "$BENIGN_PORTS"    ALERT_PORTS     "$ALERT_PORTS"
	_overlap MALICIOUS_PORTS "$MALICIOUS_PORTS" ALERT_PORTS     "$ALERT_PORTS"
	_overlap ALERT_PORTS     "$ALERT_PORTS"     PRESERVE_PORTS  "$PRESERVE_PORTS"
	# The bank's port must not appear in any of the three, because it is in ALLOWED_PORTS:
	# anything it shares a list with inherits the ALLOW label whether that is true or not.
	_overlap BANK_PORT "$BANK_PORT" BENIGN_PORTS    "$BENIGN_PORTS"
	_overlap BANK_PORT "$BANK_PORT" MALICIOUS_PORTS "$MALICIOUS_PORTS"
	_overlap BANK_PORT "$BANK_PORT" ALERT_PORTS     "$ALERT_PORTS"

	# The web front must answer exactly the benign ports: a benign port it does not serve puts
	# bare connects to a closed port back into the benign traffic, which is what made innocent
	# users look like scanners to the IDS.
	local web; web=$(printf '%s,%s' "$WEB_HTTP_PORTS" "$WEB_HTTPS_PORTS")
	if [[ "$(_ports_of "$web" | tr '\n' ,)" != "$(_ports_of "$BENIGN_PORTS" | tr '\n' ,)" ]]; then
		echo "WEB_HTTP_PORTS + WEB_HTTPS_PORTS ($web) must equal BENIGN_PORTS ($BENIGN_PORTS)" >&2
		bad=1
	fi

	# iptables' multiport match takes at most 15 ports, and silently refuses the rule above
	# that — which would leave a window with no verdict lines at all.
	local n; n=$(_ports_of "$ALLOWED_PORTS" | wc -l)
	if [[ "$n" -gt 15 ]]; then
		echo "ALLOWED_PORTS has $n ports; iptables multiport accepts at most 15" >&2
		bad=1
	fi

	unset -f _ports_of _overlap
	return "$bad"
}
