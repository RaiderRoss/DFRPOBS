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

# Ports the firewall denies — the sweep an attacker runs looking for a way in.
#
# Deliberately wide. The firewall logs a BLOCK however few ports are touched, but an
# IDS decides "vertical port scan" from the number of DISTINCT ports one source reaches
# for on one host inside a timewindow — measured at around 10 for Slips. A thin list
# leaves the IDS silent about an attack the firewall recorded plainly, which is the
# opposite of the correlation this exists to demonstrate. None may overlap BENIGN_PORTS.
MALICIOUS_PORTS="21,22,23,25,53,110,111,135,137,139,143,161,389,445,512,513,514,873,993,995,1080,1433,1521,2049,2375,3306,3389,5060,5432,5900,6379,8443,9200,11211,27017"

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
