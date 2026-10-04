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

# Everything the subnet is permitted to reach, for the verdict LOG rules. The BLOCK rule
# is "everything else", so a permitted port missing from here is logged as BLOCK.
# iptables multiport accepts at most 15 ports.
ALLOWED_PORTS="$BENIGN_PORTS,$ALERT_PORTS"

ALERT_LISTENER="$PDE_ROOT/Firewall/alert_listener.py"

# Host services kept reachable while ufw is up, so a default-deny firewall does not cut
# off the dev stack or the Windows host's access to it. Overlaps MALICIOUS_PORTS on 22
# and 5432 — see the rule ordering in lab.sh, which is what stops that overlap
# mislabelling attacker traffic as permitted.
PRESERVE_PORTS="22,5432,5433,8080,9000,9001,19092,8081"

UFW_LOG="/var/log/ufw.log"
KERN_LOG="/var/log/kern.log"

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

# Exempts loopback traffic from the lab firewall's default deny and from its audit log.
# Called right after `ufw enable`; ufw rebuilds its chains on the next reload or disable,
# so `down` and the capture's exit trap remove these with the rest of the raw rules.
#
# Two problems, both fatal to the IDS:
#
#  - Under WSL with networkingMode=mirrored, 127.0.0.1 is routed over `loopback0`, not
#    `lo`, and ufw only exempts `lo`. Every new connection Slips' processes open to their
#    Redis on 127.0.0.1:6379 falls through to the default deny, Slips times out on its own
#    message bus, analyses zero flows and never alerts — while Zeek, which needs no Redis,
#    keeps writing conn.log and makes it look as though everything is working.
#
#  - At LOGLEVEL=full ufw logs every packet with no rate limit, and Slips <-> Redis is
#    by far the busiest traffic on the host: 3.6 GB each of ufw.log, kern.log and syslog
#    in under half an hour, with rsyslog pinned on a CPU.
#
# Neither loses evidence. Loopback traffic can never carry SRC=10.99.0.*, and the capture
# keeps only those lines — see the extraction in simulate-firewall.sh.
#   firewall_exempt_loopback
firewall_exempt_loopback() {
	local cmd prefix iface
	for cmd in iptables ip6tables; do
		command -v "$cmd" >/dev/null || continue
		[[ $cmd == iptables ]] && prefix=ufw || prefix=ufw6
		for iface in lo loopback0; do
			ip link show "$iface" >/dev/null 2>&1 || continue
			# RETURN from the audit chains: the packet carries on to the real verdict,
			# it is simply not logged.
			"$cmd" -I "${prefix}-before-logging-input" 1 -i "$iface" -j RETURN 2>/dev/null || true
			"$cmd" -I "${prefix}-before-logging-output" 1 -o "$iface" -j RETURN 2>/dev/null || true
			# ufw already accepts lo; loopback0 is the one it does not know about.
			if [[ $iface == loopback0 ]]; then
				"$cmd" -I "${prefix}-before-input" 1 -i "$iface" -j ACCEPT 2>/dev/null || true
				"$cmd" -I "${prefix}-before-output" 1 -o "$iface" -j ACCEPT 2>/dev/null || true
			fi
		done
	done
}

# Where Slips keeps its live output for a session — the directory it is started with -o.
#   ids_sessions_dir    echoes the directory (not created)
#
# Normally output/sessions in the repo. But under WSL the repo usually lives on a Windows
# drive (/mnt/c, a 9p filesystem), and there Slips reads nothing: Zeek writes conn.log
# into the session directory and Slips' input process never picks a line of it up, so it
# profiles zero flows and never alerts, with no error anywhere. Measured side by side on
# the same veth and the same traffic: 0 profiles on /mnt/c, 138 profiles and 7 alerts on
# ext4. So on 9p the session moves to the Linux filesystem.
#
# Nothing downstream needs it in the repo: each captured window already gets its own copy
# of the IDS evidence (ids_<ts>.alerts.log), and the session path is recorded in the lab
# state for everything that follows it.
ids_sessions_dir() {
	local repo_dir="$PDE_ROOT/output/sessions" probe="$PDE_ROOT/output"
	[[ -d "$probe" ]] || probe="$PDE_ROOT"
	if [[ "$(stat -f -c %T "$probe" 2>/dev/null)" == "v9fs" ]]; then
		echo "${PDE_IDS_SESSIONS:-/var/lib/pde-lab/sessions}"
	else
		echo "${PDE_IDS_SESSIONS:-$repo_dir}"
	fi
}

SLIPS_FORWARDER="$PDE_ROOT/IDS/slips_forwarder.py"

# Starts the forwarder that sends Slips' alerts to the Evidence Repository as trigger
# events, detached like the alert listener and for the same reason.
#   slips_forwarder_start <slips-out> <pidfile> <logfile>    echoes the PID
#
# It follows alerts.log for the life of the lab, and keeps retrying if the repository's
# broker is not up yet, so the lab does not depend on the compose stack being started
# first. KAFKA_BOOTSTRAP_SERVERS, KAFKA_EVIDENCE_TOPIC and DFRAAS_IDS_SOURCE_KEY pass
# through from the environment.
slips_forwarder_start() {
	local slips_out="$1" pidfile="$2" logfile="$3" i
	rm -f "$pidfile"
	setsid python3 "$SLIPS_FORWARDER" --slips-out "$slips_out" --pidfile "$pidfile" \
		</dev/null >"$logfile" 2>&1 &
	for ((i = 0; i < 50; i++)); do
		if [[ -s "$pidfile" ]]; then
			cat "$pidfile"
			return 0
		fi
		sleep 0.1
	done
	echo "the Slips forwarder did not come up; its output:" >&2
	sed 's/^/    /' "$logfile" >&2 2>/dev/null || true
	return 1
}

# Stops it, checking the PID against the command line first, as alert_listener_stop does.
# SIGTERM lets it finish the send in hand and record its offset.
#   slips_forwarder_stop [pid]
slips_forwarder_stop() {
	local pid="${1:-}"
	if [[ -n "$pid" && -r "/proc/$pid/cmdline" ]] \
		&& [[ "$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)" == *slips_forwarder.py* ]]; then
		kill "$pid" 2>/dev/null || true
		return 0
	fi
	pkill -f -- "IDS/slips_forwarder.py" 2>/dev/null || true
}
