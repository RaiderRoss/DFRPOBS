#!/usr/bin/env bash
# ==============================================================
#  Slips lifecycle helpers for the PDE capture.
#
#  Sourced by simulate-firewall.sh when --with-ids is given. Slips runs with
#  --net=host, so it can sniff the veth the firewall simulator creates and
#  observe exactly the packets ufw is logging — one window, two independent
#  accounts of the same traffic.
#
#  Not a standalone script: it defines functions and touches no global state
#  beyond the two container names below.
# ==============================================================

SLIPS_IMG="${SLIPS_IMG:-stratosphereips/slips:latest}"
# Deliberately distinct from the names slips-cli.sh uses, so a running lab
# console is never adopted or torn down by a capture.
SLIPS_CONTAINER="${SLIPS_CONTAINER:-pde-slips}"
SLIPS_REDIS="${SLIPS_REDIS:-pde-slips-redis}"

_slips_running() { docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$1"; }

slips_preflight() {
	command -v docker >/dev/null 2>&1 || { echo "docker not found" >&2; return 1; }
	docker info >/dev/null 2>&1 || { echo "cannot reach the docker daemon" >&2; return 1; }
	docker image inspect "$SLIPS_IMG" >/dev/null 2>&1 || {
		echo "slips image not present: $SLIPS_IMG" >&2
		echo "  docker pull $SLIPS_IMG   (about 6GB)" >&2
		return 1
	}
	# slips-cli.sh's containers also bind 6379 with --net=host, so both cannot
	# hold the port. Refuse rather than fight over it.
	if _slips_running slips || _slips_running slips-redis; then
		echo "the slips lab console is already running (containers 'slips'/'slips-redis')" >&2
		echo "  stop it first: option 2 in Anomaly Detection/Scripts/slips-cli.sh" >&2
		return 1
	fi
	return 0
}

# Redis holds all Slips state and is the bus between its ~18 processes.
# v1.1.22 crashes if it has to start Redis itself, so it must already be
# listening before Slips launches.
slips_start_redis() {
	if _slips_running "$SLIPS_REDIS"; then return 0; fi
	docker rm -f "$SLIPS_REDIS" >/dev/null 2>&1 || true
	docker run -d --net=host --name "$SLIPS_REDIS" "$SLIPS_IMG" \
		/redis-stable/src/redis-server config/redis.conf.template \
		--port 6379 --bind 127.0.0.1 --daemonize no >/dev/null || return 1
	local i
	for i in $(seq 1 20); do
		if docker exec "$SLIPS_REDIS" /redis-stable/src/redis-cli -p 6379 ping 2>/dev/null | grep -q PONG; then
			return 0
		fi
		sleep 1
	done
	echo "redis did not become ready" >&2
	return 1
}

# $1 interface to sniff, $2 host directory for Slips output
slips_start() {
	local iface="$1" outdir="$2"
	mkdir -p "$outdir"
	docker rm -f "$SLIPS_CONTAINER" >/dev/null 2>&1 || true
	docker run -d --net=host --cap-add=NET_ADMIN --name "$SLIPS_CONTAINER" \
		-v "$outdir":/output "$SLIPS_IMG" \
		./slips.py -i "$iface" -o /output >/dev/null
}

# Slips loads 15 modules and 45+ threat-intel feeds before it reads a single
# packet. Nothing may be generated until this returns, or the window's traffic
# is simply missed. $1 = timeout in seconds.
slips_wait_ready() {
	local timeout="${1:-240}" waited=0
	while [ "$waited" -lt "$timeout" ]; do
		if docker logs "$SLIPS_CONTAINER" 2>&1 | grep -q "Started Input Process"; then
			return 0
		fi
		if ! _slips_running "$SLIPS_CONTAINER"; then
			echo "slips exited during startup; last lines:" >&2
			docker logs "$SLIPS_CONTAINER" 2>&1 | tail -5 >&2
			return 1
		fi
		sleep 5
		waited=$((waited + 5))
	done
	echo "slips did not report readiness within ${timeout}s" >&2
	return 1
}

slips_stop() {
	docker rm -f "$SLIPS_CONTAINER" >/dev/null 2>&1 || true
	docker rm -f "$SLIPS_REDIS" >/dev/null 2>&1 || true
}

# Slices Slips' evidence to the capture window and writes it to $4.
#   $1 slips output dir   $2 window start (ISO)   $3 window end (ISO)   $4 destination
# Echoes "<total> <in_window>" so the caller can report both.
slips_collect() {
	local slips_out="$1" start="$2" end="$3" dest="$4"
	python3 - "$slips_out/alerts/alerts.log" "$start" "$end" "$dest" <<'PY'
import sys, os
from datetime import datetime, timezone

src, start_s, end_s, dest = sys.argv[1:5]

def parse(s):
    s = s.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    # Slips may write a naive local timestamp; assume UTC rather than drop the
    # line, since dropping would silently shrink the evidence.
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

start, end = parse(start_s), parse(end_s)
total = kept = 0
lines = []
if os.path.exists(src):
    for line in open(src, errors="replace"):
        if not line.strip():
            continue
        total += 1
        ts = parse(line.split(" ", 1)[0])
        # A line whose timestamp cannot be parsed is kept: an unreadable
        # timestamp is a reason to look at the evidence, not to discard it.
        if ts is None or (start <= ts <= end):
            kept += 1
            lines.append(line)
open(dest, "w").writelines(lines)
print("%d %d" % (total, kept))
PY
}

# Evidence counts by Slips' own threat scale, for the manifest.
# $1 = the sliced evidence file. Echoes "critical high medium low info".
slips_severity_counts() {
	python3 - "$1" <<'PY'
import sys, os, re
levels = ["critical", "high", "medium", "low", "info"]
counts = dict.fromkeys(levels, 0)
path = sys.argv[1]
if os.path.exists(path):
    for line in open(path, errors="replace"):
        m = re.search(r"Threat level:\s*(\w+)", line)
        if m and m.group(1).lower() in counts:
            counts[m.group(1).lower()] += 1
print(" ".join(str(counts[l]) for l in levels))
PY
}
