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

# Typical time to readiness, used only to pace the progress bar. Measured at ~46s here;
# the bar is an estimate against this, never a claim about state.
SLIPS_EXPECTED_STARTUP="${SLIPS_EXPECTED_STARTUP:-50}"

# Caps at 99% until readiness is actually observed, so a slow start looks slow instead
# of looking finished. A bar sitting at 100% while nothing happens is worse than none.
_slips_bar() {
	local elapsed="$1" finished="${2:-0}" label="${3:-}" width=30 pct filled i bar=""
	if [ "$finished" = "1" ]; then
		pct=100
	else
		pct=$(( elapsed * 100 / SLIPS_EXPECTED_STARTUP ))
		[ "$pct" -gt 99 ] && pct=99
	fi
	filled=$(( pct * width / 100 ))
	for ((i = 0; i < width; i++)); do
		if [ "$i" -lt "$filled" ]; then bar="${bar}█"; else bar="${bar}░"; fi
	done
	if [ "$finished" = "1" ]; then
		printf '\r  Slips  [%s] %3ds  ready%-38s\n' "$bar" "$elapsed" ""
	else
		printf '\r  Slips  [%s] %3ds  %-38s' "$bar" "$elapsed" "$label"
	fi
}

# Slips loads 15 modules and 45+ threat-intel feeds before it reads a single
# packet. Nothing may be generated until this returns, or the window's traffic
# is simply missed. $1 = timeout in seconds.
slips_wait_ready() {
	local timeout="${1:-240}" waited=0 phase="starting container"
	# Only draw for a human. Piped or logged, the carriage returns are noise, so that
	# path keeps the old quiet 5-second poll.
	local tty=0; [ -t 1 ] && tty=1

	while [ "$waited" -lt "$timeout" ]; do
		if docker logs "$SLIPS_CONTAINER" 2>&1 | grep -q "Started Input Process"; then
			[ "$tty" = 1 ] && _slips_bar "$waited" 1
			return 0
		fi
		if ! _slips_running "$SLIPS_CONTAINER"; then
			[ "$tty" = 1 ] && printf '\n'
			echo "slips exited during startup; last lines:" >&2
			docker logs "$SLIPS_CONTAINER" 2>&1 | tail -5 >&2
			return 1
		fi

		if [ "$tty" = 1 ]; then
			# Phase comes from Slips' own log rather than being inferred from the
			# clock, so the label says what is actually happening.
			if docker logs "$SLIPS_CONTAINER" 2>&1 | grep -qi "loading"; then
				phase="loading modules and threat-intel feeds"
			fi
			[ "$waited" -gt "$SLIPS_EXPECTED_STARTUP" ] && phase="still loading (longer than usual)"
			_slips_bar "$waited" 0 "$phase"
			sleep 1
			waited=$((waited + 1))
		else
			sleep 5
			waited=$((waited + 5))
		fi
	done
	[ "$tty" = 1 ] && printf '\n'
	echo "slips did not report readiness within ${timeout}s" >&2
	return 1
}

slips_stop() {
	docker rm -f "$SLIPS_CONTAINER" >/dev/null 2>&1 || true
	docker rm -f "$SLIPS_REDIS" >/dev/null 2>&1 || true
}

# Byte length of the evidence file right now, for use as a later read boundary.
# Echoes 0 if Slips has not written anything yet.
slips_alerts_offset() {
	local f="$1/alerts/alerts.log"
	if [ -f "$f" ]; then stat -c %s "$f"; else echo 0; fi
}

# Slices Slips' evidence to the capture window and writes it to $5.
#   $1 slips output dir   $2 byte offset to read from   $3 window start (ISO)
#   $4 window end (ISO)   $5 destination
# Echoes "<total> <in_window>".
#
# Reads a bounded byte range rather than requiring Slips to be stopped. A real IDS runs
# continuously and is *read* against, never halted to be collected from; the offset is
# the same mechanism the ufw capture uses while rsyslog keeps writing underneath it.
slips_collect() {
	local slips_out="$1" offset="$2" start="$3" end="$4" dest="$5"
	python3 - "$slips_out/alerts/alerts.log" "$start" "$end" "$dest" "$offset" <<'PY'
import sys, os
from datetime import datetime, timezone

src, start_s, end_s, dest = sys.argv[1:5]
offset = int(sys.argv[5])

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
    end_byte = os.path.getsize(src)          # boundary taken once, now
    with open(src, "rb") as fh:
        fh.seek(offset)
        chunk = fh.read(max(0, end_byte - offset)).decode("utf-8", "replace")
    # A write may be in flight at the boundary, so a trailing fragment without its
    # newline is not a complete finding yet. Dropping it here means it is picked up
    # whole by the next read rather than recorded twice, half each time.
    if chunk and not chunk.endswith("\n"):
        chunk = chunk[:chunk.rfind("\n") + 1] if "\n" in chunk else ""
    for line in chunk.splitlines(keepends=True):
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
