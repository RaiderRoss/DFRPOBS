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
		# Version-dependent: 1.1.x prints "Started Input Process", the current image prints the
		# Zeek interface line. Matching only the old one waits out the full timeout against a
		# Slips that is already reading packets.
		if docker logs "$SLIPS_CONTAINER" 2>&1 \n			| grep -qE "Started Input Process|Zeek is logging all traffic on interface"; then
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
        # Alert lines put a colon straight after the timestamp ("<iso>: Src IP ...
        # Generated an alert"), where evidence lines put a space. Stripped so an alert is
        # sliced by its own time rather than kept only because it failed to parse.
        ts = parse(line.split(" ", 1)[0].rstrip(":"))
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

# Slips' own alert verdicts in the sliced evidence, for the manifest. Evidence is what
# Slips saw; an alert is Slips deciding one source crossed its threshold.
# $1 = the sliced evidence file. Echoes one number.
slips_alert_count() {
	local n
	# grep -c prints 0 AND exits 1 on no match; `|| true` keeps the one 0.
	n=$(grep -cE "(Generated an alert|Is blocked) given enough evidence on timewindow" "$1" 2>/dev/null || true)
	printf '%s' "${n:-0}"
}

# ===========================================================================
# Remote mode: the sensor here, the analysis on the research VM.
#
# tcpdump writes the veth to one pcap for the life of the lab — the sensor never stops.
# Each window is the slice of that file written while the window was open, taken by byte
# offset exactly as the ufw log is, then shipped to the VM and analysed there by Slips in
# file mode. Packets keep the timestamps the kernel gave them here, on the same clock the
# window bounds and the firewall log use, so the IDS evidence lines up with them without
# any correction. Slips starts fresh per window, which is the one thing this mode gives up:
# its per-source profile no longer carries over between windows.
#
# Requires Remote/vm-lib.sh sourced (vm_ssh).
# ===========================================================================

# Starts the capture, detached, and echoes tcpdump's PID once the file exists.
#   pcap_capture_start <iface> <pcap> <logfile>
pcap_capture_start() {
	local iface="$1" pcap="$2" logfile="$3" i
	mkdir -p "$(dirname "$pcap")"
	# -U: write each packet as it is captured, so the file on disk is never more than one
	# packet behind the wire — what makes a byte offset a meaningful moment.
	# -Z root: keep writing as root; the output directory is not the tcpdump user's.
	# -s 0: whole packets. The IDS needs payloads only for what is unencrypted, but a
	# truncated capture is a decision nobody could undo later.
	setsid tcpdump -i "$iface" -U -s 0 -Z root -w "$pcap" </dev/null >"$logfile" 2>&1 &
	local pid=$!
	for ((i = 0; i < 50; i++)); do
		# The pcap global header is 24 bytes and is written as soon as the file opens.
		if [[ -s "$pcap" ]] && [[ $(stat -c %s "$pcap") -ge 24 ]]; then
			echo "$pid"
			return 0
		fi
		kill -0 "$pid" 2>/dev/null || break
		sleep 0.1
	done
	echo "tcpdump did not start on $iface; its output:" >&2
	sed 's/^/    /' "$logfile" >&2 2>/dev/null || true
	return 1
}

# PID checked against the command line before it is signalled, as the alert listener's is.
pcap_capture_stop() {
	local pid="${1:-}"
	if [[ -n "$pid" && -r "/proc/$pid/cmdline" ]] \
		&& [[ "$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)" == *tcpdump* ]]; then
		kill -INT "$pid" 2>/dev/null || true   # INT: tcpdump flushes and closes the file
	fi
}

pcap_offset() { stat -c %s "$1" 2>/dev/null || echo 0; }

# Writes the packets captured after <offset> to <dest> as a standalone pcap.
#   pcap_slice <pcap> <offset> <dest>     echoes "<packets> <first_ts> <last_ts>"
#
# Walks record headers from the start of the file rather than seeking to the offset: the
# offset was taken while tcpdump was writing and may fall inside a record, and a slice
# that began mid-record would be garbage from its first byte. A record belongs to the
# window if it *starts* at or after the offset; one still being written at the end is
# left out, and is picked up whole by the next window instead of split across two.
pcap_slice() {
	python3 - "$1" "$2" "$3" <<'PY'
import os, struct, sys
src, offset, dest = sys.argv[1], int(sys.argv[2]), sys.argv[3]
size = os.path.getsize(src)                     # boundary taken once, now
with open(src, "rb") as fh:
    header = fh.read(24)
    if len(header) < 24:
        sys.exit("capture has no pcap header")
    magic = struct.unpack("<I", header[:4])[0]
    if magic in (0xa1b2c3d4, 0xa1b23c4d):
        endian = "<"
    elif magic in (0xd4c3b2a1, 0x4d3cb2a1):
        endian = ">"
    else:
        sys.exit("not a pcap file (magic %08x)" % magic)
    nano = magic in (0xa1b23c4d, 0x4d3cb2a1)
    pos, count, first, last = 24, 0, None, None
    with open(dest, "wb") as out:
        out.write(header)
        while pos + 16 <= size:
            fh.seek(pos)
            rec = fh.read(16)
            ts_sec, ts_frac, incl, _orig = struct.unpack(endian + "IIII", rec)
            end = pos + 16 + incl
            if end > size:
                break                                # still being written
            if pos >= offset:
                fh.seek(pos)
                out.write(fh.read(16 + incl))
                ts = ts_sec + ts_frac / (1e9 if nano else 1e6)
                first = ts if first is None else first
                last = ts
                count += 1
            pos = end
print(count, "%.6f" % (first or 0), "%.6f" % (last or 0))
PY
}

SLIPS_REMOTE_DIR="${SLIPS_REMOTE_DIR:-pde-slips}"

slips_remote_preflight() {
	vm_reachable || {
		echo "the research VM is not reachable (status: $(vm_status || echo unknown)) — ./vm.sh start" >&2
		return 1
	}
	vm_ssh "docker image inspect '$SLIPS_IMG' >/dev/null 2>&1" </dev/null || {
		echo "the VM has no Slips image ($SLIPS_IMG) — on the VM: docker pull $SLIPS_IMG" >&2
		return 1
	}
	# Not a failure — the first window would simply wait for the feeds — but worth saying
	# before a capture looks hung for several minutes.
	local warm
	warm=$(vm_ssh "bash \"\$HOME/$VM_REPO_DIR/PDE Sources/Remote/slips-warm.sh\" status" </dev/null 2>/dev/null || true)
	if [[ "$warm" != "warm" ]]; then
		echo "note: Slips' threat-intel cache on the VM is $warm; the first window may take ~7 min" >&2
	fi
	return 0
}

# Ships one window's pcap to the VM, runs Slips over it, and brings the output home.
#   slips_remote_analyse <pcap> <stamp> <dest_dir>
# dest_dir receives Slips' whole output tree (alerts.log, alerts.json, zeek_files/...).
slips_remote_analyse() {
	local pcap="$1" stamp="$2" dest="$3"
	local rdir="$SLIPS_REMOTE_DIR/$stamp"

	vm_ssh "rm -rf \"\$HOME/$rdir\" && mkdir -p \"\$HOME/$rdir\" && cat > \"\$HOME/$rdir/window.pcap\"" < "$pcap" \
		|| { echo "could not upload the window's pcap" >&2; return 1; }

	# Redis is the VM's standing one (Remote/slips-warm.sh), which also holds Slips' cache
	# of ~45 threat-intel feeds: a Slips run against an empty cache downloads them all first
	# (measured at 7 minutes), against a warm one it analyses a window in about one. Slips in
	# file mode exits on its own once it has read the whole capture; the timeout guards a hang.
	vm_ssh "set -e
		bash \"\$HOME/$VM_REPO_DIR/PDE Sources/Remote/slips-warm.sh\" redis
		timeout 900 docker run --rm --net=host -v \"\$HOME/$rdir\":/output '$SLIPS_IMG' \
			./slips.py -f /output/window.pcap -o /output/out > \"\$HOME/$rdir/slips-run.log\" 2>&1
		sudo chown -R \"\$(id -u):\$(id -g)\" \"\$HOME/$rdir\"
		mkdir -p \"\$HOME/$rdir/out/alerts\"
		test -f \"\$HOME/$rdir/out/alerts/alerts.log\" || touch \"\$HOME/$rdir/out/alerts/alerts.log\"" </dev/null \
		|| { echo "Slips failed on the VM; see ~/$rdir/slips-run.log there" >&2; return 1; }

	mkdir -p "$dest"
	vm_ssh "tar -C \"\$HOME/$rdir/out\" -cf - ." </dev/null | tar -C "$dest" -xf - \
		|| { echo "could not fetch Slips' output" >&2; return 1; }
}
