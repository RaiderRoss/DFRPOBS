#!/usr/bin/env bash
# ==============================================================
#  Runs ON the research VM. The remote-access source.
#
#    collect-auth.sh offset
#    collect-auth.sh collect <offset> <start_iso> <end_iso> <outdir> [tun_dev]
#
#  Every window's traffic arrives inside an authenticated SSH
#  session — the tunnel. This is the record of who opened it.
#  It is the source that attributes the session to a person,
#  which no other source in the lab can do: the firewall has an
#  address, the bank has a login, and neither says who sat down.
#
#  THE WINDOW DOES NOT BOUND THIS SOURCE THE WAY IT BOUNDS THE
#  OTHERS. The tunnel is opened when the lab is built and carries
#  every window after it, so the login that matters usually
#  happened BEFORE the window opened. Slicing to the window alone
#  would produce an empty file, which reads as "nobody
#  authenticated" — the opposite of the truth. So two things are
#  collected: the lines inside the window, and the establishing
#  login of the session the window's traffic actually arrived in,
#  whenever that happened.
# ==============================================================
set -u

die() { printf '[collect-auth] error: %s\n' "$*" >&2; exit 1; }

AUTH_LOG=/var/log/auth.log
SSH_UNIT=ssh

# Which record to read. auth.log is preferred because a byte offset is an exact boundary,
# the same mechanism the ufw log uses; journald is the fallback on an image where rsyslog
# is not installed, and is bounded by time instead.
_source_kind() {
	if [[ -r "$AUTH_LOG" ]]; then echo file; else echo journal; fi
}

# ---------------------------------------------------------------------------
# offset — the boundary taken before the window opens
# ---------------------------------------------------------------------------
cmd_offset() {
	case "$(_source_kind)" in
		file)    printf 'file:%s\n' "$(stat -c %s "$AUTH_LOG" 2>/dev/null || echo 0)" ;;
		journal)
			# --show-cursor prints the cursor after the (empty) output; -n0 asks for no lines.
			local cur
			cur=$(journalctl -u "$SSH_UNIT" -n0 --show-cursor 2>/dev/null | sed -n 's/^-- cursor: //p')
			printf 'journal:%s\n' "${cur:-}" ;;
	esac
}

# ---------------------------------------------------------------------------
# Which session is the tunnel?
#
# The sshd session that carries the tun device has it open as a file descriptor, so it can
# be identified exactly rather than guessed at from timing. That PID is what appears in its
# own log lines, which is what ties the evidence to one session instead of to "some login
# around then" — this VM accepts an SSH connection for every remote command the lab runs,
# so there are many, and only one of them is the tunnel.
#
# OpenSSH 9.8 split the session process out as sshd-session, so both names are matched.
# ---------------------------------------------------------------------------
_tunnel_pids() {
	local dev="${1:-}" pid fd
	[[ -n "$dev" ]] || return 0
	# /proc/<pid>/fdinfo is not enough: the tun is a chardev with no name in fdinfo, so the
	# link target is what identifies it. A session's fd to /dev/net/tun resolves there.
	for pid in $(pgrep -x 'sshd|sshd-session' 2>/dev/null); do
		for fd in /proc/"$pid"/fd/*; do
			[[ -e "$fd" ]] || continue
			if [[ "$(readlink -f "$fd" 2>/dev/null)" == "/dev/net/tun" ]]; then
				echo "$pid"
				break
			fi
		done
	done
}

# ---------------------------------------------------------------------------
# collect
# ---------------------------------------------------------------------------
cmd_collect() {
	local offset="$1" start="$2" end="$3" outdir="$4" dev="${5:-}"
	mkdir -p "$outdir" || die "cannot write $outdir"
	local out="$outdir/auth.log" meta="$outdir/auth.meta.json"
	: > "$out"

	local kind="${offset%%:*}" pos="${offset#*:}"
	local window_lines=0 session_lines=0 method=""

	# --- the window's own lines -------------------------------------------
	local win; win=$(mktemp)
	case "$kind" in
		file)
			method="byte offset into $AUTH_LOG"
			[[ -r "$AUTH_LOG" ]] || die "$AUTH_LOG is not readable (run under sudo)"
			tail -c "+$((pos + 1))" "$AUTH_LOG" 2>/dev/null > "$win" || true ;;
		journal)
			method="journald cursor for unit $SSH_UNIT"
			if [[ -n "$pos" ]]; then
				journalctl -u "$SSH_UNIT" --after-cursor "$pos" --no-pager -o short-iso-precise \
					> "$win" 2>/dev/null || true
			else
				journalctl -u "$SSH_UNIT" --since "$start" --until "$end" --no-pager \
					-o short-iso-precise > "$win" 2>/dev/null || true
			fi ;;
		*) die "unrecognised offset '$offset'" ;;
	esac
	# `|| true`, never `|| echo 0`: grep -c prints "0" AND exits 1 when nothing
	# matches, so a fallback echo appends a second 0 and the value arrives as "0\n0".
	# simulate-firewall.sh documents this trap; this walked into it.
	window_lines=$(grep -c . "$win" 2>/dev/null || true)
	window_lines=${window_lines:-0}

	# --- the session the window arrived in --------------------------------
	# Collected whatever its age, because the login that authorised this window is the
	# reason the window exists. Marked so nobody reading the file mistakes a line from
	# before the window for something that happened inside it.
	local pids sess; sess=$(mktemp)
	pids=$(_tunnel_pids "$dev" | sort -u | tr '\n' ' ')
	if [[ -n "${pids// /}" ]]; then
		local p
		for p in $pids; do
			case "$kind" in
				file)    grep -E "sshd(-session)?\[$p\]" "$AUTH_LOG" 2>/dev/null ;;
				journal) journalctl -u "$SSH_UNIT" --no-pager -o short-iso-precise 2>/dev/null \
				           | grep -E "sshd(-session)?\[$p\]" ;;
			esac
		done >> "$sess"
	fi
	# `|| true`, never `|| echo 0`: grep -c prints "0" AND exits 1 when nothing
	# matches, so a fallback echo appends a second 0 and the value arrives as "0\n0".
	# simulate-firewall.sh documents this trap; this walked into it.
	session_lines=$(grep -c . "$sess" 2>/dev/null || true)
	session_lines=${session_lines:-0}

	# The evidence file: the session's establishing lines first, then the window's, each
	# under a marker. The markers are the collector's, not the source's, and are commented
	# as such — the log lines themselves are byte-for-byte what sshd wrote.
	{
		printf '### pde-collector: establishing session for the tunnel device %s (pids: %s)\n' \
			"${dev:-unknown}" "${pids:-none identified}"
		printf '### these lines may predate the window; they are the login the window arrived under\n'
		cat "$sess"
		printf '### pde-collector: sshd records inside the window %s .. %s\n' "$start" "$end"
		cat "$win"
	} > "$out"
	rm -f "$win" "$sess"

	local sha; sha=$(sha256sum "$out" | cut -d' ' -f1)

	# Counted rather than described: an accepted login is the event this source exists for.
	local accepted failed
	accepted=$(grep -cE 'Accepted (publickey|password|keyboard-interactive)' "$out" 2>/dev/null || true)
	failed=$(grep -cE 'Failed (publickey|password)|Invalid user|authentication failure' "$out" 2>/dev/null || true)

	python3 - "$meta" "$sha" "${accepted:-0}" "${failed:-0}" "$window_lines" "$session_lines" \
		"$method" "${pids:-}" "$start" "$end" <<'PY'
import json, subprocess, sys
meta, sha, accepted, failed, win_lines, sess_lines, method, pids, start, end = sys.argv[1:11]

def run(*c):
    try:
        return subprocess.run(c, capture_output=True, text=True).stdout.strip()
    except OSError:
        return ""

json.dump({
    "pde_source": "auth",
    "product": "openssh-sshd",
    "version": run("sshd", "-V").splitlines()[0] if run("sshd", "-V") else run("ssh", "-V"),
    "host": run("hostname"),
    "collection_method": method,
    "window": {"start_utc": start, "end_utc": end},
    "tunnel_session_pids": [p for p in pids.split() if p],
    "counts": {
        "accepted_logins": int(accepted),
        "failed_attempts": int(failed),
        "lines_in_window": int(win_lines),
        "lines_for_tunnel_session": int(sess_lines),
    },
    "sha256": sha,
}, open(meta, "w"), indent=2)
PY

	printf 'AUTH_OK sha256=%s accepted=%s failed=%s window_lines=%s session_lines=%s pids=%s\n' \
		"$sha" "${accepted:-0}" "${failed:-0}" "$window_lines" "$session_lines" "${pids:-none}"
}

case "${1:-}" in
	offset)  cmd_offset ;;
	collect)
		[[ $# -ge 5 ]] || die "collect <offset> <start_iso> <end_iso> <outdir> [tun_dev]"
		cmd_collect "$2" "$3" "$4" "$5" "${6:-}" ;;
	*) sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'; exit 1 ;;
esac
