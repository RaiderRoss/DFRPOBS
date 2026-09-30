#!/usr/bin/env bash
# ==============================================================
#  Runs ON the research VM, as root (sudo).
#
#    read-window.sh offset <path|journal>
#    read-window.sh slice  <path|journal> <offset> <outdir> <name>
#
#  Once the firewall and the IDS run on the VM, their records are
#  on the VM, and a window is still a bounded read against
#  something that keeps being written — the same mechanism as
#  before, one machine further away.
#
#  Two kinds of record, because the two sources keep theirs
#  differently:
#
#    a file      bounded by a BYTE OFFSET, as the lab always did.
#                Slips' alerts.log is read this way.
#
#    journal     bounded by a JOURNAL CURSOR. The firewall is read
#                this way, and not from /var/log/ufw.log, because
#                on this VM that file does not receive the lines:
#                measured, the netfilter LOG rules fired 628 times
#                for a window, `journalctl -k` held those lines,
#                and /var/log/ufw.log held none of them. rsyslog
#                is in the path for the file and is not delivering
#                them; the journal is where the kernel's own
#                record actually is, so that is what is read.
#
#  This deliberately does no parsing beyond the [UFW prefix the
#  journal needs to stay a sane size. Slicing to the window,
#  filtering by address and counting verdicts all stay on the lab
#  machine, in the code that already does them, so there is one
#  implementation of each rather than a second one here that has
#  to agree with it.
#
#  Root because /var/log/* is root:adm, Slips writes its output as
#  root from inside its container, and the kernel journal needs
#  privilege to read.
# ==============================================================
set -u

die() { printf '[read-window] error: %s\n' "$*" >&2; exit 1; }

# Everything the kernel logged through ufw's chains. The same selection rsyslog's own
# 20-ufw.conf makes, so this is the same record it would have written.
JOURNAL_FILTER='[UFW '

cmd_offset() {
	local path="$1"
	if [[ "$path" == "journal" ]]; then
		# --show-cursor prints the cursor after the (empty) output; -n0 asks for no lines.
		local cur
		cur=$(journalctl -k -n0 --show-cursor 2>/dev/null | sed -n 's/^-- cursor: //p')
		printf 'cursor:%s\n' "${cur:-}"
	elif [[ -e "$path" ]]; then
		stat -c %s "$path"
	else
		# 0 for a file that is not there yet: Slips creates alerts.log only when it has its
		# first finding, and "not there yet" is a legitimate window start, not a failure.
		echo 0
	fi
}

cmd_slice() {
	local path="$1" offset="$2" outdir="$3" name="$4"
	mkdir -p "$outdir" || die "cannot write $outdir"
	local dest="$outdir/$name"

	if [[ "$path" == "journal" ]]; then
		local cursor="${offset#cursor:}"
		if [[ -n "$cursor" ]]; then
			journalctl -k --after-cursor "$cursor" -o short-iso-precise --no-pager 2>/dev/null \
				| grep -F "$JOURNAL_FILTER" > "$dest" || : > "$dest"
		else
			# No cursor to read from — a journal that had nothing in it when the window
			# opened. Bounded by time instead, generously, since the window's own slicing
			# happens on the lab machine anyway.
			journalctl -k --since '-15min' -o short-iso-precise --no-pager 2>/dev/null \
				| grep -F "$JOURNAL_FILTER" > "$dest" || : > "$dest"
		fi
	elif [[ ! -e "$path" ]]; then
		# An empty slice rather than an error, for the same reason as above. The caller is
		# told how many bytes it got and can decide whether nothing is suspicious.
		: > "$dest"
	else
		# The end boundary is wherever the file happens to be now. Taken by tail from the
		# offset rather than by seeking a length computed earlier, so a write landing while
		# this runs extends the slice instead of corrupting it.
		tail -c "+$((offset + 1))" "$path" > "$dest" 2>/dev/null || : > "$dest"
	fi

	local bytes sha lines
	bytes=$(stat -c %s "$dest")
	sha=$(sha256sum "$dest" | cut -d' ' -f1)
	lines=$(wc -l < "$dest")
	printf '{"file": "%s", "from": "%s", "bytes": %s, "lines": %s, "sha256": "%s"}\n' \
		"$name" "$offset" "$bytes" "$lines" "$sha"
}

case "${1:-}" in
	offset) [[ $# -eq 2 ]] || die "offset <path|journal>"; cmd_offset "$2" ;;
	slice)  [[ $# -eq 5 ]] || die "slice <path|journal> <offset> <outdir> <name>"
	        cmd_slice "$2" "$3" "$4" "$5" ;;
	*) sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'; exit 1 ;;
esac
