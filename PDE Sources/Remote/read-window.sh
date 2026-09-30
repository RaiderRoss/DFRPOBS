#!/usr/bin/env bash
# ==============================================================
#  Runs ON the research VM, as root (sudo).
#
#    read-window.sh offset <path>
#    read-window.sh slice  <path> <offset> <outdir> <name>
#
#  Once the firewall and the IDS run on the VM, their logs are on
#  the VM, and a window is still a bounded read against a file
#  that keeps being written — the same mechanism as before, one
#  machine further away.
#
#  This deliberately does no parsing. It hands back a byte range
#  and its digest; the slicing, filtering and counting stay on the
#  lab machine in the code that already does them, so there is one
#  implementation of each rather than a second one here that has
#  to agree with it.
#
#  Root because /var/log/ufw.log is root:adm, and Slips writes its
#  output tree as root from inside its container.
# ==============================================================
set -u

die() { printf '[read-window] error: %s\n' "$*" >&2; exit 1; }

cmd_offset() {
	local path="$1"
	# 0 for a file that does not exist yet: Slips creates alerts.log only when it has its
	# first finding, and "not there yet" is a legitimate window start, not a failure.
	if [[ -e "$path" ]]; then stat -c %s "$path"; else echo 0; fi
}

cmd_slice() {
	local path="$1" offset="$2" outdir="$3" name="$4"
	mkdir -p "$outdir" || die "cannot write $outdir"
	local dest="$outdir/$name"

	if [[ ! -e "$path" ]]; then
		# An empty slice rather than an error, for the same reason as above. The caller is
		# told how many bytes it got and can decide whether nothing is suspicious.
		: > "$dest"
	else
		# The end boundary is wherever the file happens to be now. Taken by tail from the
		# offset rather than by seeking a length computed earlier, so a write landing while
		# this runs extends the slice instead of corrupting it.
		tail -c "+$((offset + 1))" "$path" > "$dest" 2>/dev/null || : > "$dest"
	fi

	local bytes sha
	bytes=$(stat -c %s "$dest")
	sha=$(sha256sum "$dest" | cut -d' ' -f1)
	printf '{"file": "%s", "from_offset": %s, "bytes": %s, "sha256": "%s"}\n' \
		"$name" "$offset" "$bytes" "$sha"
}

case "${1:-}" in
	offset) [[ $# -eq 2 ]] || die "offset <path>"; cmd_offset "$2" ;;
	slice)  [[ $# -eq 5 ]] || die "slice <path> <offset> <outdir> <name>"; cmd_slice "$2" "$3" "$4" "$5" ;;
	*) sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'; exit 1 ;;
esac
