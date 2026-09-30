#!/usr/bin/env bash
# ==============================================================
#  Reading a VM-side log as a window, from the lab machine.
#
#  Sourced when the lab runs over the tunnel device, where the
#  firewall and the IDS observe traffic on the VM and therefore
#  write their logs there.
#
#  The shape is the same as it always was — take a byte offset
#  before the window, read from it afterwards — with the file one
#  machine away. What comes back is the RAW byte range, written to
#  a local file; the filtering, slicing and counting are then done
#  by the same code that did them when the log was local, so there
#  is one implementation of each and no second one to keep in step.
#
#  Requires lab-config.sh and Remote/vm-lib.sh sourced first.
#  Defines functions only.
# ==============================================================

REMOTE_READER='PDE Sources/Remote/read-window.sh'

# Where the sources write on the VM.
VM_UFW_LOG="${VM_UFW_LOG:-/var/log/ufw.log}"

remote_source_preflight() {
	vm_ssh "test -f \"\$HOME/$VM_REPO_DIR/$REMOTE_READER\"" </dev/null 2>/dev/null || {
		echo "the VM's checkout predates Remote/read-window.sh — ./vm.sh sync" >&2
		return 1
	}
	vm_ssh "sudo -n true" </dev/null 2>/dev/null || {
		echo "the VM's $VM_USER cannot sudo without a password; its logs cannot be read" >&2
		return 1
	}
	# rsyslog has to be running there for the same reason it had to be running here: the
	# kernel's LOG target reaches a file through it, and without it the firewall's evidence
	# is an empty file rather than an error.
	vm_ssh "pgrep -x rsyslogd >/dev/null" </dev/null 2>/dev/null || {
		echo "rsyslogd is not running on the VM; ufw lines would never reach $VM_UFW_LOG" >&2
		return 1
	}
	return 0
}

# Byte size of a VM-side file right now, for use as a later read boundary.
#   remote_offset <path>     echoes a number, 0 if the file is not there yet
remote_offset() {
	vm_ssh "sudo bash \"\$HOME/$VM_REPO_DIR/$REMOTE_READER\" offset '$1'" </dev/null 2>/dev/null \
		| grep -m1 -E '^[0-9]+$' || echo 0
}

# Brings one window's byte range home.
#   remote_slice <path> <offset> <stamp> <name> <local_dest>
# Writes the raw range to local_dest and echoes "<bytes> <sha256>".
#
# The digest is taken on the VM before the bytes move and checked here after they arrive, so
# "nothing happened to this on the way home" is a checked statement. It covers the transfer
# only: the evidence artifact is what the caller then builds out of these bytes, and that is
# hashed separately where it is written.
remote_slice() {
	local path="$1" offset="$2" stamp="$3" name="$4" dest="$5"
	local rdir="pde-read/$stamp" meta bytes sha local_sha

	meta=$(vm_ssh "sudo bash \"\$HOME/$VM_REPO_DIR/$REMOTE_READER\" slice '$path' '$offset' \
		\"\$HOME/$rdir\" '$name'" </dev/null | grep -m1 '^{') \
		|| { echo "could not slice $path on the VM" >&2; return 1; }

	read -r bytes sha < <(python3 -c '
import json, sys
m = json.loads(sys.argv[1])
print(m["bytes"], m["sha256"])
' "$meta") || { echo "unreadable slice summary from the VM: $meta" >&2; return 1; }

	# Root wrote it there; read it back as root too, or an unreadable file arrives as an
	# empty one and the window silently loses a source.
	vm_ssh "sudo cat \"\$HOME/$rdir/$name\"" </dev/null > "$dest" || return 1

	local_sha=$(sha256sum "$dest" | cut -d' ' -f1)
	if [[ "$local_sha" != "$sha" ]]; then
		echo "transfer changed $name: VM ${sha:0:16}, here ${local_sha:0:16}" >&2
		return 1
	fi
	printf '%s %s\n' "$bytes" "$sha"
}

# Brings Slips' whole output tree home, the way the older remote mode did.
#   remote_slips_fetch <vm_output_dir> <local_dest>
#
# The tree, not just alerts.log: zeek_files/conn.log is the flow record the findings were
# drawn from, and "on what basis" is a question an investigation will ask. The whole file is
# fetched rather than a slice, so the offset taken before the window still means what it
# meant on the VM and the existing slicer can be pointed straight at it.
#
# Read as root: Slips writes its output from inside the container as root, so the lab's
# account cannot read the tree, and an unreadable tree would arrive as an empty one.
remote_slips_fetch() {
	local vm_out="$1" dest="$2"
	mkdir -p "$dest"
	vm_ssh "sudo tar -C \"$vm_out\" -cf - ." </dev/null | tar -C "$dest" -xf - \
		|| { echo "could not fetch Slips' output tree from the VM" >&2; return 1; }
	# Slips creates alerts.log only once it has a finding, and the slicer must have a file to
	# read: an absent one would abort the capture where an empty one correctly says "nothing".
	if [[ ! -f "$dest/alerts/alerts.log" ]]; then
		mkdir -p "$dest/alerts"
		: > "$dest/alerts/alerts.log"
	fi
	return 0
}

# The facts the firewall manifest records about the product that produced the log. Read from
# the VM, because in this mode the firewall is the VM's, and a manifest naming this machine's
# ufw and kernel would be describing software that did not log anything.
#   remote_firewall_facts     echoes "<ufw version>|<kernel release>|<hostname>"
remote_firewall_facts() {
	vm_ssh "printf '%s|%s|%s\n' \"\$(ufw --version 2>/dev/null | head -1)\" \
		\"\$(uname -r)\" \"\$(hostname)\"" </dev/null 2>/dev/null | grep -m1 '|' \
		|| printf 'unknown|unknown|%s\n' "$VM_NAME"
}
