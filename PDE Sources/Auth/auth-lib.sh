#!/usr/bin/env bash
# ==============================================================
#  Remote-access source helpers for the PDE capture.
#
#  Sourced by simulate-firewall.sh when the lab runs over the
#  tunnel device. sshd on the research VM is the source; this side
#  drives its collector over vm-lib.sh and brings the evidence
#  home, checking on arrival the digest taken before it moved.
#
#  One PDE source comes out of a window:
#    auth   the VM's sshd record of the session the window's
#           traffic arrived in — who opened the tunnel, when
#
#  Requires lab-config.sh and Remote/vm-lib.sh sourced first.
#  Defines functions only.
# ==============================================================

AUTH_COLLECTOR='PDE Sources/Auth/collect-auth.sh'

auth_preflight() {
	local out
	vm_reachable || {
		echo "the research VM is not reachable (status: $(vm_status || echo unknown)) — ./vm.sh start" >&2
		return 1
	}
	# One session, not three. Every extra SSH round trip is another chance to hit the
	# intermittent IAP failures this VM shows under load, and the previous version reported
	# any of them as "cannot sudo" — which sent the reader after a sudoers problem that did
	# not exist. The remote side names the condition; SSH failing is reported as itself.
	out=$(vm_ssh "test -f \"\$HOME/$VM_REPO_DIR/$AUTH_COLLECTOR\" || { echo NOCOLLECTOR; exit 0; }
		sudo -n true 2>/dev/null || { echo NOSUDO; exit 0; }
		echo OK" </dev/null 2>/dev/null) || {
		echo "could not reach the VM to check the auth source (the SSH call itself failed)" >&2
		return 1
	}
	case "$out" in
		*OK*)          return 0 ;;
		*NOCOLLECTOR*) echo "the VM's checkout predates the auth source — ./vm.sh sync" >&2; return 1 ;;
		*NOSUDO*)      echo "the VM's $VM_USER cannot sudo without a password; sshd's log cannot be read" >&2
		               return 1 ;;
		*)             echo "unexpected reply from the VM's auth preflight: '$out'" >&2; return 1 ;;
	esac
}

# The boundary taken before the window opens: a byte offset into auth.log, or a journald
# cursor on an image without it. Opaque here on purpose — the collector decides which
# record it is reading and this side only carries the token back to it.
auth_offset() {
	vm_ssh "sudo bash \"\$HOME/$VM_REPO_DIR/$AUTH_COLLECTOR\" offset" </dev/null | grep -m1 -E '^(file|journal):'
}

# Collects the window's sshd evidence on the VM, then fetches it.
#   auth_collect <stamp> <offset> <start_utc> <end_utc> <run_dir>
# Leaves in run_dir: auth_<stamp>.log and auth_<stamp>.meta.json.
# Echoes the collector's own one-line summary.
auth_collect() {
	local stamp="$1" offset="$2" start="$3" end="$4" run_dir="$5"
	local rdir="pde-auth/$stamp" summary

	summary=$(vm_ssh "sudo bash \"\$HOME/$VM_REPO_DIR/$AUTH_COLLECTOR\" collect '$offset' '$start' '$end' \
		\"\$HOME/$rdir\" '$TUN_DEV'" </dev/null | grep -m1 '^AUTH_OK') \
		|| { echo "the auth collector failed on the VM" >&2; return 1; }

	vm_ssh "cat \"\$HOME/$rdir/auth.log\""       </dev/null > "$run_dir/auth_${stamp}.log"       || return 1
	vm_ssh "cat \"\$HOME/$rdir/auth.meta.json\"" </dev/null > "$run_dir/auth_${stamp}.meta.json" || return 1

	# The digest was taken on the VM before the file moved; matching it here is what makes
	# "nothing happened to this on the way home" a checked statement rather than an
	# assumption, exactly as for the banking artifacts.
	python3 - "$run_dir" "$stamp" <<'PY' || return 1
import hashlib, json, sys
run, stamp = sys.argv[1:3]
meta = json.load(open("%s/auth_%s.meta.json" % (run, stamp)))
local = hashlib.sha256(open("%s/auth_%s.log" % (run, stamp), "rb").read()).hexdigest()
if local != meta["sha256"]:
    sys.exit("transfer changed the auth evidence: VM %s, here %s"
             % (meta["sha256"][:16], local[:16]))
PY

	printf '%s\n' "$summary"
}
