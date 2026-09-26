#!/usr/bin/env bash
# ==============================================================
#  Banking source helpers for the PDE capture.
#
#  Sourced by simulate-firewall.sh when the lab runs with the
#  banking source. The bank (Fineract) and its collectors run on
#  the research VM; this side drives them over vm-lib.sh and
#  brings the evidence home.
#
#  Two PDE sources come out of one window:
#    banking-events  the business events Fineract published to
#                    Kafka — what happened
#    banking-audit   its command audit trail — who did it, with
#                    what parameters
#
#  Requires lab-config.sh and Remote/vm-lib.sh sourced first.
#  Defines functions only.
# ==============================================================

BANK_SEED="${BANK_SEED:-$PDE_ROOT/Banking/seed.json}"
BANK_URL="https://${HOST_IP}:${BANK_PORT}/fineract-provider"
BANK_GEN="$PDE_ROOT/Banking/generate_banking.py"
BANK_MANIFEST_BUILDER="$PDE_ROOT/Banking/build_manifest.py"
# Read from the compose file rather than restated, so the manifest names the image that
# actually runs and the two cannot drift.
BANK_FINERACT_IMAGE="$(awk '/image: *apache\/fineract/ {print $2; exit}' "$PDE_ROOT/../Fineract/docker-compose-fineract.yml" 2>/dev/null)"
BANK_FINERACT_IMAGE="${BANK_FINERACT_IMAGE:-unknown}"

# The VM-side command prefix for the Kafka collector. Run from the VM's checkout, whose
# compose file defines the pde-collector service under the `pde` profile.
_bank_compose() {
	printf 'cd "$HOME/%s/Fineract" && docker compose -f docker-compose-fineract.yml --profile pde' "$VM_REPO_DIR"
}

banking_preflight() {
	[[ -r "$BANK_SEED" ]] || {
		echo "no bank seed at $BANK_SEED — seed the bank first (console: sources -> seed, or Banking/README.md)" >&2
		return 1
	}
	vm_reachable || {
		echo "the research VM is not reachable (status: $(vm_status || echo unknown)) — ./vm.sh start" >&2
		return 1
	}
	vm_ssh "test -f \"\$HOME/$VM_REPO_DIR/PDE Sources/Banking/collect-audit.sh\"" </dev/null 2>/dev/null || {
		echo "the VM's checkout predates the banking source — ./vm.sh sync" >&2
		return 1
	}
	return 0
}

# The topic's end offsets right now, as the JSON collect_window.py's `offsets` prints.
# Taken before the window opens; everything published after it is at or beyond these.
banking_offsets() {
	local out
	out=$(vm_ssh "$(_bank_compose) run --rm -T pde-collector offsets 2>/dev/null" </dev/null) || return 1
	# compose may print notices; the result is the one line that is a JSON object.
	grep -m1 '^{' <<< "$out"
}

# Collects both banking artifacts for a window, on the VM, then fetches them.
#   banking_collect <stamp> <offsets_json> <start_utc> <end_utc> <expect> <run_dir>
# Leaves in run_dir: banking-events_<stamp>.jsonl, banking-events_<stamp>.raw.jsonl,
# banking-audit_<stamp>.jsonl, and banking_<stamp>.collection.json (both collectors'
# own summaries, including the digests they took on the VM).
banking_collect() {
	local stamp="$1" offsets="$2" start="$3" end="$4" expect="$5" run_dir="$6"
	local rdir="pde-collect/$stamp"
	local ev au

	# Events first: it triggers the publish job and waits for the window's events to land,
	# and its settle time is the longest part of collection.
	# Exported, not prefixed: _bank_compose begins with `cd`, and a VAR=value prefix
	# applies only to the first command of the list — compose would never see it and would
	# mount its default directory instead of this window's.
	ev=$(vm_ssh "mkdir -p \"\$HOME/$rdir\" && export PDE_COLLECT_DIR=\"\$HOME/$rdir\" && $(_bank_compose) run --rm -T pde-collector \
		collect --from '$offsets' --start '$start' --end '$end' --expect '$expect' --trigger-job \
		2>>\"\$HOME/$rdir/collector.log\"" </dev/null | grep -m1 '^{') \
		|| { echo "the events collector failed; see ~/$rdir/collector.log on the VM" >&2; return 1; }

	au=$(vm_ssh "bash \"\$HOME/$VM_REPO_DIR/PDE Sources/Banking/collect-audit.sh\" '$start' '$end' \"\$HOME/$rdir\"" \
		</dev/null | grep -m1 '^{') \
		|| { echo "the audit collector failed" >&2; return 1; }

	vm_ssh "cat \"\$HOME/$rdir/events.jsonl\""     </dev/null > "$run_dir/banking-events_${stamp}.jsonl"     || return 1
	vm_ssh "cat \"\$HOME/$rdir/events.raw.jsonl\"" </dev/null > "$run_dir/banking-events_${stamp}.raw.jsonl" || return 1
	vm_ssh "cat \"\$HOME/$rdir/audit.jsonl\""      </dev/null > "$run_dir/banking-audit_${stamp}.jsonl"      || return 1

	printf '{"events": %s, "audit": %s}\n' "$ev" "$au" > "$run_dir/banking_${stamp}.collection.json"

	# The digests were taken on the VM before the files moved. Matching them here is what
	# makes "nothing happened to these on the way home" a checked statement.
	python3 - "$run_dir" "$stamp" <<'PY'
import hashlib, json, sys
run, stamp = sys.argv[1:3]
c = json.load(open("%s/banking_%s.collection.json" % (run, stamp)))
pairs = [("banking-events_%s.jsonl" % stamp, c["events"]["files"]["events.jsonl"]),
         ("banking-events_%s.raw.jsonl" % stamp, c["events"]["files"]["events.raw.jsonl"]),
         ("banking-audit_%s.jsonl" % stamp, c["audit"]["files"]["audit.jsonl"])]
bad = []
for name, remote in pairs:
    local = hashlib.sha256(open("%s/%s" % (run, name), "rb").read()).hexdigest()
    if local != remote:
        bad.append("%s: VM %s, here %s" % (name, remote[:16], local[:16]))
if bad:
    sys.exit("transfer changed the banking evidence:\n  " + "\n  ".join(bad))
PY
}
