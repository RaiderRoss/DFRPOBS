#!/usr/bin/env bash
# ==============================================================
#  Banking source helpers for the PDE capture.
#
#  Sourced by simulate-firewall.sh when the lab runs with the
#  banking source. The bank (Fineract) and its collectors run
#  either on the research VM or on this machine (BANK_WHERE,
#  which the lab records); the same commands run in both places
#  and the evidence is brought into the window either way.
#
#  Two PDE sources come out of one window:
#    banking-events  the business events Fineract published to
#                    Kafka — what happened
#    banking-audit   its command audit trail — who did it, with
#                    what parameters
#
#  Requires lab-config.sh sourced first, and Remote/vm-lib.sh too
#  when the bank is on the VM. Defines functions only.
# ==============================================================

# "vm": the research VM, reached over SSH. "local": this machine (Banking/local-bank.sh).
BANK_WHERE="${BANK_WHERE:-vm}"
if [[ "$BANK_WHERE" == "local" ]]; then
	BANK_SEED="${BANK_SEED:-$LOCAL_BANK_SEED}"
	BANK_HOST_DESC="this machine"
	BANK_WORK_DESC="$PDE_ROOT/output/sessions/bank-collect"
else
	BANK_SEED="${BANK_SEED:-$PDE_ROOT/Banking/seed.json}"
	BANK_HOST_DESC="$VM_NAME"
	BANK_WORK_DESC="~/pde-collect on $VM_NAME"
fi
BANK_URL="https://${HOST_IP}:${BANK_PORT}/fineract-provider"
BANK_GEN="$PDE_ROOT/Banking/generate_banking.py"
BANK_MANIFEST_BUILDER="$PDE_ROOT/Banking/build_manifest.py"
# Read from the compose file rather than restated, so the manifest names the image that
# actually runs and the two cannot drift.
BANK_FINERACT_IMAGE="$(awk '/image: *apache\/fineract/ {print $2; exit}' "$PDE_ROOT/../Fineract/docker-compose-fineract.yml" 2>/dev/null)"
BANK_FINERACT_IMAGE="${BANK_FINERACT_IMAGE:-unknown}"

# Runs one shell command where the bank is, with stdin closed. Two variables are set for
# it, so one command text serves both places:
#   PDE_BANK_REPO  that machine's checkout of this repository
#   PDE_BANK_WORK  a working directory for the collectors' output
_bank_sh() {
	if [[ "$BANK_WHERE" == "local" ]]; then
		local key=""
		# Compose checks the SecureRS listener's ${SECURERS_API_KEY:?} on every command, though
		# the lab never starts it; a placeholder unless Fineract/.env sets a real one. See
		# Banking/local-bank.sh.
		grep -qsE '^SECURERS_API_KEY=.' "$FINERACT_DIR/.env" || key="unused-listener-not-started-by-the-lab"
		PDE_BANK_REPO="$(cd "$PDE_ROOT/.." && pwd)" \
		PDE_BANK_WORK="$PDE_ROOT/output/sessions/bank-collect" \
		SECURERS_API_KEY="${SECURERS_API_KEY:-$key}" \
			bash -c "$1" </dev/null
	else
		vm_ssh "PDE_BANK_REPO=\"\$HOME/$VM_REPO_DIR\"; PDE_BANK_WORK=\"\$HOME/pde-collect\"; $1" </dev/null
	fi
}

# The command prefix for the Kafka collector, as _bank_sh runs it. The checkout's compose
# file defines the pde-collector service under the `pde` profile.
_bank_compose() {
	printf '%s' 'cd "$PDE_BANK_REPO/Fineract" && docker compose -f docker-compose-fineract.yml --profile pde'
}

banking_preflight() {
	if [[ ! -r "$BANK_SEED" ]]; then
		if [[ "$BANK_WHERE" == "local" ]]; then
			echo "the local bank has not been seeded ($BANK_SEED) — Banking/local-bank.sh seed" >&2
		else
			echo "no bank seed at $BANK_SEED — seed the bank first (console: sources -> seed, or Banking/README.md)" >&2
		fi
		return 1
	fi
	if [[ "$BANK_WHERE" == "local" ]]; then
		local_bank_healthy || {
			echo "the local bank is not up (${BANK_STATE:-$(local_bank_state)}) — Banking/local-bank.sh up" >&2
			return 1
		}
		return 0
	fi
	vm_reachable || {
		echo "the research VM is not reachable (status: $(vm_status || echo unknown)) — ./vm.sh start" >&2
		return 1
	}
	_bank_sh "test -f \"\$PDE_BANK_REPO/PDE Sources/Banking/collect-audit.sh\"" 2>/dev/null || {
		echo "the VM's checkout predates the banking source — ./vm.sh sync" >&2
		return 1
	}
	return 0
}

# The topic's end offsets right now, as the JSON collect_window.py's `offsets` prints.
# Taken before the window opens; everything published after it is at or beyond these.
#
# Retried, because the first capture after `lab.sh up` lands on a loaded host: Slips is still
# starting its 27 processes, the load average was measured at 5.5 on the VM's four vCPUs, and
# one SSH round trip in that spike can simply drop. Twice that failed a capture that worked
# when run again seconds later. A read of offsets is safe to repeat.
banking_offsets() {
	local out attempt
	for attempt in 1 2 3; do
		out=$(_bank_sh "$(_bank_compose) run --rm -T pde-collector offsets 2>/dev/null") \
			&& grep -q '^{' <<< "$out" && break
		out=""
		[[ $attempt -lt 3 ]] && { echo "  offsets not read (attempt $attempt); retrying" >&2; sleep 5; }
	done
	[[ -n "$out" ]] || return 1
	# compose may print notices; the result is the one line that is a JSON object.
	grep -m1 '^{' <<< "$out"
}

# Collects both banking artifacts for a window where the bank is, then brings them into the
# window's directory.
#   banking_collect <stamp> <offsets_json> <start_utc> <end_utc> <expect> <run_dir>
# Leaves in run_dir: banking-events_<stamp>.jsonl, banking-events_<stamp>.raw.jsonl,
# banking-audit_<stamp>.jsonl, and banking_<stamp>.collection.json (both collectors'
# own summaries, including the digests they took where they ran).
banking_collect() {
	local stamp="$1" offsets="$2" start="$3" end="$4" expect="$5" run_dir="$6"
	local work="\$PDE_BANK_WORK/$stamp"
	local ev au

	# Events first: it triggers the publish job and waits for the window's events to land,
	# and its settle time is the longest part of collection.
	# Exported, not prefixed: _bank_compose begins with `cd`, and a VAR=value prefix
	# applies only to the first command of the list — compose would never see it and would
	# mount its default directory instead of this window's.
	ev=$(_bank_sh "mkdir -p \"$work\" && export PDE_COLLECT_DIR=\"$work\" && $(_bank_compose) run --rm -T pde-collector \
		collect --from '$offsets' --start '$start' --end '$end' --expect '$expect' --trigger-job \
		2>>\"$work/collector.log\"" | grep -m1 '^{') \
		|| { echo "the events collector failed; see $stamp/collector.log in $BANK_WORK_DESC" >&2; return 1; }

	au=$(_bank_sh "bash \"\$PDE_BANK_REPO/PDE Sources/Banking/collect-audit.sh\" '$start' '$end' \"$work\"" \
		| grep -m1 '^{') \
		|| { echo "the audit collector failed" >&2; return 1; }

	_bank_sh "cat \"$work/events.jsonl\""     > "$run_dir/banking-events_${stamp}.jsonl"     || return 1
	_bank_sh "cat \"$work/events.raw.jsonl\"" > "$run_dir/banking-events_${stamp}.raw.jsonl" || return 1
	_bank_sh "cat \"$work/audit.jsonl\""      > "$run_dir/banking-audit_${stamp}.jsonl"      || return 1

	printf '{"events": %s, "audit": %s}\n' "$ev" "$au" > "$run_dir/banking_${stamp}.collection.json"

	# The digests were taken where the collectors ran, before the files moved. Matching them
	# here is what makes "nothing happened to these on the way" a checked statement.
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
        bad.append("%s: where collected %s, here %s" % (name, remote[:16], local[:16]))
if bad:
    sys.exit("moving the banking evidence changed it:\n  " + "\n  ".join(bad))
PY
}
