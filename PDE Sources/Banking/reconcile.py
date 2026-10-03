#!/usr/bin/env python3
"""
Reconciles a banking window's evidence against its ground truth.

The network sources can only reconcile their own totals — verdict lines against line
counts. Banking can do better, because the lab *caused* every transaction and knows what
each one should have left behind. So each operation that changes something is looked for
in both artifacts:

  audit   (action, entity, resource_id, maker)   one m_portfolio_command_source row
  events  (type, identifying payload fields)     every business event it should publish

Most operations publish one event whose payload id is the operation's own resource. A
transfer publishes two — a withdrawal on the payer's account and a deposit on the payee's —
and neither carries the transfer's id, so those are identified by account and amount.

Reads (a balance check, a statement) change nothing, so the bank records nothing for them.
They are counted, and excluded from completeness, rather than reported as missing.

The result says, per artifact, "N of N operations present", and names any that are not. It
also reports the opposite direction — rows and events inside the window that the scenario
does not explain (the publish job writes its own EXECUTEJOB row, and anyone else using the
bank would appear) — because an artifact holding more than the scenario is a finding, not
noise.

Reads only; writes a JSON summary to stdout.

  reconcile.py --truth banking.groundtruth.json --audit audit.jsonl --events events.jsonl
"""

import argparse
import json
import re
import statistics
import sys
from collections import Counter
from datetime import datetime, timezone


def parse(ts):
    ts = ts.replace("Z", "+00:00")
    # Postgres renders fractional seconds with as many digits as it has, and
    # datetime.fromisoformat before 3.11 accepts only 3 or 6. A real window died on
    # '2026-09-30T16:39:16.61888+00:00' — five digits. Padded to six rather than
    # truncated, so the instant is unchanged.
    m = re.match(r"^(.*[.])(\d{1,6})([+-]\d{2}:?\d{2}|)$", ts)
    if m:
        ts = m.group(1) + m.group(2).ljust(6, "0") + m.group(3)
    dt = datetime.fromisoformat(ts)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def load_jsonl(path):
    with open(path) as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _same(field, have, want):
    """Payload amounts arrive as strings with eight decimals ('17.00000000'); ids as numbers.
    Compared by value, not by rendering."""
    if have is None or want is None:
        return False
    if field == "amount":
        try:
            return round(float(have), 2) == round(float(want), 2)
        except (TypeError, ValueError):
            return False
    return str(have) == str(want)


def _expected_events(op):
    """The events an operation should have published. Ground truths written before
    transfers existed name one event and key it by the operation's resource id."""
    if "expected_events" in op:
        return op["expected_events"] or []
    if op.get("expected_event"):
        return [{"type": op["expected_event"], "match": {"id": op.get("resource_id")}}]
    return []


def reconcile(truth, audit, events):
    ok = [o for o in truth["operations"] if o["outcome"] == "ok"]
    writes = [o for o in ok if o.get("expected_audit")]

    audit_index = Counter()
    audit_rows = {}
    for r in audit:
        key = (r.get("action_name"), r.get("entity_name"), r.get("resource_id"), r.get("maker_username"))
        audit_index[key] += 1
        audit_rows.setdefault(key, []).append(r)

    by_type = {}
    for i, e in enumerate(events):
        by_type.setdefault((e.get("event") or {}).get("type"), []).append((i, e.get("payload") or {}))
    used = set()

    audit_missing, event_missing, clock = [], [], []
    audit_left = audit_index.copy()
    events_expected = events_found = ops_with_all_events = 0
    for o in writes:
        akey = (o["expected_audit"][0], o["expected_audit"][1], o.get("resource_id"), o["username"])
        if audit_left[akey] > 0:
            audit_left[akey] -= 1
            # The bank's own timestamp for the command against the moment the lab sent it:
            # clock offset plus request latency, measured per operation rather than assumed.
            row = audit_rows[akey][audit_index[akey] - audit_left[akey] - 1]
            if o.get("sent_at") and row.get("made_on_date_utc"):
                clock.append((parse(row["made_on_date_utc"]) - parse(o["sent_at"])).total_seconds())
        else:
            audit_missing.append({"seq": o["seq"], "kind": o["kind"], "by": o["username"],
                                  "resource_id": o.get("resource_id")})

        all_found = True
        for spec in _expected_events(o):
            events_expected += 1
            hit = next((i for i, p in by_type.get(spec["type"], [])
                        if i not in used and all(_same(k, p.get(k), v) for k, v in spec["match"].items())), None)
            if hit is None:
                all_found = False
                event_missing.append({"seq": o["seq"], "kind": o["kind"], "expected": spec["type"],
                                      "match": spec["match"]})
            else:
                used.add(hit)
                events_found += 1
        ops_with_all_events += all_found

    unexplained_rows = Counter()
    for key, n in audit_left.items():
        if n > 0:
            unexplained_rows["%s %s by %s" % (key[0], key[1], key[3])] += n
    unexplained_events = Counter()
    for t, items in by_type.items():
        for i, _ in items:
            if i not in used:
                unexplained_events[t] += 1

    return {
        "operations_ok": len(ok),
        "writes_ok": len(writes),
        "reads_ok": len(ok) - len(writes),
        "operations_malicious_ok": sum(1 for o in ok if o["label"] == "malicious"),
        "audit": {
            "present": len(writes) - len(audit_missing),
            "of": len(writes),
            "missing": audit_missing,
            "unexplained_rows": dict(sorted(unexplained_rows.items())),
        },
        "events": {
            "operations_with_all_their_events": ops_with_all_events,
            "of": len(writes),
            "events_found": events_found,
            "events_expected": events_expected,
            "missing": event_missing,
            # Secondary events a command raises alongside the ones expected of it (a disbursal
            # also raises its transaction), plus anything the scenario did not cause.
            "unexplained_events": dict(sorted(unexplained_events.items())),
        },
        "bank_minus_lab_seconds": None if not clock else {
            "median": round(statistics.median(clock), 3),
            "min": round(min(clock), 3),
            "max": round(max(clock), 3),
            "samples": len(clock),
            "note": "made_on_date_utc (bank clock) minus sent_at (lab clock); includes "
                    "request latency, so it is an upper bound on clock skew",
        },
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--truth", required=True)
    ap.add_argument("--audit", required=True)
    ap.add_argument("--events", required=True)
    args = ap.parse_args()
    result = reconcile(json.load(open(args.truth)), load_jsonl(args.audit), load_jsonl(args.events))
    json.dump(result, sys.stdout, indent=2)
    print()


if __name__ == "__main__":
    main()
