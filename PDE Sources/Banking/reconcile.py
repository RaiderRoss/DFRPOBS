#!/usr/bin/env python3
"""
Reconciles a banking window's evidence against its ground truth.

The network sources can only reconcile their own totals — verdict lines against line
counts. Banking can do better, because the lab *caused* every transaction and knows the
id each one was given. So each operation is looked for in both artifacts by an exact key:

  audit   (action, entity, resource_id, maker)  one m_portfolio_command_source row
  events  (event type, payload id)              one published business event

The result says, per artifact, "N of N operations present", and names any that are not.
It also reports the opposite direction — rows and events inside the window that the
scenario does not explain (the publish job writes its own EXECUTEJOB row, and anyone else
using the bank would appear) — because an artifact holding more than the scenario is a
finding, not noise.

Reads only; writes a JSON summary to stdout.

  reconcile.py --truth banking.groundtruth.json --audit audit.jsonl --events events.jsonl
"""

import argparse
import json
import statistics
import sys
from collections import Counter
from datetime import datetime, timezone


def parse(ts):
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def load_jsonl(path):
    with open(path) as fh:
        return [json.loads(line) for line in fh if line.strip()]


def reconcile(truth, audit, events):
    ops = [o for o in truth["operations"] if o["outcome"] == "ok"]

    audit_index = Counter()
    audit_rows = {}
    for r in audit:
        key = (r.get("action_name"), r.get("entity_name"), r.get("resource_id"), r.get("maker_username"))
        audit_index[key] += 1
        audit_rows.setdefault(key, []).append(r)
    event_index = Counter()
    for e in events:
        ev = e.get("event") or {}
        pid = (e.get("payload") or {}).get("id")
        event_index[(ev.get("type"), pid)] += 1

    audit_missing, event_missing, clock = [], [], []
    audit_left, event_left = audit_index.copy(), event_index.copy()
    for o in ops:
        akey = (o["expected_audit"][0], o["expected_audit"][1], o.get("resource_id"), o["username"])
        if audit_left[akey] > 0:
            audit_left[akey] -= 1
            # The bank's own timestamp for the command against the moment the lab sent it:
            # clock offset plus request latency, measured per operation rather than assumed.
            row = audit_rows[akey][audit_index[akey] - audit_left[akey] - 1]
            if o.get("sent_at") and row.get("made_on_date_utc"):
                clock.append((parse(row["made_on_date_utc"]) - parse(o["sent_at"])).total_seconds())
        else:
            audit_missing.append({"seq": o["seq"], "kind": o["kind"], "resource_id": o.get("resource_id")})
        ekey = (o["expected_event"], o.get("resource_id"))
        if event_left[ekey] > 0:
            event_left[ekey] -= 1
        else:
            event_missing.append({"seq": o["seq"], "kind": o["kind"], "expected": o["expected_event"]})

    def unexplained(left, label):
        out = Counter()
        for key, n in left.items():
            if n > 0:
                out[label(key)] += n
        return dict(sorted(out.items()))

    return {
        "operations_ok": len(ops),
        "operations_malicious_ok": sum(1 for o in ops if o["label"] == "malicious"),
        "audit": {
            "present": len(ops) - len(audit_missing),
            "missing": audit_missing,
            "unexplained_rows": unexplained(audit_left, lambda k: "%s %s by %s" % (k[0], k[1], k[3])),
        },
        "events": {
            "present": len(ops) - len(event_missing),
            "missing": event_missing,
            # Secondary events a command raises alongside its primary one (a client created
            # active also raises ClientActivate; a disbursal also raises its transaction).
            "unexplained_events": unexplained(event_left, lambda k: k[0]),
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
