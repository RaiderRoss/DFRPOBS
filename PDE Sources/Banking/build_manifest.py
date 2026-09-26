#!/usr/bin/env python3
"""
Writes banking_<stamp>.manifest.json for one captured window: provenance, window bounds,
how each artifact's timestamps are to be read, what the collectors did, whether the
evidence accounts for every operation the scenario performed, and the digests.

Reads, from the window directory:
  banking_<stamp>.groundtruth.json     generate_banking.py
  banking_<stamp>.collection.json      both collectors' own summaries (banking-lib.sh)
  banking-events_<stamp>.jsonl, banking-events_<stamp>.raw.jsonl, banking-audit_<stamp>.jsonl

Prints one summary line. The collection summary is folded into the manifest and removed:
the manifest is the record, and two files saying the same thing would one day disagree.
"""

import argparse
import hashlib
import json
import os
import sys

from reconcile import load_jsonl, reconcile


def describe(path):
    with open(path, "rb") as fh:
        data = fh.read()
    return {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
            "lines": data.count(b"\n")}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--stamp", required=True)
    ap.add_argument("--start", required=True)
    ap.add_argument("--end", required=True)
    ap.add_argument("--duration", type=int, required=True)
    ap.add_argument("--rate", type=float, required=True)
    ap.add_argument("--vm", required=True)
    ap.add_argument("--fineract-image", required=True)
    ap.add_argument("--bank-url", required=True)
    args = ap.parse_args()

    d, s = args.run_dir, args.stamp
    p = lambda name: os.path.join(d, name % s)
    truth = json.load(open(p("banking_%s.groundtruth.json")))
    collection = json.load(open(p("banking_%s.collection.json")))
    events_file, raw_file, audit_file = (p("banking-events_%s.jsonl"), p("banking-events_%s.raw.jsonl"),
                                         p("banking-audit_%s.jsonl"))
    result = reconcile(truth, load_jsonl(audit_file), load_jsonl(events_file))

    ev, au = collection["events"], collection["audit"]
    attacker = next((u["ip"] for u in truth["users"] if u["role"] == "malicious"), None)
    ok = result["operations_ok"]

    manifest = {
        "source": {
            "pde_sources": ["banking-events", "banking-audit"],
            "product": "Apache Fineract",
            "image": args.fineract_image,
            "tenant": truth.get("tenant"),
            "tenant_timezone": truth.get("tenant_tz"),
            "host": "research VM %s" % args.vm,
            "reached_at": args.bank_url,
            "collection_method": {
                "banking-events": "Fineract's external-events Kafka topic, read on the VM between broker "
                                  "offsets taken before the window opened and the topic's end after it "
                                  "closed; each message decoded with the pinned Avro schemas and kept if "
                                  "its createdAt falls inside the window",
                "banking-audit": "m_portfolio_command_source (Fineract's command audit trail) queried on the "
                                 "VM for rows whose made_on_date_utc falls inside the window, joined to "
                                 "m_appuser for the maker's and checker's logins",
            },
        },
        "window": {"start_utc": args.start, "end_utc": args.end, "duration_seconds": args.duration},
        "scenario": {
            "profile": truth["profile"],
            "benign_operations_per_second": args.rate,
            "seed": truth["seed"],
            "attacker_ip": attacker,
            "attacker_used_login": truth["staff"]["officer"]["username"] if truth["profile"] != "none" else None,
            "business_date": truth["business_date"],
        },
        "timestamps": {
            "banking-events": "event.createdAt is UTC in ISO_LOCAL_DATE_TIME — no zone suffix, as Fineract "
                              "writes it. It agrees with the staging table's created_at and with the audit "
                              "trail's made_on_date_utc to within milliseconds. kafka.timestamp_ms is when "
                              "the publish job sent it, which is later and is NOT when the transaction "
                              "happened",
            "banking-audit": "made_on_date_utc is a timestamptz rendered with +00:00. made_on_date, the "
                             "tenant-local column, is empty on this build",
            "business_date": "a tenant-local calendar date (tenant timezone %s), so near midnight UTC it "
                             "can name a different day. It is Fineract's accounting date, not a timestamp"
                             % truth.get("tenant_tz"),
            "bank_minus_lab_seconds": result["bank_minus_lab_seconds"],
        },
        "collection": {
            "banking-events": {k: v for k, v in ev.items() if k != "files"},
            "banking-audit": {k: v for k, v in au.items() if k != "files"},
        },
        "completeness": {
            "operations_ok": ok,
            "operations_malicious_ok": result["operations_malicious_ok"],
            "banking-audit": "%d of %d operations have their audit row" % (result["audit"]["present"], ok),
            "banking-events": "%d of %d operations have their event" % (result["events"]["present"], ok),
            "detail": result,
        },
        "output": {
            "banking-events_%s.jsonl" % s: dict(describe(events_file), role="evidence (banking-events)"),
            "banking-audit_%s.jsonl" % s: dict(describe(audit_file), role="evidence (banking-audit)"),
            "banking-events_%s.raw.jsonl" % s: dict(describe(raw_file),
                                                    role="the broker's own bytes for every message read; "
                                                         "not submitted — kept so the decode can be checked"),
            "banking_%s.groundtruth.json" % s: dict(describe(p("banking_%s.groundtruth.json")),
                                                     role="labels, known before sending; never submitted"),
        },
        "caveats": [
            "the bank's audit trail attributes every command to a login (maker_username), not an "
            "address: m_portfolio_command_source.client_ip exists on this build but was empty for all "
            "%d rows. Even filled, it would show the tunnel's end on the VM rather than the namespace "
            "address, as a production bank behind a proxy or load balancer would. The actor's network "
            "identity comes from this window's firewall and IDS items, joined by time"
            % au.get("rows", 0),
            "both staff users hold Fineract's stock 'Super user' role. A least-privilege teller could not "
            "have approved or disbursed a loan; the scenario models a phished credential with the "
            "authority to do so, which is what makes the maker-checker gap the finding",
            "the publish job ('Send Asynchronous Events') was triggered at collection time rather than "
            "waited for on its one-minute tick. That moves when events were sent, never their createdAt",
            "operations whose command raises more than one event (a client created active also raises "
            "ClientActivate; a disbursal also raises its transaction) appear in completeness.detail as "
            "unexplained_events — expected, and listed so the counts reconcile",
            "any audit row or event inside the window that the scenario did not cause is listed under "
            "unexplained, not removed: the publish job writes its own EXECUTEJOB row, and anyone else "
            "using the bank in the window would appear too",
            "the collector redacts credential-bearing fields in command_as_json (a user-creation command "
            "stores the new password) and marks the row collector_redacted; %d row(s) this window"
            % au.get("redacted_rows", 0),
            "the mule client's externalId carries the run's start time so windows do not collide; its "
            "name and the loan amount are reproducible from the seed, the key is not",
            "both artifacts were hashed on the VM before leaving it and verified here after transfer; "
            "the digests above are those, and are what the EvidenceItems should carry",
        ],
    }
    with open(p("banking_%s.manifest.json"), "w") as fh:
        json.dump(manifest, fh, indent=2)
    os.remove(p("banking_%s.collection.json"))

    print("banking: %d events, %d audit rows; %s; %s"
          % (ev.get("events_in_window", 0), au.get("rows", 0),
             manifest["completeness"]["banking-audit"], manifest["completeness"]["banking-events"]))


if __name__ == "__main__":
    main()
