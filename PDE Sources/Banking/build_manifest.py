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
    attacker = truth.get("attacker") or {}
    mule = truth.get("mule") or {}
    customers = [{"ip": u["ip"], "login": u.get("login")} for u in truth["users"] if u["role"] == "customer"]
    writes = result["writes_ok"]

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
            "attacker_ip": attacker.get("ip"),
            "attacker_used_login": attacker.get("login"),
            "attacker_credential": attacker.get("credential"),
            "mule_ip": mule.get("ip"),
            "mule_login": mule.get("login"),
            "mule_client": {"id": mule.get("client_id"), "external_id": mule.get("external_id"),
                            "name": mule.get("name")},
            "customers": customers,
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
            "operations_ok": result["operations_ok"],
            "writes_ok": writes,
            "reads_ok": result["reads_ok"],
            "operations_malicious_ok": result["operations_malicious_ok"],
            "banking-audit": "%d of %d operations that change something have their audit row"
                             % (result["audit"]["present"], writes),
            "banking-events": "%d of %d operations that change something have all their events "
                              "(%d of %d events)" % (result["events"]["operations_with_all_their_events"], writes,
                                                    result["events"]["events_found"],
                                                    result["events"]["events_expected"]),
            "reads": "%d reads (balance checks, statements) change nothing, so the bank records "
                     "nothing for them; they appear only in the network sources" % result["reads_ok"],
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
            "the loan officer holds Fineract's stock 'Super user' role, so one phished login could both "
            "approve and disburse. A bank would split those between people; the missing second approver "
            "(checker_username null) is the finding. Customers hold a restricted 'PDE Customer' role: "
            "they can apply for a loan but are refused approving one (HTTP 403, checked when seeding), "
            "which is why the fraud needs the officer's credential at all",
            "customers bank through Fineract's standard API with their own logins, not a self-service "
            "API: this build (1.16.0-SNAPSHOT) has none. Nothing in the standard API stops a customer's "
            "login from reading or moving another customer's money; a real bank's online-banking layer "
            "would enforce that. Every customer action is still attributed to that customer's own login",
            "the attacker's use of the officer's credential is simulated; the phishing that obtained it "
            "is not, and happened before the window",
            "the publish job ('Send Asynchronous Events') was triggered at collection time rather than "
            "waited for on its one-minute tick. That moves when events were sent, never their createdAt",
            "a transfer publishes two events — a withdrawal on the payer's account and a deposit on the "
            "payee's — neither carrying the transfer's id, so both are matched by account and amount. "
            "A disbursal also raises its transaction event, which appears in completeness.detail as "
            "unexplained — expected, and listed so the counts reconcile",
            "any audit row or event inside the window that the scenario did not cause is listed under "
            "unexplained, not removed: the publish job writes its own EXECUTEJOB row, and anyone else "
            "using the bank in the window would appear too",
            "the collector redacts credential-bearing fields in command_as_json (a user-creation command "
            "stores the new password) and marks the row collector_redacted; %d row(s) this window"
            % au.get("redacted_rows", 0),
            "the mule is a seeded customer (externalId %s) and applies again in every fraud window, so "
            "earlier windows' loans to the same client exist; this window's is the one with the "
            "resource_id recorded in the ground truth" % mule.get("external_id"),
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
