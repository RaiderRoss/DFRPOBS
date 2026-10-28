#!/usr/bin/env python3
"""
Recomputes the logging and monitoring results of the dissertation (Chapter 4, section 4.4)
from the evaluation windows. Reads only; changes nothing.

    python3 score.py                  every window folder beside this script (the 24)
    python3 score.py <folder> ...     the given window folders, e.g. ../output/<stamp>
    python3 score.py --json           the per-window figures as JSON instead of the report

Each record is checked against the window's ground truth by exact key:

  firewall      a line matches a planned connection attempt by sender address, sender port
                and destination port. A line not in the plan must be a banking operation's
                own connection: one line from that user's address to the bank's port per
                operation. A line logged BLOCK whose attempt connected is a disagreement.
  bank          Banking/reconcile.py, the same code that ran during each capture: an audit
                row by (action, record type, record number, login); an event by its type and
                the fields that identify it.
  integrity     every file re-hashed with SHA-256 against the fingerprint recorded at capture.
  IDS           per address: the alerts Slips raised, its findings and their severity, and
                which of the planned attempts its machine-learning models flagged.

Not recomputed here: the time each capture took, which the batch runner timed and which is
not stored in the windows.
"""

import argparse
import glob
import hashlib
import json
import os
import re
import sys
from collections import Counter, OrderedDict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "Banking"))
from reconcile import load_jsonl, reconcile  # noqa: E402

ORDER = ["baseline", "port-scan", "stealth", "db-probe", "brute-force", "syn-burst", "mixed",
         "guaranteed-alert"]
LEVELS = ["info", "low", "medium", "high", "critical"]

FW_LINE = re.compile(r"\[UFW (\w+)\].*?SRC=(\S+) .*?SPT=(\d+) DPT=(\d+)")
IDS_LINE = re.compile(r"Src IP (\S+)\s+\.\s+(.*)$")
IDS_LEVEL = re.compile(r"Threat level:\s*(\w+)")
IDS_ML = re.compile(r"detected by (ml_\w+?_model)\. Src IP ([\d.]+):(\d+) to ([\d.]+):(\d+)")
IDS_SCAN_PORTS = re.compile(r"Total (\d+) TCP ports were scanned")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def one(folder, pattern):
    found = glob.glob(os.path.join(folder, pattern))
    if len(found) != 1:
        sys.exit("%s: expected one %s, found %d" % (folder, pattern, len(found)))
    return found[0]


def score_window(folder):
    fw_manifest = json.load(open(one(folder, "firewall_*.manifest.json")))
    fw_truth = json.load(open(one(folder, "firewall_*.groundtruth.json")))
    bank_manifest = json.load(open(one(folder, "banking_*.manifest.json")))
    bank_truth = json.load(open(one(folder, "banking_*.groundtruth.json")))
    group = json.load(open(one(folder, "window_*.group.json")))
    stamp = group["group_id"]

    conf = fw_manifest["configuration"]
    scenario = "baseline" if not conf.get("malicious_event_pct") else conf["attack_profile"]
    w = {"window": stamp, "scenario": scenario, "seed": conf["seed"]}

    roles = {u["ip"]: u["role"] for u in fw_truth["users"]}
    honest_hosts = sorted(ip for ip, r in roles.items() if r == "benign")
    attackers = sorted(ip for ip, r in roles.items() if r == "malicious")
    attempts = fw_truth["events"]

    # --- firewall: every planned attempt, by exact key
    lines, verdicts = [], Counter()
    with open(one(folder, "firewall_*.log"), encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            if not raw.strip():
                continue
            m = FW_LINE.search(raw)
            if m:
                verdict, src, sport, dport = m.groups()
                lines.append((verdict, src, int(sport), int(dport)))
                verdicts[verdict] += 1
            else:
                lines.append(None)
    logged = Counter((s, sp, dp) for v, s, sp, dp in filter(None, lines))
    verdict_of = {(s, sp, dp): v for v, s, sp, dp in filter(None, lines)}
    key = lambda e: (e["src"], int(e["sport"]), int(e["dport"]))  # noqa: E731

    found, total = Counter(), Counter()
    for e in attempts:
        total[e["label"]] += 1
        found[e["label"]] += logged[key(e)] > 0
    w["fw_found"] = {lab: [found[lab], total[lab]] for lab in ("benign", "malicious")}
    w["fw_blocked_but_connected"] = sum(1 for e in attempts
                                        if verdict_of.get(key(e)) == "BLOCK" and e["outcome"] == "connected")
    attacker_verdicts = Counter(verdict_of.get(key(e)) for e in attempts if e["label"] == "malicious")
    w["fw_attacker_verdicts"] = dict(attacker_verdicts)

    # Lines the plan does not explain: each must be one banking operation's connection.
    bank_port = int(re.search(r":(\d+)/", bank_truth["bank_url"]).group(1))
    unplanned = logged - Counter(key(e) for e in attempts)
    by_src = Counter()
    other = 0
    for (s, sp, dp), n in unplanned.items():
        if dp == bank_port:
            by_src[s] += n
        else:
            other += n
    w["fw_unplanned"] = sum(unplanned.values())
    w["fw_unplanned_explained"] = (other == 0
                                   and by_src == Counter(o["src"] for o in bank_truth["operations"]))
    w["fw_lines"] = len(lines)
    w["fw_unparsed"] = sum(1 for x in lines if x is None)
    out = fw_manifest["output"]
    w["fw_verdicts_add_up"] = (verdicts["ALLOW"] + verdicts["BLOCK"] + verdicts["AUDIT"] == len(lines)
                               == out["lines"]
                               and verdicts["ALLOW"] == out["ufw_allow_lines"]
                               and verdicts["BLOCK"] == out["ufw_block_lines"])
    w["honest_page_loads"] = [sum(1 for e in attempts if e["label"] == "benign" and e.get("http_status") == 200),
                              total["benign"]]

    # --- bank: the capture's own reconciliation, run again
    audit = load_jsonl(one(folder, "banking-audit_*.jsonl"))
    events = load_jsonl(one(folder, "banking-events_%s.jsonl" % stamp))
    rec = reconcile(bank_truth, audit, events)
    w["bank_operations"] = len(bank_truth["operations"])
    w["bank_failed"] = sum(1 for o in bank_truth["operations"] if o["outcome"] != "ok")
    w["bank_audit"] = [rec["audit"]["present"], rec["audit"]["of"]]
    w["bank_events"] = [rec["events"]["events_found"], rec["events"]["events_expected"]]
    w["bank_unexplained_rows"] = rec["audit"]["unexplained_rows"]
    w["bank_unexplained_events"] = rec["events"]["unexplained_events"]
    w["bank_minus_lab_median_s"] = (rec["bank_minus_lab_seconds"] or {}).get("median")
    stored = bank_manifest["completeness"]["detail"]
    w["bank_same_as_capture"] = (stored["audit"]["present"] == rec["audit"]["present"]
                                 and stored["audit"]["of"] == rec["audit"]["of"]
                                 and stored["events"]["events_found"] == rec["events"]["events_found"]
                                 and stored["events"]["events_expected"] == rec["events"]["events_expected"])

    # The fraud: the mule's login creates the loan; the attacker's approves and pays it out,
    # and no second person approves.
    fraud = [o for o in bank_truth["operations"] if o["label"] == "malicious" and "loan" in o["kind"]]
    if fraud:
        rows = {(r["action_name"], r["entity_name"], r["resource_id"], r["maker_username"]): r for r in audit}
        loan = fraud[0].get("resource_id")
        mule, officer = bank_truth["mule"]["login"], bank_truth["attacker"]["login"]
        need = [("CREATE", "LOAN", loan, mule), ("APPROVE", "LOAN", loan, officer),
                ("DISBURSE", "LOAN", loan, officer)]
        w["fraud_chain"] = all(k in rows and not rows[k].get("checker_username") for k in need)

    # --- integrity: every fingerprinted file, once each
    recorded = {fw_manifest["output"]["log_file"]: fw_manifest["output"]["sha256"]}
    for item in group["items"]:
        recorded[item["file"]] = item["sha256"]
    evidence = [item["file"] for item in group["items"]]
    for name, desc in bank_manifest["output"].items():
        recorded[name] = desc["sha256"]
    intact = {name for name, want in recorded.items() if sha256(os.path.join(folder, name)) == want}
    w["evidence_intact"] = [sum(1 for f in evidence if f in intact), len(evidence)]
    w["all_files_intact"] = [len(intact), len(recorded)]
    w["evidence_read_only"] = sum(1 for f in evidence
                                  if not os.stat(os.path.join(folder, f)).st_mode & 0o222)

    # --- IDS
    alerts, levels, scan_ports = Counter(), {}, []
    ml = {}
    with open(one(folder, "ids_*.alerts.log"), encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            m = IDS_LINE.search(raw)
            if not m:
                continue
            ip, text = m.groups()
            if "Generated an alert" in text or "Is blocked" in text:
                alerts[ip] += 1
                continue
            lv = IDS_LEVEL.search(text)
            if lv:
                levels.setdefault(ip, Counter())[lv.group(1).lower()] += 1
            if "port scan" in text.lower() and ip in attackers:
                n = IDS_SCAN_PORTS.search(text)
                scan_ports.append(int(n.group(1)) if n else None)
            mm = IDS_ML.search(text)
            if mm:
                model, s, sp, d, dp = mm.groups()
                ml.setdefault(model, Counter())[(s, int(sp), int(dp))] += 1
    online = ml.get("ml_online_model", Counter())
    linear = ml.get("ml_linear_model", Counter())
    blocked_attempts = [e for e in attempts if e["label"] == "malicious" and verdict_of.get(key(e)) == "BLOCK"]
    w["ids_alerts_attacker"] = sum(alerts[a] for a in attackers)
    w["ids_honest_hosts_alerted"] = [sum(1 for h in honest_hosts if alerts[h]), len(honest_hosts)]
    w["ids_scan_findings"] = scan_ports
    w["ids_attacker_levels"] = dict(sum((levels.get(a, Counter()) for a in attackers), Counter()))
    w["ids_honest_worst_level"] = max((lv for h in honest_hosts for lv in levels.get(h, {})),
                                      key=LEVELS.index, default=None)
    w["ids_online_flagged_blocked_attacker"] = [sum(1 for e in blocked_attempts if online[key(e)]),
                                                len(blocked_attempts)]
    w["ids_online_flagged_honest"] = sum(1 for e in attempts if e["label"] == "benign" and online[key(e)])
    w["ids_linear_honest"] = sum(n for (s, _, _), n in linear.items() if s in honest_hosts)
    w["ids_lines"] = sum(1 for raw in open(one(folder, "ids_*.alerts.log"), encoding="utf-8", errors="replace")
                         if raw.strip())

    # --- collection cost: bytes of evidence per source
    w["bytes"] = {item["pde_source"]: os.path.getsize(os.path.join(folder, item["file"]))
                  for item in group["items"]}
    return w


def frac(pairs):
    return "%d/%d" % (sum(p[0] for p in pairs), sum(p[1] for p in pairs))


def num(n):
    return format(n, ",").replace(",", " ")


def report(ws):
    by = OrderedDict((s, [w for w in ws if w["scenario"] == s]) for s in ORDER)
    for w in ws:
        if w["scenario"] not in ORDER:
            by.setdefault(w["scenario"], []).append(w)
    attack = [w for w in ws if w["scenario"] != "baseline"]
    fraud = [w for w in ws if "fraud_chain" in w]
    p = print

    p("Windows: %d   connection attempts: %s (%s malicious)   banking operations: %d"
      % (len(ws), num(sum(sum(v[1] for v in w["fw_found"].values()) for w in ws)),
         num(sum(w["fw_found"]["malicious"][1] for w in ws)), sum(w["bank_operations"] for w in ws)))
    p()
    p("Results per scenario (Table: results per scenario)")
    head = ("scenario", "windows", "firewall benign", "firewall malicious", "audit rows", "events",
            "files intact", "attacker alerted", "honest hosts alerted")
    p("  %-17s %-8s %-16s %-19s %-11s %-9s %-13s %-17s %s" % head)
    for s, g in by.items():
        if not g:
            continue
        mal = frac([w["fw_found"]["malicious"] for w in g])
        p("  %-17s %-8d %-16s %-19s %-11s %-9s %-13s %-17s %s" % (
            s, len(g), frac([w["fw_found"]["benign"] for w in g]), "n/a" if mal.endswith("/0") else mal,
            frac([w["bank_audit"] for w in g]), frac([w["bank_events"] for w in g]),
            frac([w["evidence_intact"] for w in g]),
            "n/a" if s == "baseline" else "%d of %d" % (sum(w["ids_alerts_attacker"] > 0 for w in g), len(g)),
            frac([w["ids_honest_hosts_alerted"] for w in g])))
    p("  %-17s %-8d %-16s %-19s %-11s %-9s %-13s %-17s %s" % (
        "all", len(ws), frac([w["fw_found"]["benign"] for w in ws]),
        frac([w["fw_found"]["malicious"] for w in ws]), frac([w["bank_audit"] for w in ws]),
        frac([w["bank_events"] for w in ws]), frac([w["evidence_intact"] for w in ws]),
        "%d of %d" % (sum(w["ids_alerts_attacker"] > 0 for w in attack), len(attack)),
        frac([w["ids_honest_hosts_alerted"] for w in ws])))

    p()
    p("Log completeness")
    p("  firewall: planned attempts found %s; blocked but connected: %d; lines not in the plan: %d,"
      % (frac([[sum(v[0] for v in w["fw_found"].values()), sum(v[1] for v in w["fw_found"].values())] for w in ws]),
         sum(w["fw_blocked_but_connected"] for w in ws), sum(w["fw_unplanned"] for w in ws)))
    p("            each one a banking operation's connection from its user's address: %d of %d windows"
      % (sum(w["fw_unplanned_explained"] for w in ws), len(ws)))
    for s, g in by.items():
        if s == "baseline" or not g:
            continue
        p("            attacker's attempts in %-16s %s" % (
            s + ":", dict(sum((Counter(w["fw_attacker_verdicts"]) for w in g), Counter()))))
    p("  honest page loads answered 200: %s" % frac([w["honest_page_loads"] for w in ws]))
    p("  bank: operations failed %d of %d; audit rows %s; events %s; same as at capture: %d of %d windows"
      % (sum(w["bank_failed"] for w in ws), sum(w["bank_operations"] for w in ws),
         frac([w["bank_audit"] for w in ws]), frac([w["bank_events"] for w in ws]),
         sum(w["bank_same_as_capture"] for w in ws), len(ws)))
    p("        unexplained audit rows: %s" % dict(sum((Counter(w["bank_unexplained_rows"]) for w in ws), Counter())))
    p("        unexplained events:     %s" % dict(sum((Counter(w["bank_unexplained_events"]) for w in ws), Counter())))
    p("  fraud chain in the audit trail: %d of %d fraud windows" % (sum(w["fraud_chain"] for w in fraud), len(fraud)))
    clocks = [w["bank_minus_lab_median_s"] for w in ws if w["bank_minus_lab_median_s"] is not None]
    if clocks:
        p("  bank minus lab clock, median per window: %+.3f to %+.3f s" % (min(clocks), max(clocks)))

    p()
    p("Log integrity")
    p("  evidence files matching their fingerprints: %s (%s including supporting files)"
      % (frac([w["evidence_intact"] for w in ws]), frac([w["all_files_intact"] for w in ws])))
    ro = sum(w["evidence_read_only"] for w in ws)
    p("  evidence files read-only on this disk: %d of %d%s" % (
        ro, sum(w["evidence_intact"][1] for w in ws),
        "" if ro else "  (a copy, such as a git checkout, does not keep the read-only setting)"))
    p("  firewall ALLOW and BLOCK lines add up to the line count: %d of %d windows"
      % (sum(w["fw_verdicts_add_up"] for w in ws), len(ws)))

    p()
    p("IDS detection accuracy (Table: detection per attack profile)")
    p("  %-17s %-17s %-19s %-22s %s" % ("profile", "attacker alerted", "alerts per window", "scan finding (ports)",
                                       "attacker findings by level, per window"))
    for s, g in by.items():
        if s == "baseline" or not g:
            continue
        lv = sum((Counter(w["ids_attacker_levels"]) for w in g), Counter())
        p("  %-17s %-17s %-19s %-22s %s" % (
            s, "%d of %d" % (sum(w["ids_alerts_attacker"] > 0 for w in g), len(g)),
            ", ".join(str(w["ids_alerts_attacker"]) for w in g),
            "%d of %d %s" % (sum(bool(w["ids_scan_findings"]) for w in g), len(g),
                             sorted(x for w in g for x in w["ids_scan_findings"]) or ""),
            ", ".join("%s %g" % (l, round(lv[l] / len(g), 1)) for l in reversed(LEVELS) if lv[l])))
    blocked = [w for w in attack if w["ids_online_flagged_blocked_attacker"][1]]
    p("  online model flagged the attacker's blocked attempts: %s (in %d windows); honest attempts flagged: %d of %s"
      % (frac([w["ids_online_flagged_blocked_attacker"] for w in blocked]), len(blocked),
         sum(w["ids_online_flagged_honest"] for w in ws), num(sum(w["fw_found"]["benign"][1] for w in ws))))
    p("  linear model findings on honest users: %s" % num(sum(w["ids_linear_honest"] for w in ws)))
    p("  honest host-windows alerted: %s; worst finding on an honest host: %s"
      % (frac([w["ids_honest_hosts_alerted"] for w in ws]),
         max((w["ids_honest_worst_level"] for w in ws if w["ids_honest_worst_level"]), key=LEVELS.index, default="none")))
    p("  IDS lines per window: %d to %d" % (min(w["ids_lines"] for w in ws), max(w["ids_lines"] for w in ws)))

    p()
    p("Collection cost: mean bytes of evidence per window")
    for name, g in (("attack windows", attack), ("baseline windows", by.get("baseline", []))):
        if not g:
            continue
        sources = sorted({k for w in g for k in w["bytes"]})
        mean = {k: round(sum(w["bytes"].get(k, 0) for w in g) / len(g)) for k in sources}
        p("  %-17s %s total, of which %s" % (
            name + ":", num(round(sum(sum(w["bytes"].values()) for w in g) / len(g))),
            ", ".join("%s %s" % (k, num(v)) for k, v in mean.items())))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("folders", nargs="*", help="window folders (default: every one beside this script)")
    ap.add_argument("--json", action="store_true", help="print the per-window figures as JSON")
    args = ap.parse_args()
    folders = args.folders or sorted(d for d in glob.glob(os.path.join(HERE, "2026*")) if os.path.isdir(d))
    if not folders:
        sys.exit("no window folders found")
    ws = [score_window(f) for f in folders]
    if args.json:
        json.dump(ws, sys.stdout, indent=1)
        print()
    else:
        report(ws)


if __name__ == "__main__":
    main()
