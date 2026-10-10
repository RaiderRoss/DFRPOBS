#!/usr/bin/env python3
"""
Scores a replay_into_repository.py run against the ground truth.

Offline: reads results/<tag>/replay.json and the windows' own ground truth files, and never
talks to the repository, so a run can be re-scored at any time without re-running it.

What is measured, per incident (one Slips attacker in one window):

  trigger       whether the alerted address is the ground truth's attacker, or an honest user
  recall        how many of the incident's own window's four artifacts were proposed
  precision     how many proposed artifacts came from the incident's own window, rather than
                from neighbouring windows that the 30/15 minute correlation window also covers
  fraud audit   whether the bank's audit trail for the window was proposed -- the only source
                that records the fraud and the login that committed it
  review load   links an investigator must rule on with incident grouping, against what it
                would have been had each alert carried its own bundle
  rule tier     the same recall and precision over AUTO_RULE links only -- those the
                repository's correlation rules (alert-instant, shared-indicator) proposed
                above plain time overlap, and which the UI shows first

Plus, for the whole run: artifacts preserved, rejected, and whose repository digest matched
the digest recorded at capture.

"Own window" is ground truth because the lab captured every window separately: the
attacker, the evidence and the alert all belong to one 30 second window by construction.
An artifact from another window is not wrong to propose -- its coverage does overlap the
correlation window -- but it is evidence of a different session, and every one of them is a
link an investigator has to read and dismiss.

  python check_correlation.py results/eval-design
  python check_correlation.py results/eval-design results/eval-shared   # side by side

Writes summary.json and summary.md next to each replay.json.
"""

import argparse
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCES = ["firewall", "ids", "banking-events", "banking-audit"]


def parse(ts):
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def load_truth(window):
    folder = os.path.join(HERE, window["name"])
    stamp = window["stamp"]
    with open(os.path.join(folder, "firewall_%s.groundtruth.json" % stamp)) as fh:
        fw = json.load(fh)
    with open(os.path.join(folder, "banking_%s.groundtruth.json" % stamp)) as fh:
        bank = json.load(fh)
    malicious = {u["ip"] for u in fw["users"] if u["role"] != "benign"}
    if bank.get("attacker"):
        malicious.add(bank["attacker"]["ip"])
    return {"malicious": malicious, "banking_profile": bank.get("profile")}


def score_run(run_dir):
    with open(os.path.join(run_dir, "replay.json")) as fh:
        run = json.load(fh)

    windows = {w["name"]: w for w in run["windows"]}
    run_keys = {v: k for k, v in run["sourceKeys"].items()}  # source key -> pde source
    truth = {name: load_truth(w) for name, w in windows.items()}

    subs = run["submissions"]
    timings = sorted(s["elapsedMs"] for s in subs if "elapsedMs" in s)
    ingest = {
        "submitted": len(subs),
        "preserved": sum(s["status"] == "preserved" for s in subs),
        "alreadyPreserved": sum(s["status"] == "already-preserved" for s in subs),
        "rejected": sum(s["status"] == "rejected" for s in subs),
        "hashMatchesManifest": sum(bool(s.get("hashMatchesManifest")) for s in subs),
        "medianIngestMs": timings[len(timings) // 2] if timings else None,
    }

    expected_keys = {k for e in run["expectedIncidents"].values() for k in e["incidentKeys"]}
    incidents = []
    for bundle in run["bundles"]:
        inc = bundle["incident"]
        key = inc["incidentKey"]
        window_name, ip, _tw = key.rsplit("/", 2)
        if window_name not in windows:
            continue
        own = windows[window_name]
        own_start = parse(own["start"])

        by_source = defaultdict(list)
        foreign, other_window_offsets = 0, []
        rule_links, rule_own_links, rule_own_sources = 0, 0, set()
        for link in bundle["links"]:
            is_rule = link["method"] == "AUTO_RULE"
            rule_links += is_rule
            source = run_keys.get(link["sourceKey"])
            if source is None:
                foreign += 1  # evidence from outside this run that shares the work group
                continue
            stamp = (link["sourceArtifactId"] or "").rsplit("_", 1)[-1]
            if stamp == own["stamp"]:
                by_source[source].append(link)
                if is_rule:
                    rule_own_links += 1
                    rule_own_sources.add(source)
            else:
                other_window_offsets.append(
                    (parse(link["eventStart"]) - own_start).total_seconds() / 60.0)

        own_found = {s for s in SOURCES if by_source.get(s)}
        total = sum(len(v) for v in by_source.values()) + len(other_window_offsets) + foreign
        incidents.append({
            "incidentKey": key,
            "window": window_name,
            "profile": own["profile"],
            "seed": own["seed"],
            "alertedIp": ip,
            "triggerIsAttacker": ip in truth[window_name]["malicious"],
            "alerts": inc["alertCount"],
            "status": inc["correlationStatus"],
            "windowMinutes": round((parse(inc["windowEnd"]) - parse(inc["windowStart"])).total_seconds() / 60, 1),
            "linksTotal": total,
            "linksOwnWindow": len(own_found),
            "linksOtherWindows": len(other_window_offsets),
            "linksForeign": foreign,
            "otherWindowsSpanMinutes": [round(min(other_window_offsets), 1),
                                        round(max(other_window_offsets), 1)]
            if other_window_offsets else None,
            "ownSourcesFound": sorted(own_found),
            "ownSourcesMissing": [s for s in SOURCES if s not in own_found],
            "recall": len(own_found) / len(SOURCES),
            "precision": len(own_found) / total if total else None,
            "fraudAuditProposed": "banking-audit" in own_found,
            "reviewLoadGrouped": total,
            "reviewLoadPerAlert": total * inc["alertCount"],
            "lateArrivalLinks": sum(l["lateArrival"] for l in bundle["links"]),
            "methods": dict(Counter(l["method"] for l in bundle["links"])),
            "ruleLinks": rule_links,
            "ruleOwnSourcesFound": sorted(rule_own_sources),
            "ruleRecall": len(rule_own_sources) / len(SOURCES),
            "rulePrecision": rule_own_links / rule_links if rule_links else None,
        })
    incidents.sort(key=lambda i: i["window"])

    seen_keys = {i["incidentKey"] for i in incidents}
    n = len(incidents) or 1
    summary = {
        "tag": run["tag"],
        "classification": run["classification"],
        "workGroups": run["workGroups"],
        "ingest": ingest,
        "incidentsExpected": len(expected_keys),
        "incidentsFound": len(seen_keys & expected_keys),
        "incidentsMissing": sorted(expected_keys - seen_keys),
        "alerts": sum(i["alerts"] for i in incidents),
        "triggersOnAttacker": sum(i["triggerIsAttacker"] for i in incidents),
        "meanRecall": sum(i["recall"] for i in incidents) / n,
        "meanPrecision": sum(i["precision"] or 0 for i in incidents) / n,
        "fraudAuditProposed": sum(i["fraudAuditProposed"] for i in incidents),
        "perSourceRecall": {s: sum(s in i["ownSourcesFound"] for i in incidents) for s in SOURCES},
        "reviewLoadGrouped": sum(i["reviewLoadGrouped"] for i in incidents),
        "reviewLoadPerAlert": sum(i["reviewLoadPerAlert"] for i in incidents),
        "ruleLinks": sum(i["ruleLinks"] for i in incidents),
        "meanRuleRecall": sum(i["ruleRecall"] for i in incidents) / n,
        "meanRulePrecision": sum(i["rulePrecision"] or 0 for i in incidents) / n,
        "ruleFraudAuditProposed": sum("banking-audit" in i["ruleOwnSourcesFound"] for i in incidents),
        "incidents": incidents,
    }
    return summary


def markdown(s):
    n = len(s["incidents"])
    out = ["# Correlation results: %s (classification: %s)" % (s["tag"], s["classification"]), ""]
    ing = s["ingest"]
    out += ["## Preservation", "",
            "| Submitted | Preserved | Already preserved | Rejected | Repository digest = capture digest |",
            "|---|---|---|---|---|",
            "| %d | %d | %d | %d | %d of %d |" % (ing["submitted"], ing["preserved"], ing["alreadyPreserved"],
                                                 ing["rejected"], ing["hashMatchesManifest"], ing["preserved"]),
            ""]
    out += ["## Incidents", "",
            "%d alerts grouped into %d incidents (%d expected); %d of %d triggered on the attacker." % (
                s["alerts"], n, s["incidentsExpected"], s["triggersOnAttacker"], n), "",
            "| Window | Profile | Alerts | Links | Own window (of 4) | Other windows | Missing own sources | Audit trail proposed |",
            "|---|---|---|---|---|---|---|---|"]
    for i in s["incidents"]:
        span = i["otherWindowsSpanMinutes"]
        out.append("| %s | %s | %d | %d | %d | %d%s | %s | %s |" % (
            i["window"].split("_")[0], i["profile"], i["alerts"], i["linksTotal"], i["linksOwnWindow"],
            i["linksOtherWindows"], " (%+.0f to %+.0f min)" % tuple(span) if span else "",
            ", ".join(i["ownSourcesMissing"]) or "none", "yes" if i["fraudAuditProposed"] else "**no**"))
    out += ["", "## Summary", "",
            "| Measure | Value |", "|---|---|",
            "| Mean recall (own-window artifacts proposed) | %.0f%% |" % (100 * s["meanRecall"]),
            "| Mean precision (proposed artifacts from own window) | %.0f%% |" % (100 * s["meanPrecision"]),
            "| Incidents whose bank audit trail was proposed | %d of %d |" % (s["fraudAuditProposed"], n),
            "| Per-source recall | %s |" % ", ".join("%s %d/%d" % (k, v, n) for k, v in s["perSourceRecall"].items()),
            "| Links to review, grouped by incident | %d |" % s["reviewLoadGrouped"],
            "| Links to review, one bundle per alert | %d |" % s["reviewLoadPerAlert"],
            "| Links matched by rule (shown first) | %d |" % s["ruleLinks"],
            "| Mean recall, rule-matched links only | %.0f%% |" % (100 * s["meanRuleRecall"]),
            "| Mean precision, rule-matched links only | %.0f%% |" % (100 * s["meanRulePrecision"]),
            "| Audit trail among rule-matched links | %d of %d |" % (s["ruleFraudAuditProposed"], n),
            ""]
    if s["incidentsMissing"]:
        out += ["**Incidents expected but not found:** " + ", ".join(s["incidentsMissing"]), ""]
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("runs", nargs="+", help="results folder(s), each holding a replay.json")
    args = ap.parse_args()

    summaries = []
    for run_dir in args.runs:
        if not os.path.isfile(os.path.join(run_dir, "replay.json")):
            sys.exit("no replay.json in %s" % run_dir)
        s = score_run(run_dir)
        with open(os.path.join(run_dir, "summary.json"), "w", encoding="utf-8") as fh:
            json.dump(s, fh, indent=2)
        md = markdown(s)
        with open(os.path.join(run_dir, "summary.md"), "w", encoding="utf-8") as fh:
            fh.write(md)
        print(md)
        summaries.append(s)

    if len(summaries) > 1:
        print("\n# Comparison\n")
        print("| Measure | " + " | ".join(s["classification"] for s in summaries) + " |")
        print("|---|" + "---|" * len(summaries))
        rows = [
            ("Incidents", lambda s: "%d" % len(s["incidents"])),
            ("Mean recall", lambda s: "%.0f%%" % (100 * s["meanRecall"])),
            ("Mean precision", lambda s: "%.0f%%" % (100 * s["meanPrecision"])),
            ("Audit trail proposed", lambda s: "%d of %d" % (s["fraudAuditProposed"], len(s["incidents"]))),
            ("Links to review (grouped)", lambda s: "%d" % s["reviewLoadGrouped"]),
            ("Links to review (per alert)", lambda s: "%d" % s["reviewLoadPerAlert"]),
            ("Links matched by rule", lambda s: "%d" % s["ruleLinks"]),
            ("Rule-tier recall", lambda s: "%.0f%%" % (100 * s["meanRuleRecall"])),
            ("Rule-tier precision", lambda s: "%.0f%%" % (100 * s["meanRulePrecision"])),
        ]
        for label, fn in rows:
            print("| %s | %s |" % (label, " | ".join(fn(s) for s in summaries)))


if __name__ == "__main__":
    main()
