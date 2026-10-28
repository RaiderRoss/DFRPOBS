#!/usr/bin/env python3
"""
Replays the captured evaluation windows into the DFRaaS Evidence Repository, end to end.

The batch in this folder measured the capture layer: whether each source recorded what
happened, and whether its files stayed intact. This script measures the repository: every
window's four artifacts are preserved through POST /api/evidence-items, every Slips alert
is forwarded over Kafka by the real slips_forwarder.py, the repository's own correlation
pass groups the alerts into incidents and proposes evidence for each, and the result is
written out for check_correlation.py to score against the ground truth.

Nothing here reimplements the repository. Evidence goes in through the same endpoint a
collector uses, alerts through the same topic and forwarder the live lab uses, and the
bundles come back from the same endpoints the investigator UI reads.

Order matters, and is fixed: all evidence first, then the alerts. The windows were captured
days ago, so every incident's window ended long before the repository's settle-after
allowance (1 h by default), and the first correlation pass closes it. Evidence submitted
after that pass would never be linked. Live, evidence arrives continuously and the
late-arrival path covers stragglers; a replay has no stragglers, only an order.

Each run is isolated by its --tag. Source keys and work groups are suffixed with it, so a
second run, or a run under another --classification, neither collides with an earlier one
nor sees its evidence in its bundles. Re-running the same tag is safe: the repository
dedupes artifacts on (source, artifact id) and alerts on (source, event id), and both are
derived from the capture, so a repeat changes nothing and reports what is already there.

Classification (--classification) decides which work group each source is registered
under, and correlation searches only the work group of the source that raised the alert:

  design   as in the dissertation's evidence source table: firewall and IDS under Network
           Security (WG5), the bank's event stream under Public-Facing Digital Channels
           (WG7), its audit trail under Internal/Privileged User Access (WG8).
  shared   all four sources under one Online Banking work group.

Running both and comparing them is the point: under "design", an IDS alert can only ever
be linked to network evidence, so the bank's audit trail -- the one source that shows the
fraud and who committed it -- is never proposed to the investigator.

  python replay_into_repository.py --dry-run
  python replay_into_repository.py --classification design
  python replay_into_repository.py --classification shared
  python check_correlation.py results/design

Needs the repository's compose stack (Postgres, MinIO, Redpanda) and the backend running.
Standard library only.
"""

import argparse
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
FORWARDER = os.path.join(HERE, "..", "IDS", "slips_forwarder.py")

# Mirrors submit-evidence.sh: the same four collectors, the same base keys and types, and
# the same artifact id rule (<source>_<window stamp>), so a replayed item is the item the
# live script would have sent.
SOURCES = {
    "firewall": {"key": "pde-sim-ufw-01", "name": "PDE testbed firewall (ufw)",
                 "type": "FIREWALL", "content_type": "text/plain"},
    "ids": {"key": "pde-sim-slips-01", "name": "PDE testbed IDS (Slips)",
            "type": "IDS", "content_type": "text/plain"},
    "banking-events": {"key": "pde-sim-fineract-events-01",
                       "name": "PDE testbed bank event stream (Fineract)",
                       "type": "BANKING_EVENTS", "content_type": "application/x-ndjson"},
    "banking-audit": {"key": "pde-sim-fineract-audit-01",
                      "name": "PDE testbed bank audit trail (Fineract)",
                      "type": "DB_AUDIT", "content_type": "application/x-ndjson"},
}

WORK_GROUPS = {
    "NETWORK_SECURITY": "WG5 Network Security and Anti-Hacking",
    "PUBLIC_FACING_CHANNELS": "WG7 Public-Facing Digital Channels",
    "PRIVILEGED_ACCESS": "WG8 Internal and Privileged User Access",
    "ONLINE_BANKING": "Online Banking",
}

CLASSIFICATIONS = {
    "design": {"firewall": "NETWORK_SECURITY", "ids": "NETWORK_SECURITY",
               "banking-events": "PUBLIC_FACING_CHANNELS", "banking-audit": "PRIVILEGED_ACCESS"},
    "shared": {"firewall": "ONLINE_BANKING", "ids": "ONLINE_BANKING",
               "banking-events": "ONLINE_BANKING", "banking-audit": "ONLINE_BANKING"},
}

SETTLED = {"CORRELATED", "CLOSED"}


def log(msg):
    print("  " + msg, file=sys.stderr, flush=True)


def fail(msg):
    print("  error: " + msg, file=sys.stderr)
    sys.exit(1)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------------- HTTP

class Api:

    def __init__(self, base, auth):
        self.base = base.rstrip("/")
        self.auth = "Basic " + base64.b64encode(auth.encode()).decode()

    def request(self, method, path, body=None, content_type=None):
        """Returns (status, parsed JSON or None). Never raises on an HTTP error status."""
        req = urllib.request.Request(self.base + path, data=body, method=method)
        req.add_header("Authorization", self.auth)
        req.add_header("Accept", "application/json")
        if content_type:
            req.add_header("Content-Type", content_type)
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                status, raw = resp.status, resp.read()
        except urllib.error.HTTPError as ex:
            status, raw = ex.code, ex.read()
        except urllib.error.URLError as ex:
            fail("could not reach %s (%s) -- is the backend running?" % (self.base, ex.reason))
        try:
            return status, json.loads(raw) if raw else None
        except ValueError:
            return status, {"raw": raw.decode("utf-8", "replace")}

    def get(self, path, **params):
        query = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
        return self.request("GET", path + ("?" + query if query else ""))

    def post_json(self, path, payload):
        return self.request("POST", path, json.dumps(payload).encode(), "application/json")

    def post_multipart(self, path, parts):
        """parts: list of (name, filename or None, content type, bytes)."""
        boundary = "----dfraas-replay-" + uuid.uuid4().hex
        out = []
        for name, filename, ctype, data in parts:
            disp = 'form-data; name="%s"' % name
            if filename:
                disp += '; filename="%s"' % filename
            out.append(("--%s\r\nContent-Disposition: %s\r\nContent-Type: %s\r\n\r\n"
                        % (boundary, disp, ctype)).encode())
            out.append(data)
            out.append(b"\r\n")
        out.append(("--%s--\r\n" % boundary).encode())
        return self.request("POST", path, b"".join(out), "multipart/form-data; boundary=" + boundary)

    def paged(self, path, **params):
        """Every element of a Spring PagedModel endpoint."""
        items, page = [], 0
        while True:
            status, body = self.get(path, page=page, size=200, **params)
            if status != 200:
                fail("GET %s returned HTTP %s: %s" % (path, status, body))
            items.extend(body.get("content", []))
            meta = body.get("page", {})
            page += 1
            if page >= meta.get("totalPages", 0):
                return items


# --------------------------------------------------------------------------- windows

def load_windows(evaluation_dir, only):
    """Every captured window, with each source's artifact checked against its manifest."""
    windows = []
    for name in sorted(os.listdir(evaluation_dir)):
        folder = os.path.join(evaluation_dir, name)
        stamp = name.split("_", 1)[0]
        group_path = os.path.join(folder, "window_%s.group.json" % stamp)
        if not os.path.isfile(group_path):
            continue
        if only and name not in only and stamp not in only:
            continue
        with open(group_path) as fh:
            group = json.load(fh)
        artifacts = {}
        for item in group["items"]:
            path = os.path.join(folder, item["file"])
            if not os.path.isfile(path):
                fail("%s: %s is listed in the group manifest but missing" % (name, item["file"]))
            actual = sha256_file(path)
            if actual != item["sha256"]:
                # The same refusal submit-evidence.sh makes: a file that changed since
                # capture is a local finding, not something to hand the repository.
                fail("%s: %s no longer matches the digest recorded at capture "
                     "(manifest %s, now %s)" % (name, item["file"], item["sha256"], actual))
            artifacts[item["pde_source"]] = {"file": item["file"], "path": path,
                                             "sha256": item["sha256"]}
        windows.append({
            "name": name,
            "stamp": stamp,
            "folder": folder,
            "start": group["window"]["start_utc"],
            "end": group["window"]["end_utc"],
            "profile": group["scenario"]["attack_profile"],
            "seed": group["scenario"]["seed"],
            "artifacts": artifacts,
        })
    return windows


def count_alerts(ids_path):
    """(alert lines, distinct (ip, timewindow) pairs) in a windowed alerts.log, using the
    forwarder's own pattern so the expectation cannot drift from what it sends."""
    sys.path.insert(0, os.path.dirname(FORWARDER))
    from slips_forwarder import ALERT_RE  # noqa: E402
    lines, keys = 0, set()
    with open(ids_path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = ALERT_RE.match(line.rstrip("\r\n"))
            if m:
                lines += 1
                keys.add((m.group("ip"), m.group("tw")))
    return lines, keys


# --------------------------------------------------------------------------- steps

def ensure_work_groups(api, codes, tag, dry_run):
    ids = {}
    for code in sorted(set(codes)):
        tagged = "%s_%s" % (code, tag.upper().replace("-", "_"))
        if dry_run:
            ids[code] = "<%s>" % tagged
            log("would use or create work group %s" % tagged)
            continue
        status, body = api.get("/api/work-groups", classificationCode=tagged)
        if status == 200 and body:
            ids[code] = body[0]["id"]
            log("work group %s exists" % tagged)
            continue
        status, body = api.post_json("/api/work-groups", {
            "name": "%s (evaluation run %s)" % (WORK_GROUPS[code], tag),
            "classificationCode": tagged})
        if status != 201:
            fail("could not create work group %s (HTTP %s): %s" % (tagged, status, body))
        ids[code] = body["id"]
        log("created work group %s" % tagged)
    return ids


def ensure_sources(api, classification, work_group_ids, tag, dry_run):
    keys = {}
    for source, spec in SOURCES.items():
        key = "%s-%s" % (spec["key"], tag)
        keys[source] = key
        if dry_run:
            log("would use or register %s under %s" % (key, classification[source]))
            continue
        status, body = api.get("/api/evidence-sources", sourceKey=key)
        if status == 200 and body:
            registered = body[0]["workGroupId"]
            wanted = work_group_ids[classification[source]]
            if registered != wanted:
                # Registration is permanent and decides classification, so a key already
                # registered elsewhere cannot be quietly reused under another one.
                fail("source %s is already registered under work group %s, not %s -- "
                     "use a different --tag" % (key, registered, wanted))
            log("source %s exists" % key)
            continue
        status, body = api.post_json("/api/evidence-sources", {
            "sourceKey": key,
            "displayName": "%s [eval %s]" % (spec["name"], tag),
            "workGroupId": work_group_ids[classification[source]],
            "sourceType": spec["type"],
        })
        if status != 201:
            fail("could not register %s (HTTP %s): %s" % (key, status, body))
        log("registered %s under %s" % (key, classification[source]))
    return keys


def submit_evidence(api, windows, source_keys, dry_run):
    results = []
    for w in windows:
        for source in SOURCES:
            art = w["artifacts"].get(source)
            if art is None:
                log("%s: no %s artifact captured" % (w["name"], source))
                continue
            artifact_id = "%s_%s" % (source, w["stamp"])
            metadata = {
                "sourceKey": source_keys[source],
                "sourceArtifactId": artifact_id,
                "eventStart": w["start"],
                "eventEnd": w["end"],
                "sourceSha256": art["sha256"],
            }
            record = {"window": w["name"], "source": source, "sourceKey": source_keys[source],
                      "sourceArtifactId": artifact_id, "file": art["file"],
                      "bytes": os.path.getsize(art["path"]), "manifestSha256": art["sha256"]}
            if dry_run:
                record["status"] = "dry-run"
                results.append(record)
                continue
            with open(art["path"], "rb") as fh:
                data = fh.read()
            started = time.monotonic()
            status, body = api.post_multipart("/api/evidence-items", [
                ("metadata", None, "application/json", json.dumps(metadata).encode()),
                ("file", art["file"], SOURCES[source]["content_type"], data),
            ])
            record["httpStatus"] = status
            record["elapsedMs"] = round((time.monotonic() - started) * 1000)
            if status == 201:
                record.update(status="preserved", itemId=body["id"],
                              repositoryHash=body["currentHash"],
                              hashMatchesManifest=body["currentHash"] == art["sha256"])
            elif status == 409:
                record["status"] = "already-preserved"
            else:
                record.update(status="rejected", response=body)
                log("%s: %s rejected with HTTP %s: %s" % (w["name"], source, status, body))
            results.append(record)
        log("%s: submitted %d artifact(s)" % (w["name"], len(w["artifacts"])))
    return results


def forward_alerts(windows, ids_key, args):
    """Runs the real forwarder once over each window's IDS artifact. The window's folder
    name becomes the Slips session, so its alerts form incidents of their own."""
    expected, tmp = {}, tempfile.mkdtemp(prefix="dfraas-replay-")
    try:
        for w in windows:
            art = w["artifacts"].get("ids")
            if art is None:
                continue
            lines, keys = count_alerts(art["path"])
            if not lines:
                continue
            expected[w["name"]] = {"alerts": lines,
                                   "incidentKeys": sorted("%s/%s/tw%s" % (w["name"], ip, tw)
                                                          for ip, tw in keys)}
            session = os.path.join(tmp, w["name"])
            os.makedirs(os.path.join(session, "alerts"))
            shutil.copyfile(art["path"], os.path.join(session, "alerts", "alerts.log"))
            cmd = [sys.executable, FORWARDER, "--slips-out", session, "--once",
                   "--source-system", ids_key, "--sink", "stdout" if args.dry_run else args.sink,
                   "--bootstrap", args.bootstrap, "--topic", args.topic,
                   "--rpk-container", args.rpk_container,
                   "--offset-file", os.path.join(session, "forwarder.offset")]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                fail("forwarder failed on %s:\n%s" % (w["name"], result.stderr or result.stdout))
            log("%s: forwarded %d alert(s) as %d incident key(s)" % (w["name"], lines, len(keys)))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return expected


def wait_for_correlation(api, ids_key, expected, timeout):
    """Polls until every expected incident exists and a correlation pass has completed on
    it. The consumer and the scheduler are asynchronous; this is the only wait."""
    want = {k for e in expected.values() for k in e["incidentKeys"]}
    want_alerts = sum(e["alerts"] for e in expected.values())
    deadline = time.monotonic() + timeout
    while True:
        incidents = api.paged("/api/incidents", sourceSystem=ids_key)
        seen = {i["incidentKey"]: i for i in incidents}
        alerts = sum(i["alertCount"] for i in incidents)
        settled = [k for k in want if k in seen and seen[k]["correlationStatus"] in SETTLED]
        log("incidents %d/%d, alerts %d/%d, correlated %d/%d" % (
            len(want & seen.keys()), len(want), alerts, want_alerts, len(settled), len(want)))
        if len(settled) == len(want) and alerts >= want_alerts:
            return incidents
        if time.monotonic() > deadline:
            log("timed out after %ds; writing what is there" % timeout)
            return incidents
        time.sleep(10)


def collect_bundles(api, incidents):
    bundles = []
    for inc in incidents:
        links = api.paged("/api/incidents/%s/links" % inc["id"])
        bundles.append({"incident": inc, "links": [{
            "linkId": l["id"],
            "method": l["linkMethod"],
            "disposition": l["disposition"],
            "lateArrival": l["lateArrival"],
            "sourceKey": l.get("evidenceSourceKey"),
            "sourceArtifactId": (l.get("evidenceItem") or {}).get("sourceArtifactId"),
            "itemId": (l.get("evidenceItem") or {}).get("id"),
            "eventStart": (l.get("evidenceItem") or {}).get("eventStart"),
            "eventEnd": (l.get("evidenceItem") or {}).get("eventEnd"),
            "rationale": l["rationale"],
        } for l in links]})
    return bundles


# --------------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--classification", choices=sorted(CLASSIFICATIONS), default="design")
    ap.add_argument("--tag", help="isolates this run's sources and work groups "
                                  "(default: eval-<classification>)")
    ap.add_argument("--url", default=os.environ.get("DFRAAS_URL", "http://localhost:8080"))
    ap.add_argument("--auth", default=os.environ.get("DFRAAS_AUTH", "admin:admin"))
    ap.add_argument("--windows", nargs="*", help="only these windows (folder name or stamp)")
    ap.add_argument("--sink", choices=["auto", "kafka", "rpk"], default="auto",
                    help="how the forwarder reaches Kafka (default: auto)")
    ap.add_argument("--bootstrap", default=os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:19092"))
    ap.add_argument("--topic", default=os.environ.get("KAFKA_EVIDENCE_TOPIC", "evidence-events"))
    ap.add_argument("--rpk-container", default=os.environ.get("DFRAAS_REDPANDA_CONTAINER", "dfraas-redpanda"))
    ap.add_argument("--timeout", type=int, default=300,
                    help="seconds to wait for the correlation pass (default 300; it sweeps once a minute)")
    ap.add_argument("--out", help="results folder (default: results/<tag>)")
    ap.add_argument("--dry-run", action="store_true",
                    help="check the windows and show what would be sent; changes nothing")
    args = ap.parse_args()

    tag = args.tag or "eval-%s" % args.classification
    classification = CLASSIFICATIONS[args.classification]
    out_dir = args.out or os.path.join(HERE, "results", tag)
    api = Api(args.url, args.auth)

    windows = load_windows(HERE, set(args.windows or []))
    if not windows:
        fail("no captured windows found in %s" % HERE)
    log("%d window(s), every artifact matches its capture manifest" % len(windows))

    if not args.dry_run:
        status, _ = api.get("/api/work-groups")
        if status == 401:
            fail("authentication failed -- set --auth or DFRAAS_AUTH")
        if status != 200:
            fail("the repository answered HTTP %s on /api/work-groups" % status)

    started = datetime.now(timezone.utc)
    work_group_ids = ensure_work_groups(api, classification.values(), tag, args.dry_run)
    source_keys = ensure_sources(api, classification, work_group_ids, tag, args.dry_run)

    # Evidence strictly before alerts; see the module docstring.
    submissions = submit_evidence(api, windows, source_keys, args.dry_run)
    expected = forward_alerts(windows, source_keys["ids"], args)
    total_alerts = sum(e["alerts"] for e in expected.values())
    log("%d alert(s) in %d window(s), expected as %d incident(s)" % (
        total_alerts, len(expected), sum(len(e["incidentKeys"]) for e in expected.values())))

    if args.dry_run:
        log("dry run: nothing was sent")
        return

    incidents = wait_for_correlation(api, source_keys["ids"], expected, args.timeout)
    bundles = collect_bundles(api, incidents)

    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "replay.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump({
            "tag": tag,
            "classification": args.classification,
            "workGroups": {code: {"id": wid, "sources": sorted(s for s, c in classification.items()
                                                               if c == code)}
                           for code, wid in work_group_ids.items()},
            "sourceKeys": source_keys,
            "repository": args.url,
            "startedAt": started.isoformat(),
            "finishedAt": datetime.now(timezone.utc).isoformat(),
            "windows": [{k: w[k] for k in ("name", "stamp", "start", "end", "profile", "seed")}
                        for w in windows],
            "submissions": submissions,
            "expectedIncidents": expected,
            "bundles": bundles,
        }, fh, indent=2)
    rejected = [s for s in submissions if s["status"] == "rejected"]
    log("wrote %s (%d submission(s), %d rejected; %d incident(s))" % (
        os.path.relpath(out_path), len(submissions), len(rejected), len(bundles)))
    log("next: python check_correlation.py %s" % os.path.relpath(out_dir))


if __name__ == "__main__":
    main()
