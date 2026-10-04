#!/usr/bin/env python3
"""
Tamper tests against the DFRaaS Evidence Repository: what it detects, prevents, and misses.

Each test attacks evidence in one way, and states before running what the repository should
do about it. The attacker in T2-T5 is the privileged insider of the threat model: someone
who can write to the object store or the database directly, past the repository's own API,
which is exactly the actor forensic readiness exists to catch.

  T1  artifact altered in transit      one byte changed, original digest still claimed
  T2  evidence altered in storage      object overwritten in MinIO, then re-verified
  T3  custody entry edited             a row of custody_event changed in Postgres
  T4a custody entries reordered        two rows' sequence numbers swapped
  T4b custody entry deleted (middle)   an interior row removed
  T5  custody chain truncated (end)    the newest row removed -- the known gap
  T6  duplicate submission             an already preserved artifact sent again

Every test works on an item of its own, preserved fresh from a real window's firewall log
under this run's --tag, so the evaluation runs' evidence is never touched. Items are never
removed afterwards: the repository has no delete, and a tampered item that stays
COMPROMISED is itself part of the record of the test.

Outcomes are classified, not just passed or failed:

  REJECTED    the API refused the attack (T1, T6)
  PREVENTED   the database refused the write (what T3-T5 should report once append-only
              is enforced below the application)
  DETECTED    the write succeeded and the repository's verification found it
  UNDETECTED  the write succeeded and verification still reports the chain intact

T5 is expected UNDETECTED today. That is the limitation the dissertation already states:
hash chaining cannot see a missing tail from inside. The test records the head hash before
and after, to show that a head witnessed outside the database would catch it.

  python tamper_tests.py                     # all tests, results/tamper/
  python tamper_tests.py --only T2 T5
  python tamper_tests.py --window 20260930232604_db-probe

Needs the backend and the compose stack, and docker on PATH: T2 writes through the MinIO
container's mc client, T3-T5 through the Postgres container's psql.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

from replay_into_repository import HERE, Api, fail, load_windows, log

ALL_TESTS = ["T1", "T2", "T3", "T4a", "T4b", "T5", "T6"]


# --------------------------------------------------------------------------- privileged access

class Insider:
    """Direct access to the stores, bypassing the repository."""

    def __init__(self, args):
        self.args = args
        self.mc_ready = False

    def sql(self, statement):
        """Runs SQL as the database owner. Returns (succeeded, output)."""
        cmd = ["docker", "exec", self.args.pg_container, "psql", "-U", self.args.pg_user,
               "-d", self.args.pg_db, "-v", "ON_ERROR_STOP=1", "-tA", "-c", statement]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode == 0, (result.stdout + result.stderr).strip()

    def _mc(self, *mc_args, data=None):
        if not self.mc_ready:
            ok = subprocess.run(["docker", "exec", self.args.minio_container, "mc", "alias", "set", "tamper",
                                 "http://localhost:9000", self.args.minio_user, self.args.minio_password],
                                capture_output=True, text=True)
            if ok.returncode != 0:
                fail("could not configure mc in %s: %s" % (self.args.minio_container, ok.stderr.strip()))
            self.mc_ready = True
        return subprocess.run(["docker", "exec", "-i", self.args.minio_container, "mc", *mc_args],
                              input=data, capture_output=True)

    def overwrite_object(self, key, data):
        result = self._mc("pipe", "tamper/%s/%s" % (self.args.bucket, key), data=data)
        if result.returncode != 0:
            fail("mc pipe failed: %s" % result.stderr.decode(errors="replace"))

    def object_exists(self, key):
        return self._mc("stat", "tamper/%s/%s" % (self.args.bucket, key)).returncode == 0


# --------------------------------------------------------------------------- harness

class Harness:

    def __init__(self, api, insider, artifact, source_key, window, nonce):
        self.api = api
        self.insider = insider
        self.artifact = artifact
        self.source_key = source_key
        self.window = window
        self.nonce = nonce
        with open(artifact["path"], "rb") as fh:
            self.original = fh.read()
        # One byte flipped mid-file: the smallest change there is, and one no reader skimming
        # a log would notice.
        mid = len(self.original) // 2
        self.altered = self.original[:mid] + bytes([self.original[mid] ^ 0x01]) + self.original[mid + 1:]

    def artifact_id(self, test):
        return "firewall_%s_%s_%s" % (self.window["stamp"], test.lower(), self.nonce)

    def storage_key(self, artifact_id):
        # EvidenceItemService.storageKeyFor
        return "%s/%s" % (self.source_key, artifact_id)

    def submit(self, artifact_id, data, claimed_sha256):
        metadata = {"sourceKey": self.source_key, "sourceArtifactId": artifact_id,
                    "eventStart": self.window["start"], "eventEnd": self.window["end"],
                    "sourceSha256": claimed_sha256}
        return self.api.post_multipart("/api/evidence-items", [
            ("metadata", None, "application/json", json.dumps(metadata).encode()),
            ("file", self.artifact["file"], "text/plain", data),
        ])

    def fresh_item(self, test, checks=2):
        """Preserves a new item and runs integrity checks on it, so its chain has entries at
        0..checks: CREATED, then HASH_VERIFIED per check. Interior tampering needs an
        interior."""
        artifact_id = self.artifact_id(test)
        status, body = self.submit(artifact_id, self.original, self.artifact["sha256"])
        if status != 201:
            fail("%s: could not preserve its test item (HTTP %s): %s" % (test, status, body))
        item_id = body["id"]
        for _ in range(checks):
            self.integrity_check(item_id)
        verification = self.verify(item_id)
        if not verification["intact"]:
            fail("%s: freshly preserved item does not verify before tampering: %s" % (test, verification))
        return item_id, artifact_id, verification

    def integrity_check(self, item_id):
        status, body = self.api.request("POST", "/api/evidence-items/%s/integrity-checks" % item_id)
        if status != 200:
            fail("integrity check on %s failed (HTTP %s): %s" % (item_id, status, body))
        return body

    def verify(self, item_id):
        status, body = self.api.get("/api/evidence-items/%s/custody/verification" % item_id)
        if status != 200:
            fail("verification of %s failed (HTTP %s): %s" % (item_id, status, body))
        return body

    def item(self, item_id):
        return self.api.get("/api/evidence-items/%s" % item_id)[1]

    def chain(self, item_id):
        return self.api.get("/api/evidence-items/%s/custody" % item_id)[1]


def result(test, attack, expected, outcome, passed, **details):
    return {"test": test, "attack": attack, "expected": expected, "outcome": outcome,
            "passed": passed, "details": details}


def sql_tamper_outcome(ok, output, verification):
    if not ok:
        return "PREVENTED", {"databaseError": output}
    return ("UNDETECTED" if verification["intact"] else "DETECTED"), {"verification": verification}


# --------------------------------------------------------------------------- tests

def t1(h):
    artifact_id = h.artifact_id("T1")
    status, body = h.submit(artifact_id, h.altered, h.artifact["sha256"])
    stored = h.insider.object_exists(h.storage_key(artifact_id))
    # The same id with the genuine bytes must then succeed: proof that the rejected attempt
    # left no row, no object and no dedupe entry behind.
    retry_status, _ = h.submit(artifact_id, h.original, h.artifact["sha256"])
    passed = status == 422 and not stored and retry_status == 201
    return result("T1", "Artifact altered in transit: one byte flipped, original digest claimed",
                  "HTTP 422; nothing stored", "REJECTED" if status == 422 else "ACCEPTED", passed,
                  httpStatus=status, response=body, objectStoredAfterRejection=stored,
                  genuineRetryHttpStatus=retry_status)


def t2(h):
    item_id, artifact_id, before = h.fresh_item("T2", checks=1)
    h.insider.overwrite_object(h.storage_key(artifact_id), h.altered)
    check = h.integrity_check(item_id)
    item = h.item(item_id)
    # Put the genuine bytes back and check again. The item must stay COMPROMISED: a match
    # after a mismatch does not undo the fact that the object was, at one point, wrong.
    h.insider.overwrite_object(h.storage_key(artifact_id), h.original)
    recheck = h.integrity_check(item_id)
    after = h.verify(item_id)
    actions = [e["action"] for e in h.chain(item_id)]
    passed = (not check["intact"]
              and check["custodyEvent"]["action"] == "HASH_MISMATCH"
              and check["expectedHash"] == h.artifact["sha256"]
              and check["observedHash"] == hashlib.sha256(h.altered).hexdigest()
              and item["status"] == "COMPROMISED"
              and item["currentHash"] == h.artifact["sha256"]
              and recheck["intact"] and recheck["status"] == "COMPROMISED"
              and after["intact"])
    return result("T2", "Evidence altered in storage: object overwritten in MinIO, bypassing the API",
                  "HASH_MISMATCH recorded; item COMPROMISED; recorded digest kept; stays COMPROMISED "
                  "after the object is restored", "DETECTED" if not check["intact"] else "UNDETECTED",
                  passed, itemId=item_id, expectedHash=check["expectedHash"],
                  observedHash=check["observedHash"], statusAfterMismatch=item["status"],
                  currentHashAfterMismatch=item["currentHash"], statusAfterRestore=recheck["status"],
                  chainActions=actions, chainIntactAfter=after["intact"], chainBefore=before)


def t3(h):
    item_id, _, before = h.fresh_item("T3")
    ok, out = h.insider.sql(
        "UPDATE custody_event SET performed_by = 'mallory' "
        "WHERE evidence_item_id = '%s' AND sequence = 1" % item_id)
    after = h.verify(item_id)
    outcome, details = sql_tamper_outcome(ok, out, after)
    passed = outcome == "PREVENTED" or (outcome == "DETECTED" and after["firstDivergentSequence"] == 1)
    return result("T3", "Custody entry edited in the database: performed_by of entry 1 rewritten",
                  "PREVENTED, or DETECTED at sequence 1", outcome, passed,
                  itemId=item_id, before=before, **details)


def t4a(h):
    item_id, _, before = h.fresh_item("T4a")
    # Three steps because (evidence_item_id, sequence) is unique.
    ok, out = h.insider.sql(
        "BEGIN; "
        "UPDATE custody_event SET sequence = 1000 WHERE evidence_item_id = '{0}' AND sequence = 1; "
        "UPDATE custody_event SET sequence = 1 WHERE evidence_item_id = '{0}' AND sequence = 2; "
        "UPDATE custody_event SET sequence = 2 WHERE evidence_item_id = '{0}' AND sequence = 1000; "
        "COMMIT;".format(item_id))
    after = h.verify(item_id)
    outcome, details = sql_tamper_outcome(ok, out, after)
    passed = outcome == "PREVENTED" or (outcome == "DETECTED" and after["firstDivergentSequence"] == 1)
    return result("T4a", "Custody entries reordered: entries 1 and 2 swapped",
                  "PREVENTED, or DETECTED at sequence 1", outcome, passed,
                  itemId=item_id, before=before, **details)


def t4b(h):
    item_id, _, before = h.fresh_item("T4b")
    ok, out = h.insider.sql(
        "DELETE FROM custody_event WHERE evidence_item_id = '%s' AND sequence = 1" % item_id)
    after = h.verify(item_id)
    outcome, details = sql_tamper_outcome(ok, out, after)
    passed = outcome == "PREVENTED" or (outcome == "DETECTED" and after["firstDivergentSequence"] == 1)
    return result("T4b", "Custody entry deleted from the middle of the chain (entry 1 of 0-2)",
                  "PREVENTED, or DETECTED at sequence 1 (the hole)", outcome, passed,
                  itemId=item_id, before=before, **details)


def t5(h):
    item_id, _, before = h.fresh_item("T5")
    ok, out = h.insider.sql(
        "DELETE FROM custody_event WHERE evidence_item_id = '%s' AND sequence = "
        "(SELECT max(sequence) FROM custody_event WHERE evidence_item_id = '%s')" % (item_id, item_id))
    after = h.verify(item_id)
    outcome, details = sql_tamper_outcome(ok, out, after)
    head_changed = after.get("headEntryHash") != before["headEntryHash"]
    # Passing here means the limitation was measured as stated, not that it is acceptable.
    passed = outcome in ("PREVENTED", "UNDETECTED")
    return result("T5", "Custody chain truncated: newest entry deleted",
                  "UNDETECTED by chain verification (known limitation); would be caught by a head "
                  "hash witnessed outside the database", outcome, passed,
                  itemId=item_id, lengthBefore=before["length"], lengthAfter=after["length"],
                  headBefore=before["headEntryHash"], headAfter=after.get("headEntryHash"),
                  externalWitnessWouldDetect=head_changed, **details)


def t6(h):
    item_id, artifact_id, before = h.fresh_item("T6", checks=0)
    status, body = h.submit(artifact_id, h.original, h.artifact["sha256"])
    after = h.verify(item_id)
    passed = status == 409 and after["length"] == before["length"]
    return result("T6", "Duplicate submission: an already preserved artifact sent again",
                  "HTTP 409; no second item; custody chain unchanged",
                  "REJECTED" if status == 409 else "ACCEPTED", passed,
                  itemId=item_id, httpStatus=status, chainLengthBefore=before["length"],
                  chainLengthAfter=after["length"])


TESTS = {"T1": t1, "T2": t2, "T3": t3, "T4a": t4a, "T4b": t4b, "T5": t5, "T6": t6}


# --------------------------------------------------------------------------- setup and report

def ensure_source(api, tag):
    code = "NETWORK_SECURITY_%s" % tag.upper().replace("-", "_")
    status, body = api.get("/api/work-groups", classificationCode=code)
    if status == 200 and body:
        wg = body[0]["id"]
    else:
        status, body = api.post_json("/api/work-groups", {
            "name": "WG5 Network Security and Anti-Hacking (tamper tests %s)" % tag,
            "classificationCode": code})
        if status != 201:
            fail("could not create work group %s (HTTP %s): %s" % (code, status, body))
        wg = body["id"]
    key = "pde-sim-ufw-01-%s" % tag
    status, body = api.get("/api/evidence-sources", sourceKey=key)
    if not (status == 200 and body):
        status, body = api.post_json("/api/evidence-sources", {
            "sourceKey": key, "displayName": "PDE testbed firewall (ufw) [tamper tests %s]" % tag,
            "workGroupId": wg, "sourceType": "FIREWALL"})
        if status != 201:
            fail("could not register %s (HTTP %s): %s" % (key, status, body))
    return key


def markdown(run):
    out = ["# Tamper test results (%s)" % run["tag"], "",
           "Window `%s`, artifact `%s`. Run %s." % (run["window"], run["artifact"], run["finishedAt"]), "",
           "| Test | Attack | Expected | Outcome | Pass |", "|---|---|---|---|---|"]
    for r in run["results"]:
        out.append("| %s | %s | %s | %s | %s |" % (
            r["test"], r["attack"], r["expected"], r["outcome"], "yes" if r["passed"] else "**no**"))
    t5r = next((r for r in run["results"] if r["test"] == "T5"), None)
    if t5r and t5r["outcome"] == "UNDETECTED":
        d = t5r["details"]
        out += ["", "**T5:** chain length %d -> %d, still verifies as intact. Head hash before `%s...`, "
                "after `%s...`; a head witnessed outside the database %s detect the truncation." % (
                    d["lengthBefore"], d["lengthAfter"], d["headBefore"][:16], (d["headAfter"] or "")[:16],
                    "would" if d["externalWitnessWouldDetect"] else "would not")]
    if run.get("databaseRoleIsSuperuser"):
        out += ["", "**Note:** the repository's database role is a superuser. Revoking UPDATE/DELETE "
                "grants does not bind a superuser, and a superuser can disable triggers, so "
                "append-only enforcement needs a separate, non-superuser application role."]
    return "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--only", nargs="+", choices=ALL_TESTS, help="run only these tests")
    ap.add_argument("--tag", default="tamper")
    ap.add_argument("--window", help="window whose firewall log is used (default: the first)")
    ap.add_argument("--url", default=os.environ.get("DFRAAS_URL", "http://localhost:8080"))
    ap.add_argument("--auth", default=os.environ.get("DFRAAS_AUTH", "admin:admin"))
    ap.add_argument("--pg-container", default="dfraas-postgres")
    ap.add_argument("--pg-user", default=os.environ.get("POSTGRES_USER", "dfraas"))
    ap.add_argument("--pg-db", default=os.environ.get("POSTGRES_DB", "dfraas"))
    ap.add_argument("--minio-container", default="dfraas-minio")
    ap.add_argument("--minio-user", default=os.environ.get("MINIO_ACCESS_KEY", "dfraas_admin"))
    ap.add_argument("--minio-password", default=os.environ.get("MINIO_SECRET_KEY", "dfraas_dev_only"))
    ap.add_argument("--bucket", default=os.environ.get("MINIO_BUCKET", "evidence-store"))
    ap.add_argument("--out", help="results folder (default: results/<tag>)")
    args = ap.parse_args()

    windows = load_windows(HERE, {args.window} if args.window else set())
    if not windows:
        fail("no matching window")
    window = windows[0]
    artifact = window["artifacts"]["firewall"]

    api = Api(args.url, args.auth)
    status, _ = api.get("/api/work-groups")
    if status != 200:
        fail("the repository answered HTTP %s on /api/work-groups" % status)
    insider = Insider(args)
    ok, superuser = insider.sql("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
    if not ok:
        fail("cannot reach Postgres through %s: %s" % (args.pg_container, superuser))

    source_key = ensure_source(api, args.tag)
    nonce = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    h = Harness(api, insider, artifact, source_key, window, nonce)
    log("tampering with copies of %s from %s, run %s" % (artifact["file"], window["name"], nonce))

    results = []
    for test in args.only or ALL_TESTS:
        r = TESTS[test](h)
        log("%-4s %-10s %s" % (r["test"], r["outcome"], "pass" if r["passed"] else "FAIL"))
        results.append(r)

    run = {"tag": args.tag, "nonce": nonce, "window": window["name"], "artifact": artifact["file"],
           "artifactSha256": artifact["sha256"], "sourceKey": source_key,
           "databaseRoleIsSuperuser": superuser.strip() == "t",
           "finishedAt": datetime.now(timezone.utc).isoformat(), "results": results}
    out_dir = args.out or os.path.join(HERE, "results", args.tag)
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "tamper.json"), "w", encoding="utf-8") as fh:
        json.dump(run, fh, indent=2)
    md = markdown(run)
    with open(os.path.join(out_dir, "tamper.md"), "w", encoding="utf-8") as fh:
        fh.write(md)
    print(md)
    failed = [r["test"] for r in results if not r["passed"]]
    if failed:
        log("did not behave as expected: %s" % ", ".join(failed))
        sys.exit(1)


if __name__ == "__main__":
    main()
