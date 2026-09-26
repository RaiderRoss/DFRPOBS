#!/usr/bin/env python3
"""
Banking activity generator for the PDE banking sources.

Runs *inside* the lab's network namespace, beside generate_traffic.py, and drives the
real Fineract API through the bank tunnel on the host (HOST_IP:BANK_PORT). Each request
leaves from its user's own address, so the same person is the same IP in the firewall log
and the IDS evidence, and the same login in the bank's audit trail. It writes no evidence
itself: the bank's audit table and its event stream are the evidence, collected
afterwards on the VM. This only decides who does what, and when.

As with the firewall generator, the plan is built up front from a seed and the ground
truth is known before a single request is sent.

Profiles:
  loan-fraud   The loan officer's credential has been phished. From the attacker's address,
               using it: onboard a new client (the mule), submit a large loan for them,
               approve it and disburse it — minutes of maker-checker work done by one login
               in seconds. Benign tellers deposit and withdraw throughout.
  none         Benign activity only: the baseline.
"""

import argparse
import json
import random
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from fineract_api import DATE_FORMAT, Fineract, fineract_date

PROFILES = {
    "loan-fraud": "A phished loan-officer credential used from the attacker's address: new "
                  "client, large loan submitted, approved and disbursed by the same login "
                  "within seconds. Benign deposits and withdrawals throughout.",
    "none": "Benign deposits and withdrawals only.",
}
DEFAULT_PROFILE = "loan-fraud"

# What each operation is expected to leave behind, used to check completeness afterwards:
# the audit row Fineract writes for the command, and the event type it publishes. Event
# names are those of the pinned image; the seed enables exactly these.
EXPECT = {
    "deposit":       {"audit": ("DEPOSIT", "SAVINGSACCOUNT"), "event": "SavingsDepositBusinessEvent"},
    "withdrawal":    {"audit": ("WITHDRAWAL", "SAVINGSACCOUNT"), "event": "SavingsWithdrawalBusinessEvent"},
    "create-client": {"audit": ("CREATE", "CLIENT"), "event": "ClientCreateBusinessEvent"},
    "submit-loan":   {"audit": ("CREATE", "LOAN"), "event": "LoanCreatedBusinessEvent"},
    "approve-loan":  {"audit": ("APPROVE", "LOAN"), "event": "LoanApprovedBusinessEvent"},
    "disburse-loan": {"audit": ("DISBURSE", "LOAN"), "event": "LoanDisbursalBusinessEvent"},
}

MULE_NAMES = [("Themba", "Zulu"), ("Anele", "Mahlangu"), ("Bongani", "Sithole"),
              ("Karabo", "Mabena"), ("Musa", "Ngcobo"), ("Palesa", "Radebe")]
FRAUD_PRINCIPAL = [180000, 240000, 320000, 450000]


def utc_now():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.isoformat().replace("+00:00", "Z")


def build_plan(seed_data, users, malicious, duration, rate, profile, rng):
    benign_ips = [u for u in users if u not in malicious]
    if not benign_ips:
        raise SystemExit("every user is malicious; nothing would be benign")
    customers = seed_data["customers"]

    ops = []
    n_benign = max(0, int(round(duration * rate)))
    for _ in range(n_benign):
        c = rng.choice(customers)
        kind = "deposit" if rng.random() < 0.6 else "withdrawal"
        # Withdrawals stay small against the seeded 25,000 opening balance, and deposits
        # outweigh them, so accounts do not drain across many windows.
        amount = rng.randint(50, 2000) if kind == "deposit" else rng.randint(20, 800)
        ops.append({"kind": kind, "label": "benign", "actor": "teller",
                    "src": rng.choice(benign_ips), "customer": c["external_id"],
                    "savings_id": c["savings_id"], "amount": amount,
                    "t_offset": rng.uniform(0.0, duration * 0.95)})

    chain = None
    if profile == "loan-fraud":
        if not malicious:
            raise SystemExit("loan-fraud needs at least one malicious user")
        first, last = rng.choice(MULE_NAMES)
        # One attacker drives the whole chain: every step depends on the id the previous
        # one returned, so it is sequential by nature. Spaced a few seconds apart, as a
        # human with a script would, and started early enough to finish inside the window.
        t = rng.uniform(duration * 0.15, duration * 0.35)
        steps = []
        for kind in ("create-client", "submit-loan", "approve-loan", "disburse-loan"):
            steps.append({"kind": kind, "t_offset": min(t, duration * 0.9)})
            t += rng.uniform(duration * 0.08, duration * 0.14)
        chain = {"src": malicious[0], "actor": "officer", "label": "malicious",
                 "mule": {"firstname": first, "lastname": last},
                 "principal": rng.choice(FRAUD_PRINCIPAL), "steps": steps}
    elif profile != "none":
        raise SystemExit("unknown banking profile: %s" % profile)

    ops.sort(key=lambda o: o["t_offset"])
    return ops, chain


def run_op(api, seed_data, op, today):
    dated = {"dateFormat": DATE_FORMAT, "locale": "en"}
    body = dict(dated, transactionDate=today, transactionAmount=op["amount"],
                paymentTypeId=seed_data["payment_type_id"])
    return api.request("POST", "/savingsaccounts/%s/transactions?command=%s"
                       % (op["savings_id"], op["kind"]), body)


def run_chain(api, seed_data, chain, t0, today, run_tag, record):
    """The fraud, step by step. A step whose predecessor failed is recorded as skipped,
    never silently dropped: the ground truth must say what did not happen as well."""
    dated = {"dateFormat": DATE_FORMAT, "locale": "en"}
    client_id = loan_id = None
    failed = False
    for step in chain["steps"]:
        delay = (t0 + step["t_offset"]) - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        kind = step["kind"]
        entry = {"kind": kind, "label": "malicious", "actor": chain["actor"], "src": chain["src"],
                 "scheduled_offset": round(step["t_offset"], 3)}
        if failed:
            record(dict(entry, outcome="skipped", reason="an earlier step failed"))
            continue
        if kind == "create-client":
            m = chain["mule"]
            req = ("POST", "/clients", dict(dated, officeId=1, legalFormId=1,
                   firstname=m["firstname"], lastname=m["lastname"],
                   externalId="pde-mule-%s" % run_tag, active=True, activationDate=today))
        elif kind == "submit-loan":
            p = chain["principal"]
            req = ("POST", "/loans", dict(dated,
                   clientId=client_id, productId=seed_data["loan_product_id"], loanType="individual",
                   principal=p, loanTermFrequency=12, loanTermFrequencyType=2, numberOfRepayments=12,
                   repaymentEvery=1, repaymentFrequencyType=2, interestRatePerPeriod=1.5,
                   interestType=0, interestCalculationPeriodType=1, amortizationType=1,
                   transactionProcessingStrategyCode="mifos-standard-strategy",
                   expectedDisbursementDate=today, submittedOnDate=today))
        elif kind == "approve-loan":
            req = ("POST", "/loans/%s?command=approve" % loan_id, dict(dated, approvedOnDate=today))
        else:  # disburse-loan
            req = ("POST", "/loans/%s?command=disburse" % loan_id, dict(dated,
                   actualDisbursementDate=today, transactionAmount=chain["principal"],
                   paymentTypeId=seed_data["payment_type_id"]))
        sent = utc_now()
        sent_mono = time.monotonic()
        try:
            status, body, elapsed = api.request(*req)
        except OSError as e:
            status, body, elapsed = None, str(e), time.monotonic() - sent_mono
        ok = status is not None and 200 <= status < 300
        if ok and kind == "create-client":
            client_id = body.get("clientId") or body.get("resourceId")
        if ok and kind == "submit-loan":
            loan_id = body.get("loanId") or body.get("resourceId")
        resource = {"create-client": client_id}.get(kind, loan_id)
        record(dict(entry, sent_at=iso(sent), actual_offset=round(sent_mono - t0, 3),
                    elapsed_s=round(elapsed, 3), http_status=status,
                    outcome="ok" if ok else "failed", resource_id=resource,
                    amount=chain["principal"] if kind in ("submit-loan", "disburse-loan") else None,
                    error=None if ok else _brief(body)))
        failed = not ok


def _brief(body):
    if isinstance(body, dict):
        return (body.get("defaultUserMessage") or body.get("developerMessage") or str(body))[:200]
    return str(body)[:200]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--list-profiles", action="store_true")
    ap.add_argument("--seed-file", help="written by fineract_seed.py")
    ap.add_argument("--url", help="provider root as the namespace sees it, e.g. https://10.99.0.1:8443/fineract-provider")
    ap.add_argument("--users", help="comma-separated source IPs, one per simulated user")
    ap.add_argument("--malicious-users", default="", help="subset of --users acting maliciously")
    ap.add_argument("--duration", type=float)
    ap.add_argument("--rate", type=float, default=0.5, help="benign banking operations per second")
    ap.add_argument("--profile", default=DEFAULT_PROFILE, choices=sorted(PROFILES))
    ap.add_argument("--seed", type=int)
    ap.add_argument("--out", help="path for the ground-truth JSON")
    ap.add_argument("--plan-only", action="store_true", help="print the plan; send nothing")
    ap.add_argument("--no-bind", action="store_true",
                    help="do not bind source addresses (testing outside the namespace only)")
    args = ap.parse_args()

    if args.list_profiles:
        json.dump({"default": DEFAULT_PROFILE, "profiles": PROFILES}, sys.stdout, indent=2)
        print()
        return
    for required in ("seed_file", "users", "duration", "seed"):
        if getattr(args, required) is None:
            ap.error("--%s is required" % required.replace("_", "-"))

    with open(args.seed_file) as fh:
        seed_data = json.load(fh)
    users = [u.strip() for u in args.users.split(",") if u.strip()]
    malicious = [u.strip() for u in args.malicious_users.split(",") if u.strip()]
    if set(malicious) - set(users):
        raise SystemExit("malicious users not in user list: %s" % sorted(set(malicious) - set(users)))

    rng = random.Random(args.seed)
    ops, chain = build_plan(seed_data, users, malicious, args.duration, args.rate, args.profile, rng)

    if args.plan_only:
        kinds = {}
        for o in ops:
            kinds[o["kind"]] = kinds.get(o["kind"], 0) + 1
        json.dump({
            "profile": args.profile,
            "benign_operations": len(ops),
            "benign_by_kind": kinds,
            "fraud_chain": None if chain is None else {
                "attacker": chain["src"], "as_user": seed_data["staff"][chain["actor"]]["username"],
                "principal": chain["principal"],
                "steps": [{"kind": s["kind"], "at_s": round(s["t_offset"], 1)} for s in chain["steps"]],
            },
        }, sys.stdout, indent=2)
        print()
        return

    for required in ("url", "out"):
        if getattr(args, required) is None:
            ap.error("--%s is required" % required)

    staff = seed_data["staff"]
    tenant = seed_data.get("tenant", "default")
    today = fineract_date(datetime.now(ZoneInfo(seed_data.get("tenant_tz", "UTC"))))

    def api_for(role, src):
        s = staff[role]
        return Fineract(args.url, s["username"], s["password"], tenant,
                        source_ip=None if args.no_bind else src)

    executed = []
    lock = threading.Lock()

    def record(entry):
        with lock:
            executed.append(entry)

    def benign(op):
        sent, sent_mono = utc_now(), time.monotonic()
        try:
            status, body, elapsed = run_op(api_for("teller", op["src"]), seed_data, op, today)
        except OSError as e:
            status, body, elapsed = None, str(e), time.monotonic() - sent_mono
        ok = status is not None and 200 <= status < 300
        # resourceId is the transaction, not the account: it is what the audit row's
        # resource_id and the event payload's id both carry, so it is the exact join key.
        record({"kind": op["kind"], "label": "benign", "actor": "teller", "src": op["src"],
                "customer": op["customer"], "savings_id": op["savings_id"],
                "resource_id": body.get("resourceId") if ok and isinstance(body, dict) else None,
                "amount": op["amount"],
                "scheduled_offset": round(op["t_offset"], 3), "actual_offset": round(sent_mono - t0, 3),
                "sent_at": iso(sent), "elapsed_s": round(elapsed, 3), "http_status": status,
                "outcome": "ok" if ok else "failed", "error": None if ok else _brief(body)})

    started = utc_now()
    t0 = time.monotonic()
    # Unique per run, not per seed: the mule's externalId must not collide with the mule a
    # previous window created from the same seed. Names stay reproducible; the key cannot.
    run_tag = started.strftime("%Y%m%d%H%M%S")
    attacker = None
    if chain:
        attacker = threading.Thread(target=run_chain, args=(
            api_for(chain["actor"], chain["src"]), seed_data, chain, t0, today, run_tag, record))
        attacker.start()
    with ThreadPoolExecutor(max_workers=8) as pool:
        for op in ops:
            delay = (t0 + op["t_offset"]) - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            pool.submit(benign, op)
    if attacker:
        attacker.join()
    finished = utc_now()

    executed.sort(key=lambda e: (e.get("sent_at") or "~", e["kind"]))
    for i, e in enumerate(executed):
        e["seq"] = i
        spec = EXPECT[e["kind"]]
        e["expected_audit"] = list(spec["audit"])
        e["expected_event"] = spec["event"]
        e["username"] = staff[e["actor"]]["username"]

    ok = [e for e in executed if e["outcome"] == "ok"]
    truth = {
        "started_utc": iso(started),
        "finished_utc": iso(finished),
        "elapsed_seconds": round(time.monotonic() - t0, 3),
        "seed": args.seed,
        "profile": args.profile,
        "bank_url": args.url,
        "tenant": tenant,
        "tenant_tz": seed_data.get("tenant_tz", "UTC"),
        "business_date": today,
        "planned_operations": len(ops) + (len(chain["steps"]) if chain else 0),
        "executed_ok": len(ok),
        "failed": sum(1 for e in executed if e["outcome"] == "failed"),
        "skipped": sum(1 for e in executed if e["outcome"] == "skipped"),
        "malicious_ok": sum(1 for e in ok if e["label"] == "malicious"),
        "users": [{"ip": u, "role": "malicious" if u in malicious else "benign"} for u in users],
        "staff": {r: {"username": s["username"], "user_id": s["user_id"]} for r, s in staff.items()},
        "operations": executed,
    }
    with open(args.out, "w") as fh:
        json.dump(truth, fh, indent=2)

    print("banking: %d operations ok (%d malicious), %d failed, %d skipped in %.1fs"
          % (len(ok), truth["malicious_ok"], truth["failed"], truth["skipped"], truth["elapsed_seconds"]))
    for e in executed:
        if e["outcome"] == "failed":
            print("  failed: %s %s HTTP %s %s" % (e["kind"], e.get("src"), e["http_status"], e.get("error")),
                  file=sys.stderr)


if __name__ == "__main__":
    main()
