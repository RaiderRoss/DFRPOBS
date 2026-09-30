#!/usr/bin/env python3
"""
Banking activity generator for the PDE banking sources.

Runs *inside* the lab's network namespace, beside generate_traffic.py, and drives the real
Fineract API. Every request leaves from its user's own address with its user's own login,
so one person is the same IP in the firewall log and the IDS evidence and the same login in
the bank's audit trail. It writes no evidence itself: the bank's audit table and its event
stream are the evidence, collected afterwards on the VM. This only decides who does what,
and when.

As with the firewall generator, the plan is built up front from a seed and the ground truth
is known before a single request is sent.

The cast, by address (with the default ten users):
  .11 - .18  eight customers, one each, banking online with their own logins: checking a
             balance, reading a statement, paying another customer
  .19        the mule — a customer too — who applies for the loan with their own login
  .20        the attacker, holding the loan officer's credential from a phishing attack
             that happened before the window; it is used, not simulated

Profiles:
  loan-fraud   The mule applies for a large loan. Seconds later, from the attacker's address
               and as the loan officer, the application is approved and paid out — work a
               bank splits between people, done by one login. The customers bank throughout.
  none         The customers' everyday banking only: the baseline.

This build of Fineract has no self-service API, so customers call the standard API with a
restricted "PDE Customer" role (fineract_seed.py). See Banking/README.md.
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
    "loan-fraud": "The mule applies for a large loan with their own login; from another address, "
                  "the phished loan officer's login approves and disburses it within seconds. "
                  "The eight customers bank online throughout.",
    "none": "The eight customers' everyday online banking only.",
}
DEFAULT_PROFILE = "loan-fraud"

# What customers do, weighted. Reads leave nothing in the bank's evidence — only in the
# network's — and are here because looking at a balance is most of what people do online.
CUSTOMER_ACTIONS = [("check-balance", 0.35), ("view-statement", 0.25), ("transfer", 0.40)]
TRANSFER_REFERENCES = ["Rent share", "Groceries", "Lunch", "Taxi fare", "Birthday gift",
                       "Electricity", "School fees", "Airtime"]
FRAUD_PRINCIPAL = [180000, 240000, 320000, 450000]


def utc_now():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.isoformat().replace("+00:00", "Z")


def expected_evidence(kind, resource_id, from_sid=None, to_sid=None, amount=None):
    """What one successful operation should leave behind: its audit row as (action, entity),
    and each event it should publish with the payload fields that identify it.

    A transfer raises two events and neither carries the transfer's id: a withdrawal on the
    payer's account and a deposit on the payee's, each identified by account and amount.
    Reads leave nothing, and say so, rather than being counted as missing."""
    if kind in ("check-balance", "view-statement"):
        return None, []
    if kind == "transfer":
        return ["CREATE", "ACCOUNTTRANSFER"], [
            {"type": "SavingsWithdrawalBusinessEvent", "match": {"accountId": from_sid, "amount": amount}},
            {"type": "SavingsDepositBusinessEvent", "match": {"accountId": to_sid, "amount": amount}},
        ]
    audit, event = {
        "apply-loan":    (["CREATE", "LOAN"], "LoanCreatedBusinessEvent"),
        "approve-loan":  (["APPROVE", "LOAN"], "LoanApprovedBusinessEvent"),
        "disburse-loan": (["DISBURSE", "LOAN"], "LoanDisbursalBusinessEvent"),
    }[kind]
    return audit, [{"type": event, "match": {"id": resource_id}}]


def assign_addresses(users, malicious, customers):
    """Who is at which address. The mule takes the last address that is not the attacker's,
    whichever profile runs, so a customer's address does not depend on whether there is a
    fraud in the window."""
    benign = [u for u in users if u not in malicious]
    if len(benign) < 2:
        raise SystemExit("need at least two non-attacker addresses: a customer and the mule")
    mule_ip, customer_ips = benign[-1], benign[:-1]
    # One customer per address, in seed order. More addresses than customers puts one
    # customer on two devices; fewer leaves some customers idle for the window.
    return mule_ip, {ip: customers[i % len(customers)] for i, ip in enumerate(customer_ips)}


def build_plan(seed_data, customer_by_ip, mule_ip, attacker_ip, duration, rate, profile, rng):
    customers = seed_data["customers"]
    names, weights = zip(*CUSTOMER_ACTIONS)
    ips = sorted(customer_by_ip)

    ops = []
    for _ in range(max(0, int(round(duration * rate)))):
        ip = rng.choice(ips)
        c = customer_by_ip[ip]
        kind = rng.choices(names, weights)[0]
        op = {"kind": kind, "src": ip, "customer": c["external_id"],
              "t_offset": rng.uniform(0.0, duration * 0.95)}
        if kind == "transfer":
            payee = rng.choice([x for x in customers if x["external_id"] != c["external_id"]])
            op.update(payee=payee["external_id"], amount=rng.randint(20, 600),
                      reference=rng.choice(TRANSFER_REFERENCES))
        ops.append(op)

    chain = None
    if profile == "loan-fraud":
        if attacker_ip is None:
            raise SystemExit("loan-fraud needs a malicious user: the attacker")
        # Sequential by nature: approval needs the id the application returned. Spaced a few
        # seconds apart, as a person working a script would, and early enough to finish.
        t = rng.uniform(duration * 0.15, duration * 0.35)
        steps = []
        for kind, actor, src in (("apply-loan", "mule", mule_ip),
                                 ("approve-loan", "officer", attacker_ip),
                                 ("disburse-loan", "officer", attacker_ip)):
            steps.append({"kind": kind, "actor": actor, "src": src, "t_offset": min(t, duration * 0.9)})
            t += rng.uniform(duration * 0.08, duration * 0.14)
        chain = {"principal": rng.choice(FRAUD_PRINCIPAL), "steps": steps}
    elif profile != "none":
        raise SystemExit("unknown banking profile: %s" % profile)

    ops.sort(key=lambda o: o["t_offset"])
    return ops, chain


def _brief(body):
    if isinstance(body, dict):
        return (body.get("defaultUserMessage") or body.get("developerMessage") or str(body))[:200]
    return str(body)[:200]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--list-profiles", action="store_true")
    ap.add_argument("--seed-file", help="written by fineract_seed.py")
    ap.add_argument("--url", help="provider root as the namespace sees it, e.g. https://10.98.0.1:8443/fineract-provider")
    ap.add_argument("--users", help="comma-separated source IPs, one per simulated user")
    ap.add_argument("--malicious-users", default="", help="subset of --users acting maliciously; the first is the attacker")
    ap.add_argument("--duration", type=float)
    ap.add_argument("--rate", type=float, default=0.5, help="customer banking actions per second")
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
    # A seed from before customers had logins would fail every request mid-window with a 401,
    # which would read like the bank refusing customers rather than a stale file.
    if "mule" not in seed_data or not all("username" in c for c in seed_data.get("customers", [])):
        raise SystemExit("%s predates customer logins; re-seed the bank: ./vm.sh seed" % args.seed_file)

    users = [u.strip() for u in args.users.split(",") if u.strip()]
    malicious = [u.strip() for u in args.malicious_users.split(",") if u.strip()]
    if set(malicious) - set(users):
        raise SystemExit("malicious users not in user list: %s" % sorted(set(malicious) - set(users)))
    attacker_ip = malicious[0] if malicious else None

    rng = random.Random(args.seed)
    mule_ip, customer_by_ip = assign_addresses(users, malicious, seed_data["customers"])
    ops, chain = build_plan(seed_data, customer_by_ip, mule_ip, attacker_ip,
                            args.duration, args.rate, args.profile, rng)
    by_ext = {c["external_id"]: c for c in seed_data["customers"]}
    officer = seed_data["staff"]["officer"]
    mule = seed_data["mule"]

    if args.plan_only:
        kinds = {}
        for o in ops:
            kinds[o["kind"]] = kinds.get(o["kind"], 0) + 1
        json.dump({
            "profile": args.profile,
            "customers": {ip: c["username"] for ip, c in sorted(customer_by_ip.items())},
            "mule": {"ip": mule_ip, "login": mule["username"]},
            "attacker": {"ip": attacker_ip, "login": officer["username"]},
            "customer_actions": len(ops),
            "customer_actions_by_kind": kinds,
            "fraud_chain": None if chain is None else {
                "principal": chain["principal"],
                "steps": [{"kind": s["kind"], "by": s["actor"], "from": s["src"], "at_s": round(s["t_offset"], 1)}
                          for s in chain["steps"]],
            },
        }, sys.stdout, indent=2)
        print()
        return

    for required in ("url", "out"):
        if getattr(args, required) is None:
            ap.error("--%s is required" % required)

    tenant = seed_data.get("tenant", "default")
    today = fineract_date(datetime.now(ZoneInfo(seed_data.get("tenant_tz", "UTC"))))
    dated = {"dateFormat": DATE_FORMAT, "locale": "en"}

    def api(login, src):
        return Fineract(args.url, login["username"], login["password"], tenant,
                        source_ip=None if args.no_bind else src)

    executed = []
    lock = threading.Lock()

    def record(entry):
        with lock:
            executed.append(entry)

    def send(client, req, t0):
        sent, sent_mono = utc_now(), time.monotonic()
        try:
            status, body, elapsed = client.request(*req)
        except OSError as e:
            status, body, elapsed = None, str(e), time.monotonic() - sent_mono
        ok = status is not None and 200 <= status < 300
        return ok, status, body, {"sent_at": iso(sent), "actual_offset": round(sent_mono - t0, 3),
                                  "elapsed_s": round(elapsed, 3), "http_status": status,
                                  "outcome": "ok" if ok else "failed", "error": None if ok else _brief(body)}

    def customer_action(op, t0):
        c = by_ext[op["customer"]]
        payee = by_ext.get(op.get("payee"))
        if op["kind"] == "check-balance":
            req = ("GET", "/savingsaccounts/%s" % c["savings_id"])
        elif op["kind"] == "view-statement":
            req = ("GET", "/savingsaccounts/%s?associations=transactions" % c["savings_id"])
        else:
            req = ("POST", "/accounttransfers", dict(dated,
                   fromOfficeId=1, fromClientId=c["client_id"], fromAccountType=2, fromAccountId=c["savings_id"],
                   toOfficeId=1, toClientId=payee["client_id"], toAccountType=2, toAccountId=payee["savings_id"],
                   transferDate=today, transferAmount=op["amount"], transferDescription=op["reference"]))
        ok, _, body, sent = send(api(c, op["src"]), req, t0)
        # For a transfer resourceId is the transfer itself: it is what its audit row carries.
        resource = body.get("resourceId") if ok and op["kind"] == "transfer" and isinstance(body, dict) else None
        audit, events = expected_evidence(op["kind"], resource, c["savings_id"],
                                          payee["savings_id"] if payee else None, op.get("amount"))
        record(dict(sent, kind=op["kind"], label="benign", actor="customer", src=op["src"],
                    username=c["username"], customer=c["external_id"],
                    payee=payee["external_id"] if payee else None, amount=op.get("amount"),
                    reference=op.get("reference"), resource_id=resource,
                    scheduled_offset=round(op["t_offset"], 3),
                    expected_audit=audit if ok else None, expected_events=events if ok else []))

    def fraud(t0):
        """The chain, step by step, each step as its own actor from its own address. A step
        whose predecessor failed is recorded as skipped, never silently dropped: the ground
        truth must say what did not happen as well."""
        logins = {"mule": mule, "officer": officer}
        loan_id, failed = None, False
        for step in chain["steps"]:
            delay = (t0 + step["t_offset"]) - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            kind, who = step["kind"], logins[step["actor"]]
            entry = {"kind": kind, "label": "malicious", "actor": step["actor"], "src": step["src"],
                     "username": who["username"], "scheduled_offset": round(step["t_offset"], 3),
                     "expected_events": []}
            if failed:
                record(dict(entry, outcome="skipped", reason="an earlier step failed", expected_audit=None))
                continue
            if kind == "apply-loan":
                req = ("POST", "/loans", dict(dated,
                       clientId=mule["client_id"], productId=seed_data["loan_product_id"], loanType="individual",
                       principal=chain["principal"], loanTermFrequency=12, loanTermFrequencyType=2,
                       numberOfRepayments=12, repaymentEvery=1, repaymentFrequencyType=2,
                       interestRatePerPeriod=1.5, interestType=0, interestCalculationPeriodType=1,
                       amortizationType=1, transactionProcessingStrategyCode="mifos-standard-strategy",
                       expectedDisbursementDate=today, submittedOnDate=today))
            elif kind == "approve-loan":
                req = ("POST", "/loans/%s?command=approve" % loan_id, dict(dated, approvedOnDate=today))
            else:
                req = ("POST", "/loans/%s?command=disburse" % loan_id, dict(dated,
                       actualDisbursementDate=today, transactionAmount=chain["principal"],
                       paymentTypeId=seed_data["payment_type_id"]))
            ok, _, body, sent = send(api(who, step["src"]), req, t0)
            if ok and kind == "apply-loan":
                loan_id = body.get("loanId") or body.get("resourceId")
            audit, events = expected_evidence(kind, loan_id)
            record(dict(entry, **sent, resource_id=loan_id,
                        amount=chain["principal"] if kind in ("apply-loan", "disburse-loan") else None,
                        expected_audit=audit if ok else None, expected_events=events if ok else []))
            failed = not ok

    started = utc_now()
    t0 = time.monotonic()
    attacker = None
    if chain:
        attacker = threading.Thread(target=fraud, args=(t0,))
        attacker.start()
    with ThreadPoolExecutor(max_workers=8) as pool:
        for op in ops:
            delay = (t0 + op["t_offset"]) - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            pool.submit(customer_action, op, t0)
    if attacker:
        attacker.join()
    finished = utc_now()

    executed.sort(key=lambda e: (e.get("sent_at") or "~", e["kind"]))
    for i, e in enumerate(executed):
        e["seq"] = i

    ok = [e for e in executed if e["outcome"] == "ok"]
    writes = [e for e in ok if e.get("expected_audit")]
    roles = {ip: "customer" for ip in customer_by_ip}
    roles[mule_ip] = "mule"
    if attacker_ip:
        roles[attacker_ip] = "attacker"
    logins = {ip: c["username"] for ip, c in customer_by_ip.items()}
    logins[mule_ip] = mule["username"]
    if attacker_ip:
        logins[attacker_ip] = officer["username"]
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
        # What the bank should hold for this window: reads leave nothing, a transfer leaves
        # two events. The events collector waits for this many, not for executed_ok.
        "expected_audit_rows": len(writes),
        "expected_events_total": sum(len(e["expected_events"]) for e in writes),
        "reads_ok": len(ok) - len(writes),
        "failed": sum(1 for e in executed if e["outcome"] == "failed"),
        "skipped": sum(1 for e in executed if e["outcome"] == "skipped"),
        "malicious_ok": sum(1 for e in ok if e["label"] == "malicious"),
        "users": [{"ip": u, "role": roles.get(u, "idle"), "login": logins.get(u)} for u in users],
        "attacker": {"ip": attacker_ip, "login": officer["username"] if chain else None,
                     "credential": "phished before the window; used, not simulated"} if attacker_ip else None,
        "mule": {"ip": mule_ip, "login": mule["username"], "name": mule["name"],
                 "client_id": mule["client_id"], "external_id": mule["external_id"]},
        "staff": {"officer": {"username": officer["username"], "user_id": officer["user_id"]}},
        "operations": executed,
    }
    with open(args.out, "w") as fh:
        json.dump(truth, fh, indent=2)

    print("banking: %d actions ok (%d writes, %d reads; %d malicious), %d failed, %d skipped in %.1fs"
          % (len(ok), len(writes), truth["reads_ok"], truth["malicious_ok"], truth["failed"],
             truth["skipped"], truth["elapsed_seconds"]))
    for e in executed:
        if e["outcome"] == "failed":
            print("  failed: %s by %s from %s: HTTP %s %s" % (e["kind"], e.get("username"), e.get("src"),
                                                           e["http_status"], e.get("error")), file=sys.stderr)


if __name__ == "__main__":
    main()
