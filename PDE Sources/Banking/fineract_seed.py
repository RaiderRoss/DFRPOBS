#!/usr/bin/env python3
"""
Prepares a Fineract instance for the PDE banking source. Idempotent: everything is found
by a stable key (username, product name, client externalId) before it is created, so this
is safe to run again — after a database wipe it simply rebuilds.

What it sets up, and why:
  - external event types      all 131 ship disabled; with none on, Fineract publishes
                              nothing and the events source would see an empty window
  - two staff users           a teller, whose deposits and withdrawals are the benign
                              baseline, and a loan officer, whose credential the scenario
                              treats as phished. Distinct users are what let the bank's
                              audit trail attribute the fraud to a login.
  - a savings and a loan product
  - benign customers          each with an active, funded savings account, so the teller
                              has real accounts to transact against inside a window

Writes the IDs and credentials the traffic generator needs to --out (gitignored). The
credentials are fixed sandbox values, chosen to satisfy the password policy this Fineract
build enforces: 12-50 characters, upper, lower, digit, special, no repeated adjacent
characters.

  python3 fineract_seed.py --url https://127.0.0.1:18443/fineract-provider
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from fineract_api import DATE_FORMAT, Fineract, FineractError, fineract_date

# Only types that exist on the pinned image (fd8fc8929) are listed; anything this build
# does not know is reported, not silently skipped.
EVENT_TYPES = [
    "ClientCreateBusinessEvent",
    "ClientActivateBusinessEvent",
    "SavingsCreateBusinessEvent",
    "SavingsApproveBusinessEvent",
    "SavingsActivateBusinessEvent",
    "SavingsDepositBusinessEvent",
    "SavingsWithdrawalBusinessEvent",
    "LoanCreatedBusinessEvent",
    "LoanApprovedBusinessEvent",
    "LoanDisbursalBusinessEvent",
    "LoanDisbursalTransactionBusinessEvent",
    "LoanTransactionMakeRepaymentPostBusinessEvent",
]

SUPER_USER_ROLE = 1  # the stock "Super user" role; see Banking/README.md on least privilege

STAFF = {
    "teller": {"username": "pde_teller", "password": "Tlr#Pde2026bank",
               "firstname": "Thandi", "lastname": "Mokoena"},
    "officer": {"username": "pde_officer", "password": "Ofc#Pde2026loan",
                "firstname": "Sipho", "lastname": "Dlamini"},
}

SAVINGS_PRODUCT = "PDE Everyday Savings"
LOAN_PRODUCT = "PDE Personal Loan"
PAYMENT_TYPE = "PDE Cash"

# Fictional customers. Their savings accounts are what the teller transacts against.
CUSTOMERS = [
    ("Lerato", "Nkosi"), ("Johan", "van Wyk"), ("Ayesha", "Patel"), ("Kagiso", "Molefe"),
    ("Naledi", "Khumalo"), ("Pieter", "Botha"), ("Zanele", "Mthembu"), ("Ravi", "Naidoo"),
]
OPENING_BALANCE = 25000


def log(msg):
    print("  " + msg, file=sys.stderr)


def enable_events(api):
    current = api.call("GET", "/externalevents/configuration", what="list event configuration")
    items = current.get("externalEventConfiguration", current) if isinstance(current, dict) else current
    known = {i["type"]: i.get("enabled") for i in items}
    wanted = [t for t in EVENT_TYPES if t in known]
    missing = [t for t in EVENT_TYPES if t not in known]
    if missing:
        log("this Fineract has no event type(s): %s" % ", ".join(missing))
    todo = [t for t in wanted if not known[t]]
    if todo:
        api.call("PUT", "/externalevents/configuration",
                 {"externalEventConfigurations": {t: True for t in wanted}},
                 what="enable event types")
    log("event types enabled: %d (%d newly)" % (len(wanted), len(todo)))
    return wanted


def ensure_user(api, role, spec):
    users = api.call("GET", "/users", what="list users")
    found = next((u for u in users if u.get("username") == spec["username"]), None)
    if found:
        log("user %s exists (id %s)" % (spec["username"], found["id"]))
        return found["id"]
    res = api.call("POST", "/users", {
        "username": spec["username"], "firstname": spec["firstname"], "lastname": spec["lastname"],
        "email": "%s@pde.invalid" % spec["username"], "officeId": 1, "roles": [SUPER_USER_ROLE],
        "sendPasswordToEmail": False, "passwordNeverExpires": True,
        "password": spec["password"], "repeatPassword": spec["password"],
    }, what="create user %s" % spec["username"])
    log("created %s user %s (id %s)" % (role, spec["username"], res["resourceId"]))
    return res["resourceId"]


def ensure_savings_product(api):
    products = api.call("GET", "/savingsproducts", what="list savings products")
    found = next((p for p in products if p.get("name") == SAVINGS_PRODUCT), None)
    if found:
        return found["id"]
    res = api.call("POST", "/savingsproducts", {
        "name": SAVINGS_PRODUCT, "shortName": "PDES", "description": "PDE lab savings account",
        "currencyCode": "USD", "digitsAfterDecimal": 2, "inMultiplesOf": 0,
        "nominalAnnualInterestRate": 5.0, "interestCompoundingPeriodType": 4,
        "interestPostingPeriodType": 4, "interestCalculationType": 1,
        "interestCalculationDaysInYearType": 365, "accountingRule": 1,
        "withdrawalFeeForTransfers": False, "allowOverdraft": False,
        "enforceMinRequiredBalance": False, "withHoldTax": False, "locale": "en",
    }, what="create savings product")
    log("created savings product %s" % res["resourceId"])
    return res["resourceId"]


def ensure_loan_product(api):
    products = api.call("GET", "/loanproducts", what="list loan products")
    found = next((p for p in products if p.get("name") == LOAN_PRODUCT), None)
    if found:
        return found["id"]
    # The same shape Fineract/Scripts/Seeding/seed-fineract.sh has been creating.
    res = api.call("POST", "/loanproducts", {
        "name": LOAN_PRODUCT, "shortName": "PDEL", "currencyCode": "USD",
        "locale": "en_GB", "dateFormat": DATE_FORMAT, "digitsAfterDecimal": 2, "inMultiplesOf": 0,
        "principal": 10000, "minPrincipal": 1000, "maxPrincipal": 500000,
        "numberOfRepayments": 12, "repaymentEvery": 1, "repaymentFrequencyType": 2,
        "interestRatePerPeriod": 1.5, "interestRateFrequencyType": 2, "amortizationType": 1,
        "interestType": 0, "interestCalculationPeriodType": 1,
        "transactionProcessingStrategyCode": "mifos-standard-strategy", "accountingRule": 1,
        "isInterestRecalculationEnabled": False, "daysInYearType": 365, "daysInMonthType": 30,
        "loanScheduleType": "CUMULATIVE", "loanScheduleProcessingType": "HORIZONTAL",
    }, what="create loan product")
    log("created loan product %s" % res["resourceId"])
    return res["resourceId"]


def ensure_payment_type(api):
    """Deposits, withdrawals and disbursals on this build refuse a request without a
    paymentTypeId, and a fresh database has none."""
    types = api.call("GET", "/paymenttypes", what="list payment types")
    found = next((t for t in types if t.get("name") == PAYMENT_TYPE), None)
    if found:
        return found["id"]
    res = api.call("POST", "/paymenttypes", {
        "name": PAYMENT_TYPE, "description": "PDE lab cash and transfer payments",
        "isCashPayment": True, "position": 1,
    }, what="create payment type")
    log("created payment type %s" % res["resourceId"])
    return res["resourceId"]


def find_client(api, external_id):
    status, body, _ = api.request("GET", "/clients/external-id/%s" % external_id)
    if status == 200 and isinstance(body, dict):
        return body["id"]
    return None


def ensure_customer(api, idx, first, last, product_id, payment_type, today):
    ext = "pde-benign-%02d" % idx
    dated = {"dateFormat": DATE_FORMAT, "locale": "en"}
    client_id = find_client(api, ext)
    if client_id is None:
        res = api.call("POST", "/clients", dict(dated,
            officeId=1, legalFormId=1, firstname=first, lastname=last,
            externalId=ext, active=True, activationDate=today), what="create client %s" % ext)
        client_id = res["clientId"]

    accounts = api.call("GET", "/clients/%s/accounts" % client_id, what="list accounts")
    savings = next((a for a in accounts.get("savingsAccounts", [])
                    if a.get("productId") == product_id and a.get("status", {}).get("active")), None)
    if savings:
        sid = savings["id"]
    else:
        res = api.call("POST", "/savingsaccounts", dict(dated, clientId=client_id, productId=product_id,
                                                        submittedOnDate=today), what="open savings")
        sid = res["savingsId"]
        api.call("POST", "/savingsaccounts/%s?command=approve" % sid, dict(dated, approvedOnDate=today),
                 what="approve savings")
        api.call("POST", "/savingsaccounts/%s?command=activate" % sid, dict(dated, activatedOnDate=today),
                 what="activate savings")

    # Funded by balance rather than by "just opened": a run that failed between opening
    # an account and funding it must not leave a customer who can never withdraw.
    balance = (api.call("GET", "/savingsaccounts/%s" % sid, what="read balance")
               .get("summary", {}).get("accountBalance", 0)) or 0
    if balance < OPENING_BALANCE:
        api.call("POST", "/savingsaccounts/%s/transactions?command=deposit" % sid,
                 dict(dated, transactionDate=today, transactionAmount=OPENING_BALANCE - balance,
                      paymentTypeId=payment_type), what="fund savings")
    return {"external_id": ext, "client_id": client_id, "savings_id": sid, "name": "%s %s" % (first, last)}


def check_login(base, tenant, spec):
    """A user who cannot authenticate would make every command of theirs a 401 mid-window,
    which reads like an attack failing rather than a setup fault. Checked here instead."""
    api = Fineract(base, spec["username"], spec["password"], tenant)
    status, body, _ = api.request("GET", "/offices")
    return status


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", required=True, help="provider root, e.g. https://127.0.0.1:18443/fineract-provider")
    ap.add_argument("--tenant", default="default")
    ap.add_argument("--tenant-tz", default="Asia/Kolkata",
                    help="the tenant's timezone; Fineract dates are tenant-local business dates")
    ap.add_argument("--admin-user", default="mifos")
    ap.add_argument("--admin-password", default="password")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "seed.json"))
    args = ap.parse_args()

    today = fineract_date(datetime.now(ZoneInfo(args.tenant_tz)))
    admin = Fineract(args.url, args.admin_user, args.admin_password, args.tenant)
    try:
        events = enable_events(admin)
        user_ids = {role: ensure_user(admin, role, spec) for role, spec in STAFF.items()}
        savings_product = ensure_savings_product(admin)
        loan_product = ensure_loan_product(admin)
        payment_type = ensure_payment_type(admin)
        customers = [ensure_customer(admin, i + 1, f, l, savings_product, payment_type, today)
                     for i, (f, l) in enumerate(CUSTOMERS)]
    except FineractError as e:
        sys.exit("seeding failed: %s" % e)
    except OSError as e:
        sys.exit("cannot reach Fineract at %s: %s — is the admin tunnel up? (./vm.sh tunnel up)" % (args.url, e))
    log("customers ready: %d, each with a funded savings account" % len(customers))

    logins = {role: check_login(args.url, args.tenant, spec) for role, spec in STAFF.items()}
    for role, status in logins.items():
        if status != 200:
            sys.exit("the %s user cannot log in (HTTP %s)" % (role, status))
    log("both staff users authenticate")

    seed = {
        "seeded_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "tenant": args.tenant,
        "tenant_tz": args.tenant_tz,
        "event_types_enabled": events,
        "staff": {role: dict(spec, user_id=user_ids[role]) for role, spec in STAFF.items()},
        "savings_product_id": savings_product,
        "loan_product_id": loan_product,
        "payment_type_id": payment_type,
        "customers": customers,
    }
    with open(args.out, "w") as fh:
        json.dump(seed, fh, indent=2)
    os.chmod(args.out, 0o600)
    log("wrote %s" % args.out)


if __name__ == "__main__":
    main()
