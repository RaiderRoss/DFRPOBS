#!/usr/bin/env python3
"""
Prepares a Fineract instance for the PDE banking source. Idempotent: everything is found
by a stable key (username, role name, product name, client externalId) before it is
created, so this is safe to run again — after a database wipe it simply rebuilds.

What it sets up, and why:
  - external event types      all 131 ship disabled; with none on, Fineract publishes
                              nothing and the events source would see an empty window
  - one member of staff       the loan officer, whose credential the scenario treats as
                              phished. Stock "Super user" role: see Banking/README.md
  - a "PDE Customer" role     what a customer's login may do: read their accounts, move
                              money, apply for a loan. Nothing administrative
  - eight customers           each a client with a funded savings account AND a login of
                              their own, so the bank's audit trail names every customer
                              individually rather than one shared account
  - the mule                  a ninth customer, with a small account and a login, who
                              applies for the fraudulent loan

Why logins on the standard API rather than Fineract's self-service API: this build
(1.16.0-SNAPSHOT, fd8fc89) does not have one. The self-service module has been removed —
no /self endpoints, no classes in any module jar — and only its "Self Service User" role
survives in the database. The standard API does not stop a customer's login from reading
or moving another customer's money; a real bank's online-banking layer would. Stated as a
limitation in Banking/README.md.

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
# does not know is reported, not silently skipped. An account transfer raises a withdrawal
# on the payer's account and a deposit on the payee's, so the savings pair covers transfers.
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
    "officer": {"username": "pde_officer", "password": "Ofc#Pde2026loan",
                "firstname": "Sipho", "lastname": "Dlamini"},
}

# What a customer's login may do, and nothing else. Reads of their own accounts, a transfer
# to another account, and a loan application — what an online-banking customer does.
# Approving and disbursing a loan are deliberately absent: only staff can do those, which
# is why the fraud needs the phished officer.
CUSTOMER_ROLE = "PDE Customer"
CUSTOMER_PERMISSIONS = [
    "READ_CLIENT", "READ_SAVINGSACCOUNT", "READ_SAVINGSPRODUCT",
    "READ_ACCOUNTTRANSFER", "CREATE_ACCOUNTTRANSFER",
    "READ_LOAN", "READ_LOANPRODUCT", "CREATE_LOAN",
]

SAVINGS_PRODUCT = "PDE Everyday Savings"
LOAN_PRODUCT = "PDE Personal Loan"
PAYMENT_TYPE = "PDE Cash"

# Fictional customers, each with a login of their own.
CUSTOMERS = [
    ("Lerato", "Nkosi"), ("Johan", "van Wyk"), ("Ayesha", "Patel"), ("Kagiso", "Molefe"),
    ("Naledi", "Khumalo"), ("Pieter", "Botha"), ("Zanele", "Mthembu"), ("Ravi", "Naidoo"),
]
OPENING_BALANCE = 25000

# The mule: a customer like the others, with a small account, whose part in the fraud is to
# apply for the loan. Not one of the names earlier versions gave a per-run mule, so an older
# window's mule cannot be mistaken for this one.
MULE = ("Lwazi", "Ndlovu")
MULE_EXTERNAL_ID = "pde-mule"
MULE_OPENING_BALANCE = 500


def log(msg):
    print("  " + msg, file=sys.stderr)


def login_for(first, last):
    """A customer's sandbox login. The password shape satisfies this build's policy and has
    no repeated adjacent characters for any of the names above."""
    return ("%s.%s" % (first, last)).lower().replace(" ", ""), "Pde#%s2026bk" % first


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


def ensure_customer_role(api):
    roles = api.call("GET", "/roles", what="list roles")
    found = next((r for r in roles if r.get("name") == CUSTOMER_ROLE), None)
    if found:
        role_id = found["id"]
    else:
        res = api.call("POST", "/roles", {
            "name": CUSTOMER_ROLE,
            "description": "PDE lab: an online-banking customer. Own accounts, transfers, loan applications.",
        }, what="create customer role")
        role_id = res["resourceId"]
        log("created role %s (id %s)" % (CUSTOMER_ROLE, role_id))
    # Set every time rather than only on creation: it is what makes the role mean what this
    # file says it means, even if someone has edited it in the UI since.
    api.call("PUT", "/roles/%s/permissions" % role_id,
             {"permissions": {p: True for p in CUSTOMER_PERMISSIONS}},
             what="set customer role permissions")
    return role_id


def ensure_user(api, username, password, first, last, role_id):
    users = api.call("GET", "/users", what="list users")
    found = next((u for u in users if u.get("username") == username), None)
    if found:
        return found["id"]
    res = api.call("POST", "/users", {
        "username": username, "firstname": first, "lastname": last,
        "email": "%s@pde.invalid" % username, "officeId": 1, "roles": [role_id],
        "sendPasswordToEmail": False, "passwordNeverExpires": True,
        "password": password, "repeatPassword": password,
    }, what="create user %s" % username)
    log("created user %s (id %s)" % (username, res["resourceId"]))
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


def ensure_customer(api, ext, first, last, product_id, payment_type, today, balance_floor):
    """A client with one active savings account holding at least balance_floor."""
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

    # Topped up by balance rather than only on opening: customers pay each other, so across
    # many windows some accounts drift down, and a re-seed restores them.
    balance = (api.call("GET", "/savingsaccounts/%s" % sid, what="read balance")
               .get("summary", {}).get("accountBalance", 0)) or 0
    if balance < balance_floor:
        api.call("POST", "/savingsaccounts/%s/transactions?command=deposit" % sid,
                 dict(dated, transactionDate=today, transactionAmount=balance_floor - balance,
                      paymentTypeId=payment_type), what="fund savings")
    return {"external_id": ext, "client_id": client_id, "savings_id": sid, "name": "%s %s" % (first, last)}


def check_login(base, tenant, username, password, path):
    """A user who cannot authenticate would make every request of theirs a 401 mid-window,
    which reads like an attack failing rather than a setup fault. Checked here instead,
    against something each user is actually allowed to read."""
    status, _, _ = Fineract(base, username, password, tenant).request("GET", path)
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
        staff_ids = {role: ensure_user(admin, s["username"], s["password"], s["firstname"], s["lastname"],
                                       SUPER_USER_ROLE) for role, s in STAFF.items()}
        customer_role = ensure_customer_role(admin)
        savings_product = ensure_savings_product(admin)
        loan_product = ensure_loan_product(admin)
        payment_type = ensure_payment_type(admin)

        customers = []
        for i, (first, last) in enumerate(CUSTOMERS):
            c = ensure_customer(admin, "pde-benign-%02d" % (i + 1), first, last,
                                savings_product, payment_type, today, OPENING_BALANCE)
            username, password = login_for(first, last)
            c.update(username=username, password=password,
                     user_id=ensure_user(admin, username, password, first, last, customer_role))
            customers.append(c)

        mule = ensure_customer(admin, MULE_EXTERNAL_ID, MULE[0], MULE[1],
                               savings_product, payment_type, today, MULE_OPENING_BALANCE)
        username, password = login_for(*MULE)
        mule.update(username=username, password=password,
                    user_id=ensure_user(admin, username, password, MULE[0], MULE[1], customer_role))
    except FineractError as e:
        sys.exit("seeding failed: %s" % e)
    except OSError as e:
        sys.exit("cannot reach Fineract at %s: %s — is the admin tunnel up? (./vm.sh tunnel up)" % (args.url, e))
    log("customers ready: %d, each with a funded savings account and a login; mule %s ready"
        % (len(customers), mule["username"]))

    failures = []
    for role, s in STAFF.items():
        st = check_login(args.url, args.tenant, s["username"], s["password"], "/offices")
        if st != 200:
            failures.append("%s (%s): HTTP %s" % (s["username"], role, st))
    for c in customers + [mule]:
        st = check_login(args.url, args.tenant, c["username"], c["password"], "/savingsaccounts/%s" % c["savings_id"])
        if st != 200:
            failures.append("%s: HTTP %s" % (c["username"], st))
    if failures:
        sys.exit("these logins cannot read what they should:\n  " + "\n  ".join(failures))
    log("all %d logins authenticate" % (len(STAFF) + len(customers) + 1))

    seed = {
        "seeded_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "tenant": args.tenant,
        "tenant_tz": args.tenant_tz,
        "event_types_enabled": events,
        "staff": {role: dict(s, user_id=staff_ids[role]) for role, s in STAFF.items()},
        "customer_role": {"name": CUSTOMER_ROLE, "id": customer_role, "permissions": CUSTOMER_PERMISSIONS},
        "savings_product_id": savings_product,
        "loan_product_id": loan_product,
        "payment_type_id": payment_type,
        "customers": customers,
        "mule": mule,
    }
    with open(args.out, "w") as fh:
        json.dump(seed, fh, indent=2)
    os.chmod(args.out, 0o600)
    log("wrote %s" % args.out)


if __name__ == "__main__":
    main()
