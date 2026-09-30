# PDE Source: Banking (Apache Fineract)

The firewall and the IDS are sources any organisation has. This one only a bank has: the
core banking system itself. It is two PDE sources, because the bank keeps two different
records of the same activity:

| source | read from | answers | registered as |
|---|---|---|---|
| `banking-events` | Fineract's `external-events` Kafka topic | **what** happened — a loan disbursed, money transferred | `pde-sim-fineract-events-01` (`BANKING_EVENTS`) |
| `banking-audit` | `m_portfolio_command_source`, the command audit table | **who** did it, with what parameters, approved by whom | `pde-sim-fineract-audit-01` (`DB_AUDIT`) |

The split is the proposal's own. §3.5.3 warns that application logs recording only
*outcomes* cannot be traced back to a person, and the event stream is exactly that kind of
log: `LoanDisbursalBusinessEvent` says a loan went out and carries only the tenant. The
audit trail is where the login lives (§3.5.4), and §4.3.1 counts a scenario a success only
if the evidence reconstructs the attack *with attribution*. One source gives the effect,
the other the actor.

## The cast

Every person is one address in the lab's namespace and one login at the bank, so they are
the same identity in the firewall log, the IDS evidence and the audit trail:

| address | who | bank login | does |
|---|---|---|---|
| `.11` – `.18` | eight customers | their own (`lerato.nkosi`, `johan.vanwyk`, …) | online banking: check a balance, read a statement, pay another customer |
| `.19` | the mule — a customer too | `lwazi.ndlovu` | applies for the loan |
| `.20` | the attacker | `pde_officer`, phished | approves the loan and pays it out |

Customers hold a restricted **PDE Customer** role: they can read accounts, transfer money
and apply for a loan, and nothing else. Seeding checks the boundary both ways — a customer
can apply for a loan, and is refused (HTTP 403) approving one. That is why the fraud needs
the loan officer's credential at all.

## The scenario — `loan-fraud`

The loan officer's credential was phished **before** the window. The phishing is not
simulated; using the credential is.

```
apply-loan      the mule applies for a large loan, with their own login, from .19
approve-loan    the attacker approves it as pde_officer, from .20
disburse-loan   and pays it out, as pde_officer, from .20
```

The application comes between 15% and 35% into the window, each step 8–14% of the window
after the last, so an approval that takes a bank days happens within seconds. Meanwhile
the customers bank as usual, at `--bank-rate` actions per second. `none` runs the
customers alone, as a baseline.

What a window shows, measured:

```
audit      CREATE LOAN by lwazi.ndlovu → APPROVE, DISBURSE by pde_officer, same loan id, no checker
events     LoanCreated, LoanApproved, LoanDisbursal
firewall   .20 blocked on dozens of ports, then permitted to the bank
ids        vertical port scan from .20
```

The fraud spans **two addresses and two logins**. The audit trail joins them by the loan's
id; the network sources place each at its address at the same moments. The link between the
network and the bank is **time plus identity**, not a shared field: see "What it cannot
show".

## How a window is collected

```
lab up --with-banking           the bank reachable from the namespace
  capture:
    offsets                      the topic's end offsets, before the window opens
    WINDOW  generate_banking.py  in the namespace, beside generate_traffic.py
    collect (on the VM)          events: trigger the publish job, read from the offsets,
                                          keep what has createdAt inside the window
                                 audit:  rows with made_on_date_utc inside the window
    fetch + verify               each file hashed on the VM, re-hashed here
    reconcile                    every operation looked for in both artifacts
```

**Two clocks, and only one bounds the window.** Fineract stages events and a scheduled
job publishes them every minute, so a Kafka timestamp says when the job ran, not when the
money moved. Offsets bound what is *read*; the envelope's `createdAt` decides what is
*kept*. The collector triggers the publish job instead of waiting out its tick — that
moves when events are sent, never their `createdAt`.

**Completeness is checked, not assumed.** The lab caused every transaction and knows what
each should have left behind, so each is looked for by an exact key:

| operation | audit row | events |
|---|---|---|
| transfer | `CREATE ACCOUNTTRANSFER`, the transfer's id, the customer | a withdrawal on the payer's account and a deposit on the payee's, matched by account and amount — neither carries the transfer's id |
| apply / approve / disburse | `CREATE` / `APPROVE` / `DISBURSE LOAN`, the loan's id, the login | `LoanCreated` / `LoanApproved` / `LoanDisbursal`, the loan's id |
| balance, statement | none | none — a read changes nothing, so it is counted, not reported missing |

The manifest says "8 of 8 operations that change something have their audit row" and
names any that do not. It also lists what the scenario does *not* explain — anyone else
using the bank in the window would appear there, which is a finding, not noise.

## Setup

The bank must be seeded once, and again after its database is wiped:

```bash
./vm.sh seed              # or: console -> 1 PDE sources -> s
```

`fineract_seed.py` is idempotent: it enables the event types, creates the loan officer,
the PDE Customer role, the products, a payment type, the eight customers and the mule —
each a client with a funded savings account and a login of their own — and checks every
login can read what it should. It writes `Banking/seed.json` (gitignored — sandbox
credentials and database ids). A `seed.json` from before customers had logins is refused
by the generator with a message saying to re-seed.

## Output

In the window's directory, beside the firewall's:

| file | |
|---|---|
| `banking-events_<ts>.jsonl` | the evidence: decoded events, one per line, with their broker coordinates |
| `banking-audit_<ts>.jsonl` | the evidence: audit rows, one per command, with maker and checker logins |
| `banking-events_<ts>.raw.jsonl` | every message read, as the broker's own bytes — not submitted; lets the decode be checked |
| `banking_<ts>.groundtruth.json` | every operation with its label, actor and login, known before sending — never submitted |
| `banking_<ts>.manifest.json` | provenance, the cast, the offsets read, how to read each timestamp, completeness, digests |

## What it cannot show

- **There is no self-service API.** This Fineract build (1.16.0-SNAPSHOT, `fd8fc89`) has no
  `/self` endpoints and no self-service classes in any module; only the old "Self Service
  User" role survives in the database. Customers therefore use the standard API with their
  own logins. Nothing in it stops a customer's login from reading or moving another
  customer's money — a real bank's online-banking layer would enforce that. Every action is
  still attributed to the customer who took it.
- **The loan officer holds the stock *Super user* role**, so one phished login can both
  approve and disburse. A bank would split those between people; the missing second approver
  (`checker_username` null) is the finding. Stated as a limitation of the scenario.
- **The phishing is not simulated.** The credential is assumed stolen before the window.
- **The bank does not record an address.** `m_portfolio_command_source.client_ip` exists
  on this build and is empty for every row. Even filled, it would show the relay or proxy in
  front of the bank, as a production bank's would. Attribution in the bank is by login; the
  network identity comes from the firewall and IDS items of the same window.
- **The mule applies in every fraud window**, so earlier windows' loans to the same client
  exist. This window's is the one whose id the ground truth records.
- **`business_date` is tenant-local** (Asia/Kolkata here), so near midnight UTC it can
  name a different day. It is an accounting date, not a timestamp.
- A user-creation command stores the new password in `command_as_json`. The collector
  redacts credential fields and marks the row `collector_redacted`, rather than changing
  it silently.

## Files

| | |
|---|---|
| `generate_banking.py` | the cast and the scenario: plan from a seed, drive the API from each person's address with their login |
| `fineract_seed.py` | one-time, idempotent bank setup: staff, the customer role, customers, the mule |
| `fineract_api.py` | a standard-library Fineract client that can bind a source address |
| `banking-lib.sh` | sourced by the capture: offsets, collection, fetch, digest checks |
| `collect-audit.sh` | runs on the VM: the audit trail for a window |
| `reconcile.py` | operations against evidence, by exact key |
| `build_manifest.py` | writes the banking manifest |

The events collector itself is `Fineract/Kafka_Listener/collect_window.py`, run as the
`pde-collector` service in the Fineract compose file: it has to sit inside the compose
network, because the broker advertises `kafka:9092`, and it decodes with the same pinned
schemas as the listener.
