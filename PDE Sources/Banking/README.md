# PDE Source: Banking (Apache Fineract)

The firewall and the IDS are sources any organisation has. This one only a bank has: the
core banking system itself. It is two PDE sources, because the bank keeps two different
records of the same activity:

| source | read from | answers | registered as |
|---|---|---|---|
| `banking-events` | Fineract's `external-events` Kafka topic | **what** happened — a loan disbursed, a deposit posted | `pde-sim-fineract-events-01` (`BANKING_EVENTS`) |
| `banking-audit` | `m_portfolio_command_source`, the command audit table | **who** did it, with what parameters, approved by whom | `pde-sim-fineract-audit-01` (`DB_AUDIT`) |

The split is the proposal's own. §3.5.3 warns that application logs recording only
*outcomes* cannot be traced back to a person, and the event stream is exactly that kind of
log: `LoanDisbursalBusinessEvent` says a loan went out and carries only the tenant. The
audit trail is where the login lives (§3.5.4), and §4.3.1 counts a scenario a success only
if the evidence reconstructs the attack *with attribution*. One source gives the effect,
the other the actor.

## The scenario — `loan-fraud`

The loan officer's credential has been phished. From the attacker's address in the lab
namespace, using it:

```
create-client   a new client — the mule
submit-loan     a large loan for them
approve-loan    approved by the same login
disburse-loan   and paid out
```

The chain starts between 15% and 35% into the window, with each step 8–14% of the window
after the last. So minutes of maker-checker work are done by one login in seconds.
Option 6 in the console prints the exact timings for the current seed. Meanwhile a teller makes
ordinary deposits and withdrawals for the benign users, at `--bank-rate` per second.
`none` runs the benign activity alone, as a baseline.

The same people are the same identities across every source. Each simulated user reaches
the bank from **their own address**, through the lab's bank tunnel on `10.99.0.1:8443`,
so the attacker who probes the host is the one who logs into the bank:

```
firewall   [UFW ALLOW] SRC=10.99.0.20 DPT=8443          — permitted: it looks like banking
ids        flows from 10.99.0.20 in this window's capture
audit      CREATE CLIENT / CREATE LOAN / APPROVE / DISBURSE  maker=pde_officer
events     ClientCreate, LoanCreated, LoanApproved, LoanDisbursal
```

The link between the network and the bank is **time plus identity**, not a shared field:
see "What it cannot show" below.

## How a window is collected

```
lab up --with-banking            tunnel 10.99.0.1:8443 -> Fineract on the VM
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

**Completeness is checked, not assumed.** The lab caused every transaction and knows the
id each was given, so each is looked for by an exact key: `(action, entity, resource_id,
maker)` in the audit trail, `(event type, payload id)` in the events. The manifest says
"14 of 14 operations have their audit row" and names any that do not. It also lists what
the scenario does *not* explain — anyone else using the bank in the window would appear
there, which is a finding, not noise.

## Setup

The bank must be seeded once, and again after its database is wiped:

```bash
./vm.sh seed              # or: console -> 1 PDE sources -> s
```

`fineract_seed.py` is idempotent: it enables the event types, creates the teller and loan
officer, the products, a payment type and eight customers with funded savings accounts,
and writes `Banking/seed.json` (gitignored — sandbox credentials and database ids).

Then turn the source on under option 1 of the console and start the sources.

## Output

In the window's directory, beside the firewall's:

| file | |
|---|---|
| `banking-events_<ts>.jsonl` | the evidence: decoded events, one per line, with their broker coordinates |
| `banking-audit_<ts>.jsonl` | the evidence: audit rows, one per command, with maker and checker logins |
| `banking-events_<ts>.raw.jsonl` | every message read, as the broker's own bytes — not submitted; lets the decode be checked |
| `banking_<ts>.groundtruth.json` | every operation with its label, known before sending — never submitted |
| `banking_<ts>.manifest.json` | provenance, the offsets read, how to read each timestamp, completeness, digests |

## What it cannot show

- **The bank does not record an address.** `m_portfolio_command_source.client_ip` exists
  on this build and is empty for every row. Even filled, it would show the tunnel's end,
  as a production bank behind a proxy would. Attribution in the bank is by login; the
  network identity comes from the firewall and IDS items of the same window.
- **Both staff users hold the stock *Super user* role.** A least-privilege teller could
  not approve a loan. The scenario models a phished credential with the authority to do
  so, which is what makes the missing second approver the finding.
- **`business_date` is tenant-local** (Asia/Kolkata here), so near midnight UTC it can
  name a different day. It is an accounting date, not a timestamp.
- The mule's `externalId` carries the run's start time so windows cannot collide. Its
  name and the loan amount are reproducible from the seed; that key is not.
- A user-creation command stores the new password in `command_as_json`. The collector
  redacts credential fields and marks the row `collector_redacted`, rather than changing
  it silently.

## Files

| | |
|---|---|
| `generate_banking.py` | the scenario: plan from a seed, drive the API from each user's address |
| `fineract_seed.py` | one-time, idempotent bank setup |
| `fineract_api.py` | a standard-library Fineract client that can bind a source address |
| `banking-lib.sh` | sourced by the capture: offsets, collection, fetch, digest checks |
| `collect-audit.sh` | runs on the VM: the audit trail for a window |
| `reconcile.py` | operations against evidence, by exact key |
| `build_manifest.py` | writes the banking manifest |

The events collector itself is `Fineract/Kafka_Listener/collect_window.py`, run as the
`pde-collector` service in the Fineract compose file: it has to sit inside the compose
network, because the broker advertises `kafka:9092`, and it decodes with the same pinned
schemas as the listener.
