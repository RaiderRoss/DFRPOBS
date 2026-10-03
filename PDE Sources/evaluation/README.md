# Evaluation windows

The 24 evidence windows from the PDE lab's evaluation batch, captured on 30 September and
1 October 2026. Each folder is one **window**: 30 seconds of simulated activity at a bank, and
everything the bank's evidence sources recorded during it. These are the windows the
dissertation's results (sections 5.3.1–5.3.3) are based on.

## What happened in each window

Ten simulated people, each with their own network address, used the bank:

- **8 customers** (`10.99.0.11`–`.18`) browsed the bank's public web site and did ordinary
  online banking with their own logins: checking a balance, reading a statement, paying
  another customer.
- **The mule** (`10.99.0.19`, login `lwazi.ndlovu`) — a customer account that receives stolen
  money — applied for a large loan.
- **The attacker** (`10.99.0.20`) had stolen a loan officer's login (`pde_officer`) in an
  earlier phishing attack, which is assumed rather than simulated. They approved and paid out
  the mule's loan, and also ran one network attack against the bank's server.

The **baseline** windows have only the honest customers: no attack and no fraud.

The network attack is what the folder name says:

| attack type | what the attacker did |
|---|---|
| baseline | no attack — honest customers only |
| port-scan | tries 34 closed ports, spread over the window |
| stealth | the same 34 ports, one attempt every half second |
| db-probe | tries only the five usual database ports |
| brute-force | 60 attempts at the remote-login port (22) |
| syn-burst | the same 60 attempts at port 22, squeezed into 3 seconds |
| mixed | a sweep of closed ports, then repeated attempts at one database port |
| guaranteed-alert | 60 completed connections to ports the IDS has never heard of |

Each attack type was run three times with a different random plan (**seed** 1001, 1002 or
1003). The same seed always produces the same plan, so any window can be reproduced.

## The folders

Named `<timestamp>_<attack type>`. The timestamp is when the window opened, in UTC
(year, month, day, hour, minute, second); the files inside carry the same timestamp.

| folder | attack type | seed |
|---|---|---|
| `20260930231144_baseline` | baseline | 1001 |
| `20261001103817_baseline` | baseline | 1002 |
| `20261001110911_baseline` | baseline | 1003 |
| `20260930230812_port-scan` | port-scan | 1001 |
| `20261001103434_port-scan` | port-scan | 1002 |
| `20261001113359_port-scan` | port-scan | 1003 |
| `20261001102606_stealth` | stealth | 1001 |
| `20261001113018_stealth` | stealth | 1002 |
| `20261001114153_stealth` | stealth | 1003 |
| `20260930232604_db-probe` | db-probe | 1001 |
| `20261001105708_db-probe` | db-probe | 1002 |
| `20261001112124_db-probe` | db-probe | 1003 |
| `20260930231853_brute-force` | brute-force | 1001 |
| `20261001104937_brute-force` | brute-force | 1002 |
| `20261001113745_brute-force` | brute-force | 1003 |
| `20260930232226_syn-burst` | syn-burst | 1001 |
| `20261001105324_syn-burst` | syn-burst | 1002 |
| `20261001111735_syn-burst` | syn-burst | 1003 |
| `20261001103021_mixed` | mixed | 1001 |
| `20261001110133_mixed` | mixed | 1002 |
| `20261001114530_mixed` | mixed | 1003 |
| `20260930231520_guaranteed-alert` | guaranteed-alert | 1001 |
| `20261001104201_guaranteed-alert` | guaranteed-alert | 1002 |
| `20261001111257_guaranteed-alert` | guaranteed-alert | 1003 |

## What is in a folder

The four **evidence files** — what a bank would hand to an investigator. They are read-only.

| file | source | what it records |
|---|---|---|
| `firewall_<ts>.log` | the bank server's firewall (ufw) | every connection attempt to the server, and whether it was let in (ALLOW) or refused (BLOCK) |
| `ids_<ts>.alerts.log` | the intrusion detection system (Slips) | what the IDS found suspicious about each address, with a severity, and any alerts it raised |
| `banking-events_<ts>.jsonl` | the bank's event stream (Fineract, via Kafka) | **what** happened in the bank: loans created, approved, paid out; money moved |
| `banking-audit_<ts>.jsonl` | the bank's audit trail (Fineract) | **who** did it: which login performed each action, and when |

Supporting files:

| file | what it is |
|---|---|
| `firewall_<ts>.manifest.json`, `banking_<ts>.manifest.json` | where each source's evidence came from, how it was collected, how to read its timestamps, and its fingerprint (SHA-256 hash) |
| `window_<ts>.group.json` | ties the four sources together as one window, with every file's fingerprint |
| `firewall_<ts>.groundtruth.json`, `banking_<ts>.groundtruth.json` | the lab's own list, written before anything was sent, of every action and whether it was honest or malicious. Used to check the evidence; **not evidence itself** and never submitted |
| `banking-events_<ts>.raw.jsonl` | the message system's raw copy of the bank events, kept so the decoded file can be checked. Not submitted |

Not included, to keep the repository small (about 7 MB per window): the IDS's internal working
files — its databases and the raw network-flow records it worked from. They stay on the lab
machine.

## Checking a file has not changed

Each evidence file's fingerprint was taken the moment it was collected. To check one:

```bash
cd 20260930230812_port-scan
sha256sum firewall_20260930230812.log
grep -o '"sha256": "[0-9a-f]*"' firewall_20260930230812.manifest.json
```

The two values must match. For the other three sources the recorded fingerprint is in
`window_<ts>.group.json`. All 96 evidence files matched when this folder was made.

## Sending a window to the Evidence Repository

From `PDE Sources/`, with the repository running (it defaults to `http://localhost:8080`):

```bash
./submit-evidence.sh --outdir evaluation --list
./submit-evidence.sh --outdir evaluation --run 20260930230812_port-scan --source banking-audit --dry-run
./submit-evidence.sh --outdir evaluation --run 20260930230812_port-scan --source banking-audit
```

`--source` is one of `firewall`, `ids`, `banking-events` or `banking-audit`; one window is four
submissions. `--dry-run` shows exactly what would be sent without sending it.

## Results in brief

- **Firewall:** every one of the 14 400 connection attempts in the ground truth is in the
  firewall logs.
- **Bank:** every action that changed something (231) has its audit-trail record and all its
  events; the full fraud — the mule applies, `pde_officer` approves and pays out, with no second
  person approving — is recorded in all 21 fraud windows.
- **Fingerprints:** all 96 evidence files match.
- **IDS:** raised no alert against an honest customer in any window. It raised alerts against
  the attacker only for db-probe and guaranteed-alert; for the other attacks it recorded
  suspicious findings (including naming the port scan) but not enough within 30 seconds to
  raise an alert. It cannot see the fraud itself, which happens inside encrypted web traffic —
  only the bank's audit trail shows it.

## Limitations worth knowing

- The users are simulated, and one person ran the whole lab.
- The bank is Apache Fineract with its standard programming interface; this version has no
  separate customer-facing online-banking interface, so customers log in to the same interface
  as staff, with a restricted role.
- The loan officer's account holds every permission, so one stolen login could both approve
  and pay out the loan.
- The bank does not record the address a request came from; who-did-what comes from logins,
  and the network sources supply the addresses.
- Windows are 30 seconds long, and the IDS started fresh for each one.
