# PDE Sources

Simulators for the Potential Digital Evidence sources in the compliance scope, `pde`, the
console that drives them, and `submit-evidence.sh`, which hands a captured source's
evidence to the Evidence Repository.

| Source | Product | Status |
|---|---|---|
| Firewall | ufw (Ubuntu Firewall) | implemented |
| IDS/IPS | Slips | implemented — correlated with the firewall over one window; analysed on the research VM or locally |
| Banking: events | Apache Fineract | implemented — the bank's business events for the window ([Banking/](Banking/README.md)) |
| Banking: audit | Apache Fineract | implemented — the bank's command audit trail: who did it |
| Authentication | Keycloak | not built yet |

The firewall and the IDS are sources any organisation has; the banking pair is what only a
bank has. The same simulated users drive all of them over one window — the attacker who
probes the host is the one who logs into the bank with a phished credential.

A capture takes one time window, and lands in a directory of its own named for that
window. With IDS correlation on, the firewall and Slips observe **the same packets** over
it and produce independent evidence; with banking on, the bank records what those users
did. `group.json` ties them together — the record an `EvidenceGroup` row would be built
from.

Fineract, the Evidence Repository and Slips can run on a GCP VM, with the lab itself on this
machine — [Remote/README.md](Remote/README.md) covers that split, the one-time setup and
`./vm.sh`. Or everything can run on this machine, with no cloud account at all: see
[Running without the cloud](#running-without-the-cloud).

## Running without the cloud

The whole lab can run on one Linux or WSL2 machine. This is how to repeat the evaluation
without access to the research VM.

| part | what it needs |
|---|---|
| the simulated users and the firewall | Linux or WSL2, administrator rights (`sudo`), `ufw`, `rsyslog`, `iptables`, Python 3.9 or later |
| the bank's public web site | `openssl`, to make its certificate |
| the IDS | Docker, and the Slips image `stratosphereips/slips:v1.1.23` (about 6 GB) |
| the bank (optional) | Docker Compose 2.24 or later, about 2 GB of images, and about 5 GB of free memory — 7 GB with the IDS |

```bash
sudo ./lab.sh up --with-ids --local-bank      # the first time also starts and seeds the bank: allow 10 minutes
sudo Firewall/simulate-firewall.sh --attack-profile port-scan --seed 1001
sudo ./lab.sh down                            # your firewall goes back to how it was
Banking/local-bank.sh stop                    # when you have finished with the bank
```

Leave out `--local-bank` to run the network sources only (the firewall and the IDS).

The same as in the cloud: the simulated users and what they do, the attack profiles, the
bank (the same images and settings), the firewall rules, the Slips version, and the
evidence files and their manifests. Different:

- **Where the traffic is observed.** The firewall and the IDS watch it on this machine rather
  than on the bank's server. The firewall's log is in this machine's local time (its manifest
  records the offset); in the cloud both logs are in UTC.
- **One network card for ten people.** All ten simulated users share one virtual network card
  here, so Slips' check for one hardware address being used by several IP addresses is
  switched off. It cannot run in the cloud either: the tunnel carries no hardware addresses.
- **Your firewall.** While the lab is up, this machine's firewall is switched on with test
  rules. `lab.sh down` puts it back.

The dissertation's results were captured in the cloud; this reproduces the same experiment
on different equipment.

## Launch

```bash
cd "PDE Sources" && ./pde
```

The console **starts the PDE sources on launch and stops them when you quit** — on
Ctrl-C too. The sources run continuously the way a bank's would; a capture is a window
read against them, not something that switches them on and off.

Starting them modifies your firewall, so launching asks for sudo. To browse captured
evidence without any of that:

```bash
./pde --no-lab
```

```
──────────────────────────────────────────────────────────────
  PDE SOURCE CONSOLE
──────────────────────────────────────────────────────────────
  ufw inactive       rsyslog running       loglevel low
  users 10 (1 attacking)   window 30s   rate 20/s   malicious 10%
  profile port-scan   seed 1337   sources firewall + ids
  captured 3   latest 20260905143000 (612 lines, 61 BLOCK)
──────────────────────────────────────────────────────────────
  1  PDE sources              (running - view, enable, disable)
  2  Capture a window         (against the running lab)
  3  Choose attack profile
  4  Configure the scenario
  5  Preview firewall changes
  6  Preview the event plan
  7  Read evidence back
  8  Verify integrity
  s  Submit to the repository   (pick the window, then the source)
  9  Help and diagnostics
  0  Quit
```

The banner is live state, re-read on every redraw: whether the sources are up, whether
rsyslog is there to file the log lines, the current scenario, and what has been captured.

**1** lists the PDE sources with their status and lets you enable or disable them, choose
where the IDS runs, seed the bank, and start or stop the research VM. The firewall is the
base source and cannot be turned off — it owns the topology the traffic runs on. The IDS
and banking are optional; changing either while the sources are running prompts for a
restart, since every source attaches when the sources start.

## Attack profiles (option 3)

A firewall log has no "malicious" column — only a source, a destination port and a
verdict — so an attack is only ever a *shape*. Each profile changes which ports the
attacker reaches for and how attempts are spread in time:

| Profile | Shape in the log |
|---|---|
| `port-scan` | **vertical scan** — one target, many ports, down the port list |
| `brute-force` | one SRC, one DPT, many SPTs — repeated BLOCKs on 22 |
| `db-probe` | a narrow vertical scan: database ports only, deliberate |
| `stealth` | evenly spaced, maximal gaps — under rate thresholds |
| `syn-burst` | every attempt in one short spike against one port |
| `mixed` | sweep first, then sustained pressure on a single port |
| `guaranteed-alert` | **permitted** connections to ports Slips has no record of — built so the IDS raises a real alert |

The first six are **vertical** in shape, because every simulated user targets the single host
`10.99.0.1`. A **horizontal** scan is the other axis — one port swept across many hosts —
and needs several addresses on the host side of the veth, which the current topology does
not have. Slips detects both, and horizontal is one of its more reliable signatures, so
it is worth adding when the correlation needs to be richer.

`guaranteed-alert` exists to get an *alert* out of Slips, not just evidence. Slips alerts
only when one source's weighted evidence in a one-hour timewindow reaches 15, and a port
scan tops out around 5 — so the other profiles produce findings and never an alert. This
one completes connections to a handful of ports Slips has no service record for
(`ALERT_PORTS` in `lab-config.sh`), each worth 0.8, planning 38 per attacker against the
19 needed. The firewall permits them and a listener on the host answers, so the firewall
log shows `[UFW ALLOW]`: the firewall let the attack through, and only the IDS can say it
was hostile. It needs the IDS source on. The arithmetic is in
[IDS/README.md](IDS/README.md#getting-a-real-alert).

Option **6** prints the port histogram for the selected profile without sending
anything, so you can compare shapes before committing one to the dataset.

## Configuration (option 4)

Persists to `pde.conf`. `MALICIOUS_PCT` (share of *events*) and `MALICIOUS_USERS` (how
many *users* attack) are independent knobs — the brief's "10%, 10:1" conflates them, and
10:1 users is 9.09%, not 10%. The console shows the resulting event totals as you edit.

`SEED` makes a run reproducible, which matters if the dataset ends up in a paper.

## Sources lifecycle

`lab.sh` owns the standing infrastructure and the console drives it:

```
./lab.sh up --with-ids --ids-remote --with-banking
                           topology, firewall, packet capture, bank tunnel - left running
./lab.sh up --with-ids     ...or Slips locally, sniffing the veth live
./lab.sh up --with-ids --local-bank
                           ...or everything on this machine, the bank included
./lab.sh status            what is up, or whether a session was orphaned
./lab.sh down              restore the firewall, tear everything down
```

A capture detects a running lab and takes a window against it. With no lab up it falls
back to building and restoring its own — the original one-shot path, exit trap included:

```bash
sudo Firewall/simulate-firewall.sh          # uses the lab if one is up
```

**While the sources are up your firewall is enabled with test rules** (at `logging low`; the
lab's own rules log every connection the simulated users attempt).
The console restores it when you quit. If the machine reboots first, `ufw.service` is
enabled and the firewall comes back up still carrying those rules — so the console
detects the orphaned session on next launch and offers to restore it. `.lab/` holds the
backup that makes that possible, which is why it lives in the repo rather than `/tmp`
(cleared on boot) and why it is gitignored.

## IDS correlation (option 1 → enable the IDS source)

With the IDS source enabled, Slips sniffs the veth continuously while windows are
captured, so both sources observe the same packets and each writes its own evidence. This is the piece that makes
the evidence model real: one attack, one window, two independent accounts of it.

```
▲ high   new vertical port scan to IP 10.99.0.1 from 10.99.0.20.
         Total 10 TCP ports were scanned. Confidence: 1.0. by Slips
```

Slips' ~50s of start-up is paid once when the sources come up, not per capture, so a
correlated window costs `duration + drain`. See [IDS/README.md](IDS/README.md) for the
ordering constraints and why `MALICIOUS_PORTS` is deliberately wide.

## Output

One directory per captured window, named for its timestamp. The window is the unit of
evidence — an `EvidenceGroup` is exactly "these files, this window" — so the filesystem
says the same thing the group manifest does:

```
output/
  20260906204848/                  one window
    firewall.log                   the ufw lines, chmod 444 - this is the evidence
    firewall.manifest.json         provenance, window bounds, counts, sha256
    firewall.groundtruth.json      every event with its label, known before sending
    ids.alerts.log                 IDS evidence for the same window
    group.json                     both sources, shared bounds, both digests
    ids/                           Slips' working tree (one-shot captures only)
  sessions/
    ids-20260906194723/            Slips' tree for a lab session, spanning its windows
```

Names inside carry no timestamp: the directory already does.

The sha256 is computed before anything else touches the file, per the SecureRS ingestion
rule — it is what the `EvidenceItem` should carry. Option **8** recomputes it.

## Into the Evidence Repository

A capture only becomes evidence once the repository holds it.

**One `EvidenceItem` references one artifact.** A window captured with the IDS on holds
two logs from two collectors, so it becomes *two* items filed under *two* registered
sources — sent one at a time, not bundled into one upload. Option **s** asks for the
window first and then for the source within it, and `submit-evidence.sh` takes the same
two choices as flags:

```bash
./submit-evidence.sh --list                    # windows on disk, and what each holds
./submit-evidence.sh --dry-run                 # exactly what would be sent; sends nothing
./submit-evidence.sh                           # firewall log of the latest window
./submit-evidence.sh --source ids              # the IDS evidence for that same window
./submit-evidence.sh --run 20260906204848 --source ids
```

Each source registers separately — they are different collectors observing different
things, and classification is assigned per source. Registration takes a work group id and
is deliberately not automatic:

```bash
curl -u admin:admin http://localhost:8080/api/work-groups   # find the work group id
./submit-evidence.sh --source firewall --register-with <workGroupId>
./submit-evidence.sh --source ids      --register-with <workGroupId>
```

| source | artifact | digest read from | filed under |
|---|---|---|---|
| `firewall` | `firewall_<ts>.log` | `firewall_<ts>.manifest.json` | `pde-sim-ufw-01` (`FIREWALL`) |
| `ids` | `ids_<ts>.alerts.log` | `window_<ts>.group.json` | `pde-sim-slips-01` (`IDS`) |
| `banking-events` | `banking-events_<ts>.jsonl` | `window_<ts>.group.json` | `pde-sim-fineract-events-01` (`BANKING_EVENTS`) |
| `banking-audit` | `banking-audit_<ts>.jsonl` | `window_<ts>.group.json` | `pde-sim-fineract-audit-01` (`DB_AUDIT`) |

With the repository on the research VM (the default, `REPO_ON_VM=1`), the console opens
the admin tunnel itself and submits to `localhost:18080`. From the command line:
`./vm.sh tunnel up`, then `DFRAAS_URL=http://localhost:18080 ./submit-evidence.sh ...`.
Set `REPO_ON_VM=0` in `pde.conf` for a repository running locally.

What each item carries:

| manifest | becomes | |
|---|---|---|
| `window.start_utc` / `end_utc` | `eventStart` / `eventEnd` | the coverage window correlation runs along — not when we stored it |
| the recorded `sha256` | checked, never stored | the repository recomputes its own digest and compares |
| the log file | the stored object | re-hashed after storage, before any row is written |
| `firewall_<ts>` / `ids_<ts>` | `sourceArtifactId` | the dedupe key, so re-submitting one is rejected rather than preserved twice |

Both items carry the **same** `eventStart`/`eventEnd`, because both collectors observed
the same packets over the same period. That shared window is what correlation lines them
up along — the whole point of capturing from more than one source at once.

The work group is not sent: classification is inherited from the registered source, so a
collector cannot file its own output under a classification nobody assigned it.
`groundtruth.json` is not sent either — labels known before the packets left are research
metadata, and the repository has nowhere truthful to put them.

## Scripting

The console is the human front end; the simulator underneath stays flag-driven, so runs
can be scripted or reproduced without it — the same split as `slips-cli.sh` and
`slips-demo.sh`:

```bash
Firewall/simulate-firewall.sh --dry-run
sudo Firewall/simulate-firewall.sh --users 10 --duration 30 \
     --malicious-pct 10 --attack-profile brute-force --seed 1337

# firewall + IDS over one window
sudo Firewall/simulate-firewall.sh --with-ids --duration 30 --attack-profile port-scan
```

See [Firewall/README.md](Firewall/README.md) for why the logs are real rather than
synthesised, the Docker interaction, and why ufw's own logging level is not what records
the evidence, and
[IDS/README.md](IDS/README.md) for how Slips is attached to the same window.

## Note

The executable bit is recorded in git (`100755`), so a fresh clone works. It has to be
set explicitly with `git update-index --chmod=+x`, because this repo has
`core.fileMode = false` — git ignores the filesystem's mode entirely, so making a script
executable locally is invisible to it.

That same setting means editing these files from Windows can drop the local bit without
git noticing. If `./pde` gives `Permission denied`, restore it **from inside WSL** — a
`chmod` over `\\wsl.localhost` does not take:

```bash
chmod +x pde lab.sh Firewall/simulate-firewall.sh Firewall/generate_traffic.py
```

`lab-config.sh` and `IDS/slips-lib.sh` are sourced rather than run, and are deliberately
not executable.
