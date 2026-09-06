# PDE Sources

Simulators for the three Potential Digital Evidence sources in the compliance scope, and
`pde`, the console that drives them.

| Source | Product | Status |
|---|---|---|
| Firewall | ufw (Ubuntu Firewall) | implemented |
| IDS/IPS | Slips | implemented — correlated with the firewall over one window |
| Authentication | Keycloak | not built yet |

A capture takes one time window. With IDS correlation on, the firewall and Slips observe
**the same packets** over that window and produce independent evidence, tied together by
`window_<ts>.group.json` — the record an `EvidenceGroup` row would be built from.

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
  9  Help and diagnostics
  0  Quit
```

The banner is live state, re-read on every redraw: whether the sources are up, whether
rsyslog is there to file the log lines, the current scenario, and what has been captured.

**1** lists the three PDE sources with their status and lets you enable or disable them.
The firewall is the base source and cannot be turned off — it owns the topology the
traffic runs on. The IDS is optional; toggling it while the sources are running prompts
for a restart, since Slips attaches to the interface at start-up.

## Attack profiles (option 3)

A firewall log has no "malicious" column — only a source, a destination port and a
verdict — so an attack is only ever a *shape*. Each profile changes which ports the
attacker reaches for and how attempts are spread in time:

| Profile | Shape in the log |
|---|---|
| `port-scan` | one SRC, many different DPTs — a wide BLOCK fan-out |
| `brute-force` | one SRC, one DPT, many SPTs — repeated BLOCKs on 22 |
| `db-probe` | database ports only — narrow and deliberate |
| `stealth` | evenly spaced, maximal gaps — slips rate thresholds |
| `syn-burst` | every attempt in one short spike against one port |
| `mixed` | sweep first, then sustained pressure on a single port |

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
./lab.sh up --with-ids     topology, firewall, and Slips - left running
./lab.sh status            what is up, or whether a session was orphaned
./lab.sh down              restore the firewall, tear everything down
```

A capture detects a running lab and takes a window against it. With no lab up it falls
back to building and restoring its own — the original one-shot path, exit trap included:

```bash
sudo Firewall/simulate-firewall.sh          # uses the lab if one is up
```

**While the sources are up your firewall is enabled with test rules and `LOGLEVEL=full`.**
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

Per captured window, in `output/`:

| File | |
|---|---|
| `firewall_<ts>.log` | the ufw lines, `chmod 444` — **this is the evidence** |
| `firewall_<ts>.manifest.json` | provenance, window bounds, counts, **sha256** |
| `firewall_<ts>.groundtruth.json` | every event with its label, known before sending |
| `ids_<ts>.alerts.log` | Slips evidence for the same window (IDS correlation on) |
| `ids_<ts>/` | Slips' working tree, including `zeek_files/conn.log` |
| `window_<ts>.group.json` | both sources, shared window bounds, both digests |

The sha256 is computed before anything else touches the file, per the SecureRS ingestion
rule — it is what the `EvidenceItem` should carry. Option **8** recomputes it.

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
synthesised, the Docker interaction, and why `ufw logging full` is mandatory, and
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
