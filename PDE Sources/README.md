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

```
──────────────────────────────────────────────────────────────
  PDE SOURCE CONSOLE
──────────────────────────────────────────────────────────────
  ufw inactive       rsyslog running       loglevel low
  users 10 (1 attacking)   window 30s   rate 20/s   malicious 10%
  profile port-scan   seed 1337   sources firewall + ids
  captured 3   latest 20260905143000 (612 lines, 61 BLOCK)
──────────────────────────────────────────────────────────────
  1  Capture a window
  2  Choose attack profile
  3  Configure the scenario
  4  Preview firewall changes
  5  Preview the event plan
  6  Read evidence back
  7  Verify integrity
  8  How firewall evidence works
  9  Environment check
  0  Quit
```

The banner is live state, re-read on every redraw: whether ufw is active, whether
rsyslog is up to file the log lines, the current scenario, and what has been captured.

Start with **9** (environment check) and **4**/**5** (previews) — none of them touch
anything. **1** is the only option that modifies the host.

## Attack profiles (option 2)

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

Option **5** prints the port histogram for the selected profile without sending
anything, so you can compare shapes before committing one to the dataset.

## Configuration (option 3)

Persists to `pde.conf`. `MALICIOUS_PCT` (share of *events*) and `MALICIOUS_USERS` (how
many *users* attack) are independent knobs — the brief's "10%, 10:1" conflates them, and
10:1 users is 9.09%, not 10%. The console shows the resulting event totals as you edit.

`SEED` makes a run reproducible, which matters if the dataset ends up in a paper.

## IDS correlation (option 3 → 7)

With it on, Slips sniffs the veth while the firewall window runs, so both sources
observe the same packets and each writes its own evidence. This is the piece that makes
the evidence model real: one attack, one window, two independent accounts of it.

```
▲ high   new vertical port scan to IP 10.99.0.1 from 10.99.0.20.
         Total 10 TCP ports were scanned. Confidence: 1.0. by Slips
```

A correlated run costs about `60 + duration + drain` seconds — most of it Slips loading
its modules before the window can open. See [IDS/README.md](IDS/README.md) for the
ordering constraints and why `MALICIOUS_PORTS` is deliberately wide.

## Output

Three files per run, in `output/`:

| File | |
|---|---|
| `firewall_<ts>.log` | the ufw lines, `chmod 444` — **this is the evidence** |
| `firewall_<ts>.manifest.json` | provenance, window bounds, counts, **sha256** |
| `firewall_<ts>.groundtruth.json` | every event with its label, known before sending |
| `ids_<ts>.alerts.log` | Slips evidence for the same window (IDS correlation on) |
| `ids_<ts>/` | Slips' working tree, including `zeek_files/conn.log` |
| `window_<ts>.group.json` | both sources, shared window bounds, both digests |

The sha256 is computed before anything else touches the file, per the SecureRS ingestion
rule — it is what the `EvidenceItem` should carry. Option **7** recomputes it.

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

If you edit these scripts from Windows rather than inside WSL, the executable bit can be
dropped. Restore it **from inside WSL** (a `chmod` over `\\wsl.localhost` does not take):

```bash
chmod +x pde Firewall/simulate-firewall.sh Firewall/generate_traffic.py IDS/slips-lib.sh
```
