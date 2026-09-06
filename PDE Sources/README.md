# PDE Sources

Simulators for the three Potential Digital Evidence sources in the compliance scope,
`pde`, the console that drives them, and `submit-evidence.sh`, which hands a captured
window to the Evidence Repository.

| Source | Product | Status |
|---|---|---|
| Firewall | ufw (Ubuntu Firewall) | implemented |
| IDS/IPS | Slips | see `Anomaly Detection/Scripts/slips-cli.sh` |
| Authentication | Keycloak | not built yet |

Each run captures one time window from one source. Three sources over the same window
are what a single evidence group should reference.

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
  profile port-scan   seed 1337
  captured 3   latest 20260905143000 (612 lines, 61 BLOCK)
──────────────────────────────────────────────────────────────
  1  Capture a window
  2  Choose attack profile
  3  Configure the scenario
  4  Preview firewall changes
  5  Preview the event plan
  6  Read evidence back
  7  Verify integrity
  s  Submit to the repository
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

## Output

Three files per run, in `output/`:

| File | |
|---|---|
| `firewall_<ts>.log` | the ufw lines, `chmod 444` — **this is the evidence** |
| `firewall_<ts>.manifest.json` | provenance, window bounds, counts, **sha256** |
| `firewall_<ts>.groundtruth.json` | every event with its label, known before sending |

The sha256 is computed before anything else touches the file, per the SecureRS ingestion
rule — it is what the `EvidenceItem` should carry. Option **7** recomputes it.

## Into the Evidence Repository

A capture only becomes evidence once the repository holds it. Option **s** submits one,
and `submit-evidence.sh` does the same thing without the console:

```bash
./submit-evidence.sh --dry-run     # exactly what would be sent; sends nothing
./submit-evidence.sh               # submit the most recent capture
./submit-evidence.sh --run 20260905143000
```

The source has to be registered once before its first upload. That is where
classification is decided, so it takes a work group id and is deliberately not automatic:

```bash
curl -u admin:admin http://localhost:8080/api/work-groups   # find the work group id
./submit-evidence.sh --register-with <workGroupId>
```

One run becomes one `EvidenceItem`:

| manifest | becomes | |
|---|---|---|
| `window.start_utc` / `end_utc` | `eventStart` / `eventEnd` | the coverage window correlation runs along — not when we stored it |
| `output.sha256` | checked, never stored | the repository recomputes its own digest and compares |
| `firewall_<ts>.log` | the stored object | re-hashed after storage, before any row is written |
| `firewall_<ts>` | `sourceArtifactId` | the dedupe key, so re-submitting a run is rejected rather than preserved twice |

The work group is not sent: classification is inherited from the registered source, so a
collector cannot file its own output under a classification nobody assigned it.
`groundtruth.json` is not sent either — labels known before the packets left are research
metadata, and the repository has nowhere truthful to put them.

The digest travels as a **claim**. This script re-checks the file locally before sending,
so a log that changed since capture is caught here as a local finding rather than looking
like a transport failure; the repository then recomputes the digest from the bytes that
actually arrive, stores only its own value, and rejects a mismatch as a 422 with nothing
preserved. Those two checks are what make "nothing happened to this file between capture
and preservation" a verified statement rather than an assumption.

Defaults are `http://localhost:8080`, source key `pde-sim-ufw-01` and `admin:admin`.
Override them with `DFRAAS_URL`, `DFRAAS_SOURCE_KEY` and `DFRAAS_AUTH` in `pde.conf` —
the backend runs on the host in some setups and inside WSL in others, and `localhost`
does not always mean the same machine. Option **9** reports whether the repository
answers and whether the source is registered.

## Scripting

The console is the human front end; the simulator underneath stays flag-driven, so runs
can be scripted or reproduced without it — the same split as `slips-cli.sh` and
`slips-demo.sh`:

```bash
Firewall/simulate-firewall.sh --dry-run
sudo Firewall/simulate-firewall.sh --users 10 --duration 30 \
     --malicious-pct 10 --attack-profile brute-force --seed 1337
```

See [Firewall/README.md](Firewall/README.md) for why the logs are real rather than
synthesised, the Docker interaction, and why `ufw logging full` is mandatory.

## Note

If you edit these scripts from Windows rather than inside WSL, the executable bit can be
dropped. Restore it **from inside WSL** (a `chmod` over `\\wsl.localhost` does not take):

```bash
chmod +x pde submit-evidence.sh Firewall/simulate-firewall.sh Firewall/generate_traffic.py
```
