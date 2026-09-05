# PDE Sources

Simulators for the three Potential Digital Evidence sources the compliance scope names,
plus `pde`, the CLI that drives them.

| Source | Product | Status |
|---|---|---|
| Firewall | ufw (Ubuntu Firewall) | implemented |
| IDS/IPS | Slips | not built yet |
| Authentication | Keycloak | not built yet |

Each run captures one time window from one source. Three sources over the same window
are what a single `EvidenceItem` group should reference.

## Quick start

```bash
./pde doctor      # can this machine actually capture ufw logs?
./pde preview     # what a run would do — no root, no packets, nothing changed
./pde run         # run it (prompts for confirmation, then sudo)
./pde show latest # what came out
```

## Commands

**Simulation**

| Command | |
|---|---|
| `pde sources` | list PDE sources and what is implemented |
| `pde run [SOURCE]` | run a simulation (default: firewall) |
| `pde attacks` | attack profiles, and how each looks in the log |
| `pde preview` | firewall changes + event plan, without touching anything |

**Captured output**

| Command | |
|---|---|
| `pde ls` | list captured runs |
| `pde show [RUN]` | run summary; `--log` for colourised lines, `--truth` for labels |
| `pde verify [RUN]` | re-hash the log and check it against the manifest |
| `pde path [RUN]` | print file paths, one per line (pipe-friendly) |
| `pde clean` | delete captured runs |

**Setup**

| Command | |
|---|---|
| `pde doctor` | check the environment can actually capture logs |
| `pde config` | show or change defaults |
| `pde help [COMMAND]` | overview, or detail for one command |

`RUN` is a run id (`20260905143000`) or `latest`, which is the default.

## Attack profiles

Selected with `--profile`. A firewall log has no "malicious" column — only a source, a
destination port and a verdict — so an attack is only ever a *shape*. Each profile
changes which ports the attacker reaches for and how attempts are spread in time:

| Profile | Shape in the log |
|---|---|
| `port-scan` | one SRC, many different DPTs, spread across the window (default) |
| `brute-force` | one SRC, one DPT, many distinct SPTs |
| `db-probe` | database ports only — narrow and deliberate |
| `stealth` | evenly spaced with maximal gaps, under rate-based thresholds |
| `syn-burst` | everything compressed into a short spike against one port |
| `mixed` | sweep first, then sustained pressure on one port |

`pde preview --profile X` prints the port histogram, so you can see the shape before
generating anything. `mixed` at 30s, for instance, produces 2–3 attempts on each scanned
port plus ~26 on the one it settles on.

## Configuration

Defaults live in `pde.conf` (created on first `pde config set`) and are overridden by
flags on any individual run.

```bash
pde config show
pde config set DURATION 60
pde config set ATTACK_PROFILE stealth
```

Keys: `USERS`, `DURATION`, `RATE`, `MALICIOUS_PCT`, `MALICIOUS_USERS`,
`ATTACK_PROFILE`, `SEED`, `OUTDIR`.

`MALICIOUS_PCT` (share of *events*) and `MALICIOUS_USERS` (how many *users* attack) are
independent knobs — see [Firewall/README.md](Firewall/README.md) on why the brief's
"10%, 10:1" needs disambiguating before it goes in a write-up.

## Output

Three files per run, in `output/`:

| File | |
|---|---|
| `firewall_<ts>.log` | the ufw lines, `chmod 444` — **this is the evidence** |
| `firewall_<ts>.manifest.json` | provenance, window bounds, counts, **sha256** |
| `firewall_<ts>.groundtruth.json` | every event with its label, known before sending |

The manifest's `sha256` is computed before anything else touches the file, per the
SecureRS ingestion rule — it is what the `EvidenceItem` should carry. `pde verify`
recomputes it.

## Notes

`pde run` modifies the host firewall for the duration of the window and restores it on
exit, including on Ctrl-C. It confirms before doing so; `pde preview` shows the exact
changes first. See [Firewall/README.md](Firewall/README.md) for the Docker interaction
and why `ufw logging full` is mandatory rather than a preference.

If you edit these scripts from Windows rather than inside WSL, the executable bit can be
dropped — `chmod +x pde Firewall/*.sh Firewall/*.py` restores it.
