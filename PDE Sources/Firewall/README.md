# PDE Source: Ubuntu Firewall (ufw)

Produces a **real** ufw log file for a controlled scenario, rather than a synthetic one.

## Why real traffic rather than mock lines

The experimental control and the log format are two different things, and only one of
them should be synthetic.

- **Mock generator**: you author strings shaped like ufw output. The format is your
  reconstruction from documentation, so "is this actually what ufw emits?" is a fair
  challenge and you have no answer beyond "I read the man page".
- **This script**: the *traffic* is synthetic — 10 users, 30 seconds, 10% malicious, all
  yours to control. The *log lines* are written by the kernel's netfilter LOG target as
  real packets cross the real INPUT chain. The format is authentic by construction.

The synthetic layer moves from "the evidence" (indefensible to fabricate) to "the
scenario" (exactly what a testbed is for).

This works in WSL2: `CONFIG_NETFILTER_XT_TARGET_LOG=m` with `xt_LOG.ko` present, systemd
enabled, and `rsyslogd` running with the stock `/etc/rsyslog.d/20-ufw.conf` rule.

## How it works

1. A network namespace holds one IP per simulated user (`10.99.0.11`–`10.99.0.20`),
   connected to the host by a veth pair. A "user" in a firewall log *is* a source IP, so
   each one needs a genuinely distinct address.
2. ufw is enabled with `logging full` and rules that permit the benign ports and leave
   the "sensitive" ports to the default DROP.
3. `generate_traffic.py` runs inside the namespace and opens real TCP connections on a
   seeded schedule. Benign users touch permitted ports (→ `[UFW ALLOW]`); attackers sweep
   denied ports (→ `[UFW BLOCK]`). That verdict is the only thing that makes an event
   malicious at this layer — a firewall log has no "malicious" column.
4. The window's log lines are extracted by byte offset, hashed, and set read-only.

## Usage

Normally you drive this through the CLI one level up, which adds environment checks,
attack selection and output access — see [../README.md](../README.md):

```bash
../pde doctor
../pde preview
../pde run --duration 30 --profile port-scan
```

The script is also usable directly:

```bash
./simulate-firewall.sh --dry-run          # review the firewall changes first — no root needed
sudo ./simulate-firewall.sh --users 10 --duration 30 --malicious-pct 10 \
     --attack-profile brute-force
```

Output lands in `PDE Sources/output/`:

| File | Contents |
|---|---|
| `firewall_<ts>.log` | the ufw lines, `chmod 444` — this is the evidence |
| `firewall_<ts>.manifest.json` | provenance, window bounds, counts, **sha256** |
| `firewall_<ts>.groundtruth.json` | every planned event with its label and source port |

The manifest's `sha256` is computed before anything else touches the file, per the
SecureRS ingestion rule — it is what the `EvidenceItem` should carry.

`groundtruth.json` is research metadata, not evidence: labels are known *before* the
packets are sent, so evaluation never has to infer them back out of the logs.

## Two things worth knowing

**`ufw logging full` is mandatory, not a preference.** At the default `low` (and at
`medium`/`high`) ufw rate-limits its own LOG rules to `3/min`. A 30-second window would
yield a handful of lines no matter how much traffic you generate. This is the single
easiest way to get a silently near-empty dataset.

**It touches the host firewall.** The script snapshots `/etc/ufw/user.rules`, the
`ENABLED` and `LOGLEVEL` values, and restores them on exit — including on Ctrl-C. Still:
enabling a default-deny firewall on a host running Docker can disturb container
networking while it is up (ufw sets `DEFAULT_FORWARD_POLICY=DROP`). `PRESERVE_PORTS` in
the script keeps the dev stack's ports reachable; extend it if you add services. Run
`--dry-run` first.

## Parameters

`--users`, `--duration`, `--rate`, `--malicious-pct`, `--malicious-users`, `--seed`,
`--outdir`.

`--malicious-pct` (share of *events*) and `--malicious-users` (how many *users* attack)
are independent knobs. The brief's "10%, 10:1" conflates them — 10:1 users is 9.09% of
users, which is not 10% of events. Defaults here are 1 attacker in 10 users generating
10% of events; state explicitly which one the write-up means.

`--seed` makes a run reproducible, which matters if the dataset ends up in a paper.

## Status

Verified: syntax, `--dry-run`, and the traffic generator end to end (30 events in 3.0s
against loopback, correct source-port binding and outcomes).

Not yet verified: the privileged path — namespace creation, `ufw enable`, and the log
capture itself. That needs a `sudo` run, which is the next step.
