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
2. ufw is enabled, at `logging low`, with rules that permit the benign ports and deny
   everything else from the users' subnet. Two logging rules of the lab's own record a
   verdict line for every connection the users attempt.
3. `generate_traffic.py` runs inside the namespace and opens real TCP connections on a
   seeded schedule. Benign users touch permitted ports (→ `[UFW ALLOW]`); attackers sweep
   denied ports (→ `[UFW BLOCK]`). That verdict is the only thing that makes an event
   malicious at this layer — a firewall log has no "malicious" column.
4. The window's log lines are extracted by byte offset, hashed, and set read-only.

## Usage

Normally you drive this through the console one level up, which adds the environment
check, attack selection, previews and evidence viewing — see [../README.md](../README.md):

```bash
cd .. && ./pde
```

The script stays flag-driven so runs can be scripted or reproduced without the console:

```bash
./simulate-firewall.sh --dry-run          # review the firewall changes first — no root needed
sudo ./simulate-firewall.sh --users 10 --duration 30 --attack-profile brute-force
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

**The verdict lines come from the lab's own rules, not from ufw's logging level.** ufw
limits the lines its own rules write to 3 a minute, whatever its level, so a 30-second
window would yield a handful of lines however much traffic crossed — a silently
near-empty dataset. The lab installs its own logging rules for the users' traffic, with no
limit, and leaves ufw's level at `low`. `full` is worse than useless here: it logs every
packet the machine handles, faster than the kernel's log buffer drains, and lines are lost
(measured on the research VM, where it cost windows thousands of lines).

**It touches the host firewall.** The script snapshots `/etc/ufw/user.rules`, the
`ENABLED` and `LOGLEVEL` values, and restores them on exit — including on Ctrl-C. Still:
enabling a default-deny firewall on a host running Docker can disturb container
networking while it is up (ufw sets `DEFAULT_FORWARD_POLICY=DROP`). `PRESERVE_PORTS` in
the script keeps the dev stack's ports reachable; extend it if you add services. Run
`--dry-run` first.

## Parameters

`--users`, `--duration`, `--rate`, `--malicious-pct`, `--malicious-users`,
`--attack-profile`, `--seed`, `--outdir`.

`--attack-profile` is one of `port-scan`, `brute-force`, `db-probe`, `stealth`,
`syn-burst`, `mixed`, `guaranteed-alert`. Each changes both the ports the attacker reaches for and how the
attempts are spread in time; `generate_traffic.py --list-profiles` describes them, and
`--plan-only` prints the resulting port histogram without sending anything.
`guaranteed-alert` is the exception: its ports are *permitted*, and answered by a
listener the script starts on the host, so its attempts complete and log as ALLOW.

`--malicious-pct` (share of *events*) and `--malicious-users` (how many *users* attack)
are independent knobs. The brief's "10%, 10:1" conflates them — 10:1 users is 9.09% of
users, which is not 10% of events. Defaults here are 1 attacker in 10 users generating
10% of events; state explicitly which one the write-up means.

`--seed` makes a run reproducible, which matters if the dataset ends up in a paper.

## Status

Verified without root: syntax, `--dry-run`, the traffic generator end to end (30 events
in 3.0s against loopback, correct source-port binding and outcomes), and all six attack
profiles producing distinct port distributions.

Verified with root on WSL2 (kernel `6.18.33.2-microsoft-standard-WSL2`, ufw 0.36.1): the
privileged path end to end — namespace creation, `ufw enable` at `logging full`, the
capture, and the restore on exit.

| run | lines | BLOCK | ALLOW | AUDIT |
|---|---|---|---|---|
| `20260906194400` port-scan, 10 users, 30s @ 20/s | 2595 | 60 | 540 | 1995 |
| `20260906204848` port-scan, same scenario, IDS on | 1684 | 56 | 524 | 1104 |

The verdicts reconcile exactly with the line count in both. The second run also carried
Slips over the same window and produced 3 high-severity findings, and its 4 missing
BLOCKs are explained: two attempts to 5432 reached a published Docker container through
`nat/PREROUTING`, which runs before ufw's filter chain — so ufw never saw them. That is a
real demonstration that firewall evidence alone can be incomplete.

**The failure mode to check first is rsyslog.** Stopped, the capture still runs: it
generates real traffic, restores the firewall, and extracts nothing, because there is no
`/var/log/ufw.log` to read. The console's environment check reports it. This pre-flight
costs nothing and touches no firewall state — it proves both that the daemon is up and
that the stock `20-ufw.conf` rule is filing `[UFW ` lines to the right file:

```bash
logger -p kern.info "[UFW TEST] plumbing check" && sleep 2 && grep "UFW TEST" /var/log/ufw.log
```
