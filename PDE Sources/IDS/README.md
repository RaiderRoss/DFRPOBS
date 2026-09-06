# PDE Source: IDS (Slips)

Slips observes the same packets the firewall logs, over the same window, so one attack
produces two independent accounts of itself.

## How it joins the firewall capture

Slips runs `--net=host`, so it can sniff the veth that `simulate-firewall.sh` creates.
No separate traffic is generated for it — it watches the firewall run:

```
netns + veth created
  └─ Slips starts on veth-pde-h, loads modules      ~46s on this machine
       └─ ufw rules applied, logging full
            └─ WINDOW: traffic generated             30s
                 └─ ufw log extracted by byte offset
            └─ Slips drains, then stops              45s
                 └─ evidence sliced to the window
```

The ordering is not incidental:

- **Slips starts before the window**, because it loads 15 modules and 45+ threat-intel
  feeds before reading a single packet. A window opened during startup is not observed.
- **ufw is configured after Slips is ready**, so `logging full` is active for the window
  rather than for the two minutes Slips spends starting.
- **Slips is drained after the window**, because it raises evidence in batches once it
  has seen the flows. Collecting the instant the window closes reliably gets an empty
  file.
- **Slips is stopped before its files are read.** `alerts.log` is appended to while it
  runs, and evidence should not be collected from a moving target.

## Usage

```bash
../pde                      # option 3 -> 7 turns IDS correlation on, then option 1
```

Or directly:

```bash
sudo ../Firewall/simulate-firewall.sh --with-ids --duration 30 --attack-profile port-scan
```

## What it detects

Verified against a 35-port vertical scan:

```
▲ high   new vertical port scan to IP <target> from <attacker>.
         Total 10 TCP ports were scanned. Confidence: 1.0. by Slips
```

Slips' vertical-scan threshold sits at around **10 distinct ports** to one host inside a
timewindow. That is why `MALICIOUS_PORTS` in the firewall simulator is deliberately wide
(35 ports): the firewall records a BLOCK however few ports are touched, but a thin port
list leaves the IDS silent about an attack the firewall logged plainly — which is the
opposite of the correlation this exists to demonstrate.

Alongside the scan finding, Slips emits one `info` line per connection
(`Connecting to private IP ... on destination port: N`). Those are context, not
accusations; `slips-format.py --brief` collapses them so the findings that matter stay
visible.

Only vertical scans are reachable in the current topology, since every simulated user
targets one host. Horizontal scans and ICMP sweeps — two of Slips' most reliable
detections — need several host-side addresses on the veth.

## Output

| File | |
|---|---|
| `ids_<ts>.alerts.log` | evidence sliced to the window, `chmod 444` |
| `ids_<ts>/` | Slips' full working tree, including `zeek_files/conn.log` |
| `window_<ts>.group.json` | both sources, the shared window, and both digests |

`conn.log` is kept deliberately: it is the flow record the findings were derived from,
and "on what basis" is a question an investigation will ask.

## Two things to know

**Slips' timewindows are its own.** It profiles per source IP in 1-hour timewindows and
its alert threshold (0.25 by default) accumulates across that hour, not across our 30
seconds. Our slice by timestamp bounds the *evidence lines*; it does not change how
Slips decided to raise them.

**It will not share the port with the lab console.** `slips-cli.sh` runs containers
named `slips`/`slips-redis` and binds 6379 with `--net=host`; this uses `pde-slips` /
`pde-slips-redis`. Preflight refuses to start if the lab console is up, rather than
fighting over the port.
