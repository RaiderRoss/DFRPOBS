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
            └─ alerts.log byte offset recorded
                 └─ WINDOW: traffic generated        30s
                 └─ ufw log read from its offset
            └─ Slips drains                          45s
                 └─ alerts read from their offset, while Slips still runs
       └─ Slips stopped — teardown, the veth is going away
```

The ordering is not incidental:

- **Slips starts before the window**, because it loads 15 modules and 45+ threat-intel
  feeds before reading a single packet. A window opened during startup is not observed.
- **ufw is configured after Slips is ready**, so `logging full` is active for the window
  rather than for the two minutes Slips spends starting.
- **Slips is drained after the window**, because it raises evidence in batches once it
  has seen the flows. Collecting the instant the window closes reliably gets an empty
  file.
- **Slips is never stopped in order to be read.** An IDS is a continuously running
  system that gets *read against*; no bank halts one to collect from it, and modelling
  it that way would carry the wrong assumption into the Evidence Repository's ingestion
  design. Consistency comes from a byte offset recorded before the window plus the
  timestamp slice — the same mechanism the ufw capture uses while `rsyslog` keeps
  writing underneath it. A trailing fragment without its newline is a write still in
  flight, so it is left for the next read rather than recorded as a finding.
  Slips is stopped afterwards only because the veth it is attached to is being
  destroyed with the rest of the run.

## Remote mode — the sensor here, the analysis on the research VM

The default now (`IDS_REMOTE=1`), because Slips is the heaviest thing in the lab and the
research VM has room for it:

```
lab up --with-ids --ids-remote
  └─ tcpdump -U on veth-pde-h → output/sessions/ids-<ts>/veth.pcap      all session
capture:
  └─ pcap byte offset recorded
       └─ WINDOW
       └─ the window's packets sliced out by that offset → ids_<ts>.pcap, hashed
            └─ shipped to the VM, `slips.py -f` over it, output tree brought home
```

The slice uses the same mechanism as the ufw log. A packet belongs to the window if its
record *starts* after the offset. A record still being written at the end is left for the
next window, whole, rather than split across two. The packets keep the timestamps this
machine's kernel gave them, on the same clock as the window bounds and the firewall log, so
the IDS evidence lines up with both without correction. Measured: 740 packets analysed in
63 s, 21 alerts.

What this mode changes is the principle below that Slips is never stopped to be read.
**The sensor is never stopped; the analysis is per window.** Slips starts fresh for each
window, so its per-source profile and alert threshold do not carry over between windows as
they do for a Slips sniffing continuously. An alert in remote mode was earned inside that
window alone. The group manifest says which mode produced it.

Slips caches ~45 threat-intel feeds in redis on the VM. A run against an empty cache
downloads them all first — 7 minutes, measured — and a VM stop empties it, so the VM
re-warms the cache after every start (`Remote/slips-warm.sh`). Set `IDS_REMOTE=0` in
`pde.conf` to run Slips locally in Docker, as described below.

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

Inside the captured window's own directory, `output/<ts>/`:

| File | |
|---|---|
| `ids_<ts>.alerts.log` | evidence sliced to the window, `chmod 444` |
| `ids_<ts>.pcap` | remote mode: the packets Slips analysed, hashed before they left |
| `window_<ts>.group.json` | every source, the shared window, and every digest |
| `ids_<ts>/` | Slips' full working tree — remote mode and one-shot captures |

Under a lab, Slips spans many windows, so its working tree lives once per session at
`output/sessions/ids-<lab-ts>/` rather than being copied into each window.

`conn.log` is kept deliberately: it is the flow record the findings were derived from,
and "on what basis" is a question an investigation will ask.

## Getting a real alert

Evidence is not an alert. Slips raises an alert only when one source's weighted evidence
inside one timewindow reaches `detection_threshold × width / 60` — `0.25 × 3600 / 60 = 15`
with its defaults — where each finding weighs its threat level (`info 0`, `low 0.2`,
`medium 0.5`, `high 0.8`, `critical 1`) times its confidence. The port scan above peaks at
about 5.4 for the attacker, so it yields findings and can never yield an alert.

The `guaranteed-alert` profile is built from that arithmetic, read out of Slips' source:

| | |
|---|---|
| finding | `Connection to unknown destination port` — HIGH if the connection was **established**, MEDIUM if not, confidence 1.0, once per connection |
| weight | 0.8 per completed connection |
| needed | ⌈15 / 0.8⌉ = **19** completed connections per attacker |
| planned | **38** per attacker, shared out evenly across attackers |
| ports | `ALERT_PORTS` in `lab-config.sh` — none in Slips' `services.csv` or its organisation port list |

Two conditions make it hold, and the lab provides both. The connections must
**complete**, so the ports are permitted from the subnet and a listener on the host
accepts and closes each one. And there must be **five or fewer** distinct ports: the
vertical-scan detector marks a source a port scanner above five, and a marked scanner has
its unknown-port evidence suppressed — the very findings the alert is built from.

The ground truth's `alert_guarantee` records `completed_per_attacker` and
`traffic_sufficient`, which say whether the *traffic* delivered. Whether Slips *alerted*
is its own output: `alerts` in the group manifest counts its verdict lines —

```
<iso>: Src IP 10.99.0.20                . Generated an alert given enough evidence on timewindow 1. (real time <iso>)
```

An alert resets that source's total to zero, and evidence already inside an alert is not
counted again, so each capture has to cross the threshold on its own. This profile does
so per window.

## Two things to know

**Slips' timewindows are its own.** It profiles per source IP in 1-hour timewindows and
its alert threshold (0.25 by default) accumulates across that hour, not across our 30
seconds. Our slice by timestamp bounds the *evidence lines*; it does not change how
Slips decided to raise them.

**It will not share the port with the lab console.** `slips-cli.sh` runs containers
named `slips`/`slips-redis` and binds 6379 with `--net=host`; this uses `pde-slips` /
`pde-slips-redis`. Preflight refuses to start if the lab console is up, rather than
fighting over the port.
