#!/usr/bin/env python3
"""
Traffic generator for the Ubuntu Firewall (ufw) PDE source.

Runs *inside* a network namespace that holds one IP address per simulated user, and
opens real TCP connections towards the host end of the veth pair. It writes no logs of
its own: the evidence is whatever ufw's kernel LOG target produces as these packets
cross the host's INPUT chain. This process only decides who connects to what, and when.

The event plan is built up front from a seed, so a run is reproducible and the
ground-truth labels are known before a single packet is sent — the labels are not
inferred afterwards from the logs.
"""

import argparse
import json
import random
import socket
import sys
import time
from datetime import datetime, timezone


# ---------- Attack profiles ----------
# Each profile changes two things: which ports the attacker reaches for, and how the
# attempts are distributed in time. Those two choices are what give each attack a
# distinguishable shape in the resulting log — which is the point, since a firewall log
# has no "malicious" column and detection has only the pattern to work with.
ATTACK_PROFILES = {
    "port-scan": "Wide sweep across many denied ports. The classic reconnaissance "
                 "signature: one SRC, many different DPTs, spread evenly over the window.",
    "brute-force": "Repeated attempts against a single authentication port. One SRC, one "
                   "DPT, many distinct SPTs — credential stuffing as seen from the network.",
    "db-probe": "Database ports only (1433/3306/5432/6379/27017). Narrow and deliberate: "
                "an attacker who already knows what they are looking for.",
    "stealth": "Evenly spaced attempts with maximal gaps between them, across a wide port "
               "range. Shaped to sit underneath rate-based detection thresholds.",
    "syn-burst": "Every attempt compressed into a short burst against one port. Flood-"
                 "shaped — a spike rather than a spread.",
    "mixed": "Two phases: a sweep first, then sustained pressure on a single port. "
             "Approximates reconnaissance followed by exploitation.",
}
DEFAULT_PROFILE = "port-scan"

DB_PORTS = [1433, 3306, 5432, 6379, 27017]
AUTH_PORTS = [22, 3389, 23]


def utc_now():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.isoformat().replace("+00:00", "Z")


def _sweep(count, ports, rng):
    """Draws ports without replacement per pass, so a sweep fans out rather than
    hammering one port by chance."""
    out = []
    while len(out) < count:
        block = ports[:]
        rng.shuffle(block)
        out.extend(block)
    return out[:count]


def _pick(preferred, available):
    return next((p for p in preferred if p in available), available[0])


def plan_malicious(profile, count, duration, malicious_ports, rng):
    """Returns [(dport, t_offset), ...] for the attacker's attempts."""
    if count == 0:
        return []

    if profile == "port-scan":
        ports = _sweep(count, malicious_ports, rng)
        times = [rng.uniform(0, duration) for _ in range(count)]

    elif profile == "brute-force":
        target = _pick(AUTH_PORTS, malicious_ports)
        ports = [target] * count
        times = [rng.uniform(0, duration) for _ in range(count)]

    elif profile == "db-probe":
        pool = [p for p in DB_PORTS if p in malicious_ports] or malicious_ports
        ports = _sweep(count, pool, rng)
        times = [rng.uniform(0, duration) for _ in range(count)]

    elif profile == "stealth":
        ports = _sweep(count, malicious_ports, rng)
        # Even spacing with light jitter. Uniform random draws clump together by
        # chance, which is exactly the burstiness this profile exists to avoid.
        step = duration / max(1, count)
        times = [min(duration, i * step + rng.uniform(0, step * 0.25))
                 for i in range(count)]

    elif profile == "syn-burst":
        target = _pick(AUTH_PORTS, malicious_ports)
        burst = max(1.0, duration * 0.1)
        start = rng.uniform(0, max(0.0, duration - burst))
        ports = [target] * count
        times = [start + rng.uniform(0, burst) for _ in range(count)]

    elif profile == "mixed":
        n_scan = int(count * 0.6)
        n_focus = count - n_scan
        half = duration / 2.0
        target = _pick(DB_PORTS + AUTH_PORTS, malicious_ports)
        ports = _sweep(n_scan, malicious_ports, rng) + [target] * n_focus
        times = ([rng.uniform(0, half) for _ in range(n_scan)]
                 + [rng.uniform(half, duration) for _ in range(n_focus)])

    else:
        raise SystemExit("unknown attack profile: %s (see --list-profiles)" % profile)

    return list(zip(ports, times))


def build_plan(users, malicious_ips, duration, rate, malicious_pct,
               benign_ports, malicious_ports, profile, rng):
    total = max(1, int(round(duration * rate)))

    benign_ips = [u for u in users if u not in malicious_ips]
    if not benign_ips:
        raise SystemExit("every user is malicious; nothing would be benign")

    if malicious_ips:
        n_malicious = int(round(total * malicious_pct / 100.0))
        if n_malicious == 0:
            print("warning: malicious users defined but malicious_pct rounds to 0 events",
                  file=sys.stderr)
    else:
        # No attacker means no malicious events, and the shortfall goes to benign rather
        # than quietly shrinking the run below the requested rate.
        if malicious_pct > 0:
            print("warning: malicious_pct=%s but no malicious users; generating an "
                  "all-benign run" % malicious_pct, file=sys.stderr)
        n_malicious = 0
    n_benign = total - n_malicious

    events = []
    for _ in range(n_benign):
        events.append({
            "src": rng.choice(benign_ips),
            "dport": rng.choice(benign_ports),
            "label": "benign",
            "t_offset": rng.uniform(0.0, duration),
        })

    for dport, t_offset in plan_malicious(profile, n_malicious, duration,
                                          malicious_ports, rng):
        events.append({
            "src": rng.choice(malicious_ips),
            "dport": dport,
            "label": "malicious",
            "t_offset": t_offset,
        })

    events.sort(key=lambda e: e["t_offset"])
    for i, e in enumerate(events):
        e["seq"] = i
    return events


def attempt(src_ip, dst_ip, dport, timeout):
    """
    One TCP connection attempt. The outcome is incidental — a blocked SYN times out and
    that is fine. What matters is that the packet crossed the firewall and was logged.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        s.bind((src_ip, 0))
        sport = s.getsockname()[1]
        try:
            s.connect((dst_ip, dport))
            return sport, "connected"
        except socket.timeout:
            return sport, "timeout"
        except ConnectionRefusedError:
            # Passed the firewall, nothing listening. Still an ALLOW in the log.
            return sport, "refused"
        except OSError as exc:
            return sport, "error:%s" % (exc.errno,)
    finally:
        s.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--list-profiles", action="store_true",
                    help="print the attack profiles as JSON and exit")
    ap.add_argument("--users", help="comma-separated source IPs, one per simulated user")
    ap.add_argument("--malicious-users",
                    help="comma-separated subset of --users acting maliciously "
                         "(empty string for none)")
    ap.add_argument("--target", help="destination IP (host side of veth)")
    ap.add_argument("--duration", type=float, help="seconds")
    ap.add_argument("--rate", type=float, default=20.0, help="events per second (total)")
    ap.add_argument("--malicious-pct", type=float, default=10.0,
                    help="share of events that are malicious")
    ap.add_argument("--attack-profile", default=DEFAULT_PROFILE,
                    choices=sorted(ATTACK_PROFILES), help="attacker behaviour")
    ap.add_argument("--benign-ports", help="comma-separated, firewall-permitted")
    ap.add_argument("--malicious-ports", help="comma-separated, firewall-denied")
    ap.add_argument("--connect-timeout", type=float, default=0.25)
    ap.add_argument("--seed", type=int, help="makes a run reproducible")
    ap.add_argument("--out", help="path for the ground-truth event JSON")
    ap.add_argument("--plan-only", action="store_true",
                    help="build and print the plan without sending any packets")
    args = ap.parse_args()

    if args.list_profiles:
        json.dump({"default": DEFAULT_PROFILE, "profiles": ATTACK_PROFILES},
                  sys.stdout, indent=2)
        print()
        return

    for required in ("users", "malicious_users", "target", "duration",
                     "benign_ports", "malicious_ports", "seed", "out"):
        if getattr(args, required) is None:
            ap.error("--%s is required" % required.replace("_", "-"))

    users = [u.strip() for u in args.users.split(",") if u.strip()]
    malicious = [u.strip() for u in args.malicious_users.split(",") if u.strip()]
    benign_ports = [int(p) for p in args.benign_ports.split(",") if p.strip()]
    malicious_ports = [int(p) for p in args.malicious_ports.split(",") if p.strip()]

    unknown = set(malicious) - set(users)
    if unknown:
        raise SystemExit("malicious users not in user list: %s" % sorted(unknown))

    rng = random.Random(args.seed)
    plan = build_plan(users, malicious, args.duration, args.rate, args.malicious_pct,
                      benign_ports, malicious_ports, args.attack_profile, rng)

    if args.plan_only:
        summary = {}
        for e in plan:
            if e["label"] == "malicious":
                summary[e["dport"]] = summary.get(e["dport"], 0) + 1
        json.dump({
            "attack_profile": args.attack_profile,
            "planned_events": len(plan),
            "malicious_events": sum(1 for e in plan if e["label"] == "malicious"),
            "benign_events": sum(1 for e in plan if e["label"] == "benign"),
            "malicious_port_histogram": dict(sorted(summary.items())),
            "first_10": [{k: e[k] for k in ("seq", "src", "dport", "label")}
                         for e in plan[:10]],
        }, sys.stdout, indent=2)
        print()
        return

    started = utc_now()
    t0 = time.monotonic()
    executed = []
    late = 0

    for e in plan:
        target_t = t0 + e["t_offset"]
        delay = target_t - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        else:
            late += 1
        sent_at = utc_now()
        sport, outcome = attempt(e["src"], args.target, e["dport"], args.connect_timeout)
        executed.append({
            "seq": e["seq"],
            "sent_at": iso(sent_at),
            "src": e["src"],
            "sport": sport,
            "dst": args.target,
            "dport": e["dport"],
            "label": e["label"],
            "outcome": outcome,
        })

    finished = utc_now()

    ground_truth = {
        "started_utc": iso(started),
        "finished_utc": iso(finished),
        "elapsed_seconds": round(time.monotonic() - t0, 3),
        "seed": args.seed,
        "attack_profile": args.attack_profile,
        "planned_events": len(plan),
        "executed_events": len(executed),
        "malicious_events": sum(1 for e in executed if e["label"] == "malicious"),
        "benign_events": sum(1 for e in executed if e["label"] == "benign"),
        # Attempts that could not be issued on schedule. A non-zero count means the
        # requested rate outran what the host could drive, and the realised arrival
        # pattern is compressed relative to the plan.
        "events_behind_schedule": late,
        "users": [{"ip": u, "role": "malicious" if u in malicious else "benign"} for u in users],
        "events": executed,
    }

    with open(args.out, "w") as fh:
        json.dump(ground_truth, fh, indent=2)

    print("generated %d events (%d malicious, %d benign) in %.1fs; %d behind schedule"
          % (len(executed), ground_truth["malicious_events"],
             ground_truth["benign_events"], ground_truth["elapsed_seconds"], late))


if __name__ == "__main__":
    main()
