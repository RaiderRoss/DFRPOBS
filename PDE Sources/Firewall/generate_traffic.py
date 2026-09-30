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
import math
import random
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone


# ---------- Attack profiles ----------
# Each profile changes two things: which ports the attacker reaches for, and how the
# attempts are distributed in time. Those two choices are what give each attack a
# distinguishable shape in the resulting log — which is the point, since a firewall log
# has no "malicious" column and detection has only the pattern to work with.
ATTACK_PROFILES = {
    "port-scan": "A VERTICAL scan: one target host, many denied ports, spread over the "
                 "window. Vertical means down the port list of a single machine; a "
                 "horizontal scan is the other axis — one port across many hosts — and "
                 "is not reachable here, because every simulated user targets one host.",
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
    "guaranteed-alert": "Built to make the IDS raise a real alert, not just evidence. "
                        "Completed connections to a few ports Slips has no service "
                        "record for, which the firewall permits and a listener on the "
                        "host answers, at twice what Slips' threshold needs per "
                        "attacker. The firewall logs them ALLOW: it let the attack "
                        "through, and only the IDS can say it was hostile.",
}
DEFAULT_PROFILE = "port-scan"

DB_PORTS = [1433, 3306, 5432, 6379, 27017]
AUTH_PORTS = [22, 3389, 23]

# guaranteed-alert, derived from Slips' source rather than tuned by trial:
#   - an alert fires when one source's weighted evidence inside one timewindow reaches
#     detection_threshold * width / 60, which is 0.25 * 3600 / 60 = 15 by default
#   - an ESTABLISHED connection to a port Slips has no record of is "unknown destination
#     port" evidence at HIGH (0.8) with confidence 1.0, raised once per connection
# so 19 completed connections from one source are the fewest that can cross it.
SLIPS_THRESHOLD_IN_WIDTH = 0.25 * 3600 / 60
UNKNOWN_PORT_ESTABLISHED_WEIGHT = 0.8 * 1.0
ALERT_MIN_ESTABLISHED = math.ceil(SLIPS_THRESHOLD_IN_WIDTH / UNKNOWN_PORT_ESTABLISHED_WEIGHT)
# Planned at twice the minimum, as margin for connections that do not complete. Slips
# accumulates per source IP, so this is per attacker.
ALERT_ATTEMPTS_PER_ATTACKER = 2 * ALERT_MIN_ESTABLISHED
# Slips' vertical-scan detector counts only connections that FAILED, and only above five
# distinct ports. Keeping to five makes marking the attacker a port scanner impossible
# even if every connection failed, and a marked scanner has its unknown-port evidence
# suppressed.
ALERT_MAX_DISTINCT_PORTS = 5


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


def plan_malicious(profile, count, duration, malicious_ports, rng, alert_ports=None):
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

    elif profile == "guaranteed-alert":
        if not alert_ports:
            raise SystemExit("guaranteed-alert needs --alert-ports")
        if len(set(alert_ports)) > ALERT_MAX_DISTINCT_PORTS:
            raise SystemExit("guaranteed-alert takes at most %d distinct ports; more "
                             "lets Slips mark the attacker a port scanner and suppress "
                             "the evidence the alert is built from"
                             % ALERT_MAX_DISTINCT_PORTS)
        ports = _sweep(count, alert_ports, rng)
        times = [rng.uniform(0, duration) for _ in range(count)]

    else:
        raise SystemExit("unknown attack profile: %s (see --list-profiles)" % profile)

    return list(zip(ports, times))


def build_plan(users, malicious_ips, duration, rate, malicious_pct,
               benign_ports, malicious_ports, profile, rng, alert_ports=None):
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

    if profile == "guaranteed-alert":
        if not malicious_ips:
            raise SystemExit("guaranteed-alert needs at least one malicious user")
        # Raised to the floor rather than left to the percentage: this profile exists so
        # the alert is not left to chance, and a small share of a short window would
        # plan too few connections to cross the threshold.
        floor = ALERT_ATTEMPTS_PER_ATTACKER * len(malicious_ips)
        if n_malicious < floor:
            print("note: guaranteed-alert raises malicious events from %d to %d "
                  "(%d per attacker; Slips needs %d completed per attacker)"
                  % (n_malicious, floor, ALERT_ATTEMPTS_PER_ATTACKER,
                     ALERT_MIN_ESTABLISHED), file=sys.stderr)
            n_malicious = floor
        if n_malicious >= total:
            raise SystemExit("guaranteed-alert needs %d malicious events but the window "
                             "has only %d; raise --rate or --duration" % (floor, total))
    n_benign = total - n_malicious

    events = []
    for _ in range(n_benign):
        events.append({
            "src": rng.choice(benign_ips),
            "dport": rng.choice(benign_ports),
            "label": "benign",
            "t_offset": rng.uniform(0.0, duration),
        })

    for i, (dport, t_offset) in enumerate(plan_malicious(
            profile, n_malicious, duration, malicious_ports, rng, alert_ports)):
        events.append({
            # Slips accumulates per source IP, so guaranteed-alert shares its attempts
            # out evenly: a random draw could leave one attacker under the threshold.
            # Every other profile keeps the random draw, so its seeded runs are unchanged.
            "src": (malicious_ips[i % len(malicious_ips)]
                    if profile == "guaranteed-alert" else rng.choice(malicious_ips)),
            "dport": dport,
            "label": "malicious",
            "t_offset": t_offset,
        })

    events.sort(key=lambda e: e["t_offset"])
    for i, e in enumerate(events):
        e["seq"] = i
    return events


# Ports on which a benign request is sent over TLS; the rest are plain HTTP.
TLS_PORTS = {443}
_CLIENT_TLS = ssl.create_default_context()
_CLIENT_TLS.check_hostname = False
_CLIENT_TLS.verify_mode = ssl.CERT_NONE      # the lab's web front is self-signed


def web_request(sock, dst_ip, dport):
    """Loads a page over an open connection and returns the HTTP status, or None.

    Benign users used to connect and close at once, sending nothing — zero-byte flows that a
    flow-based IDS reads as a scan. A customer loads a page, so these do: a GET, the reply
    read to the end. Only benign attempts do this; the attacker's sweep stays a bare connect,
    because that is what a sweep is."""
    try:
        if dport in TLS_PORTS:
            sock = _CLIENT_TLS.wrap_socket(sock, server_hostname=None)
        sock.sendall(("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (PDE lab customer)\r\n"
                      "Accept: text/html\r\nConnection: close\r\n\r\n" % dst_ip).encode())
        data = b""
        while len(data) < 65536:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        first = data.split(b"\r\n", 1)[0].split()
        return int(first[1]) if len(first) > 1 and first[1].isdigit() else None
    except (OSError, ValueError):
        return None


def attempt(src_ip, dst_ip, dport, timeout, request=False):
    """
    One TCP connection attempt. The outcome is incidental — a blocked SYN times out and
    that is fine. What matters is that the packet crossed the firewall and was logged.
    With request=True a connection that opens is used to load a page (web_request).

    Returns the moment the SYN actually went out as well, on both clocks: wall time for
    the record, monotonic for measuring drift against the plan.
    """
    sent_mono = time.monotonic()
    sent_at = utc_now()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        s.bind((src_ip, 0))
        sport = s.getsockname()[1]
        http_status = None
        try:
            s.connect((dst_ip, dport))
            outcome = "connected"
            if request:
                http_status = web_request(s, dst_ip, dport)
        except socket.timeout:
            outcome = "timeout"
        except ConnectionRefusedError:
            # Passed the firewall, nothing listening. Still permitted, still logged.
            outcome = "refused"
        except OSError as exc:
            outcome = "error:%s" % (exc.errno,)
        return sport, outcome, sent_at, sent_mono, http_status
    finally:
        s.close()


def per_attacker(events, outcome=None):
    """Malicious attempts per source IP, optionally only those with a given outcome."""
    counts = {}
    for e in events:
        if e["label"] == "malicious" and (outcome is None or e.get("outcome") == outcome):
            counts[e["src"]] = counts.get(e["src"], 0) + 1
    return dict(sorted(counts.items()))


def alert_guarantee(profile, events, completed=False):
    """What guaranteed-alert needs from Slips and, once sent, whether the traffic gave it.

    traffic_sufficient is a claim about the TRAFFIC only: every attacker completed enough
    connections to cross the threshold. Whether Slips then alerted is the IDS's own
    output, read from its log and never inferred here.
    """
    if profile != "guaranteed-alert":
        return None
    out = {
        "slips_threshold": SLIPS_THRESHOLD_IN_WIDTH,
        "weight_per_completed_connection": UNKNOWN_PORT_ESTABLISHED_WEIGHT,
        "min_completed_per_attacker": ALERT_MIN_ESTABLISHED,
        "planned_per_attacker": per_attacker(events),
    }
    if completed:
        done = per_attacker(events, outcome="connected")
        out["completed_per_attacker"] = {ip: done.get(ip, 0) for ip in out["planned_per_attacker"]}
        out["traffic_sufficient"] = all(n >= ALERT_MIN_ESTABLISHED
                                        for n in out["completed_per_attacker"].values())
    return out


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
    ap.add_argument("--alert-ports",
                    help="comma-separated, firewall-permitted and answered by a listener; "
                         "the guaranteed-alert profile's targets")
    ap.add_argument("--connect-timeout", type=float, default=0.25)
    ap.add_argument("--max-inflight", type=int, default=64,
                    help="concurrent connection attempts; must exceed rate * "
                         "connect-timeout or blocked attempts will queue and drift")
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
    alert_ports = [int(p) for p in (args.alert_ports or "").split(",") if p.strip()]

    unknown = set(malicious) - set(users)
    if unknown:
        raise SystemExit("malicious users not in user list: %s" % sorted(unknown))

    rng = random.Random(args.seed)
    plan = build_plan(users, malicious, args.duration, args.rate, args.malicious_pct,
                      benign_ports, malicious_ports, args.attack_profile, rng, alert_ports)

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
            "malicious_per_attacker": per_attacker(plan),
            "alert_guarantee": alert_guarantee(args.attack_profile, plan),
            "first_10": [{k: e[k] for k in ("seq", "src", "dport", "label")}
                         for e in plan[:10]],
        }, sys.stdout, indent=2)
        print()
        return

    started = utc_now()
    t0 = time.monotonic()
    late = 0
    pending = []

    # Attempts are dispatched to a pool rather than run in series. A blocked SYN has
    # nothing to answer it and so occupies the whole connect timeout; run serially, a
    # 30s window at 10% malicious spent roughly 15s of its budget waiting and fired
    # 275 of 600 events behind schedule. That compression flattens precisely the timing
    # differences the attack profiles exist to encode — stealth's even spacing and
    # syn-burst's spike both collapse toward the same shape.
    with ThreadPoolExecutor(max_workers=args.max_inflight) as pool:
        for e in plan:
            delay = (t0 + e["t_offset"]) - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            else:
                late += 1
            pending.append((e, pool.submit(attempt, e["src"], args.target,
                                           e["dport"], args.connect_timeout,
                                           e["label"] == "benign")))

    finished = utc_now()

    executed = []
    drift_total = 0.0
    drift_max = 0.0
    for e, future in pending:
        sport, outcome, sent_at, sent_mono, http_status = future.result()
        # How far the SYN actually went out from where the plan wanted it. Measured
        # rather than assumed: a saturated pool queues silently, and a queued attempt
        # is late in a way the scheduling loop above cannot see.
        drift = abs((sent_mono - t0) - e["t_offset"])
        drift_total += drift
        drift_max = max(drift_max, drift)
        executed.append({
            "seq": e["seq"],
            "sent_at": iso(sent_at),
            "scheduled_offset": round(e["t_offset"], 3),
            "actual_offset": round(sent_mono - t0, 3),
            "src": e["src"],
            "sport": sport,
            "dst": args.target,
            "dport": e["dport"],
            "label": e["label"],
            "outcome": outcome,
            "http_status": http_status,
        })
    executed.sort(key=lambda x: x["seq"])

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
        # Attempts the scheduling loop reached after their slot had already passed.
        "events_behind_schedule": late,
        # What the packets actually did, which is the number that matters: if mean
        # drift approaches the inter-arrival gap, the realised traffic no longer has
        # the temporal shape the profile specified and the run should be rated down.
        "dispatch_drift_mean_s": round(drift_total / max(1, len(executed)), 4),
        "dispatch_drift_max_s": round(drift_max, 4),
        "alert_guarantee": alert_guarantee(args.attack_profile, executed, completed=True),
        "users": [{"ip": u, "role": "malicious" if u in malicious else "benign"} for u in users],
        "events": executed,
    }

    with open(args.out, "w") as fh:
        json.dump(ground_truth, fh, indent=2)

    print("generated %d events (%d malicious, %d benign) in %.1fs; "
          "dispatch drift mean %.3fs max %.3fs"
          % (len(executed), ground_truth["malicious_events"],
             ground_truth["benign_events"], ground_truth["elapsed_seconds"],
             ground_truth["dispatch_drift_mean_s"],
             ground_truth["dispatch_drift_max_s"]))

    guarantee = ground_truth["alert_guarantee"]
    if guarantee:
        print("guaranteed-alert: completed connections per attacker %s; Slips needs %d each"
              % (guarantee["completed_per_attacker"], ALERT_MIN_ESTABLISHED))
        if not guarantee["traffic_sufficient"]:
            print("warning: an attacker completed fewer connections than the threshold "
                  "needs, so no alert is guaranteed for it. Check that the alert "
                  "listener is up and the alert ports are permitted.", file=sys.stderr)


if __name__ == "__main__":
    main()
