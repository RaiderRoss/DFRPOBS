#!/usr/bin/env python3
"""
Forwards Slips' alerts to the Evidence Repository as trigger events, over Kafka.

Tails Slips' alerts.log while Slips runs and publishes one message per alert verdict --
the "Generated an alert given enough evidence on timewindow N" lines -- to the topic the
repository's EvidenceEventConsumer reads. Evidence lines are not forwarded on their own:
evidence is what Slips saw, an alert is Slips deciding one source crossed its threshold,
and only the second is an anchor worth correlating from. The evidence behind each alert
travels inside its payload instead, so the trigger event records why it fired.

This is the alert half of the testbed's integration. The evidence half is
submit-evidence.sh, which uploads the windowed alerts.log as an artifact; the two meet in
the repository's correlation pass, which links this alert to every artifact whose
coverage window overlaps it.

Delivery is at-least-once, matching the consumer:

  * eventId is derived from the alert line itself, so forwarding the same alert twice --
    after a restart, or a re-read -- produces the same id, and the repository's
    (sourceSystem, eventId) dedupe drops the second.
  * incidentKey is <session>/<ip>/tw<N>. Slips re-alerts every time an attacker's evidence
    crosses the threshold again within a timewindow, so one attack is several alerts; the
    repository files alerts sharing a key under one incident, with one evidence bundle.
    The session (the Slips output directory's name) is part of the key because Slips
    numbers timewindows from 1 on every run, and tw1 today is not tw1 tomorrow.
  * The read offset is saved only after the broker has acknowledged everything before
    it, so a crash re-sends rather than skips.
  * A trailing line without its newline is a write still in flight. It is left for the
    next read, as slips-lib.sh's slice does, rather than sent half-written.

Sinks, chosen with --sink:

  kafka   kafka-python-ng, to --bootstrap (default localhost:19092, Redpanda's host
          listener). The real path.
  rpk     `docker exec <container> rpk topic produce`, for a machine without the Python
          client. Needs only the Redpanda container the repository's compose file runs.
  stdout  prints each message. Nothing is sent; for checking what would be.
  auto    kafka if the client is installed, otherwise rpk. The default.
"""

import argparse
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

# An IPv4 address, or an IPv6 one. Spelled out rather than "[0-9.]+" because Slips pads
# the address and then writes a full stop, and a loose class swallows that stop or, made
# lazy, stops at the first one inside the address.
IP = r"\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]*:[0-9A-Fa-f:]+"

# "<iso>: Src IP 10.99.0.20                . Generated an alert given enough evidence on
#  timewindow 1. (real time: <iso>)". "Is blocked" is the same verdict from a Slips run
# with blocking enabled. The colon straight after the timestamp is what distinguishes an
# alert line from an evidence line, which puts a space there. Slips 1.1.23 writes a colon
# after "real time"; the colon is optional here so older output still matches.
ALERT_RE = re.compile(
    r"^(?P<ts>\S+?):\s+Src IP\s+(?P<ip>" + IP + r")\s*\.\s+"
    r"(?P<verdict>Generated an alert|Is blocked) given enough evidence on timewindow\s+(?P<tw>\d+)"
    r"(?:.*?\(real time:?\s+(?P<real>[^)]+)\))?")

SRC_IP_RE = re.compile(r"Src IP\s+(?P<ip>" + IP + ")")

TRIGGER_TYPES = {"Generated an alert": "SLIPS_ALERT", "Is blocked": "SLIPS_BLOCK"}

# Evidence lines carried per source between alerts. Slips resets a source's accumulated
# evidence when it alerts, so the lines since the previous alert are the ones that added
# up to this one. Capped so a source that never crosses the threshold cannot grow the
# buffer without bound; the cap is recorded in the payload when it bites.
MAX_EVIDENCE_LINES = 200

POLL_SECONDS = 1.0

# Wait before retrying after the broker refused or was unreachable.
RETRY_SECONDS = 5.0

running = True


def log(msg):
    print("[%s] %s" % (datetime.now(timezone.utc).strftime("%H:%M:%S"), msg), flush=True)


def parse_ts(s):
    """ISO timestamp to an aware UTC datetime, or None.

    A naive timestamp is assumed UTC, as slips-lib.sh's slice assumes, rather than
    dropped: the lab VM runs in UTC, and a dropped alert is a silent gap.
    """
    if not s:
        return None
    # The "(real time ...)" suffix is written 2026/10/04 11:18:03.796742 — slashes, which
    # fromisoformat rejects. The alert-line timestamp itself is proper ISO.
    s = re.sub(r"^(\d{4})/(\d{2})/(\d{2})", r"\1-\2-\3", s.strip())
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


def iso(dt):
    return dt.isoformat().replace("+00:00", "Z")


class Tail:
    """Reads complete lines from a file that is still being written."""

    def __init__(self, path):
        self.path = path
        self.offset = 0

    def read_lines(self):
        """Complete lines appended since the last call, as (line, end_offset) pairs."""
        try:
            size = os.path.getsize(self.path)
        except FileNotFoundError:
            return []
        if size < self.offset:
            # Truncated or replaced -- a new Slips run writing into the same directory.
            log("%s shrank (%d < %d); reading it again from the start" % (self.path, size, self.offset))
            self.offset = 0
        if size == self.offset:
            return []
        with open(self.path, "rb") as fh:
            fh.seek(self.offset)
            chunk = fh.read(size - self.offset)
        out = []
        pos = self.offset
        for raw in chunk.splitlines(keepends=True):
            if not raw.endswith(b"\n"):
                break  # in flight; picked up whole on a later read
            pos += len(raw)
            out.append((raw.decode("utf-8", "replace").rstrip("\r\n"), pos))
        self.offset = pos
        return out


class Forwarder:

    def __init__(self, source_system, sink, offset_file, session):
        self.source_system = source_system
        self.session = session
        self.sink = sink
        self.offset_file = offset_file
        self.sent_offset = self._load_offset()
        self.evidence = defaultdict(lambda: deque(maxlen=MAX_EVIDENCE_LINES))
        self.dropped = defaultdict(int)
        self.forwarded = 0

    def _load_offset(self):
        try:
            with open(self.offset_file) as fh:
                return int(fh.read().strip() or 0)
        except (FileNotFoundError, ValueError):
            return 0

    def _save_offset(self, offset):
        tmp = self.offset_file + ".tmp"
        with open(tmp, "w") as fh:
            fh.write(str(offset))
        os.replace(tmp, self.offset_file)
        self.sent_offset = offset

    def handle(self, line, end_offset):
        """Processes one complete line. Lines at or before the saved offset are replayed
        only to rebuild each source's evidence context; their alerts were already sent."""
        if not line.strip():
            return
        m = ALERT_RE.match(line)
        if not m:
            ip = SRC_IP_RE.search(line)
            if ip:
                buf = self.evidence[ip.group("ip")]
                if len(buf) == buf.maxlen:
                    self.dropped[ip.group("ip")] += 1
                buf.append(line)
            return

        ip = m.group("ip")
        context = list(self.evidence.pop(ip, []))
        dropped = self.dropped.pop(ip, 0)
        if end_offset <= self.sent_offset:
            return

        message = self.message(m, line, context, dropped)
        self.sink.send(key=ip, value=message)
        self.forwarded += 1
        log("forwarded %s %s from %s (timewindow %s, %d evidence lines)" % (
            message["triggerType"], message["eventId"], ip, m.group("tw"), len(context)))

    def message(self, m, line, context, dropped):
        fired = parse_ts(m.group("ts"))
        real = parse_ts(m.group("real"))
        fired_from = "alert line"
        if fired is None:
            # Better a firedAt marked as a stand-in than no trigger event at all; the
            # payload says which clock it came from.
            fired, fired_from = (real, "real time") if real else (datetime.now(timezone.utc), "forwarder clock")

        digest = hashlib.sha256(line.encode("utf-8")).hexdigest()
        return {
            # Derived from the line, so a re-sent alert carries the same id and is
            # deduplicated by the repository rather than recorded twice.
            "eventId": "%s-tw%s-%s" % (m.group("ip"), m.group("tw"), digest[:16]),
            "sourceSystem": self.source_system,
            "incidentKey": "%s/%s/tw%s" % (self.session, m.group("ip"), m.group("tw")),
            "triggerType": TRIGGER_TYPES[m.group("verdict")],
            "firedAt": iso(fired),
            # Ignored by the consumer's parser but kept in the payload it stores, which is
            # the point: the trigger event retains the alert as Slips wrote it.
            "slips": {
                "srcIp": m.group("ip"),
                "timewindow": int(m.group("tw")),
                "verdict": m.group("verdict"),
                "realTime": iso(real) if real else None,
                "firedAtFrom": fired_from,
                "line": line,
                "lineSha256": digest,
                "evidence": context,
                "evidenceTruncated": dropped,
            },
        }

    def commit(self, offset):
        """Saves the offset once the sink has delivered everything before it."""
        if offset > self.sent_offset:
            self.sink.flush()
            self._save_offset(offset)


# --------------------------------------------------------------------------- sinks

class KafkaSink:

    def __init__(self, bootstrap, topic):
        from kafka import KafkaProducer  # kafka-python-ng; imported here so other sinks need nothing
        self.factory = KafkaProducer
        self.bootstrap = bootstrap
        self.topic = topic
        self.producer = None
        self.pending = []

    def _connected(self):
        # Connected on first use rather than at start-up, so a broker that is not up yet is
        # a retry in the main loop instead of an exit -- the lab can come up before the
        # repository's compose stack does.
        if self.producer is None:
            self.producer = self.factory(
                bootstrap_servers=self.bootstrap,
                # acks=all and retries: an alert lost between here and the broker is a gap
                # in the record, which is the failure this whole system exists to prevent.
                acks="all",
                retries=5,
                key_serializer=lambda k: k.encode("utf-8"),
                value_serializer=lambda v: json.dumps(v, separators=(",", ":")).encode("utf-8"))
        return self.producer

    def send(self, key, value):
        self.pending.append(self._connected().send(self.topic, key=key, value=value))

    def flush(self):
        # get() rather than producer.flush() alone: flush waits for sends to finish but
        # does not report the ones that failed, and the offset must not move past those.
        pending, self.pending = self.pending, []
        for future in pending:
            future.get(timeout=30)

    def close(self):
        if self.producer is not None:
            self.producer.close(timeout=10)


class RpkSink:

    def __init__(self, container, topic):
        self.container = container
        self.topic = topic

    def send(self, key, value):
        # Synchronous: rpk exits once the broker acknowledges, so flush has nothing left.
        body = json.dumps(value, separators=(",", ":"))
        result = subprocess.run(
            ["docker", "exec", "-i", self.container, "rpk", "topic", "produce", self.topic, "-k", key],
            input=body + "\n", capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            raise RuntimeError("rpk produce failed: %s" % (result.stderr.strip() or result.stdout.strip()))

    def flush(self):
        pass

    def close(self):
        pass


class StdoutSink:

    def send(self, key, value):
        print(json.dumps({"key": key, "value": value}, indent=2), flush=True)

    def flush(self):
        pass

    def close(self):
        pass


def container_running(name):
    try:
        out = subprocess.run(["docker", "ps", "--format", "{{.Names}}"],
                             capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.TimeoutExpired):
        return False
    return name in out.split()


def make_sink(args):
    choice = args.sink
    if choice == "auto":
        try:
            import kafka  # noqa: F401
            choice = "kafka"
        except ImportError:
            if not container_running(args.rpk_container):
                raise SystemExit(
                    "no Kafka client: pip install kafka-python-ng, or start the repository's "
                    "compose stack so the '%s' container can be used through rpk" % args.rpk_container)
            choice = "rpk"
    if choice == "kafka":
        log("sink: kafka at %s, topic %s" % (args.bootstrap, args.topic))
        return KafkaSink(args.bootstrap, args.topic)
    if choice == "rpk":
        log("sink: rpk in container %s, topic %s" % (args.rpk_container, args.topic))
        return RpkSink(args.rpk_container, args.topic)
    log("sink: stdout (nothing is sent)")
    return StdoutSink()


# --------------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--slips-out", required=True,
                    help="Slips' output directory, the one holding alerts/alerts.log")
    ap.add_argument("--source-system",
                    default=os.environ.get("DFRAAS_IDS_SOURCE_KEY", "pde-sim-slips-01"),
                    help="sourceSystem on every trigger event. Must equal the source key the "
                         "IDS is registered under, or the repository cannot correlate its "
                         "alerts (default: $DFRAAS_IDS_SOURCE_KEY or pde-sim-slips-01)")
    ap.add_argument("--sink", choices=["auto", "kafka", "rpk", "stdout"], default="auto")
    ap.add_argument("--bootstrap", default=os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:19092"))
    ap.add_argument("--topic", default=os.environ.get("KAFKA_EVIDENCE_TOPIC", "evidence-events"))
    ap.add_argument("--rpk-container", default=os.environ.get("DFRAAS_REDPANDA_CONTAINER", "dfraas-redpanda"))
    ap.add_argument("--offset-file",
                    help="where the read position is kept between runs "
                         "(default: <slips-out>/forwarder.offset)")
    ap.add_argument("--once", action="store_true",
                    help="forward what is in the file now and exit, instead of following it")
    ap.add_argument("--pidfile", help="written with this process's PID once it is running")
    args = ap.parse_args()

    alerts_log = os.path.join(args.slips_out, "alerts", "alerts.log")
    session = os.path.basename(os.path.normpath(args.slips_out))
    offset_file = args.offset_file or os.path.join(args.slips_out, "forwarder.offset")

    def stop(_signum, _frame):
        global running
        running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    sink = make_sink(args)

    if args.pidfile:
        with open(args.pidfile, "w") as fh:
            fh.write(str(os.getpid()))

    forwarded = 0
    try:
        while running:
            # Each pass reads the file from the start, replaying what was already sent
            # only to rebuild each source's evidence context. A failed send starts a new
            # pass rather than carrying on: the evidence buffers it consumed are gone, and
            # replaying from the start is what puts them back.
            forwarder = Forwarder(args.source_system, sink, offset_file, session)
            tail = Tail(alerts_log)
            log("following %s as %s (resuming after byte %d)" % (
                alerts_log, args.source_system, forwarder.sent_offset))
            try:
                follow(tail, forwarder, alerts_log, args.once)
                forwarded += forwarder.forwarded
                break
            except Exception as ex:  # broker down, rpk failing, timeout
                forwarded += forwarder.forwarded
                if args.once:
                    raise
                log("send failed, retrying in %ds from the last acknowledged alert: %s" % (RETRY_SECONDS, ex))
                time.sleep(RETRY_SECONDS)
    finally:
        sink.close()
        log("stopped; %d alert(s) forwarded this run" % forwarded)


def follow(tail, forwarder, alerts_log, once):
    waiting_logged = False
    while running:
        if not os.path.exists(alerts_log) and not waiting_logged:
            log("waiting for Slips to create %s" % alerts_log)
            waiting_logged = True
        last = None
        for line, end_offset in tail.read_lines():
            forwarder.handle(line, end_offset)
            last = end_offset
        if last is not None:
            forwarder.commit(last)
        if once:
            return
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
