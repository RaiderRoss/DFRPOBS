#!/usr/bin/env python3
"""
Window collector for the PDE banking-events source.

Reads Fineract's external-events topic between two sets of broker offsets and writes what
it finds, for one capture window. It is the Kafka counterpart of the byte-offset reads the
firewall and IDS captures make: `offsets` is taken as the window opens, `collect` reads
from there once it has closed. The broker keeps the topic for days, so nothing has to be
running between captures.

Two clocks matter and only one of them bounds the window. Fineract stages events in
m_external_event and a scheduled job publishes them on a one-minute tick, so an event's
Kafka timestamp says when the job ran, not when the transaction happened. The envelope's
createdAt is the business event's own time, and that is what is sliced on. Offsets only
bound the *read*.

Two files are written, and only the first is the evidence artifact:
  events.jsonl       the in-window events, decoded: envelope, payload, broker coordinates
  events.raw.jsonl   every message read in the offset range, as the broker's own bytes
                     (base64), un-transcribed. Kept so the decode can be checked rather
                     than trusted; the schemas it needs are pinned in ./schemas.

Runs inside the compose network (the broker advertises kafka:9092, which only resolves
there), via the `pde-collector` service:

  docker compose -f docker-compose-fineract.yml --profile pde run --rm pde-collector offsets
  docker compose ... run --rm pde-collector collect --from '<offsets json>' \\
      --start 2026-09-25T20:00:00Z --end 2026-09-25T20:00:30Z --expect 12 --trigger-job
"""

import argparse
import base64
import contextlib
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone

import requests
import urllib3
from kafka import KafkaConsumer, TopicPartition

from listener import BOOTSTRAP, SCHEMA_DIRS, decode_avro, load_schemas, make_serialisable

TOPIC = os.environ.get("PDE_EVENTS_TOPIC", "external-events")
OUT_DIR = os.environ.get("PDE_OUT_DIR", "/out")
FINERACT_URL = os.environ.get("FINERACT_URL", "https://fineract-manager:8443/fineract-provider/api/v1")
FINERACT_AUTH = (os.environ.get("FINERACT_USER", "mifos"), os.environ.get("FINERACT_PASS", "password"))
FINERACT_TENANT = os.environ.get("FINERACT_TENANT", "default")
PUBLISH_JOB = "Send Asynchronous Events"
ENVELOPE = "org.apache.fineract.avro.MessageV1"
BULK = "org.apache.fineract.avro.BulkMessagePayloadV1"

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def utc_now():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.isoformat().replace("+00:00", "Z")


def parse_utc(s):
    """Window bounds carry a Z; envelope createdAt carries no zone at all, but is documented
    as UTC (ISO_LOCAL_DATE_TIME). Both come back aware, in UTC."""
    s = s.strip().replace("Z", "+00:00")
    dt = datetime.fromisoformat(s)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def consumer():
    # No group: nothing is committed, so this never moves the SecureRS listener's position
    # or anyone else's. Offsets are ours to state explicitly.
    return KafkaConsumer(bootstrap_servers=BOOTSTRAP, group_id=None, enable_auto_commit=False)


def end_offsets(c):
    c.topics()  # refreshes metadata; partitions_for_topic answers from the cache
    parts = c.partitions_for_topic(TOPIC)
    if not parts:
        return {}
    tps = [TopicPartition(TOPIC, p) for p in sorted(parts)]
    return {tp.partition: off for tp, off in c.end_offsets(tps).items()}


def cmd_offsets(_args):
    c = consumer()
    ends = end_offsets(c)
    c.close()
    # An absent topic is not an error: Fineract creates it on first publish, and then
    # everything on it is after this moment, i.e. offset 0 in every partition.
    json.dump({"topic": TOPIC, "taken_utc": iso(utc_now()),
               "end_offsets": {str(p): o for p, o in ends.items()}}, sys.stdout)
    print()


def trigger_publish_job():
    """Runs the job that moves staged events onto the topic, rather than waiting out its
    one-minute tick. It changes when an event is *sent*, never its createdAt, so the
    business record is untouched. Returns the job id, or None if it could not be run."""
    headers = {"Fineract-Platform-TenantId": FINERACT_TENANT}
    try:
        jobs = requests.get(f"{FINERACT_URL}/jobs", auth=FINERACT_AUTH, headers=headers,
                            verify=False, timeout=15).json()
        job = next(j for j in jobs if j.get("displayName") == PUBLISH_JOB)
        r = requests.post(f"{FINERACT_URL}/jobs/{job['jobId']}?command=executeJob",
                          auth=FINERACT_AUTH, headers=headers, verify=False, timeout=30)
        return job["jobId"] if r.status_code < 300 else None
    except Exception as e:  # reported, never fatal: the job also runs on its own tick
        print(f"could not trigger '{PUBLISH_JOB}': {e}", file=sys.stderr)
        return None


def decode(msg_value, schemas):
    """Envelope and payload, as far as the pinned schemas allow. A message that cannot be
    decoded is still recorded — in the raw file, and here with its error — never dropped."""
    out = {"event": None, "payload": None, "payload_error": None}
    try:
        env = decode_avro(msg_value, schemas[ENVELOPE])
    except Exception as e:
        out["payload_error"] = f"envelope decode failed: {e}"
        return out
    out["event"] = make_serialisable({k: v for k, v in env.items() if k != "data"})
    name, data = env.get("dataschema", ""), env.get("data")
    if not data:
        return out
    if name not in schemas:
        out["payload_error"] = f"schema '{name}' not loaded"
        return out
    try:
        payload = decode_avro(data, schemas[name])
        # A bulk message nests further Avro payloads. Its items carry no createdAt of their
        # own, so they can only be placed in time by the envelope's.
        if name == BULK:
            for item in payload.get("datas", []):
                inner = item.pop("data", None)
                item_schema = schemas.get(item.get("dataschema", ""))
                if inner and item_schema:
                    item["payload"] = decode_avro(inner, item_schema)
        out["payload"] = make_serialisable(payload)
    except Exception as e:
        out["payload_error"] = f"payload decode failed: {e}"
    return out


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def cmd_collect(args):
    start, end = parse_utc(args.start), parse_utc(args.end)
    start_offsets = {int(p): int(o) for p, o in json.loads(args.from_offsets).get("end_offsets", {}).items()}

    # load_schemas reports progress on stdout, which is this command's result channel.
    with contextlib.redirect_stdout(sys.stderr):
        schemas = load_schemas(SCHEMA_DIRS)

    triggers = []
    if args.trigger_job:
        job = trigger_publish_job()
        triggers.append({"at_utc": iso(utc_now()), "job_id": job})

    c = consumer()
    assigned = set()
    raw, decoded = [], []
    deadline = time.monotonic() + args.timeout
    last_new = time.monotonic()
    last_trigger = time.monotonic()
    settled = False

    while True:
        ends = end_offsets(c)
        new_parts = [p for p in ends if p not in assigned]
        if new_parts:
            # assign() replaces the whole assignment and can drop the positions of
            # partitions already being read, so they are noted first and restored after.
            kept = {p: c.position(TopicPartition(TOPIC, p)) for p in assigned}
            assigned.update(new_parts)
            tps = [TopicPartition(TOPIC, p) for p in sorted(assigned)]
            c.assign(tps)
            for tp in tps:
                # Partitions absent from the recorded offsets start at 0: the topic (or the
                # partition) was created after the window opened, so all of it is in range.
                c.seek(tp, kept.get(tp.partition, start_offsets.get(tp.partition, 0)))

        got_any = False
        while True:
            batch = c.poll(timeout_ms=1000)
            if not batch:
                break
            for tp, msgs in batch.items():
                for m in msgs:
                    got_any = True
                    d = decode(m.value, schemas)
                    created = (d["event"] or {}).get("createdAt")
                    try:
                        in_window = created is not None and start <= parse_utc(created) <= end
                    except ValueError:
                        # An unreadable timestamp is a reason to look, not to discard.
                        in_window = True
                    raw.append({"partition": m.partition, "offset": m.offset,
                                "kafka_timestamp_ms": m.timestamp, "in_window": in_window,
                                "key_b64": base64.b64encode(m.key or b"").decode(),
                                "value_b64": base64.b64encode(m.value or b"").decode()})
                    if in_window:
                        d["kafka"] = {"topic": m.topic, "partition": m.partition,
                                      "offset": m.offset, "timestamp_ms": m.timestamp}
                        decoded.append(d)
        if got_any:
            last_new = time.monotonic()

        now = time.monotonic()
        quiet = now - last_new
        # Done when at least the expected number of in-window events has arrived and the
        # topic has then been quiet for a moment — the publisher sends in batches, so the
        # first arrival is not the last.
        if len(decoded) >= args.expect and quiet >= args.settle:
            settled = True
            break
        if now >= deadline:
            break
        # Nothing new for a while and still short: the staged events may be waiting for the
        # next tick. Nudging the job again is cheaper than waiting it out.
        if args.trigger_job and quiet >= 15 and now - last_trigger >= 15:
            job = trigger_publish_job()
            triggers.append({"at_utc": iso(utc_now()), "job_id": job})
            last_trigger = now
        time.sleep(1)

    read_to = {str(p): c.position(TopicPartition(TOPIC, p)) for p in sorted(assigned)}
    c.close()

    decoded.sort(key=lambda d: ((d["event"] or {}).get("createdAt") or "",
                                d["kafka"]["partition"], d["kafka"]["offset"]))
    raw.sort(key=lambda r: (r["partition"], r["offset"]))

    os.makedirs(args.out_dir, exist_ok=True)
    events_path = os.path.join(args.out_dir, "events.jsonl")
    raw_path = os.path.join(args.out_dir, "events.raw.jsonl")
    with open(events_path, "w") as fh:
        for d in decoded:
            fh.write(json.dumps(d, sort_keys=True) + "\n")
    with open(raw_path, "w") as fh:
        for r in raw:
            fh.write(json.dumps(r, sort_keys=True) + "\n")

    by_type = {}
    for d in decoded:
        t = (d["event"] or {}).get("type", "undecodable")
        by_type[t] = by_type.get(t, 0) + 1
    created = [d["event"]["createdAt"] for d in decoded if d["event"] and d["event"].get("createdAt")]

    json.dump({
        "topic": TOPIC,
        "window": {"start_utc": iso(start), "end_utc": iso(end)},
        "offsets_from": {str(p): o for p, o in sorted(start_offsets.items())},
        "offsets_read_to": read_to,
        "messages_read": len(raw),
        "events_in_window": len(decoded),
        "events_outside_window": len(raw) - len(decoded),
        "undecodable": sum(1 for d in decoded if d["payload_error"]),
        "by_type": dict(sorted(by_type.items())),
        "first_created_at": min(created) if created else None,
        "last_created_at": max(created) if created else None,
        "expected_at_least": args.expect,
        "settled": settled,
        "publish_job_triggers": triggers,
        "files": {"events.jsonl": sha256(events_path), "events.raw.jsonl": sha256(raw_path)},
        "collected_utc": iso(utc_now()),
    }, sys.stdout)
    print()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("offsets", help="print the topic's end offsets now, as JSON")
    col = sub.add_parser("collect", help="read from recorded offsets and write the window's events")
    col.add_argument("--from", dest="from_offsets", required=True,
                     help="the JSON `offsets` printed when the window opened")
    col.add_argument("--start", required=True, help="window start, UTC ISO 8601")
    col.add_argument("--end", required=True, help="window end, UTC ISO 8601")
    col.add_argument("--out-dir", default=OUT_DIR)
    col.add_argument("--expect", type=int, default=0,
                     help="stop early once at least this many in-window events have arrived")
    col.add_argument("--settle", type=float, default=5.0,
                     help="seconds of quiet required after the expected count is reached")
    col.add_argument("--timeout", type=float, default=120.0,
                     help="give up waiting for stragglers after this many seconds")
    col.add_argument("--trigger-job", action="store_true",
                     help=f"run '{PUBLISH_JOB}' now instead of waiting for its tick")
    args = ap.parse_args()
    {"offsets": cmd_offsets, "collect": cmd_collect}[args.cmd](args)


if __name__ == "__main__":
    main()
