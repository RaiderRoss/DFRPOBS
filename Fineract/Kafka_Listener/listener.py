# listener.py — Fineract Kafka external-event listener with Avro decoding
import io
import json
import os
import time
from datetime import datetime
from decimal import Decimal
from pathlib import Path

import fastavro
from kafka import KafkaConsumer
from kafka.errors import NoBrokersAvailable

TOPICS = ["external-events"]
BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
SCHEMA_DIRS = [
    Path(os.environ.get("AVRO_SCHEMA_DIR", "/schemas")),
    Path(os.environ.get("AVRO_TEMPLATE_DIR", "/schemas-templates")),
]

CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"

# ── Load all .avsc schemas ───────────────────────────────────────────────────
# Fineract uses "bigdecimal" as a type alias in .avsc files. It's not a real
# Avro named type — it's a logical type shortcut that the Gradle codegen
# expands. We do the same: inline-replace every "bigdecimal" reference in the
# raw JSON before handing it to fastavro.
BIGDECIMAL_INLINE = {
    "type": "bytes",
    "logicalType": "decimal",
    "precision": 27,
    "scale": 8,
}


def _replace_bigdecimal(obj):
    """Recursively replace the string 'bigdecimal' with the inline schema."""
    if obj == "bigdecimal":
        return BIGDECIMAL_INLINE
    if isinstance(obj, list):
        return [_replace_bigdecimal(v) for v in obj]
    if isinstance(obj, dict):
        return {k: _replace_bigdecimal(v) for k, v in obj.items()}
    return obj


def load_schemas(schema_dirs) -> dict:
    """Load every .avsc file, fix bigdecimal refs, and parse them all against
    a single shared named-type registry so cross-file references resolve.

    fastavro.schema.load_schema()'s built-in cross-file resolution assumes
    each referenced type lives in a file named after its *fully-qualified*
    name (e.g. org.apache.fineract.avro.generic.v1.EnumOptionDataV1.avsc).
    Fineract's .avsc files are named after the short type name only
    (EnumOptionDataV1.avsc), so that lookup silently fails and every schema
    that references another file's named type gets skipped.

    Instead, we parse the raw JSON dicts directly with fastavro.parse_schema,
    passing the same `named_schemas` dict to every call. Each successful
    parse registers its named types (records/enums/fixed) into that shared
    dict, making them available to later parses regardless of which file
    they came from. Because parse order matters (a type must be registered
    before anything that references it), we sweep the pending list
    repeatedly until a full pass makes no further progress.
    """
    if not isinstance(schema_dirs, list):
        schema_dirs = [schema_dirs]

    # Collect all raw schemas and apply bigdecimal replacement
    raw_schemas = []  # (filename, fqn, raw_dict)

    for d in schema_dirs:
        if not d.exists():
            print(f"  {DIM}schema dir not found: {d}{RESET}", flush=True)
            continue
        found = sorted(d.rglob("*.avsc"))
        print(f"  Found {len(found)} .avsc files in {d}", flush=True)
        for avsc in found:
            with open(avsc) as f:
                raw = json.load(f)
            if "name" not in raw:
                continue
            raw = _replace_bigdecimal(raw)
            ns = raw.get("namespace", "")
            fqn = f"{ns}.{raw['name']}" if ns else raw["name"]
            raw_schemas.append((avsc.name, fqn, raw))

    print(f"  {len(raw_schemas)} schema files to process", flush=True)

    named_schemas = {}
    top_level = {}  # fqn -> parsed schema
    pending = raw_schemas
    last_errors = {}

    progress = True
    while pending and progress:
        progress = False
        still_pending = []
        for filename, fqn, raw in pending:
            try:
                parsed = fastavro.parse_schema(raw, named_schemas=named_schemas)
                top_level[fqn] = parsed
                progress = True
            except Exception as e:
                last_errors[filename] = e
                still_pending.append((filename, fqn, raw))
        pending = still_pending

    for filename, fqn, raw in pending:
        print(f"  {YELLOW}skip {filename}: {last_errors.get(filename)}{RESET}", flush=True)

    return top_level


def make_serialisable(obj):
    """Recursively convert bytes / Decimal so json.dumps works."""
    if isinstance(obj, bytes):
        try:
            return obj.decode("utf-8")
        except UnicodeDecodeError:
            return obj.hex()
    if isinstance(obj, Decimal):
        return str(obj)
    if isinstance(obj, dict):
        return {k: make_serialisable(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [make_serialisable(v) for v in obj]
    return obj


# Avro Single Object Container magic marker (spec §12)
AVRO_SINGLE_OBJECT_MAGIC = b'\xc3\x01'


def strip_avro_header(raw_bytes: bytes) -> bytes:
    """If the bytes start with the Avro single-object container header
    (2 magic bytes + 8 byte schema fingerprint), strip it."""
    if raw_bytes[:2] == AVRO_SINGLE_OBJECT_MAGIC:
        return raw_bytes[10:]
    return raw_bytes


def decode_avro(raw_bytes: bytes, schema):
    """Deserialise Avro bytes using the given parsed schema."""
    reader = io.BytesIO(strip_avro_header(raw_bytes))
    return fastavro.schemaless_reader(reader, schema)


def print_event(msg, schemas):
    """Decode a Fineract MessageV1 envelope and pretty-print it."""
    ts = datetime.now().strftime("%H:%M:%S")

    # Decode the outer MessageV1 envelope
    envelope_schema = schemas.get("org.apache.fineract.avro.MessageV1")
    if envelope_schema is None:
        print(f"{YELLOW}[{ts}] ⚠ MessageV1 schema not loaded — raw dump:{RESET}", flush=True)
        print(msg.value[:300], flush=True)
        return

    try:
        envelope = decode_avro(msg.value, envelope_schema)
    except Exception as e:
        print(f"{YELLOW}[{ts}] ⚠ Envelope decode failed ({e}) — raw bytes:{RESET}", flush=True)
        print(msg.value[:300], flush=True)
        return

    event_type = envelope.get("type", "?")
    category = envelope.get("category", "?")
    created = envelope.get("createdAt", "?")
    data_schema_name = envelope.get("dataschema", "")

    # Header
    print(f"\n{CYAN}{'─' * 72}{RESET}", flush=True)
    print(f"{BOLD}{GREEN}[{ts}] {event_type}{RESET}", flush=True)
    print(f"  {DIM}category:{RESET}  {category}", flush=True)
    print(f"  {DIM}created:{RESET}   {created}", flush=True)
    print(f"  {DIM}tenant:{RESET}    {envelope.get('tenantId', '?')}", flush=True)
    print(f"  {DIM}schema:{RESET}    {data_schema_name}", flush=True)
    print(f"  {DIM}topic:{RESET}     {msg.topic}  p={msg.partition}  o={msg.offset}", flush=True)

    # Decode the inner data payload
    inner_bytes = envelope.get("data")
    if inner_bytes and data_schema_name and data_schema_name in schemas:
        try:
            payload = decode_avro(inner_bytes, schemas[data_schema_name])
            payload = make_serialisable(payload)
            # Filter out null fields for readability
            payload = {k: v for k, v in payload.items() if v is not None}
            print(f"  {DIM}payload:{RESET}", flush=True)
            print(json.dumps(payload, indent=4, default=str), flush=True)
        except Exception as e:
            print(f"  {YELLOW}payload decode failed: {e}{RESET}", flush=True)
            print(f"  raw data bytes ({len(inner_bytes)}): {inner_bytes[:200]}", flush=True)
    elif inner_bytes:
        print(f"  {YELLOW}schema '{data_schema_name}' not loaded — raw data ({len(inner_bytes)} bytes){RESET}",
              flush=True)
    else:
        print(f"  {DIM}(no data payload){RESET}", flush=True)


# ── Main ─────────────────────────────────────────────────────────────────────
print(f"{BOLD}Loading Avro schemas from {SCHEMA_DIRS}...{RESET}", flush=True)
schemas = load_schemas(SCHEMA_DIRS)
print(f"Loaded {len(schemas)} schemas", flush=True)

consumer = None
while consumer is None:
    try:
        consumer = KafkaConsumer(
            bootstrap_servers=BOOTSTRAP,
            auto_offset_reset="earliest",
            group_id="debug-listener",
        )
        print(f"{GREEN}Connected to Kafka at {BOOTSTRAP}{RESET}", flush=True)
    except NoBrokersAvailable:
        print("Kafka not ready, retrying in 5s...", flush=True)
        time.sleep(5)

consumer.subscribe(TOPICS)
print(f"Subscribed to: {TOPICS}", flush=True)
print(f"{CYAN}Waiting for events...{RESET}\n", flush=True)

for msg in consumer:
    if msg.topic == "external-events":
        print_event(msg, schemas)
    else:
        # job-topic messages — just print basic info
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"\n{DIM}[{ts}] job-topic  p={msg.partition}  o={msg.offset}  "
              f"len={len(msg.value)}{RESET}", flush=True)
        print(f"  {msg.value[:200]}", flush=True)