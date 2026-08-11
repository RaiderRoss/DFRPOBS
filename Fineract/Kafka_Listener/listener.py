# listener.py — Fineract Kafka external-event listener with Avro decoding.

import base64
import hashlib
import io
import json
import os
import re
import socket
import time
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

import fastavro
import requests
import urllib3
from kafka import KafkaConsumer
from kafka.errors import NoBrokersAvailable

TOPICS = ["external-events"]
BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
GROUP_ID = os.environ.get("KAFKA_GROUP_ID", "securers-ingest")
AUTO_OFFSET_RESET = os.environ.get("KAFKA_AUTO_OFFSET_RESET", "earliest")
SCHEMA_DIRS = [
    Path(os.environ.get("AVRO_SCHEMA_DIR", "/schemas")),
    Path(os.environ.get("AVRO_TEMPLATE_DIR", "/schemas-templates")),
]

SECURERS_URL = os.environ.get(
    "SECURERS_URL", "https://host.docker.internal:8443/pde/add/"
)
SECURERS_API_KEY = os.environ.get("SECURERS_API_KEY", "").strip()
SECURERS_TIMEOUT = float(os.environ.get("SECURERS_TIMEOUT", "30"))
MAX_ATTEMPTS = int(os.environ.get("SECURERS_MAX_ATTEMPTS", "10"))
DEAD_LETTER_PATH = os.environ.get("DEAD_LETTER_PATH", "").strip()
VERBOSE = os.environ.get("LISTENER_VERBOSE", "0").lower() not in ("0", "false", "no", "off")

# SecureRS uses self-signed cert generated on first start, so verification is off by default
_CA_BUNDLE = os.environ.get("SECURERS_CA_BUNDLE", "").strip()
if _CA_BUNDLE:
    VERIFY = _CA_BUNDLE
else:
    VERIFY = os.environ.get("SECURERS_VERIFY_SSL", "0").lower() not in (
        "0", "false", "no", "off",
    )
if VERIFY is False:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"


def log(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"{DIM}[{ts}]{RESET} {msg}", flush=True)


# Load all .avsc schemas
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

    raw_schemas = [] 

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
    top_level = {}
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


# Map Fineract event to SecureRS PDE model
IP_MAX, MACHINE_MAX, USER_MAX, FILENAME_MAX = 16, 50, 50, 200

def _resolve_source_ip() -> str:
    """Best-effort origin address for the evidence.

    PDE.ip is a CharField(max_length=16), so this has to be an IPv4 literal.
    """
    explicit = os.environ.get("SECURERS_SOURCE_IP", "").strip()
    if explicit:
        return explicit[:IP_MAX]
    try:
        return socket.gethostbyname(
            os.environ.get("FINERACT_HOST", "fineract-manager")
        )[:IP_MAX]
    except OSError:
        return "0.0.0.0"


SOURCE_IP = _resolve_source_ip()
MACHINE_OVERRIDE = os.environ.get("SECURERS_MACHINE", "").strip()
USER_OVERRIDE = os.environ.get("SECURERS_USER", "").strip()
# TODO:Placeholder relevance score until the anomaly detector scores events
RANK = float(os.environ.get("SECURERS_RANK", "0.0"))


def _as_user(tenant_id: str) -> str:
    """SecureRS routes per-user detail pages through `details/(?P<user>\\w+)$`,
    so anything outside [A-Za-z0-9_] would make the stored evidence
    unreachable from the UI."""
    raw = USER_OVERRIDE or f"fineract_{tenant_id or 'unknown'}"
    return (re.sub(r"\W+", "_", raw) or "fineract")[:USER_MAX]


def _as_filename(event_type: str, created_at: str, idempotency_key: str) -> str:
    stem = f"{event_type}_{created_at}_{idempotency_key}"
    return re.sub(r"[^A-Za-z0-9._-]+", "-", stem)[:FILENAME_MAX] + ".json"


def build_record(msg, schemas):
    """Decode a MessageV1 envelope into the payload SecureRS expects.

    Returns a dict of POST fields plus the document bytes, or None if the
    message could not be decoded (caller dead-letters those).
    """
    envelope_schema = schemas.get("org.apache.fineract.avro.MessageV1")
    if envelope_schema is None:
        return None, "MessageV1 schema not loaded"

    try:
        envelope = decode_avro(msg.value, envelope_schema)
    except Exception as e:
        return None, f"envelope decode failed: {e}"

    data_schema_name = envelope.get("dataschema", "")
    inner_bytes = envelope.get("data")
    payload, payload_error = None, None
    if inner_bytes and data_schema_name in schemas:
        try:
            payload = make_serialisable(decode_avro(inner_bytes, schemas[data_schema_name]))
        except Exception as e:
            payload_error = f"payload decode failed: {e}"
    elif inner_bytes:
        payload_error = f"schema '{data_schema_name}' not loaded"

    document = {
        "event": {k: v for k, v in envelope.items() if k != "data"},
        "payload": payload,
        "kafka": {
            "topic": msg.topic,
            "partition": msg.partition,
            "offset": msg.offset,
            "timestamp": msg.timestamp,
        },
        "capture": {
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "listener_group": GROUP_ID,
            "payload_error": payload_error,
        },
    }
    if payload_error:
        document["payload_raw_b64"] = base64.b64encode(inner_bytes or b"").decode()

    blob = json.dumps(document, indent=2, sort_keys=True, default=str).encode("utf-8")
    digest = hashlib.md5(blob).hexdigest()

    event_type = str(envelope.get("type", "UnknownEvent"))
    filename = _as_filename(
        event_type,
        str(envelope.get("createdAt", "")),
        str(envelope.get("idempotencyKey", f"{msg.partition}-{msg.offset}")),
    )

    return {
        "blob": blob,
        "digest": digest,
        "filename": filename,
        "event_type": event_type,
        "category": str(envelope.get("category", "?")),
        "fields": {
            "ip": SOURCE_IP,
            "machine": (MACHINE_OVERRIDE or str(envelope.get("source", "fineract")))[:MACHINE_MAX],
            "user": _as_user(str(envelope.get("tenantId", ""))),
            "rank": str(RANK),
            "filename": filename,
            "md5sum": digest,
        },
    }, None


# Submit
SESSION = requests.Session()

def submit_once(record):
    """POST one record. Returns (ok, retryable, detail)."""
    try:
        response = SESSION.post(
            SECURERS_URL,
            data=record["fields"],
            files={"pde": (record["filename"], record["blob"], "application/json")},
            headers={
                "X-API-KEY": SECURERS_API_KEY,
                "MD5SUM": record["digest"],
            },
            timeout=SECURERS_TIMEOUT,
            verify=VERIFY,
            # SecureRS sets SECURE_SSL_REDIRECT, so an http:// URL answers 301.
            # Following it would silently replay the POST as a bodyless GET so we surface it as an error instead.
            allow_redirects=False,
        )
    except requests.exceptions.RequestException as e:
        return False, True, f"{type(e).__name__}: {e}"

    if response.is_redirect:
        location = response.headers.get("Location", "?")
        return False, True, (
            f"HTTP {response.status_code} redirect to {location} — "
            "SECURERS_URL is probably http:// against an ENFORCE_SSL=True instance"
        )
    if response.status_code >= 500:
        return False, True, f"HTTP {response.status_code}"
    if response.status_code >= 400:
        return False, False, f"HTTP {response.status_code}: {response.text[:200]}"

    try:
        body = response.json()
    except ValueError:
        return False, False, f"non-JSON response: {response.text[:200]}"

    if body.get("status") == "Success":
        return True, False, ""
    return False, False, f"rejected: {body}"


def submit(record):
    """Retry transient failures with capped exponential backoff."""
    delay, detail = 1.0, "no attempt made"
    for attempt in range(1, MAX_ATTEMPTS + 1):
        ok, retryable, detail = submit_once(record)
        if ok:
            return True, ""
        if not retryable:
            return False, detail
        log(f"{YELLOW}retry {attempt}/{MAX_ATTEMPTS} in {delay:.0f}s — {detail}{RESET}")
        time.sleep(delay)
        delay = min(delay * 2, 60.0)
    return False, f"gave up after {MAX_ATTEMPTS} attempts — {detail}"


def dead_letter(msg, reason, record=None):
    """Park an event we could not file, so nothing is lost silently."""
    log(f"{RED}✗ DEAD-LETTER p{msg.partition} o{msg.offset} — {reason}{RESET}")
    if not DEAD_LETTER_PATH:
        return
    entry = {
        "reason": reason,
        "topic": msg.topic,
        "partition": msg.partition,
        "offset": msg.offset,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "raw_b64": base64.b64encode(msg.value or b"").decode(),
    }
    if record:
        entry["filename"] = record["filename"]
        entry["md5"] = record["digest"]
    try:
        path = Path(DEAD_LETTER_PATH)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError as e:
        log(f"{RED}  could not write dead-letter file: {e}{RESET}")


# Main
if not SECURERS_API_KEY:
    raise SystemExit(
        "SECURERS_API_KEY is not set. Create an API key in the SecureRS admin "
        "(https://localhost:8443/admin/ -> API Key Permissions -> API keys) and "
        "pass the full '<prefix>.<secret>' value."
    )

print(f"{BOLD}Loading Avro schemas from {SCHEMA_DIRS}...{RESET}", flush=True)
schemas = load_schemas(SCHEMA_DIRS)
print(f"Loaded {len(schemas)} schemas", flush=True)

print(f"{BOLD}SecureRS target{RESET}  {SECURERS_URL}", flush=True)
print(f"  {DIM}tls verify:{RESET} {VERIFY}", flush=True)
print(f"  {DIM}attributed:{RESET} ip={SOURCE_IP} rank={RANK}", flush=True)
print(f"  {DIM}dead-letter:{RESET} {DEAD_LETTER_PATH or '(disabled — failures are logged only)'}", flush=True)

consumer = None
while consumer is None:
    try:
        consumer = KafkaConsumer(
            bootstrap_servers=BOOTSTRAP,
            auto_offset_reset=AUTO_OFFSET_RESET,
            group_id=GROUP_ID,
            enable_auto_commit=False,
        )
        print(f"{GREEN}Connected to Kafka at {BOOTSTRAP}{RESET}", flush=True)
    except NoBrokersAvailable:
        print("Kafka not ready, retrying in 5s...", flush=True)
        time.sleep(5)

consumer.subscribe(TOPICS)
print(f"Subscribed to: {TOPICS} as group '{GROUP_ID}'", flush=True)
print(f"{CYAN}Waiting for events...{RESET}\n", flush=True)

for msg in consumer:
    if msg.topic not in TOPICS:
        consumer.commit()
        continue

    record, error = build_record(msg, schemas)
    if record is None:
        dead_letter(msg, error)
        consumer.commit()
        continue

    ok, detail = submit(record)
    if ok:
        log(
            f"{GREEN}✓{RESET} {BOLD}{record['event_type']}{RESET} "
            f"{DIM}{record['category']}  p{msg.partition} o{msg.offset}  "
            f"{len(record['blob'])}B  md5={record['digest'][:8]}…{RESET}"
        )
        if VERBOSE:
            print(record["blob"].decode("utf-8"), flush=True)
    else:
        dead_letter(msg, detail, record)

    consumer.commit()
