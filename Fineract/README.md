# Fineract Working Notes

Reference notes for poking at the running instance. For getting the stack up in
the first place, see [Fineract_Setup.md](./Fineract_Setup.md).

## Run

```bash
cp .env.example .env   # then set SECURERS_API_KEY -- fetch from SecureRS dashboard
docker compose -f docker-compose-fineract.yml up -d
```

Fineract image is pulled from Docker Hub at a pinned tag.
The listener however is built locally.

`.env` is required: the listener refuses to start without a SecureRS API key.

## Seed

```bash
chmod +x Scripts/Seeding/seed-fineract.sh
./Scripts/Seeding/seed-fineract.sh
```

Needs `jq`. Writes a timestamped log to the current directory.

> `seed-loan.sh` currently uses `$OFFICE_ID` / `$STAFF_ID` = 1 which is created during the `seed-fineract.sh` script.

## View DB

```bash
docker exec -it fineract-db-1 psql -U postgres -d fineract_default
```

Use `\dt` to list tables. The seed script touches `m_office`, `m_staff`,
`m_client`, `m_product_loan` and `m_savings_product`.

---

# External events

External events are the state-changing actions we capture and make available to
Kafka. They land in `m_external_event` with status **TO_BE_SENT**. The "Send
Asynchronous Events" scheduled job picks them up and publishes to Kafka on a
one-minute tick, but can be triggered manually:

```bash
curl -sk -X POST "https://localhost:8443/fineract-provider/api/v1/jobs/$(
  curl -sk https://localhost:8443/fineract-provider/api/v1/jobs \
    -H "Authorization: Basic $(echo -n mifos:password | base64)" \
    -H "Fineract-Platform-TenantId: default" | jq -r '.[] | select(.displayName=="Send Asynchronous Events") | .jobId'
)?command=executeJob" \
  -H "Authorization: Basic $(echo -n mifos:password | base64)" \
  -H "Fineract-Platform-TenantId: default"
```

## Viewing events

Three ways to check, in pipeline order:

- **Database** — the staging table, before anything hits Kafka. If this is
  empty, the event type is disabled (see below) and nothing downstream will
  ever fire.

```bash
docker exec -it fineract-db-1 psql -U postgres -d fineract_default \
-c "SELECT id, type, category, status, created_at, sent_at FROM m_external_event ORDER BY id DESC LIMIT 10;"
```

- **Kafka topic** — what actually landed. Raw Avro bytes, not readable.

```bash
docker exec -it fineract-kafka-1 /opt/kafka/bin/kafka-console-consumer.sh \
  --bootstrap-server localhost:9092 \
  --topic external-events \
  --from-beginning \
  --max-messages 10
```

- **Listener** — decoded and filed into SecureRS. These can be viewed after logging into SecureRS.

- **SecureRS** — the far end of the pipeline. Events appear under the
  `fineract_default` user at <https://localhost:8443/pde/>.

## Configuring Events

All 131 event types are **disabled by default**, therefore nothing will show until we configure which events we want to listen to.
Settings live in the tenant database, so they are lost on `down -v` and must be re-applied.

See what's available to turn on:

```bash
curl -sk https://localhost:8443/fineract-provider/api/v1/externalevents/configuration \
  -H "Authorization: Basic $(echo -n mifos:password | base64)" \
  -H "Fineract-Platform-TenantId: default" | jq .
```

Turn on collection for specific types:

```bash
curl -sk -X PUT https://localhost:8443/fineract-provider/api/v1/externalevents/configuration \
  -H "Authorization: Basic $(echo -n mifos:password | base64)" \
  -H "Fineract-Platform-TenantId: default" \
  -H "Content-Type: application/json" \
  -d '{
    "externalEventConfigurations": {
      "ClientActivateBusinessEvent": true,
      "ClientCreateBusinessEvent": true,
      "LoanCreatedBusinessEvent": true,
      "LoanApprovedBusinessEvent": true,
      "LoanDisbursalBusinessEvent": true,
      "LoanRepaymentTransactionBusinessEvent": true,
      "SavingsActivateBusinessEvent": true,
      "SavingsDepositBusinessEvent": true
    }
  }'
```

---

# Kafka

Runs in KRaft mode — no ZooKeeper. Two topics, both auto-created on first use:

| Topic | Written by | Read by |
|-------|-----------|---------|
| `external-events` | manager | `Kafka_Listener` |
| `job-topic` | manager | worker |

The compose file runs 1 manager and 1 worker (`replicas: 1`), which is enough
at our scale. To add workers, raise `replicas` and widen the published range —
it is already `8444-8445:8443`, so two workers fit without further changes.

Jobs are dispatched over Kafka rather than Spring events, because the
Spring-events handler only works when manager and worker share a JVM. That is
set in `config/docker/env/kafka-client.env`; emptying that file makes the
manager fail startup validation.

## Avro schemas

The listener decodes events using the `.avsc` files vendored in
`Kafka_Listener/schemas/`, baked into its image at build time. They are a pinned
copy from Fineract's `fineract-avro-schemas/src/main/`, matching the image tag
in the compose file.

After editing `listener.py` or the schemas:

```bash
docker compose -f docker-compose-fineract.yml up -d --build listener
```

Fineract's `.avsc` files use `bigdecimal` as a type alias, which is not a real
Avro named type — `listener.py` inlines it before parsing.

---

# SecureRS ingestion

The listener does not just print events — it files each one into the SecureRS
evidence repository (`../Evidence Repository/SecureRS`) as a potential digital
evidence (PDE) record.

## Pipeline

```
Fineract ──▶ m_external_event ──▶ Kafka(external-events) ──▶ listener ──▶ SecureRS /pde/add/
                                                                 │
                                                                 └─▶ /dead-letter/events.jsonl
```

Each event becomes one JSON document — the decoded `MessageV1` envelope, the
decoded payload, the Kafka coordinates it arrived on, and the time the listener
observed it — POSTed as a file upload. SecureRS hashes it on the way in,
encrypts it at rest, and gives it a random on-disk name.

## Setup

1. **Move SecureRS off port 8443.** `fineract-manager` already publishes 8443
   and the workers hold 8444–8445. In `Evidence Repository/SecureRS/.env`:

   ```
   HTTPS_PORT=9443
   SITE_URL=https://localhost:9443/
   ENFORCE_SSL=True
   ```

   Then `docker compose up -d` that project. This is the only change the
   SecureRS side needs, and it is a gitignored `.env`, not code.

2. **Create an API key.** Log in at <https://localhost:9443/admin/> →
   *API Key Permissions* → *API keys* → *Add*. The full `<prefix>.<secret>`
   value is shown **once**, at creation.

3. **Point the listener at it.** `cp .env.example .env`, set
   `SECURERS_API_KEY`, then:

   ```bash
   docker compose -f docker-compose-fineract.yml up -d --build listener
   ```

Stored evidence appears under the user `fineract_default` (`fineract_` + the
Fineract tenant id) at <https://localhost:9443/pde/>.

## Field mapping

`pde.models.PDE` is narrow and `pde.views.add` does no validation beyond the
hash check. A missing or oversized field surfaces as a 500 error.
The listener therefore clamps everything to the column widths:

| PDE column | Source | Notes |
|---|---|---|
| `pde` | the JSON document | the evidence artefact itself |
| `hash` / `MD5SUM` | MD5 of that document | checked twice; header must match the form field |
| `user` | `fineract_<tenantId>` | sanitised to `\w+`, or the details page 404s |
| `machine` | envelope `source` | truncated to 50 |
| `ip` | resolved `fineract-manager` | IPv4 only — the column is 16 chars |
| `rank` | `SECURERS_RANK` | placeholder `0.0` until the anomaly detector scores events |
| `filename` | `<type>_<createdAt>_<idempotencyKey>.json` | label only; on-disk name is randomised |

## Delivery guarantees

Offsets are committed only after SecureRS accepts an event, so a repository
outage replays rather than drops. The trade-off is **at-least-once**: a crash
between the POST and the commit re-files that event, and SecureRS has no unique
constraint to collapse the duplicate. The envelope's `idempotencyKey` is stored
in every document, so duplicates are identifiable after the fact.

Transient failures (connection refused, 5xx, an unexpected redirect) retry with
exponential backoff. Permanent ones (403 from a bad key, or SecureRS answering
`{"status": "Error"}`) are written to the dead-letter volume rather than
retried forever:

```bash
docker compose -f docker-compose-fineract.yml exec listener cat /dead-letter/events.jsonl
```

Each line holds the failure reason plus the original Kafka bytes, base64'd, so
nothing is lost.
