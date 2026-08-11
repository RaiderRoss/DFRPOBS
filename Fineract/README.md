# Fineract Working Notes

Reference notes for poking at the running instance. For getting the stack up in
the first place, see [Fineract_Setup.md](./Fineract_Setup.md).

## Run

```bash
docker compose -f docker-compose-fineract.yml up -d
```

No build step — the Fineract image is pulled from Docker Hub at a pinned tag.
(This used to be `./gradlew :fineract-provider:jibDockerBuild` against a local
checkout plus `docker-compose-postgresql-kafka.yml`; both are gone.)

## Seed

```bash
chmod +x Scripts/Seeding/seed-fineract.sh
./Scripts/Seeding/seed-fineract.sh
```

Needs `jq`. Writes a timestamped log to the current directory.

> `seed-client.sh` is currently broken — it uses `$OFFICE_ID` / `$STAFF_ID`
> without setting them.

## View DB

```bash
docker exec -it fineract-db-1 psql -U postgres -d fineract_default
```

Use `\dt` to list tables. The seed script touches `m_office`, `m_staff`,
`m_client`, `m_product_loan` and `m_savings_product`.

Tenant registry (rarely needed) lives in a separate database:

```bash
docker exec -it fineract-db-1 psql -U postgres -d fineract_tenants
```

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

- **Listener** — decoded and pretty-printed, which is usually what you want:

```bash
docker logs -f fineract-listener-1
```

## Configuring Events

All 131 event types are **disabled by default** — this is the single most common
reason nothing shows up. Settings live in the tenant database, so they are lost
on `down -v` and must be re-applied.

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
in the compose file — **re-copy them if you bump that tag**.

After editing `listener.py` or the schemas:

```bash
docker compose -f docker-compose-fineract.yml up -d --build listener
```

Fineract's `.avsc` files use `bigdecimal` as a type alias, which is not a real
Avro named type — `listener.py` inlines it before parsing, mirroring what the
Gradle codegen does.
