# Fineract Setup

How to run the Fineract stack used by this project, and how to get external
events flowing into the Kafka listener.

You do **not** need to clone or build Fineract. Earlier versions of this guide
described a Gradle `jibDockerBuild` from a local checkout inside WSL; that is no
longer how this works. The Fineract image is pulled from Docker Hub at a pinned
tag, and everything the stack needs is committed to this repo.

---

## Prerequisites

- [Docker Desktop](https://docs.docker.com/desktop/) (on Windows, with the WSL 2
  backend enabled). This is the only hard requirement.
- `curl` — for API calls. Ships with Windows 10+, macOS, and most Linux distros.
- `jq` — only needed for the seeding scripts and the JSON snippets below.
  Not included with Git Bash on Windows; `winget install jqlang.jq`.

No JDK, no Gradle, no Fineract source checkout. The stack runs identically from
PowerShell, Git Bash, WSL, macOS, and Linux — both images are multi-arch
(amd64 + arm64), so Apple Silicon works without emulation.

---

## Layout

```
DFRPOBS/
├── .gitattributes                  # forces LF endings (see Troubleshooting)
├── Anomaly Detection/
├── Evidence Repository/
└── Fineract/                       # <- you are here
    ├── docker-compose-fineract.yml # the whole stack
    ├── config/docker/
    │   ├── compose/postgresql.yml  # db service, extended by the compose file
    │   ├── env/                    # per-service environment
    │   └── postgresql/docker-entrypoint-initdb.d/01-init.sh
    ├── Kafka_Listener/
    │   ├── Dockerfile
    │   ├── listener.py             # consumes external-events, decodes Avro
    │   └── schemas/                # vendored .avsc files (see below)
    └── Scripts/
        ├── config.sh
        ├── reset_db.sh
        ├── Seeding/
        └── Scenarios/
```

### About `Kafka_Listener/schemas/`

The Avro schemas the listener needs to decode events are **not** part of the
published Fineract image — they live in Fineract's source tree. Rather than
require every developer to keep a Fineract checkout, the 83 `.avsc` files are
vendored into this repo and baked into the listener image at build time.

They are a pinned copy taken from `fineract-avro-schemas/src/main/` at the same
commit as the image tag below. **If you bump the Fineract image tag, re-copy the
schemas to match**, or the listener will fail to decode changed event payloads.

---

## Start the stack

From the `Fineract/` directory:

```bash
docker compose -f docker-compose-fineract.yml up -d
```

First run pulls a few hundred MB and takes a couple of minutes. After that,
startup is roughly 90 seconds — Compose waits for the manager's healthcheck
before starting the worker, so `up` returning means the stack is genuinely
ready, not just launched.

Verify:

```bash
curl -k https://localhost:8443/fineract-provider/actuator/health
# {"status":"UP","groups":["liveness","readiness"]}
```

`-k` is required throughout: Fineract serves HTTPS with a self-signed cert.

### What runs

| Service            | Host port | Purpose                                        |
|--------------------|-----------|------------------------------------------------|
| `fineract-manager` | 8443      | API + batch manager. This is the one you call.  |
| `fineract-worker`  | 8444      | Batch worker; takes jobs over Kafka.            |
| `db`               | 5432      | PostgreSQL 18.3.                                |
| `kafka`            | 9092      | KRaft mode, no ZooKeeper.                       |
| `listener`         | –         | Consumes `external-events`, prints decoded JSON.|

On first boot `01-init.sh` creates the `postgres` role plus the
`fineract_tenants` and `fineract_default` databases; Fineract then runs its
Liquibase migrations. Both Kafka topics (`external-events`, `job-topic`) are
auto-created.

---

## Enable external events (required)

**All 131 external event types ship disabled.** Until you turn some on, the
`m_external_event` table stays empty, nothing reaches Kafka, and the listener
sits at `Waiting for events...` looking broken. This is stock Fineract
behaviour, not a misconfiguration.

See what is available:

```bash
curl -sk https://localhost:8443/fineract-provider/api/v1/externalevents/configuration \
  -H "Authorization: Basic $(echo -n mifos:password | base64)" \
  -H "Fineract-Platform-TenantId: default" | jq .
```

Turn on the ones you need:

```bash
curl -sk -X PUT https://localhost:8443/fineract-provider/api/v1/externalevents/configuration \
  -H "Authorization: Basic $(echo -n mifos:password | base64)" \
  -H "Fineract-Platform-TenantId: default" \
  -H "Content-Type: application/json" \
  -d '{
    "externalEventConfigurations": {
      "ClientCreateBusinessEvent": true,
      "ClientActivateBusinessEvent": true,
      "LoanCreatedBusinessEvent": true,
      "LoanApprovedBusinessEvent": true,
      "LoanDisbursalBusinessEvent": true,
      "LoanRepaymentTransactionBusinessEvent": true,
      "SavingsActivateBusinessEvent": true,
      "SavingsDepositBusinessEvent": true
    }
  }'
```

This is per-tenant database state, so it does **not** survive wiping the
database with `down -v`. Re-run it after any reset.

---

## Watch events flow

Create something:

```bash
curl -sk -X POST https://localhost:8443/fineract-provider/api/v1/clients \
  -H "Authorization: Basic $(echo -n mifos:password | base64)" \
  -H "Fineract-Platform-TenantId: default" \
  -H "Content-Type: application/json" \
  -d '{"officeId":1,"legalFormId":1,"firstname":"Test","lastname":"Client",
       "active":true,"activationDate":"1 January 2026",
       "dateFormat":"dd MMMM yyyy","locale":"en"}'
```

Then watch the listener decode it:

```bash
docker logs -f fineract-listener-1
```

Events are written to `m_external_event` with status `TO_BE_SENT` and published
by the **Send Asynchronous Events** job, which runs on a one-minute tick — so
expect up to ~60s of lag. To push them immediately:

```bash
JOB_ID=$(curl -sk https://localhost:8443/fineract-provider/api/v1/jobs \
  -H "Authorization: Basic $(echo -n mifos:password | base64)" \
  -H "Fineract-Platform-TenantId: default" \
  | jq -r '.[] | select(.displayName=="Send Asynchronous Events") | .jobId')

curl -sk -X POST "https://localhost:8443/fineract-provider/api/v1/jobs/${JOB_ID}?command=executeJob" \
  -H "Authorization: Basic $(echo -n mifos:password | base64)" \
  -H "Fineract-Platform-TenantId: default"
```

Inspect the outbox directly, or read the topic raw:

```bash
docker exec -it fineract-db-1 psql -U postgres -d fineract_default \
  -c "SELECT id, type, status, created_at, sent_at FROM m_external_event ORDER BY id DESC LIMIT 10;"

docker exec -it fineract-kafka-1 /opt/kafka/bin/kafka-console-consumer.sh \
  --bootstrap-server localhost:9092 --topic external-events \
  --from-beginning --max-messages 10
```

(The console consumer prints raw Avro bytes — the listener is what decodes them.)

---

## API basics

Default admin credentials:

| | |
|-|-|
| Username | `mifos` |
| Password | `password` |
| Tenant   | `default` |

Every request needs:

```bash
-H "Authorization: Basic $(echo -n mifos:password | base64)" \
-H "Fineract-Platform-TenantId: default" \
-H "Content-Type: application/json"
```

Base URL: `https://localhost:8443/fineract-provider/api/v1`

---

## Common commands

Run from `Fineract/`. All work from any shell on any OS.

| Task | Command |
|------|---------|
| Start | `docker compose -f docker-compose-fineract.yml up -d` |
| Stop (keep data) | `docker compose -f docker-compose-fineract.yml down` |
| Stop and wipe data | `docker compose -f docker-compose-fineract.yml down -v` |
| Rebuild listener after editing `listener.py` or schemas | `docker compose -f docker-compose-fineract.yml up -d --build listener` |
| Follow API logs | `docker logs -f fineract-fineract-manager-1` |
| Follow decoded events | `docker logs -f fineract-listener-1` |
| psql shell | `docker exec -it fineract-db-1 psql -U postgres -d fineract_default` |
| List Kafka topics | `docker exec -it fineract-kafka-1 /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --list` |
| Health | `curl -k https://localhost:8443/fineract-provider/actuator/health` |

After `down -v` you must re-enable external event types (see above).