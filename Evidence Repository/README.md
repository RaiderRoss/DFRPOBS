# DFRaaS — Digital Forensic Readiness as a Service

## What it is
A digital evidence management system for a bank, running alongside existing infrastructure. It automatically collects and preserves evidence for defined security/incident events (triggered by SIEM, IDS, or similar), and lets investigators retrieve that evidence later.

Design is inspired by two references:
- **K-FFRaaS** — a forensic readiness *process model* for financial institutions (based on ISO/IEC 27043), organized into Planning, Implementation, and Assessment phases. It defines the "work group" concept and the readiness-before-investigation philosophy.
- **SecureRS** (Singh, Ikuesan & Venter, 2022, IEEE Access) — a concrete secure-storage *engineering pattern*: hash files before any other processing touches them, encrypt at rest (AES), verify integrity on access, and gate downloads behind OTP/2FA.

K-FFRaaS shapes the domain model and process states.
SecureRS shapes the ingestion/storage/integrity mechanics — and modified/scaled for finance-sector use rather than used as-is.

## Base architecture (Java)
Backend (Java, Spring Boot) is layered as:
`SecurityConfiguration → _Resource (API layer) → _Service (business logic) → _Repository (persistence) → Entity`, with `DTO` + `Mapper` classes shaping what the API exposes, and Liquibase (`Master.xml` + changesets) managing schema.

## Current data model
- **WorkGroup** — `id, name, classificationCode` — the business-unit classification evidence is tagged with (K-FFRaaS concept).
- **TriggerEvent** — `id, externalEventId, sourceSystem, triggerType, firedAt, receivedAt, payload, payloadSha256` — the SIEM/IDS alert that caused ingestion. Four fields beyond the original sketch, each load-bearing: `externalEventId` is the source's own identifier and the only thing dedupe can key on (`id` is generated here, so it never repeats across deliveries); `receivedAt` is the database's account of when we saw the alert, kept distinct from the sender-supplied `firedAt`; and `payload` + `payloadSha256` retain the original alert and its digest, because the alert is itself part of the evidentiary record. Unique on `(sourceSystem, externalEventId)` — composite, because alert numbering is per-vendor.
- **EvidenceItem** — `id, workGroupId, triggerEventId, storageRef, currentHash, status` — the hub entity; references the stored object and its current integrity state.
- **CustodyEvent** — `id, evidenceItemId, action, performedBy, previousHash, newHash, occurredAt` — append-only chain-of-custody ledger; every state-changing action on evidence creates one.
- **IntegrityCheck** — `id, evidenceItemId, computedHash, matchesStored, checkedAt` — periodic/on-demand re-verification, separate from custody events, matching SecureRS's verify-on-read pattern.
- **AppUser** — `id, username, role, mfaEnabled`.
- **AccessLog** — `id, evidenceItemId, userId, action, occurredAt` — every read/view, logged separately from custody-changing actions (compliance requirement).

## Storage & infrastructure
- **MinIO** — evidence blob storage (object storage), referenced by `EvidenceItem.storageRef`. Should use envelope encryption via a real KMS/HSM (not a static key in config, which is what the SecureRS prototype does).
- **Postgres** — all metadata/entities, managed via Liquibase.
- **Kafka** (Redpanda locally, for lightweight Kafka-API-compatible dev) — decouples SIEM/IDS trigger publishing from the ingestion pipeline. Topic `evidence-events`, currently planned to partition by `workGroupId` 
- Ingestion consumer is **idempotent**, deduping on `(sourceSystem, externalEventId)` inside a single transaction backed by `uq_trigger_event_source_external`, since Kafka's default delivery is at-least-once.
- Poison messages (unparseable or invalid) are logged and skipped rather than retried, because a malformed payload fails identically forever and would block its partition. They should go to a dead-letter topic — not yet wired.
- Schema registry (Avro/Protobuf) recommended for the evidence-event schema as it evolves.
- Kafka retention/compaction policy for raw trigger events is a separate decision from MinIO's evidence retention policy.

## Security & compliance principles (from SecureRS, adapted)
- Hash evidence (SHA-256+) **before** any other processing touches it, on ingest.
- Re-verify hash on every read/export, not just at ingest.
- Encrypt at rest via KMS/HSM-backed envelope encryption.
- OTP/2FA step-up authentication specifically gating evidence **export/download** actions, enforced in `SecurityConfiguration`.
- Internal service-to-service auth via OAuth2/mTLS rather than static API keys (finance-grade requirement, vs. SecureRS prototype's static keys).
- Evidence records are **soft-delete only** — never hard-deleted.
- Compliance target is jurisdiction-appropriate (e.g. POPIA/GDPR/SOC 2/PCI-DSS as relevant) rather than CJIS, which is US law-enforcement specific.
- Schema migrations are themselves auditable events — reviewed and versioned carefully.

## Project scaffolding
- **Mono-repo**: `/backend` (Spring Boot/Java), `/frontend`, `/docs` (diagrams), `docker-compose.yml` at repo root.
- **Backend packages** mirror the layered architecture: `config, resource, service, repository, entity, dto, mapper`, plus `exception` for the domain exceptions the service layer raises and the API layer translates.
- **Liquibase** changelog structure: `db.changelog-master.xml` includes numbered changesets under `changes/`.
- **Local dev stack** (`docker-compose.yml`, repo root): Postgres, MinIO (+ auto bucket-creation init container), Redpanda (+ console UI for topic inspection).

## Running locally

Prerequisites: JDK 21, Docker, and the bundled Maven wrapper.

```bash
cp .env.example .env          # dev-only placeholder credentials
docker compose up -d          # Postgres, MinIO (+bucket), Redpanda (+console)
cd backend && ./mvnw spring-boot:run
```

Liquibase applies liquibase changes on first boot, the app then listens on 8080.
`./mvnw test` runs the suite against Testcontainers and needs no running stack.

| Service          | URL / port                    | Dev credentials             |
|------------------|-------------------------------|-----------------------------|
| Backend API      | http://localhost:8080         | `admin` / `admin` (Basic)   |
| Actuator health  | http://localhost:8080/actuator/health | open (no auth)      |
| Postgres         | `localhost:5433`              | `dfraas` / `dfraas_dev_only`|
| MinIO console    | http://localhost:9001         | `dfraas_admin` / `dfraas_dev_only` |
| Kafka (Redpanda) | `localhost:19092`             | none                        |
| Redpanda console | http://localhost:8081         | none                        |
| Swagger          | http://localhost:8080/swagger-ui/index.html | none          |

Two host ports differ from the in-container defaults, both because the app runs on the
host while its dependencies run in Docker:

- **Postgres is published on 5433, not 5432**, because a host-level Postgres already
  occupies 5432 on at least one dev machine. Inside the compose network it is still 5432.
- **Kafka is published on 19092, not 9092.** Redpanda runs two listeners: `internal`
  (`redpanda:9092`, for containers such as redpanda-console) and `external`
  (`localhost:19092`, for the host-run app). A Kafka client bootstraps and is then
  redirected to whatever address the broker *advertises*, so a host client pointed at 9092
  would connect once and then fail on the unresolvable `redpanda` hostname — which is why
  9092 is deliberately not published to the host.

All credentials above are dev-only placeholders

## Open questions
1. Whether WorkGroup classification on ingest is fully automated (mapping table from SIEM alert type) or requires human review before storage.
2. **`EvidenceItem` → `TriggerEvent` cardinality and nullability.** The relationship is one-to-many, not one-to-one: a single alert can reasonably preserve several artifacts (auth log, firewall log, DB audit trail), so the FK stays on `EvidenceItem` and must *not* be given a unique constraint. The open part is nullability, and the answer looks like `NULL`-able: a `NOT NULL` `trigger_event_id` means evidence can only exist because an alert fired, which makes the system purely reactive and abandons the readiness half of K-FFRaaS — scheduled preservation, compliance holds and manual preservation by an investigator all have no trigger event. Provenance is not lost by allowing null, because every `EvidenceItem` gets a mandatory opening `CustodyEvent` carrying `performedBy` and `action`; that is the universal provenance record, and `TriggerEvent` is the narrower automated *cause* when there was one. Explicitly rejected: synthesising a placeholder `TriggerEvent` for manual preservation, which would mean inventing an alert that never fired in the one table whose job is to record alerts that did.
3. **Ingestion is not yet resumable, and this is a latent data-loss bug.** `recordIfAbsent` commits the trigger event, then `EvidenceEventConsumer` returns early whenever `created == false`. If the consumer dies (or MinIO is unavailable) after that commit but before the blob is stored, the Kafka offset was never committed, so the record is redelivered — and on redelivery the trigger event exists, `created` is `false`, and the consumer returns early. No `EvidenceItem` is ever created, silently and permanently. The dedupe key is currently *"has this alert been recorded"* when it needs to be *"has this alert been fully processed"*. Options: (a) one transaction over everything — rejected, the MinIO write sits outside the database transaction and reintroduces the dual-write problem; (b) early-return only when the trigger event already has evidence items — correct but turns the guard into a join, and gets murky once one trigger legitimately yields several items over time; (c) **preferred** — a processing state on `TriggerEvent` (`RECEIVED` → `PROCESSED`, plus a terminal `FAILED`), resuming when the state is `RECEIVED` and skipping only on `PROCESSED`. Unlike `EvidenceStatus` this set is closed and internal, so it is a safe place for a native Postgres enum. It also makes *"which alerts were received but never preserved"* queryable, which is precisely the question a readiness audit asks and which nothing in the schema can currently answer. To be resolved with the `EvidenceItem` changeset, since the guard has nothing to check until then.
4. **How manual and scheduled preservation enter the system.** Kafka is currently the only ingress — `TriggerEventResource` exposes no create endpoint, and a test asserts `405`. Anything may produce to `evidence-events`, and `sourceSystem`. Question is whether to add manual replay and scheduled collection. Should this publish to the topic or bypass trigger events entirely and create an `EvidenceItem` with a null `trigger_event_id` per item 3.
5. `EvidenceItem`, `CustodyEvent`, `IntegrityCheck`, `AppUser` and `AccessLog` remain unwritten, and each needs its own Liquibase changeset first. Planned order: `AppUser` next (so custody and access records have a real subject to reference before the append-only tables exist), then `EvidenceItem`, `CustodyEvent`, `IntegrityCheck`, `AccessLog`.
6. `EvidenceEventConsumer` records and hashes the trigger event, but the storage half — MinIO blob, `EvidenceItem`, opening `CustodyEvent`, one transaction — is still TODO 3 and blocked on those entities.
