# DFRaaS — Digital Forensic Readiness as a Service

## What it is
A digital evidence management system for a bank, running alongside existing infrastructure. It automatically collects and preserves evidence for defined security/incident events (triggered by SIEM, IDS, or similar), and lets investigators retrieve that evidence later.

Design is inspired by two references:
- **K-FFRaaS** — a forensic readiness *process model* for financial institutions (based on ISO/IEC 27043), organized into Planning, Implementation, and Assessment phases. It defines the "work group" concept and the readiness-before-investigation philosophy.
- **SecureRS** (Singh, Ikuesan & Venter, 2022, IEEE Access) — a concrete secure-storage *engineering pattern*: hash files before any other processing touches them, encrypt at rest (AES), verify integrity on access, and gate downloads behind OTP/2FA.

The system is being adapted from both — K-FFRaaS shapes the domain model and process states, SecureRS shapes the ingestion/storage/integrity mechanics — and modified/scaled for finance-sector use rather than used as-is.

## Base architecture (Java)
Backend (Java, Spring Boot) is layered as:
`SecurityConfiguration → _Resource (API layer) → _Service (business logic) → _Repository (persistence) → Entity`, with `DTO` + `Mapper` classes shaping what the API exposes, and Liquibase (`Master.xml` + changesets) managing schema.

## Current data model
- **WorkGroup** — `id, name, classificationCode` — the business-unit classification evidence is tagged with (K-FFRaaS concept).
- **TriggerEvent** — `id, sourceSystem, triggerType, firedAt` — the SIEM/IDS alert that caused ingestion.
- **EvidenceItem** — `id, workGroupId, triggerEventId, storageRef, currentHash, status` — the hub entity; references the stored object and its current integrity state.
- **CustodyEvent** — `id, evidenceItemId, sequence, action, performedBy, performedByUsername, previousHash, newHash, occurredAt` — append-only chain-of-custody ledger, hash-chained per evidence item. Every action on an item appends one. See [Chain of custody](#chain-of-custody) for the chaining rule and what it does and does not prove. `performedByUsername` is a denormalised snapshot alongside the `performedBy` FK: the AppUser row can be renamed or removed, and a custody entry has to remain readable on its own years later.
- **IntegrityCheck** — `id, evidenceItemId, computedHash, matchesStored, checkedAt` — periodic/on-demand re-verification, separate from custody events, matching SecureRS's verify-on-read pattern.
- **AppUser** — `id, username, role, mfaEnabled`.
- **AccessLog** — `id, evidenceItemId, userId, action, occurredAt` — every read/view, logged separately from custody-changing actions (compliance requirement). **Unresolved:** this overlaps the custody chain now that reads are custody events — see open question 4.

## Chain of custody

Every EvidenceItem owns one chain, and the chain answers **what**, **when** and **by
whom** for everything that happens to that item — creation, hashing, reading, export,
relocation, status change. One ordered ledger per item, not a log per action type.

**The chaining rule.** Each entry's hash covers the previous entry's hash:

```
newHash = H( previousHash ‖ canonical(event) )
```

- The **first** entry is the item's own `CREATED` event, not an empty file. An item that
  exists with an empty chain has an unexplained origin.
- Genesis uses a **fixed constant** for `previousHash` rather than null, so verification
  is one uniform loop instead of a special case that has to be right twice.
- `canonical(event)` must be **frozen and versioned** — field order, encoding, timestamp
  precision. The day serialisation changes, every historical chain stops verifying and
  you cannot distinguish tampering from a format change.

**Ordering.** `sequence` is per item, with a unique constraint on
`(evidenceItemId, sequence)`. Without it two concurrent actions both read the same
`previousHash` and the chain forks — the same check-then-act gap the ingestion consumer
has to close on `triggerEventId`, and a unique constraint is again what actually closes
it rather than a preceding lookup.

**Transactionality.** A custody entry is written in the *same transaction* as the action
it records. A crash between "moved the object" and "logged the move" leaves evidence with
an unexplained gap, which is the one thing custody must never have. This is the reason
the ledger is a **table and not a file**: a file write cannot enlist in the Postgres
transaction. A custody *file* is derived on demand for export or handover — the table
stays authoritative, so there is never a question of which one wins.

**What the chain proves, and what it does not.** Linked hashes make *modification of an
interior entry* detectable. On their own they do not detect:

- **Truncation** — remove the last N entries and what remains still verifies cleanly.
  Nothing inside the chain states how long it ought to be.
- **Wholesale re-chaining** — anyone who can write the ledger can recompute every hash
  from genesis and produce a valid chain saying whatever they like.

Which means the chain alone is defeated by precisely the actor forensic readiness exists
to catch: the insider with write access. It needs at least one of:

- append-only enforced **below** the application (Postgres permissions or a trigger
  rejecting `UPDATE`/`DELETE` on the custody table; MinIO object-lock for exported files)
- the head hash **anchored** somewhere the writer does not control — a WORM bucket, a
  signed timestamp, a second system. Even periodic anchoring bounds how much history can
  be silently rewritten
- **per-entry signatures**, so forging requires a key rather than database access

Until one of those exists, the honest claim is "a consistent chain", not "the chain".

## Storage & infrastructure
- **MinIO** — evidence blob storage (object storage), referenced by `EvidenceItem.storageRef`. Should use envelope encryption via a real KMS/HSM (not a static key in config, which is what the SecureRS prototype does).
- **Postgres** — all metadata/entities, managed via Liquibase.
- **Kafka** (Redpanda locally, for lightweight Kafka-API-compatible dev) — decouples SIEM/IDS trigger publishing from the ingestion pipeline. Topic `evidence-events`, currently planned to partition by `workGroupId` (tradeoff: guarantees ordering within a work group, but risks a "hot" partition if one work group generates disproportionate alert volume — composite keying by `sourceSystem + workGroupId` was discussed as an alternative, not yet decided).
  - Ingestion consumer must be **idempotent** (dedupe on `triggerEventId`), since Kafka's default delivery is at-least-once.
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
2. Final Kafka partition key strategy (`workGroupId` alone vs. composite key).
3. How the custody chain is anchored, and how append-only is enforced beneath the
   application. Without one of these the chain is tamper-evident against partial edits
   only, and re-chaining by anyone with write access stays undetectable. Deciding this
   is what turns "hash chained" into a defensible admissibility claim, so it is a
   prerequisite for the custody work rather than a follow-up to it.
4. Whether reads live in the custody chain or in `AccessLog`. The two currently overlap:
   the data model says reads are logged separately, while the custody design treats
   reading as a custody event. Two records of who-read-what will drift, and a court
   asking "who accessed this" should not get two answers. Leaning towards one chain per
   item with `AccessLog` as a projection over it — a read genuinely is custody-relevant,
   and one ordered ledger is easier to defend than two logs that must be reconciled. The
   cost is volume, since reads dominate, so verification would need to be incremental
   rather than re-hashing from genesis on every check.
5. `WorkGroup` is now implemented end to end (entity → repository → DTO → mapper → service → resource, at `/api/work-groups`) and serves as the template for the entities that follow. It exposes read and create only: update/delete need the soft-delete and custody semantics described above, which are not built yet. `TriggerEvent`, `EvidenceItem`, `CustodyEvent`, `IntegrityCheck`, `AppUser` and `AccessLog` remain unwritten, and each needs its own Liquibase changeset first.