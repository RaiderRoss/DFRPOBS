# DFRaaS — Digital Forensic Readiness as a Service

## What it is
A digital evidence management system for a bank, running alongside existing infrastructure. It automatically collects and preserves evidence for defined security/incident events (triggered by SIEM, IDS, or similar), and lets investigators retrieve that evidence later.

Design is inspired by two references:
- **K-FFRaaS** — a forensic readiness *process model* for financial institutions (based on ISO/IEC 27043), organized into Planning, Implementation, and Assessment phases. It defines the "work group" concept and the readiness-before-investigation philosophy.
- **SecureRS** (Singh, Ikuesan & Venter, 2022, IEEE Access) — a concrete secure-storage *engineering pattern*: hash files before any other processing touches them, encrypt at rest (AES), verify integrity on access, and gate downloads behind OTP/2FA.

The system is being adapted from both — K-FFRaaS shapes the domain model and process states, SecureRS shapes the ingestion/storage/integrity mechanics — and modified/scaled for finance-sector use rather than used as-is.

## Base architecture (layered, Java + Vue)
Backend (Java, Spring Boot) is layered as:
`SecurityConfiguration → _Resource (API layer) → _Service (business logic) → _Repository (persistence) → Entity`, with `DTO` + `Mapper` classes shaping what the API exposes, and Liquibase (`Master.xml` + changesets) managing schema.

Frontend (Vue) follows: `Index.ts → .vue views / .component.ts controllers → .Service.ts`, calling the backend API layer.

## Key design decision: readiness vs. investigation are separate
Evidence collection happens continuously and automatically (K-FFRaaS "readiness"), independent of whether any formal investigation ever occurs. A **Case** is a separate, later concept that could allow linking of evidence via a many-to-many join.

**Case is deferred as an optional future extension.** Current focus is the evidence/integrity/custody core only.

## Current data model (core, Case excluded for now)
- **WorkGroup** — `id, name, classificationCode` — the business-unit classification evidence is tagged with (K-FFRaaS concept).
- **TriggerEvent** — `id, sourceSystem, triggerType, firedAt` — the SIEM/IDS alert that caused ingestion.
- **EvidenceItem** — `id, workGroupId, triggerEventId, storageRef, currentHash, status` — the hub entity; references the stored object and its current integrity state.
- **CustodyEvent** — `id, evidenceItemId, action, performedBy, previousHash, newHash, occurredAt` — append-only chain-of-custody ledger; every state-changing action on evidence creates one.
- **IntegrityCheck** — `id, evidenceItemId, computedHash, matchesStored, checkedAt` — periodic/on-demand re-verification, separate from custody events, matching SecureRS's verify-on-read pattern.
- **AppUser** — `id, username, role, mfaEnabled`.
- **AccessLog** — `id, evidenceItemId, userId, action, occurredAt` — every read/view, logged separately from custody-changing actions (compliance requirement).

**Deferred (future extension):**
- **Case** — `id, caseNumber, status, openedAt`
- **CaseEvidenceLink** — `id, caseId, evidenceItemId, linkedByUserId, linkedAt` — join entity; an evidence item can belong to multiple cases and vice versa.

**Decided:** `EvidenceStatus` / `CustodyAction` are **Postgres native enum types** (`CREATE TYPE ... AS ENUM`), chosen for DB-level integrity given the compliance context. Consequences to plan for (verified against Postgres 16.15):

- JPA needs `@JdbcTypeCode(SqlTypes.NAMED_ENUM)` on those fields.
- `ALTER TYPE ... ADD VALUE` *does* run inside a transaction on PG12+, but the new value **cannot be used in that same transaction** (`ERROR: unsafe use of new value`). So a changeset that adds a status and then backfills rows to it must be split into two changesets.
- There is no `DROP VALUE` in Postgres. Removing a value means recreating the type and rewriting every dependent column, so rollbacks are effectively forward-only.
- Net effect: the value set is expensive to change after the fact, which raises the cost of guessing wrong up front — see open question 1.

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

## Project scaffolding decisions
- **Mono-repo**: `/backend` (Spring Boot/Java), `/frontend` (Vue/Vite), `/docs/architecture` (diagrams), `docker-compose.yml` at repo root.
- **Backend packages** mirror the layered architecture: `config, resource, service, repository, entity, dto, mapper`.
- **Liquibase** changelog structure: `db.changelog-master.xml` includes numbered changesets under `changes/`. First changesets built: `0000-enable-extensions` (pgcrypto for `gen_random_uuid()`) and `0001-create-work-group-table` (with seed data), each with rollback blocks. Files live at `backend/src/main/resources/liquibase/`.
- **Local dev stack** (`docker-compose.yml`, repo root): Postgres, MinIO (+ auto bucket-creation init container), Redpanda (+ console UI for topic inspection).
- **Conventions locked early**: Spotless/Checkstyle (Java), ESLint + Prettier (Vue), enforced before feature code is written.

## Running locally

Prerequisites: JDK 21, Docker, and the bundled Maven wrapper (no local Maven needed).

```bash
cp .env.example .env          # dev-only placeholder credentials
docker compose up -d          # Postgres, MinIO (+bucket), Redpanda (+console)
cd backend && ./mvnw spring-boot:run
```

Liquibase applies `0000` and `0001` on first boot; the app then listens on 8080.
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

If backend is later containerised itself, it will join the compose network and should
switch to `redpanda:9092` and `postgres:5432`.

All credentials above are dev-only placeholders and are overridden by environment
variables in any real deployment — see `.env.example` for the full list.

## Open questions to resolve next
1. Whether WorkGroup classification on ingest is fully automated (mapping table from SIEM alert type) or requires human review before storage.
2. Final Kafka partition key strategy (`workGroupId` alone vs. composite key).
3. Whether `CustodyEvent`/`AccessLog` need an optional `caseId` once Case is (re)introduced, to answer "what happened to this evidence while it was part of Case X" without joining through `CaseEvidenceLink`.
4. Backend entity/DTO/mapper/service classes for `WorkGroup` (and subsequent entities) not yet written — the layered package skeleton exists, the classes do not.