# DFRaaS — Digital Forensic Readiness as a Service

An evidence repository that runs alongside a bank's existing systems. Registered sources submit evidence **continuously**; every artifact is hashed, stored, read back and re-hashed on arrival, whether or not anything has gone wrong. When an IDS or SIEM alert arrives it does not trigger collection — it **anchors correlation**: the repository groups related alerts into an incident and proposes the evidence already preserved around it, for an investigator to confirm or dismiss. Every artifact carries a hash-chained chain of custody.

This is the prototype of the framework described in the COS700 dissertation. The PDE testbed that feeds it lives in `../PDE Sources/`.

## Why continuous collection

An alert-driven design preserves evidence *because* an alert fired, by which time the reconnaissance and initial access that preceded it were never kept. ISO/IEC 27043 readiness means preserving *before* the incident. Three design consequences follow, and most decisions below trace back to one of them:

1. **Alert-to-evidence links are many-to-many, and they are hypotheses.** A log covering an hour bears on every alert in that hour, and a time-overlap match is a rule's guess, not an observation. Links therefore record how they were made and whether a person has agreed (`EvidenceLink`).
2. **Evidence needs its own timeline.** Correlation runs on the coverage window the source asserts (`eventStart`/`eventEnd`), kept separate from when the repository received the artifact (`createdAt`), so a skewed source clock stays visible.
3. **Silence must be visible.** A dead collector looks exactly like a quiet one, so each source declares its expected reporting cadence and overdue sources can be queried.

Design references: **K-FFRaaS** (process model and work-group classification, after ISO/IEC 27043) and **SecureRS** (hash before anything else touches the bytes, verify on access, gate release behind MFA), adapted for finance-sector requirements.

## Status

Requirement IDs match Table 3.1 of the dissertation.

| Area | Status |
|---|---|
| Source registration with work group and cadence (FR1) | Implemented |
| Streamed ingestion with coverage window (FR2) | Implemented — `POST /api/evidence-items` |
| Hash on receipt, reject on mismatch with the producer's digest (FR3) | Implemented — HTTP 422 |
| Read back and re-hash before recording (FR4) | Implemented |
| Alerts as trigger events over Kafka, payload and digest kept (FR5) | Implemented — idempotent on `(sourceSystem, externalEventId)` |
| Alerts grouped into incidents | Implemented — by producer-supplied `incidentKey` |
| Correlation pass (FR6) | Implemented — scheduled, time-window overlap within one work group |
| Link review: confirm / dismiss with a reason (FR7) | Implemented — API and UI |
| Silent-source query (FR8) | Implemented as a repository query; no API endpoint |
| Hash-chained custody ledger (FR9) | Implemented, with chain verification |
| Integrity re-verification (FR10) | Partial — on demand via API; not yet automatic on read/export or scheduled |
| Append-only below the application (NFR2) | Partial — `custody_event` columns are not updatable through the app; no database-level enforcement yet |
| Authentication (NFR4) | HTTP Basic with a dev principal |
| Manual preservation (FR11), step-up MFA (NFR5), encryption at rest (NFR6), user/role model, access log, custody head anchoring | **Out of scope for the prototype** — see [Future work](#future-work) |

## Architecture

```
PDE sources ──(HTTP multipart)──▶ EvidenceItemResource ──▶ hash ▶ store in MinIO ▶ read back ▶ re-hash ▶ evidence_item + CREATED custody entry
Slips ──slips_forwarder.py──▶ Kafka "evidence-events" ──▶ EvidenceEventConsumer ──▶ trigger_event, grouped into incident
CorrelationScheduler (every minute) ──▶ CorrelationService ──▶ evidence_link (AUTO_TIME_WINDOW, PROPOSED)
Investigator UI (React) ──▶ incidents, bundles, confirm/dismiss, custody, integrity checks
```

- **Backend:** Java 21, Spring Boot, layered `Resource → Service → Repository → Entity`, with DTOs and mappers at the API edge and domain exceptions in `exception`.
- **Storage:** PostgreSQL for metadata, schema versioned with Liquibase (`backend/src/main/resources/liquibase/changes/0000`–`0009`); MinIO for artifact bytes, keyed `<sourceKey>/<sourceArtifactId>`.
- **Messaging:** Redpanda (Kafka API) locally. Delivery is at-least-once with manual acks; malformed messages are logged and skipped.
- **Frontend:** React + Vite + Ant Design in `frontend/`.

## Data model

| Entity | Purpose | Rules worth knowing |
|---|---|---|
| `WorkGroup` | K-FFRaaS classification | Seeded with two defaults; others created via API |
| `EvidenceSource` | A registered collector | `sourceKey` unique; `workGroupId` required — classification is decided at registration; null `expectedIntervalSeconds` means event-driven (never "silent"); `lastEvidenceAt` is the only mutable column |
| `EvidenceItem` | One preserved artifact | `workGroupId` is a **snapshot** of the source's group, so reclassifying a source never rewrites past evidence; unique on `(evidenceSourceId, sourceArtifactId)` (the dedupe key); coverage window both-null or both-set; `status` is `PRESERVED` / `COMPROMISED` / `ARCHIVED` / `DELETED` — never hard-deleted; `createdAt` from the database clock |
| `TriggerEvent` | One alert, every one kept | Unique on `(sourceSystem, externalEventId)`; `receivedAt` (database clock) kept apart from sender-asserted `firedAt`; original `payload` and its SHA-256 retained |
| `Incident` | Alerts one source says belong together, with one bundle | Joined by `incidentKey` (Slips forwarder sends `<session>/<ip>/tw<N>`); window = first alert − lookback (30 min) to last alert + lookahead (15 min), **frozen on the row** so a correlation can be reproduced; status `PENDING → CORRELATED → CLOSED`, or `FAILED` (retried); a new alert reopens a closed incident |
| `EvidenceLink` | Proposed or confirmed incident ↔ item association | `linkMethod` `CAUSAL` / `AUTO_RULE` / `AUTO_TIME_WINDOW` / `MANUAL`; `disposition` `PROPOSED` / `CONFIRMED` / `DISMISSED`; automated links start `PROPOSED`; a ruling needs a reason, is attributed to the authenticated user, and can be made **once** (a second ruling is a 409); dismissed links are kept; `lateArrival` marks links added after the first pass |
| `CustodyEvent` | Hash-chained ledger, one sequence per item | See [Chain of custody](#chain-of-custody-and-integrity) |

## API

All endpoints require authentication. Full schemas at `/swagger-ui/index.html`.

| Method and path | Purpose |
|---|---|
| `GET/POST /api/work-groups` | List (filter `classificationCode`) / create |
| `GET/POST /api/evidence-sources` | List (filter `sourceKey`) / register |
| `POST /api/evidence-items` | Preserve an artifact: multipart `metadata` (JSON: `sourceKey`, `sourceArtifactId`, `eventStart`, `eventEnd`, `sourceSha256`) + `file`. 201 preserved, 409 duplicate, 404 unknown source, 422 digest mismatch, 503 store unreachable |
| `GET /api/evidence-items[/{id}]` | List (filter `workGroupId`, `includeDeleted`) / fetch — digest returned, storage location never |
| `POST /api/evidence-items/{id}/integrity-checks` | Re-hash the stored object; appends `HASH_VERIFIED` or `HASH_MISMATCH` |
| `GET /api/evidence-items/{id}/custody` | The custody chain as stored, digests included |
| `GET /api/evidence-items/{id}/custody/verification` | Walk the chain: `intact`, `firstDivergentSequence`, `missingOrigin`, `headEntryHash` |
| `GET /api/trigger-events[/{id}]`, `/by-external-id` | Alerts (read-only — alerts arrive over Kafka) |
| `GET /api/incidents[/{id}]`, `/{id}/trigger-events` | Incidents and their member alerts |
| `GET /api/incidents/{id}/links` | An incident's bundle, each link with its item embedded (filter `disposition`) |
| `POST /api/evidence-links/{id}/confirm`, `/dismiss` | Rule on a proposed link, with a `reviewNote` |

## Correlation

`CorrelationScheduler` sweeps once a minute. Each incident is correlated in its own transaction: its scope is resolved from the work group of the `EvidenceSource` whose `sourceKey` equals the incident's `sourceSystem` (and frozen into `correlationScope` on first attempt), and every item in that work group whose coverage window overlaps the incident window becomes an `AUTO_TIME_WINDOW` / `PROPOSED` link with a rationale stating both windows. Correlated incidents are re-run for late-arriving evidence until `dfraas.correlation.settle-after` (1 h) has passed since the window ended, then closed. An incident from an unregistered source is `FAILED` and retried, so registering the source recovers it.

The overlap query is native SQL over a partial GiST index on `tstzrange(event_start, event_end, '[]')` — inclusive bounds so point-in-time artifacts are not lost.

**Known limitations, measured in the evaluation:**

- **Work-group scoping can hide the decisive evidence.** An IDS alert is searched only within the IDS source's work group. With sources classified as in the dissertation (network sources in WG5, bank sources in WG7/WG8), no Slips incident was ever linked to the bank's audit trail — the one source that records the fraud and who committed it.
- **Time alone is imprecise.** The 45-minute window spans several capture windows, so most proposed links belong to other sessions. Matching on a subject identifier (IP, host, account) extracted from the alert is the intended fix (future work).
- Retries have no back-off, and the sweep assumes a single running instance (`dfraas.correlation.enabled=false` on all others).

## Chain of custody and integrity

Each item's ledger starts with a `CREATED` entry written **in the same transaction** as the item. Every entry's hash covers the previous one:

```
entryHash = SHA-256( prevEntryHash ‖ canonical(entry) )      genesis prevEntryHash = 64 zeros
```

- `canonical(entry)` is built explicitly and versioned per row (`canonicalVersion`), so a format change never invalidates old chains.
- `occurredAt` (application clock) is inside the digest; `recordedAt` (database `now()`) is outside it — a gap between them exposes a backfill.
- On integrity checks, `artifactHashBefore`/`After` read as expected/observed. A mismatch moves the item to `COMPROMISED` and **keeps** the recorded digest; a later match is logged as `HASH_VERIFIED` but the item stays `COMPROMISED`.
- No endpoint accepts a custody entry; entries are written only by the action they record.

**What verification detects:** edited entries, reordered entries, entries deleted from the middle (sequence must be contiguous from 0), and an empty chain. **What it does not:** truncation of the chain's end, or a full recomputation by someone with write access to the ledger. Closing both needs the head hash witnessed outside the database (WORM storage, an RFC 3161 timestamp) or per-entry signatures — stated as a limitation, not built.

## Security posture

Implemented: authenticated access to every endpoint; hash-on-ingest with the producer's digest treated as a claim; read-back verification; storage location never exposed; reviewer identity taken from the authenticated principal; CORS allowlist.

Not implemented, and stated as prototype limitations: a user/role model (one dev principal, `admin`), step-up MFA on export/download (placeholder in `SecurityConfiguration`), encryption at rest, and service-to-service auth beyond HTTP Basic. **The application connects to Postgres as a superuser**, which no database-level append-only control can bind; enforcing NFR2 requires a separate non-superuser application role alongside the owner role used by Liquibase.

## Running locally

Prerequisites: JDK 21, Docker, Node 20.19+ (frontend, for Vite 8).

```bash
cp .env.example .env              # dev-only placeholder credentials
docker compose up -d              # Postgres, MinIO (+ bucket), Redpanda (+ console)
cd backend && ./mvnw spring-boot:run      # Liquibase migrates on start; API on :8080
cd frontend && npm install && npm run dev # UI on :5173
```

`./mvnw test` runs the suite against Testcontainers and needs no running stack.

| Service | Address | Dev credentials |
|---|---|---|
| Backend API | http://localhost:8080 | `admin` / `admin` (Basic) |
| Swagger UI | http://localhost:8080/swagger-ui/index.html | as above |
| Health | http://localhost:8080/actuator/health | open |
| Postgres | `localhost:5433` | `dfraas` / `dfraas_dev_only` |
| MinIO console | http://localhost:9001 | `dfraas_admin` / `dfraas_dev_only` |
| Kafka (Redpanda) | `localhost:19092` | none |
| Redpanda console | http://localhost:8081 | none |

Postgres is published on **5433** because a host Postgres often holds 5432. Kafka is published on **19092** (Redpanda's external listener); 9092 is internal-only, because a host client bootstrapping there would be redirected to the unresolvable `redpanda` hostname.

To start from an empty repository: `docker compose down -v && docker compose up -d`, then restart the backend so Liquibase rebuilds the schema. The evaluation scripts isolate their runs by tag, so a reset is rarely needed.

## Evaluation

Scripts and results live in `../PDE Sources/evaluation/`:

| Script | What it does | Results |
|---|---|---|
| `replay_into_repository.py` | Preserves all 24 captured windows (96 artifacts), replays the Slips alerts through the real forwarder and Kafka, waits for correlation, saves every bundle | `results/eval-design/`, `results/eval-shared/` |
| `check_correlation.py` | Scores bundles against ground truth: recall, precision, audit-trail coverage, review load | `summary.md` in each results folder |
| `tamper_tests.py` | Seven attacks on transit, storage and the custody ledger, each with a stated expected outcome | `results/tamper/tamper.md` |

Headline results: 96/96 artifacts preserved with digests matching capture; 76 alerts grouped into 6 incidents, all on the attacker (about 12× fewer links to review than one bundle per alert); bank audit trail proposed in 0 of 6 incidents under the dissertation's classification and 6 of 6 under a shared one; all tamper tests behaved as predicted, with chain truncation undetected as stated above.

## Future work

Deliberately outside the prototype's scope; each is a design position in the dissertation rather than unfinished code.

- **Subject-scoped correlation** — extract IP/host/account from the alert payload, index it on items, and emit `AUTO_RULE` links; per-alert-type windows instead of one global pair.
- **Cross-work-group correlation** — let an incident's scope name more than one work group, so network alerts can reach banking evidence.
- **Custody anchoring** — witness each chain head outside the database; record reads as custody entries rather than in a separate access log.
- **Users and access** — `AppUser` with the four framework roles (source owner, investigator, custodian, compliance officer), replacing the `performedBy` / `linkedBy` / `reviewedBy` usernames; step-up MFA on export; OAuth2/mTLS between services.
- **Storage** — envelope encryption with keys in a KMS; streaming ingest for artifacts beyond the 64 MB in-memory limit; manual preservation endpoint.
- **Operations** — separate `trigger-events` and `evidence-artifacts` topics; a dead-letter topic; scheduled integrity re-verification; an API endpoint for silent sources.
