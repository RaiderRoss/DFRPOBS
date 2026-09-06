# DFRaaS — Digital Forensic Readiness as a Service

## What it is
A digital evidence management system for a bank, running alongside existing infrastructure. Registered sources stream evidence in **continuously**; it is hashed and preserved on arrival, independently of whether anything has gone wrong. When a SIEM/IDS alert fires, a **TriggerEvent** is recorded and the system **correlates** it against evidence already preserved — everything whose coverage window overlaps the alert's — so an investigator can start from an incident and get its evidence in one place, while still reviewing individual artifacts on their own terms.

### Why collection is continuous rather than alert-driven
The original design preserved evidence *because* an alert fired. That is reaction, not readiness, and it has a blind spot that cannot be fixed within the design: by the time an IDS notices an intrusion, the reconnaissance, initial access and staging that preceded it happened hours ago, and under an alert-driven model they were never preserved. Detection is where you learn to look, not where the evidence is.

Collecting continuously and correlating retrospectively is what ISO/IEC 27043 readiness actually asks for — preserve *before* the incident, so that the record exists when someone finally needs it. It also changes what the alert is for: no longer an ingestion command, but an efficient way into a body of evidence that was already there.

Three consequences run through the whole design, and most of the decisions below follow from one of them:

1. **Alert-to-evidence is many-to-many, and it is an assertion.** A log bundle covering 10:00–11:00 bears on every alert that fired in that hour, so a foreign key cannot hold it. More importantly, a time-overlap match is a *hypothesis produced by a rule*, not an observation — it must not be presented in the same shape as established provenance. Hence `EvidenceLink`, which records how each link was made and whether a human has agreed.
2. **Evidence needs its own timeline.** Correlation asks what covers the alert's window, and `EvidenceItem.createdAt` — when *we* preserved it — is the wrong clock: an hourly bundle rolled at 15:00 and stored at 15:02 covers 14:00–15:00. Hence `eventStart`/`eventEnd`, asserted by the source and treated with the same suspicion as `TriggerEvent.firedAt`.
3. **Silence stops being visible.** A streaming source that quietly dies produces exactly what a healthy source with nothing to report produces. Under the reactive model a missing alert was noticed because someone was waiting for it; here nobody is, and the gap surfaces months later when an investigator finds the window they need is empty. Hence `EvidenceSource` with a declared cadence, and "which sources have gone quiet" as a first-class query.

**Scope, stated honestly.** This is a claim to be storage-of-record for parts of a bank's log estate, which is considerably larger than "preserve on alert". The system stores *selected evidence classes per registered source under a collection policy*, not everything. Its differentiator against the SIEM's own storage is not the storage — it is hash-on-ingest, an append-only custody chain, and integrity re-verification on every read.

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
- **EvidenceSource** — `id, sourceKey, displayName, workGroupId, sourceType, status, expectedIntervalSeconds, lastEvidenceAt, registeredAt` — a registered producer that streams evidence in continuously (changeset `0004`). `sourceKey` is the natural key a collection agent puts in its config, and is globally unique because *we* assign it at registration — unlike `TriggerEvent.externalEventId`, whose numbering belongs to a vendor. `workGroupId` is `NOT NULL`, and registration is where classification is decided; this is what resolved open question 1. `expectedIntervalSeconds` is nullable, and the null means "event-driven, silence proves nothing" — holding such a source to a cadence would manufacture a permanent false alarm. `status` (`ACTIVE` / `SUSPENDED` / `DECOMMISSIONED`) exists to tell two kinds of silence apart: a collector that stopped and a collector that was switched off are both quiet, and only one is a finding. `lastEvidenceAt` is the only mutable column and is explicitly *not* evidence — it is overwritten, so it keeps no history; the history of what a source produced is `evidence_item` itself.
- **TriggerEvent** — `id, externalEventId, sourceSystem, triggerType, firedAt, receivedAt, payload, payloadSha256, correlationStatus, correlationLookbackSeconds, correlationLookaheadSeconds, correlatedAt, correlationScope` — the SIEM/IDS alert an investigation starts from. It no longer causes ingestion; it *anchors correlation*. `externalEventId` is the source's own identifier and the only thing dedupe can key on (`id` is generated here, so it never repeats across deliveries); `receivedAt` is the database's account of when we saw the alert, kept distinct from the sender-supplied `firedAt`; `payload` + `payloadSha256` retain the original alert and its digest, because the alert is itself part of the evidentiary record. Unique on `(sourceSystem, externalEventId)` — composite, because alert numbering is per-vendor. The correlation fields (changeset `0005`) are the ones the refactor added: `correlationStatus` (`PENDING` → `CORRELATED` → `CLOSED`, plus terminal `FAILED`) is open question 3 in its new form; the lookback/lookahead **window is frozen onto the row rather than read from configuration**, because a bundle that cannot state what the system was asked to look for cannot be reproduced or defended. Lookback (30 min default) is much larger than lookahead (15 min) for the reason the whole refactor exists — the activity that matters precedes detection. `correlationScope` holds the non-time half of the rule as JSON.
- **EvidenceItem** — `id, workGroupId, evidenceSourceId, sourceArtifactId, storageRef, currentHash, status, eventStart, eventEnd, createdAt` — the hub entity; references the stored object and its current integrity state. `workGroupId` is `NOT NULL` and is a **snapshot**, not a derivation through `evidenceSourceId`: reclassifying a source next year must not silently reclassify every artifact it ever produced, each retained and released under the classification then in force. `evidenceSourceId` is nullable (manual preservation and compliance holds have no collector; inventing a "manual" source row would assert one exists). `(evidenceSourceId, sourceArtifactId)` is unique and is the streamed-ingestion dedupe key — Postgres treats NULLs as distinct, so manual items never collide with each other. `eventStart`/`eventEnd` are the source-asserted coverage window and the axis correlation runs along; both nullable or both set (`CHECK`), because half a window looks answerable and answers wrongly, and a null window means the item can only be linked by hand rather than that it is deficient. `storageRef` is a MinIO object key rather than a URL, and is unique: two items sharing one object would mean two custody chains and two retention decisions over the same bytes. `status` is `VARCHAR` + CHECK rather than a native enum, because the set is business-facing and will need to shrink as well as grow — `PRESERVED`, `COMPROMISED` (a re-verification found a mismatch), `ARCHIVED`, `DELETED` (the soft delete; evidence is never removed). `createdAt` is stamped by the database clock, as everywhere else, and is kept *alongside* the coverage window rather than replacing it — the gap between the two is how a skewed source clock becomes visible. **No `triggerEventId`**: dropped in `0005`, see `EvidenceLink`. Not modelled here: who preserved it — that is `CustodyEvent`'s job.
- **EvidenceLink** — `id, triggerEventId, evidenceItemId, linkMethod, disposition, rationale, linkedBy, linkedAt, reviewedBy, reviewedAt, lateArrival` — the reviewable association between an alert and evidence bearing on it (changeset `0005`), replacing `evidence_item.trigger_event_id`. A join *entity*, not a `@ManyToMany`, and the second reason matters more than the first: the cardinality is genuinely many-to-many, but the link is also an **assertion** rather than a fact. `linkMethod` runs strongest to weakest — `CAUSAL` (collected *because* the alert fired; the only one that is an observation, and the value the old FK migrated to), `AUTO_RULE` (matched on host/account/session), `AUTO_TIME_WINDOW` (overlap only), `MANUAL`. `disposition` is `PROPOSED` / `CONFIRMED` / `DISMISSED`; automated links start `PROPOSED`, because finding an overlap is a reason to look, not a finding. **Dismissed, never deleted** — "an investigator considered this and set it aside" is part of the investigative record and exactly what a defence would probe. `rationale` is what makes "why is this item in this bundle?" answerable a year later. Attribution is enforced in the database: a `MANUAL` link must name who made it, a `DISMISSED` one must name a reviewer (nothing automated may decide evidence is irrelevant), while `CONFIRMED` deliberately need not — a `CAUSAL` link is confirmed by observation, and requiring a reviewer would force ingestion to invent one. `lateArrival` flags links added by a re-correlation pass, which is normal rather than exceptional once collection is decoupled from alerting. Unique on `(triggerEventId, evidenceItemId)`, which is what makes re-correlation idempotent.
- **CustodyEvent** — `id, evidenceItemId, sequence, action, performedBy, performedByUsername, previousHash, newHash, occurredAt` — append-only chain-of-custody ledger, hash-chained per evidence item; every action on an item appends one. See [Chain of custody](#chain-of-custody) for the chaining rule and what it does and does not prove. `sequence` is per item with a unique constraint on `(evidenceItemId, sequence)`: without it two concurrent appends read the same `previousHash` and the chain forks. `performedByUsername` is a denormalised snapshot beside the `performedBy` FK — the AppUser row can be renamed or removed, and a custody entry has to stay readable on its own years later.
- **IntegrityCheck** — `id, evidenceItemId, computedHash, matchesStored, checkedAt` — periodic/on-demand re-verification, separate from custody events, matching SecureRS's verify-on-read pattern.
- **AppUser** — `id, username, role, mfaEnabled`.
- **AccessLog** — `id, evidenceItemId, userId, action, occurredAt` — every read/view, logged separately from custody-changing actions (compliance requirement). **Unresolved:** this overlaps the custody chain now that reads are treated as custody events — see open question 10.

## Storage & infrastructure
- **MinIO** — evidence blob storage (object storage), referenced by `EvidenceItem.storageRef`. Should use envelope encryption via a real KMS/HSM (not a static key in config, which is what the SecureRS prototype does).
- **Postgres** — all metadata/entities, managed via Liquibase.
- **Kafka** (Redpanda locally, for lightweight Kafka-API-compatible dev) — decouples publishing from the ingestion pipeline. **Should now be two topics, and currently is one.** `evidence-events` carries alerts despite its name, a leftover from when alerts and evidence were the same message. They should split into `trigger-events` (low volume, one row per alert, partition by `workGroupId`) and `evidence-artifacts` (high volume, continuous, partition by source or asset to keep per-source ordering). Different volumes, different retention, and — the operational reason — a slow artifact stream must not be able to stall alert processing behind it on a shared partition.
- Alert ingestion is **idempotent**, deduping on `(sourceSystem, externalEventId)` inside a single transaction backed by `uq_trigger_event_source_external`, since Kafka's default delivery is at-least-once. Artifact ingestion needs the same guarantee on `(evidenceSourceId, sourceArtifactId)`, backed by `uq_evidence_item_source_artifact` — and needs it more, because that stream is orders of magnitude larger, so redelivery is a daily occurrence rather than an edge case.
- **Correlation is a separate pass**, not part of the listener's transaction. It reads the work queue (`TriggerEventRepository.findByCorrelationStatusInOrderByReceivedAtAsc` over `PENDING` + `FAILED`, served by the partial index `ix_trigger_event_correlation_pending`), resolves each alert's window, and matches with `EvidenceItemRepository.findOverlappingCoverage`. Keeping it out of the listener matters for two reasons: an over-broad scope would stall the alert partition behind it, and evidence covering the window may not have been preserved yet. Re-correlation for late arrivals is then the same code path rather than a special case.
- The overlap query is **native SQL over a GiST range index**. JPQL has no overlap operator, and expressing it as two independent inequalities leaves the planner close to a sequential scan of a table that grows at the rate the whole estate produces. `ix_evidence_item_coverage` indexes `tstzrange(event_start, event_end, '[]')` so Postgres' `&&` is used directly. Inclusive `'[]'` bounds throughout: a point-in-time artifact has `eventStart = eventEnd`, and a half-open range over a zero-length interval is empty — it would silently exclude exactly the memory captures and single transaction records an investigation most wants. The index is partial (`WHERE event_start IS NOT NULL`) because `tstzrange(NULL, NULL)` is *unbounded* and would otherwise overlap every alert ever fired.
- **Source liveness monitoring** (`EvidenceSourceRepository.findSilentSources`) is the readiness audit for continuous collection: active sources with a declared cadence whose `COALESCE(lastEvidenceAt, registeredAt)` is past due. Also native, because the deadline uses each source's *own* cadence and HQL cannot build an interval from a column. The case worth catching most is a collector misconfigured on the day it was onboarded, which has delivered nothing ever since and has never once looked broken.
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

## Chain of custody

Every EvidenceItem owns one chain, answering **what**, **when** and **by whom** for
everything that happens to that item — creation, hashing, reading, export, relocation,
status change. One ordered ledger per item, not a log per action type.

**The chaining rule.** Each entry's hash covers the previous entry's hash:

```
newHash = H( previousHash ‖ canonical(event) )
```

- The **first** entry is the item's own `CREATED` event, not an empty chain. An item that
  exists with an empty chain has an unexplained origin.
- Genesis uses a **fixed constant** for `previousHash` rather than null, so verification
  is one uniform loop instead of a special case that has to be right twice.
- `canonical(event)` must be **frozen and versioned** — field order, encoding, timestamp
  precision. The day serialisation changes, every historical chain stops verifying and
  tampering becomes indistinguishable from a format change. Build the string explicitly
  rather than letting a JSON library decide it, and stamp each row with the version used.

**Transactionality.** A custody entry is written in the *same transaction* as the action
it records. A crash between "moved the object" and "logged the move" leaves evidence with
an unexplained gap, which is the one thing custody must never have. This is why the
ledger is a table and not a file: a file write cannot enlist in the Postgres transaction.
A custody *file* is derived on demand for export or handover; the table stays
authoritative, so there is never a question of which one wins.

**What the chain proves, and what it does not.** Linked hashes make *modification of an
interior entry* detectable. On their own they do not detect:

- **Truncation** — remove the last N entries and what remains still verifies cleanly.
  Nothing inside the chain states how long it ought to be.
- **Wholesale re-chaining** — anyone who can write the ledger can recompute every hash
  from genesis and produce a valid chain saying whatever they like.

So the chain alone is defeated by precisely the actor forensic readiness exists to catch:
the insider with write access. It needs at least one of an append-only guarantee enforced
below the application, a head hash anchored where the writer cannot reach it, or
per-entry signatures. Until then the honest claim is "a consistent chain", not "the
chain" — see open questions 8 and 9.

## Open questions
1. ~~**Whether WorkGroup classification on ingest is automated or needs human review.**~~ **Resolved** by changeset `0004`, and dissolved rather than answered. The question only existed because classification had to be inferred *per alert*, from a SIEM alert type, by a mapping table nobody had written. Under continuous collection it moves somewhere much better: a source is registered once, by a human who knows which business unit the system it collects from belongs to, and `EvidenceSource.workGroupId` is `NOT NULL`. Every item that source produces inherits that classification, snapshotted onto the item so a later reclassification of the source does not rewrite the past.
2. ~~**`EvidenceItem` → `TriggerEvent` cardinality and nullability.**~~ **Resolved twice.** `0003` made it one-to-many with a nullable, non-unique FK on `EvidenceItem`. `0005` replaced that FK entirely with `EvidenceLink` — the `0003` answer was right about cardinality and right that nullability was load-bearing, but it was answering the wrong question. A foreign key can only express *causation* ("this exists because that fired"), and once collection is continuous the artifact already existed. The relationship became many-to-many (a bundle covering an hour bears on every alert in that hour), and more importantly it became an inference that has to be labelled as one. The `0003` reasoning survives in two places: nullability's argument now applies to `evidenceSourceId`, and the rejection of a synthetic placeholder `TriggerEvent` still stands — `LinkMethod.CAUSAL` records genuine alert-driven collection without inventing an alert that never fired.
3. ~~**Ingestion is not yet resumable, and this is a latent data-loss bug.**~~ **Schema in place** (`0005`), **behaviour still to write.** The original bug — `recordIfAbsent` commits the trigger event, the consumer then dies before storing the blob, and on redelivery `created == false` sends it down the early-return path so no `EvidenceItem` is ever created — no longer exists, because the alert no longer causes preservation. But the underlying defect was that the dedupe key answered *"has this alert been recorded"* when it needed to answer *"has this alert been fully processed"*, and that gap simply moves one step along to **"this alert was recorded and never correlated"**. `TriggerEvent.correlationStatus` is the fix in its new form, and it answers the readiness question the original was reaching for: which alerts came in and produced nothing. **One documented reversal** — the earlier note argued for a native Postgres enum on the grounds that a processing state is closed and internal. Correlation status is not internal; an investigator sees "correlation still pending" against an incident and will reasonably ask for states this list does not have. So it gets `VARCHAR` + CHECK, like `EvidenceStatus`. Still to build: the correlation pass itself.
4. ~~**How manual and scheduled preservation enter the system**~~ **Streamed ingestion is built; manual preservation and link review are not.** Two endpoints now exist (see `docs/ingestion-review.md`). `POST /api/evidence-sources` registers a producer, which is where classification is decided. `POST /api/evidence-items` takes an artifact as multipart — a JSON metadata part plus the file — hashes the received bytes before anything else touches them, compares that against the digest the source asserts, stores the object under a key derived from `(sourceKey, sourceArtifactId)`, reads it back and re-hashes it, and only then writes the row. The producer's digest is never the one stored; it is a claim to be checked, and that check is the only part of the trip from collector to repository that can be verified rather than trusted. `TriggerEventResource` stays read-only and the reasoning is unchanged: an alert is something that happened to the system, whereas an artifact is something a registered collector has, so the question is not whether the caller may assert it but whether the bytes are what they say. **Still open:** manual preservation has no endpoint (null `evidenceSourceId`, usually a null coverage window, and a `MANUAL` `EvidenceLink` — a different provenance story that should not arrive at the streamed endpoint with fields left blank); confirming and dismissing a proposed link is still unwritten, and remains what makes the review workflow real rather than theoretical; and the artifact topic (see Storage & infrastructure) is still the right shape for volume, since HTTP ingestion is what a testbed needs rather than what an estate would use.
5. **Correlation scoping beyond time and classification.** `findOverlappingCoverage` scopes on work group because that is the second axis the schema already carries, and time alone is unusable — every source produces continuously, so an unscoped 45-minute window returns tens of thousands of items, which is a more expensive way of finding nothing. The real answer is a subject identifier — host, IP, account, session — matched from the alert payload and indexed on the item. That is what turns `AUTO_TIME_WINDOW` links into `AUTO_RULE` ones and makes a bundle triageable. `TriggerEvent.correlationScope` is the column it belongs in; nothing populates it yet.
6. **Per-trigger-type correlation policy.** The lookback/lookahead defaults (30 min / 15 min) are one global pair, frozen onto each row so past correlations stay reproducible. A data-exfiltration alert wants hours of lookback and a failed-login alert wants minutes, so the policy belongs with the detection catalogue rather than on `trigger_event`. Related: `CorrelationStatus.CLOSED` implies a rule for *when* the collection lag has elapsed, which nothing currently decides.
7. `CustodyEvent`, `IntegrityCheck`, `AppUser` and `AccessLog` remain unwritten, and each needs its own Liquibase changeset first. Done: `EvidenceItem` (`0003`), `EvidenceSource` (`0004`), `EvidenceLink` + correlation state (`0005`). Remaining order: `AppUser` next — and it is now more overdue than it was, because `EvidenceLink.linkedBy` and `reviewedBy` are `VARCHAR` placeholders holding what should be foreign keys, alongside `CustodyEvent.performedBy` — then `CustodyEvent`, `IntegrityCheck`, `AccessLog`.
8. **Append-only is still a convention, not a constraint.** `TriggerEvent`, `EvidenceItem` and `EvidenceLink` are all documented as effectively append-only, and all three inherit `delete` from `JpaRepository` with nothing stopping a caller. `EvidenceLink` adds a second case: a dismissed link must survive, and `TriggerEvent.correlationScope` is meant to be written exactly once but cannot be `updatable = false` because it is unknown at insert. Same job as `CustodyEvent`'s, and worth doing once for all of them.

9. **How the custody chain is anchored.** Question 8 covers stopping deletes through the
   application; this is the harder half. Even with append-only enforced, hash chaining is
   tamper-*evident* against edits to an interior entry and nothing more: truncating the
   tail still verifies, and anyone able to write the ledger can recompute it from genesis.
   Closing that needs a head hash anchored somewhere the writer does not control — a WORM
   bucket, a signed timestamp, a second system — or per-entry signatures, so forging costs
   a key rather than database access. This is what turns "hash chained" into a defensible
   admissibility claim, which makes it a prerequisite for the custody work rather than a
   follow-up to it.
10. **Whether reads live in the custody chain or in `AccessLog`.** The two now overlap:
    the data model logs reads separately, while the custody design treats reading as a
    custody event. Two records of who-read-what will drift, and a court asking "who
    accessed this" should not get two answers. Leaning towards one chain per item with
    `AccessLog` as a projection over it — a read genuinely is custody-relevant, and one
    ordered ledger is easier to defend than two that must be reconciled. It also closes a
    gap: an `access_log` row is not hash-chained, so deleting "X read this at 03:00" is
    undetectable, and read history is often the most incriminating part of the record. The
    cost is volume, since reads dominate, so verification would need to be incremental
    from a checkpointed head rather than re-hashing from genesis every time.
