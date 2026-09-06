# Refactor review — continuous collection + retrospective correlation

Scratch document for reviewing the `0004`/`0005` refactor. Delete once you have been through it; nothing else links to it.

**Test result: 78 run, 0 failures, 0 errors** (`./mvnw test`, Testcontainers against `postgres:16-alpine`, matching the compose stack).

| Test class | Tests |
|---|---|
| `EvidenceItemRepositoryTest` | 20 |
| `TriggerEventRepositoryTest` | 12 |
| `EvidenceLinkRepositoryTest` | 11 |
| `EvidenceSourceRepositoryTest` | 10 |
| `TriggerEventResourceTest` | 6 |
| `EvidenceEventConsumerTest` | 5 |
| `WorkGroupResourceTest` | 5 |
| `TriggerEventServiceTest` | 4 |
| `WorkGroupRepositoryTest` | 4 |
| `DfraasBackendApplicationTests` | 1 |

---

## 1. The one real bug the run found

**Five errors in `EvidenceSourceRepositoryTest`, one root cause**, in `EvidenceSourceRepository.findSilentSources`. Fixed; the fix is the only production change made after the first run.

### What happened

```
ERROR: operator does not exist: timestamp with time zone < interval
```

The query was written as:

```sql
COALESCE(s.last_evidence_at, s.registered_at) < :asOf - make_interval(secs => s.expected_interval_seconds)
```

A JDBC bind parameter arrives at Postgres **untyped**. To resolve `? - interval`, Postgres searches its operator candidates and finds `interval - interval → interval` fits, so it infers `?` as an `interval`. The comparison then becomes `timestamptz < interval`, for which no operator exists, and it fails at execution time.

This is worth noting for its failure *mode* rather than its severity: it is invisible to compilation, invisible to Hibernate's `ddl-auto=validate`, and invisible to any test that does not actually execute the query. Nothing but running it against a real Postgres would have caught it — which is precisely why the previous message's "compiles clean, tests not run" was not a claim that the code worked.

### The fix

Move the interval to the other side of the comparison rather than casting the parameter:

```sql
COALESCE(s.last_evidence_at, s.registered_at)
    + make_interval(secs => s.expected_interval_seconds) < :asOf
```

Now the left-hand side is unambiguously `timestamptz + interval → timestamptz`, which types the parameter correctly with no cast needed. A `CAST(:asOf AS timestamptz)` would also have worked, but this version reads as the thing it actually is — *a deadline, compared against now* — and it removes the ambiguity rather than papering over it. The reasoning is recorded in the method javadoc so the next person does not "simplify" it back.

**Note on `::` casts:** if you ever do need one in a native query here, use `CAST(x AS type)`. Hibernate parses `:` for named parameters, and `:asOf::timestamptz` is a known source of trouble.

---

## 2. Assumptions the run actually confirmed

These were load-bearing design decisions I could not verify without a database. All are now exercised by a passing test.

| Assumption | Confirmed by |
|---|---|
| `tstzrange(event_start, event_end, '[]')` is IMMUTABLE, so a **GiST expression index** on it is legal | `0004-9` applies; `findsEvidenceOverlappingTheCorrelationWindow` |
| **Inclusive `'[]'` bounds** are required — a point-in-time artifact (`eventStart == eventEnd`) would be an empty range under `'[)'` and match nothing | `pointInTimeArtifactIsMatched` |
| Postgres treats **NULLs as distinct** in a unique constraint, so manual items don't collide on `(null, null)` | `nullArtifactIdsDoNotCollide` vs `duplicateSourceArtifactIdIsRejected` |
| The **CHECK asymmetry** is expressible: `DISMISSED` requires a reviewer, `CONFIRMED` deliberately does not | `dismissalWithoutReviewerIsRejected` + `causalLinkIsConfirmedWithoutReview` |
| `FAILED` correlation must be exempt from the `correlated_at` consistency rule (a re-correlation can fail on an alert correlated last week, and that timestamp must survive) | `failedIsTheOneStatusTheTimestampSaysNothingAbout` |
| `0005-6`/`0005-7` — **migrate then drop `trigger_event_id`** — applies cleanly, and Hibernate validates the entities against the post-drop schema | `DfraasBackendApplicationTests` (full changelog + `ddl-auto=validate` on boot) |

---

## 3. What is still unverified

Listed in the order I would worry about them.

1. **The Liquibase rollback path has never been executed.** This is the real gap. `0005-7` is the only destructive changeset in the project — it drops `evidence_item.trigger_event_id` — and its rollback re-adds the column, repopulates it from `evidence_link` where `link_method = 'CAUSAL'`, and rebuilds the FK and index. That SQL is written but untested, because there is no `liquibase-maven-plugin` in `pom.xml` and no rollback goal to run. Worth fixing: add the plugin and run `liquibase:update` then `liquibase:rollbackCount -Dliquibase.rollbackCount=N` against a throwaway container. Until then, treat `0005` as forward-only in practice.
2. **Index behaviour is untested at volume.** The GiST index is *used*, but every test table holds single-digit rows, where Postgres will happily seq-scan regardless. The claim that correlation stays a query rather than a batch job is architecturally sound but not measured. An `EXPLAIN ANALYZE` against a seeded table of realistic size is the honest check.
3. **The correlation pass does not exist.** The schema, repositories and queries are in place; nothing yet reads the work queue, writes links, or moves `correlationStatus` off `PENDING`. Every `CORRELATED` row in the tests was set by hand.
4. **The Kafka topic split is documented, not implemented.** `evidence-events` still carries alerts under a name that describes evidence, and there is no artifact ingestion path at all — so nothing currently *creates* a streamed `EvidenceItem` outside of tests.
5. **Pre-existing, unrelated:** `TestcontainersConfiguration` still pins `apache/kafka-native:latest` against a compose stack that runs Redpanda. Flagged by an existing TODO, untouched by this work, and it drifts twice over.

---

## 4. Decisions I made that are yours to overrule

Each of these went one way on a judgement call. Reasoning is in the changeset comments and javadoc; this is the short list of what to push back on.

- **`correlationStatus` is `VARCHAR` + CHECK, not a native Postgres enum** — reversing the argument in the old open question 3. That argument held while the state was internal; an investigator now sees "correlation pending" against an incident and will ask for states this list lacks. Documented as an explicit reversal rather than changed quietly.
- **`findOverlappingCoverage` requires a work group.** Not optional, so an unscoped estate-wide window is unavailable rather than merely discouraged. If you want an unscoped variant for admin use, it should be a separate, obviously-named method.
- **`event_start`/`event_end` are nullable.** `NOT NULL` would either reject legitimate evidence at ingest or force a backfill inventing a coverage window from `createdAt`. A null-window item is *linkable only by hand*, not deficient.
- **`work_group_id` stays on `evidence_item`** rather than being derived through `evidence_source`. It looks redundant; it is a snapshot. Reclassifying a source must not retroactively reclassify everything it ever produced.
- **`EvidenceLink` is a join entity, not `@ManyToMany`.** The cardinality alone would not force this — the need to label a correlation as an inference does.
- **`TriggerEventDto` now imports `CorrelationStatus` from the entity package.** Conventional enough for a shared vocabulary enum, but it is a DTO reaching into `entity`, and if you would rather keep that boundary clean it needs its own DTO-side enum plus mapping.

---

## 5. Re-running

```bash
# Docker must be running — Testcontainers starts Postgres 16 and Kafka per run.
cd "Evidence Repository/backend"
./mvnw test

# Formatting is enforced; spotless:check fails the build before tests run.
./mvnw spotless:apply
```

`DfraasBackendApplicationTests` is the one that applies the full Liquibase changelog and boots with `ddl-auto=validate`, so it is the test that fails first if an entity and its changeset ever drift apart.
