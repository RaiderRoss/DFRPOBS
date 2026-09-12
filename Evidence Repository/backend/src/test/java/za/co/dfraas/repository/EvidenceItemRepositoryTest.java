package za.co.dfraas.repository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.OffsetDateTime;

import jakarta.persistence.PersistenceException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.jpa.test.autoconfigure.TestEntityManager;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.PageRequest;

import za.co.dfraas.TestcontainersConfiguration;
import za.co.dfraas.entity.EvidenceItem;
import za.co.dfraas.entity.EvidenceSource;
import za.co.dfraas.entity.EvidenceStatus;
import za.co.dfraas.entity.WorkGroup;

/**
 * The contract between {@link EvidenceItem} and Liquibase changesets
 * {@code 0003-create-evidence-item-table} and
 * {@code 0004-create-evidence-source-and-coverage-window}.
 *
 * <p>As in the sibling repository tests, {@code ddl-auto=validate} means the context fails
 * to start on any column-level disagreement, so every method here implicitly asserts that.
 * The explicit assertions cover what validation cannot see, and each corresponds to a
 * decision the changeset comments argue for.
 *
 * <p>Note what is no longer tested here and where it went. The old
 * {@code oneTriggerEventYieldsManyItems} case guarded the absence of a unique constraint on
 * {@code evidence_item.trigger_event_id}; that column was dropped in {@code 0005}, and the
 * relationship it approximated now lives in {@code EvidenceLinkRepositoryTest}, which
 * exercises it in both directions rather than only one.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import(TestcontainersConfiguration.class)
class EvidenceItemRepositoryTest {

	private static final String SHA_256_OF_EMPTY_STRING =
			"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

	/** The alert this fixture's windows are positioned around: 14:30, ±nothing yet. */
	private static final OffsetDateTime ALERT = OffsetDateTime.parse("2026-01-01T14:30:00Z");

	@Autowired
	private EvidenceItemRepository repository;

	@Autowired
	private WorkGroupRepository workGroupRepository;

	@Autowired
	private EvidenceSourceRepository evidenceSourceRepository;

	@Autowired
	private TestEntityManager entityManager;

	private WorkGroup workGroup;
	private EvidenceSource source;

	@BeforeEach
	void setUp() {
		// Seeded by changeset 0001-2, and the classification a registered source declares.
		workGroup = workGroupRepository.findByClassificationCode("ONLINE_BANKING").orElseThrow();
		source = evidenceSourceRepository.saveAndFlush(newSource("auth-syslog"));
	}

	@Test
	@DisplayName("Hibernate assigns the id, and the column default populates createdAt")
	void generatedFieldsArePopulatedOnInsert() {
		EvidenceItem saved = repository.saveAndFlush(newItem("evidence/2026/01/auth.log"));

		assertThat(saved.getId()).isNotNull();

		// Populated by the now() default and read back via @Generated(INSERT); this is the
		// assertion that fails if that annotation is ever dropped.
		assertThat(saved.getCreatedAt()).isNotNull();
		assertThat(saved.getStatus()).isEqualTo(EvidenceStatus.PRESERVED);
	}

	@Test
	@DisplayName("An item can be preserved with no source and no coverage window at all")
	void sourceAndCoverageWindowAreOptional() {
		// Manual preservation and compliance holds have no collector behind them, and no
		// coverage window the system can assert. Such an item is still fully preserved
		// evidence; it simply cannot be correlated automatically. A NOT NULL on either
		// column would reject it at ingest, or force a backfill inventing a window from
		// createdAt.
		EvidenceItem saved = repository.saveAndFlush(newItem("evidence/manual/ledger.csv"));

		assertThat(saved.getEvidenceSource()).isNull();
		assertThat(saved.getEventStart()).isNull();
		assertThat(repository.findById(saved.getId())).isPresent();
	}

	@Test
	@DisplayName("A source cannot deliver the same artifact id twice")
	void duplicateSourceArtifactIdIsRejected() {
		repository.saveAndFlush(streamedItem("evidence/auth/one.log", "auth-2026-01-01-14", ALERT, ALERT));

		// The streamed-ingestion idempotency guarantee. Kafka is at-least-once and this
		// stream is orders of magnitude larger than the alert stream, so redelivery is
		// routine rather than exceptional.
		assertThatThrownBy(() -> repository.saveAndFlush(
				streamedItem("evidence/auth/two.log", "auth-2026-01-01-14", ALERT, ALERT)))
				.isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	@DisplayName("Two manually preserved items do not collide on their null artifact ids")
	void nullArtifactIdsDoNotCollide() {
		// Postgres treats NULLs as distinct in a unique constraint, which is exactly the
		// behaviour uq_evidence_item_source_artifact needs: manual items carry null in both
		// columns and must never dedupe against each other.
		repository.saveAndFlush(newItem("evidence/manual/first.csv"));
		repository.saveAndFlush(newItem("evidence/manual/second.csv"));

		assertThat(repository.findByWorkGroupId(workGroup.getId(), PageRequest.of(0, 10)))
				.hasSize(2);
	}

	@Test
	@DisplayName("Half a coverage window is rejected")
	void incompleteCoverageWindowIsRejected() {
		EvidenceItem item = newItem("evidence/bad/half-window.log");
		item.setEventStart(ALERT);
		// eventEnd deliberately left null. Half a window is worse than none: it looks
		// answerable to a correlation query and answers wrongly.

		assertThatThrownBy(() -> repository.saveAndFlush(item))
				.isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	@DisplayName("A coverage window that ends before it starts is rejected")
	void invertedCoverageWindowIsRejected() {
		EvidenceItem item = streamedItem("evidence/bad/inverted.log", "inverted",
				ALERT, ALERT.minusHours(1));

		assertThatThrownBy(() -> repository.saveAndFlush(item))
				.isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	@DisplayName("An artifact id without a source is rejected")
	void artifactIdWithoutSourceIsRejected() {
		// Such a row could never be resolved back to anything, and worse, it would sit
		// outside uq_evidence_item_source_artifact (NULLs being distinct) and dedupe against
		// nothing at all.
		EvidenceItem item = newItem("evidence/bad/orphan-artifact.log");
		item.setSourceArtifactId("orphan");

		assertThatThrownBy(() -> repository.saveAndFlush(item))
				.isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	@DisplayName("findOverlappingCoverage returns evidence spanning the alert, and nothing outside it")
	void findsEvidenceOverlappingTheCorrelationWindow() {
		// The hourly bundle that actually contains the alert's activity — and the case that
		// motivated the whole refactor. It was preserved at 15:02, so a correlation keyed on
		// created_at would have missed it entirely.
		repository.saveAndFlush(streamedItem("evidence/auth/14-15.log", "auth-14",
				ALERT.minusMinutes(30), ALERT.plusMinutes(30)));
		// Straddles the start of the lookback: overlap is partial, which still counts.
		repository.saveAndFlush(streamedItem("evidence/fw/13-14.log", "fw-13",
				ALERT.minusMinutes(90), ALERT.minusMinutes(20)));
		// Yesterday. Same source, same classification, no temporal relevance.
		repository.saveAndFlush(streamedItem("evidence/auth/old.log", "auth-old",
				ALERT.minusDays(1), ALERT.minusDays(1).plusHours(1)));

		// The default window from TriggerEvent: 30 minutes back, 15 forward.
		var matches = repository.findOverlappingCoverage(
				workGroup.getId(), ALERT.minusMinutes(30), ALERT.plusMinutes(15), PageRequest.of(0, 20));

		assertThat(matches).extracting(EvidenceItem::getStorageRef)
				.containsExactlyInAnyOrder("evidence/auth/14-15.log", "evidence/fw/13-14.log");
	}

	@Test
	@DisplayName("A point-in-time artifact at the window boundary is still matched")
	void pointInTimeArtifactIsMatched() {
		// eventStart == eventEnd. This is why both ranges are built with inclusive '[]'
		// bounds: tstzrange(t, t, '[)') is the empty range and would overlap nothing,
		// silently excluding exactly the memory captures and single transaction records an
		// investigation most wants.
		repository.saveAndFlush(streamedItem("evidence/mem/dump.raw", "mem-1", ALERT, ALERT));

		var matches = repository.findOverlappingCoverage(
				workGroup.getId(), ALERT, ALERT, PageRequest.of(0, 20));

		assertThat(matches).extracting(EvidenceItem::getStorageRef)
				.containsExactly("evidence/mem/dump.raw");
	}

	@Test
	@DisplayName("Correlation ignores items with no coverage window and items in other work groups")
	void correlationIsScopedByWindowPresenceAndClassification() {
		// No window: cannot be placed in time, so it can only ever be linked by hand.
		repository.saveAndFlush(newItem("evidence/manual/unwindowed.csv"));

		WorkGroup other = workGroupRepository.findByClassificationCode("INTERNAL_SYSTEMS").orElseThrow();
		EvidenceItem elsewhere = newItem("evidence/other/in-window.log");
		elsewhere.setWorkGroup(other);
		elsewhere.setEventStart(ALERT);
		elsewhere.setEventEnd(ALERT);
		repository.saveAndFlush(elsewhere);

		// Time alone is not a usable predicate here: every source produces continuously, so
		// an unscoped window returns tens of thousands of items. Classification is the
		// second axis the schema already carries.
		assertThat(repository.findOverlappingCoverage(
				workGroup.getId(), ALERT.minusHours(1), ALERT.plusHours(1), PageRequest.of(0, 20)))
				.isEmpty();
	}

	@Test
	@DisplayName("Correlation skips soft-deleted evidence but keeps compromised evidence")
	void correlationExcludesDeletedButNotCompromised() {
		EvidenceItem deleted = streamedItem("evidence/gone.log", "gone", ALERT, ALERT);
		deleted.setStatus(EvidenceStatus.DELETED);
		repository.saveAndFlush(deleted);

		// COMPROMISED is deliberately still returned. An artifact that failed integrity
		// re-verification is relevant to an investigation — arguably more so, since the
		// failure is itself a finding.
		EvidenceItem compromised = streamedItem("evidence/altered.log", "altered", ALERT, ALERT);
		compromised.setStatus(EvidenceStatus.COMPROMISED);
		repository.saveAndFlush(compromised);

		assertThat(repository.findOverlappingCoverage(
				workGroup.getId(), ALERT, ALERT, PageRequest.of(0, 20)))
				.extracting(EvidenceItem::getStorageRef)
				.containsExactly("evidence/altered.log");
	}

	@Test
	@DisplayName("findByWorkGroupId pages the items preserved under one classification")
	void findsItemsByWorkGroup() {
		repository.saveAndFlush(newItem("evidence/wg/one.log"));
		repository.saveAndFlush(newItem("evidence/wg/two.log"));

		assertThat(repository.findByWorkGroupId(workGroup.getId(), PageRequest.of(0, 10)))
				.hasSize(2);
	}

	@Test
	@DisplayName("findByEvidenceSourceId pages everything one collector produced")
	void findsItemsBySource() {
		repository.saveAndFlush(streamedItem("evidence/src/one.log", "s-1", ALERT, ALERT));
		repository.saveAndFlush(streamedItem("evidence/src/two.log", "s-2", ALERT, ALERT));
		repository.saveAndFlush(newItem("evidence/src/manual.csv"));

		assertThat(repository.findByEvidenceSourceId(source.getId(), PageRequest.of(0, 10)))
				.extracting(EvidenceItem::getStorageRef)
				.containsExactlyInAnyOrder("evidence/src/one.log", "evidence/src/two.log");
	}

	@Test
	@DisplayName("findByStatusNot is the browse listing, and it withholds soft-deleted evidence")
	void listingExcludesSoftDeletedItems() {
		repository.saveAndFlush(newItem("evidence/browse/live.log"));

		EvidenceItem deleted = newItem("evidence/browse/destroyed.log");
		deleted.setStatus(EvidenceStatus.DELETED);
		repository.saveAndFlush(deleted);

		assertThat(repository.findByStatusNot(EvidenceStatus.DELETED, PageRequest.of(0, 10)))
				.extracting(EvidenceItem::getStorageRef)
				.containsExactly("evidence/browse/live.log");
	}

	@Test
	@DisplayName("findByStatusNot excludes one status rather than allow-listing several")
	void listingIncludesEveryStateThatIsNotDeleted() {
		// The reason the query is phrased as an exclusion. A COMPROMISED artifact is still
		// preserved evidence and is arguably the one an investigator most needs to see, and an
		// ARCHIVED one is intact and merely slower to retrieve. Neither may be filtered out of
		// a browse listing, and a status added later must show up by default rather than
		// vanish until someone remembers to widen an IN clause.
		EvidenceItem compromised = newItem("evidence/browse/altered.log");
		compromised.setStatus(EvidenceStatus.COMPROMISED);
		repository.saveAndFlush(compromised);

		EvidenceItem archived = newItem("evidence/browse/cold.log");
		archived.setStatus(EvidenceStatus.ARCHIVED);
		repository.saveAndFlush(archived);

		assertThat(repository.findByStatusNot(EvidenceStatus.DELETED, PageRequest.of(0, 10)))
				.extracting(EvidenceItem::getStorageRef)
				.containsExactlyInAnyOrder("evidence/browse/altered.log", "evidence/browse/cold.log");
	}

	@Test
	@DisplayName("findByWorkGroupIdAndStatusNot narrows the listing without losing the soft delete")
	void listingByWorkGroupAlsoExcludesSoftDeletedItems() {
		repository.saveAndFlush(newItem("evidence/browse/wg-live.log"));

		EvidenceItem deleted = newItem("evidence/browse/wg-destroyed.log");
		deleted.setStatus(EvidenceStatus.DELETED);
		repository.saveAndFlush(deleted);

		// The unfiltered findByWorkGroupId still sees both — the soft delete is applied by
		// this finder, not by the classification.
		assertThat(repository.findByWorkGroupId(workGroup.getId(), PageRequest.of(0, 10))).hasSize(2);

		assertThat(repository.findByWorkGroupIdAndStatusNot(
				workGroup.getId(), EvidenceStatus.DELETED, PageRequest.of(0, 10)))
				.extracting(EvidenceItem::getStorageRef)
				.containsExactly("evidence/browse/wg-live.log");
	}

	@Test
	@DisplayName("The browse listing is paged, so an unbounded table cannot be materialised in one read")
	void listingIsPaged() {
		for (int i = 0; i < 5; i++) {
			repository.saveAndFlush(newItem("evidence/browse/page-" + i + ".log"));
		}

		assertThat(repository.findByStatusNot(EvidenceStatus.DELETED, PageRequest.of(0, 2)))
				.hasSize(2)
				.extracting(EvidenceItem::getStorageRef)
				.allSatisfy(ref -> assertThat(ref).startsWith("evidence/browse/page-"));
		assertThat(repository.findByStatusNot(EvidenceStatus.DELETED, PageRequest.of(0, 2)).getTotalElements())
				.isEqualTo(5);
	}

	@Test
	@DisplayName("countByStatus answers the readiness-audit question")
	void countsItemsInAnExceptionalState() {
		repository.saveAndFlush(newItem("evidence/audit/intact.log"));

		EvidenceItem compromised = newItem("evidence/audit/altered.log");
		compromised.setStatus(EvidenceStatus.COMPROMISED);
		repository.saveAndFlush(compromised);

		assertThat(repository.countByStatus(EvidenceStatus.COMPROMISED)).isEqualTo(1);
		assertThat(repository.findByStatus(EvidenceStatus.COMPROMISED, PageRequest.of(0, 10)))
				.extracting(EvidenceItem::getStorageRef)
				.containsExactly("evidence/audit/altered.log");
	}

	@Test
	@DisplayName("status is stored by name, so the column is readable without the enum")
	void statusIsPersistedAsItsName() {
		EvidenceItem saved = repository.saveAndFlush(newItem("evidence/status/name.log"));
		entityManager.clear();

		// Guards @Enumerated(EnumType.STRING). An ordinal mapping would store 0 here, and
		// reordering the enum constants would then silently reinterpret every existing row.
		Object stored = entityManager.getEntityManager()
				.createNativeQuery("SELECT status FROM evidence_item WHERE id = :id")
				.setParameter("id", saved.getId())
				.getSingleResult();

		assertThat(stored).isEqualTo("PRESERVED");
	}

	@Test
	@DisplayName("Two items cannot claim the same storage object")
	void duplicateStorageRefIsRejected() {
		repository.saveAndFlush(newItem("evidence/dup/same-object"));

		// Sharing a key would mean two custody chains over one object, and a delete under
		// one would silently gut the other.
		assertThatThrownBy(() -> repository.saveAndFlush(newItem("evidence/dup/same-object")))
				.isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	@DisplayName("A current_hash that is not a lowercase hex digest is rejected")
	void malformedHashIsRejectedByTheCheckConstraint() {
		EvidenceItem item = newItem("evidence/bad/hash.log");
		item.setCurrentHash("not-a-sha-256");

		assertThatThrownBy(() -> repository.saveAndFlush(item))
				.isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	@DisplayName("A status outside EvidenceStatus is rejected even when the enum is bypassed")
	void unknownStatusIsRejectedByTheCheckConstraint() {
		// Deliberately a native insert: the Java enum already makes this unrepresentable,
		// so the only way to prove the database defends itself against a write that never
		// passes through this application is to be that write.
		assertThatThrownBy(() -> entityManager.getEntityManager()
				.createNativeQuery("INSERT INTO evidence_item "
						+ "(work_group_id, storage_ref, current_hash, status) "
						+ "VALUES (:workGroupId, :storageRef, :hash, 'NOT_A_STATUS')")
				.setParameter("workGroupId", workGroup.getId())
				.setParameter("storageRef", "evidence/bad/status.log")
				.setParameter("hash", SHA_256_OF_EMPTY_STRING)
				.executeUpdate())
				.isInstanceOf(PersistenceException.class);
	}

	@Test
	@DisplayName("A work group with evidence against it cannot be deleted")
	void workGroupDeleteIsRestrictedByTheForeignKey() {
		WorkGroup doomed = new WorkGroup();
		doomed.setName("Temporary");
		doomed.setClassificationCode("TEMPORARY");
		WorkGroup savedGroup = workGroupRepository.saveAndFlush(doomed);

		EvidenceItem item = newItem("evidence/restrict/held.log");
		item.setWorkGroup(savedGroup);
		repository.saveAndFlush(item);

		// Detach everything first. With the item still managed, Hibernate notices that a
		// persistent EvidenceItem points at a now-removed WorkGroup and throws
		// TransientPropertyValueException before any SQL is sent — which would leave the
		// foreign key itself untested. Clearing forces the question to the database, which
		// is where the guarantee actually lives.
		entityManager.clear();

		// RESTRICT, not CASCADE. Deleting a classification must not silently take the
		// evidence filed under it — evidence is soft-delete only.
		workGroupRepository.delete(workGroupRepository.findById(savedGroup.getId()).orElseThrow());
		assertThatThrownBy(() -> workGroupRepository.flush())
				.isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	@DisplayName("A source that has produced evidence cannot be deleted")
	void sourceDeleteIsRestrictedByTheForeignKey() {
		repository.saveAndFlush(streamedItem("evidence/restrict/from-source.log", "held", ALERT, ALERT));
		entityManager.clear();

		// The evidence would survive a cascade, but the record of what collected it would
		// not — and "where did this come from" is the first question asked of any exhibit.
		// A source that should stop is DECOMMISSIONED, never deleted.
		evidenceSourceRepository.delete(evidenceSourceRepository.findById(source.getId()).orElseThrow());
		assertThatThrownBy(() -> evidenceSourceRepository.flush())
				.isInstanceOf(DataIntegrityViolationException.class);
	}

	/** A manually preserved item: no source, no artifact id, no coverage window. */
	private EvidenceItem newItem(String storageRef) {
		EvidenceItem item = new EvidenceItem();
		item.setWorkGroup(workGroup);
		item.setStorageRef(storageRef);
		item.setCurrentHash(SHA_256_OF_EMPTY_STRING);
		item.setStatus(EvidenceStatus.PRESERVED);
		return item;
	}

	/** An item as continuous collection produces one: attributed, identified, and placed in time. */
	private EvidenceItem streamedItem(
			String storageRef, String sourceArtifactId, OffsetDateTime start, OffsetDateTime end) {
		EvidenceItem item = newItem(storageRef);
		item.setEvidenceSource(source);
		item.setSourceArtifactId(sourceArtifactId);
		item.setEventStart(start);
		item.setEventEnd(end);
		return item;
	}

	private EvidenceSource newSource(String sourceKey) {
		EvidenceSource evidenceSource = new EvidenceSource();
		evidenceSource.setSourceKey(sourceKey);
		evidenceSource.setDisplayName("Authentication syslog forwarder");
		evidenceSource.setSourceType("SYSLOG");
		evidenceSource.setWorkGroup(workGroup);
		return evidenceSource;
	}
}
