package za.co.dfraas.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.jpa.test.autoconfigure.TestEntityManager;
import org.springframework.context.annotation.Import;

import za.co.dfraas.TestcontainersConfiguration;
import za.co.dfraas.dto.CustodyChainVerification;
import za.co.dfraas.entity.CustodyAction;
import za.co.dfraas.entity.CustodyEvent;
import za.co.dfraas.entity.EvidenceItem;
import za.co.dfraas.entity.EvidenceStatus;
import za.co.dfraas.entity.WorkGroup;
import za.co.dfraas.exception.ResourceNotFoundException;
import za.co.dfraas.repository.CustodyEventRepository;
import za.co.dfraas.repository.EvidenceItemRepository;
import za.co.dfraas.repository.WorkGroupRepository;

/**
 * What the chain actually detects, against a real database.
 *
 * <p>A {@code @DataJpaTest} rather than a Mockito test, and that is not incidental. The
 * failure this class exists to prevent is a chain that verifies in memory and stops verifying
 * once it has been through Postgres — {@code timestamptz} keeps neither the offset a value was
 * written with nor anything finer than a microsecond, so a canonical form that renders
 * {@code occurredAt} any other way produces digests that are correct exactly until the first
 * restart. Mocked repositories would never see it.
 *
 * <p>The tampering cases go through native SQL on purpose. Every column on
 * {@link CustodyEvent} is {@code updatable = false}, so an edit made through the entity is
 * ignored rather than written — which means the only way to produce the row an attacker would
 * produce is to go round Hibernate, exactly as they would.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import(TestcontainersConfiguration.class)
class CustodyChainServiceTest {

	private static final String SHA_256_OF_EMPTY_STRING =
			"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

	private static final String PRINCIPAL = "j.mokoena";

	private static final OffsetDateTime OCCURRED_AT = OffsetDateTime.parse("2026-01-01T14:00:00Z");

	@Autowired
	private CustodyEventRepository repository;

	@Autowired
	private EvidenceItemRepository evidenceItemRepository;

	@Autowired
	private WorkGroupRepository workGroupRepository;

	@Autowired
	private TestEntityManager entityManager;

	private CustodyChainService service;
	private WorkGroup workGroup;
	private EvidenceItem item;

	@BeforeEach
	void setUp() {
		service = new CustodyChainService(repository, evidenceItemRepository, new HashingService());
		workGroup = workGroupRepository.findByClassificationCode("ONLINE_BANKING").orElseThrow();
		item = evidenceItemRepository.saveAndFlush(newItem("evidence/auth/14-15.log"));
	}

	@Test
	@DisplayName("The first entry starts at zero from the genesis hash")
	void openingEntryStartsTheChain() {
		CustodyEvent opening = service.recordCreation(item, PRINCIPAL, "Preserved on streamed ingest.");

		assertThat(opening.getSequence()).isZero();
		assertThat(opening.getPrevEntryHash()).isEqualTo(CustodyChainService.GENESIS_HASH);
		assertThat(opening.getAction()).isEqualTo(CustodyAction.CREATED);
		assertThat(opening.getPerformedBy()).isEqualTo(PRINCIPAL);
		// The item's digest, anchored into a record that cannot change, from a column that can.
		assertThat(opening.getArtifactHashBefore()).isNull();
		assertThat(opening.getArtifactHashAfter()).isEqualTo(item.getCurrentHash());
		// The opening entry borrows the database's clock, which is why it is written after the
		// item has been flushed.
		assertThat(opening.getOccurredAt()).isEqualTo(item.getCreatedAt());
	}

	@Test
	@DisplayName("Each entry links to the one before it, and the chain verifies")
	void chainOfSeveralEntriesVerifies() {
		service.recordCreation(item, PRINCIPAL, "Preserved on streamed ingest.");
		CustodyEvent second = append(1, "Re-verified on read.");
		CustodyEvent third = append(2, "Re-verified on read.");

		List<CustodyEvent> chain = repository.findByEvidenceItemIdOrderBySequenceAsc(item.getId());
		assertThat(chain).extracting(CustodyEvent::getSequence).containsExactly(0L, 1L, 2L);
		assertThat(second.getPrevEntryHash()).isEqualTo(chain.get(0).getEntryHash());
		assertThat(third.getPrevEntryHash()).isEqualTo(second.getEntryHash());

		CustodyChainVerification verification = service.verify(item.getId());
		assertThat(verification.intact()).isTrue();
		assertThat(verification.length()).isEqualTo(3);
		assertThat(verification.firstDivergentSequence()).isNull();
		assertThat(verification.headEntryHash()).isEqualTo(third.getEntryHash());
	}

	/**
	 * The single most likely way for this class to break, and the reason the canonical form
	 * renders {@code occurredAt} as UTC truncated to microseconds. An entry hashed from an
	 * offset timestamp with nanosecond precision verifies in memory and then fails the moment
	 * it is read back, because the column kept neither the offset nor the nanoseconds — a
	 * chain that breaks on restart for no reason a reader could see.
	 */
	@Test
	@DisplayName("A chain still verifies after a round trip, whatever offset and precision it was written with")
	void chainVerifiesAfterRoundTripFromAnOffsetNanosecondTimestamp() {
		OffsetDateTime awkward = OffsetDateTime.parse("2026-01-01T16:00:00.123456789+02:00");
		CustodyEvent appended = service.append(
				item.getId(), CustodyAction.CREATED, PRINCIPAL, awkward, null, item.getCurrentHash(), "Preserved.");

		// Normalised before hashing, so the value in memory is one the column can hold exactly.
		assertThat(appended.getOccurredAt())
				.isEqualTo(awkward.withOffsetSameInstant(ZoneOffset.UTC).truncatedTo(ChronoUnit.MICROS));

		entityManager.flush();
		entityManager.clear();

		assertThat(service.verify(item.getId()).intact()).isTrue();
	}

	@Test
	@DisplayName("An artifact with no chain is reported as missing its origin, not as intact")
	void emptyChainIsMissingItsOrigin() {
		CustodyChainVerification verification = service.verify(item.getId());

		// Not a pass. No artifact legitimately has no custody entries — the opening one is
		// written in the transaction that creates the item — so "nothing to check" is a finding.
		assertThat(verification.intact()).isFalse();
		assertThat(verification.missingOrigin()).isTrue();
		assertThat(verification.length()).isZero();
	}

	@Test
	@DisplayName("An edited attribution no longer matches the entry's own digest")
	void editedEntryFailsVerification() {
		service.recordCreation(item, PRINCIPAL, "Preserved on streamed ingest.");
		append(1, "Re-verified on read.");
		append(2, "Re-verified on read.");
		entityManager.flush();
		entityManager.clear();

		// Reassigning custody of an exhibit to someone else after the fact — the edit a custody
		// ledger exists to make impossible to do quietly.
		execute("UPDATE custody_event SET performed_by = 'someone.else' "
				+ "WHERE evidence_item_id = :itemId AND \"sequence\" = 1");

		CustodyChainVerification verification = service.verify(item.getId());
		assertThat(verification.intact()).isFalse();
		assertThat(verification.missingOrigin()).isFalse();
		assertThat(verification.firstDivergentSequence()).isEqualTo(1L);
		// The entries before the divergence still stand, which is why the position is reported
		// rather than a bare failure.
		assertThat(verification.length()).isEqualTo(3);
	}

	@Test
	@DisplayName("A rewritten detail is caught even though the text itself is never inlined")
	void editedDetailFailsVerification() {
		service.recordCreation(item, PRINCIPAL, "Preserved on streamed ingest.");
		entityManager.flush();
		entityManager.clear();

		// detail is covered as its SHA-256 rather than inlined, which keeps free text away from
		// the canonical form's field boundaries without leaving it unprotected.
		execute("UPDATE custody_event SET detail = 'Preserved after review.' "
				+ "WHERE evidence_item_id = :itemId AND \"sequence\" = 0");

		assertThat(service.verify(item.getId()).firstDivergentSequence()).isZero();
	}

	/**
	 * The case a per-row digest cannot catch on its own: every surviving entry is individually
	 * valid and still points at the one before it. What gives it away is that the ledger now
	 * claims 0, 1, 3 — which is why verification checks position as well as digests.
	 */
	@Test
	@DisplayName("An entry deleted from the middle of a chain is caught by the position check")
	void deletedMiddleEntryFailsVerification() {
		service.recordCreation(item, PRINCIPAL, "Preserved on streamed ingest.");
		append(1, "Re-verified on read.");
		append(2, "Re-verified on read.");
		append(3, "Re-verified on read.");
		entityManager.flush();
		entityManager.clear();

		execute("DELETE FROM custody_event WHERE evidence_item_id = :itemId AND \"sequence\" = 2");

		CustodyChainVerification verification = service.verify(item.getId());
		assertThat(verification.intact()).isFalse();
		// Reported at the position the hole is, not at the sequence the row sitting there
		// carries — that number points past the gap rather than at it.
		assertThat(verification.firstDivergentSequence()).isEqualTo(2L);
		assertThat(verification.length()).isEqualTo(3);
	}

	/**
	 * Two entries identical in every respect except which artifact they belong to must hash
	 * differently, or a row could be moved from one exhibit's chain to another's and still
	 * verify. Same argument for {@code sequence}, which is what stops a reordering within one
	 * chain.
	 */
	@Test
	@DisplayName("An entry is bound to its own item and position")
	void entryHashIsBoundToItemAndSequence() {
		EvidenceItem firewallLog = evidenceItemRepository.saveAndFlush(newItem("evidence/fw/14-15.log"));

		CustodyEvent onAuthLog = service.append(
				item.getId(), CustodyAction.CREATED, PRINCIPAL, OCCURRED_AT, null, SHA_256_OF_EMPTY_STRING, null);
		CustodyEvent onFirewallLog = service.append(
				firewallLog.getId(), CustodyAction.CREATED, PRINCIPAL, OCCURRED_AT, null,
				SHA_256_OF_EMPTY_STRING, null);

		assertThat(onAuthLog.getSequence()).isEqualTo(onFirewallLog.getSequence());
		assertThat(onAuthLog.getPrevEntryHash()).isEqualTo(onFirewallLog.getPrevEntryHash());
		assertThat(onAuthLog.getEntryHash()).isNotEqualTo(onFirewallLog.getEntryHash());
	}

	/**
	 * Length-prefixing every field is what makes the encoding injective, and this is the pair
	 * that shows why it is needed: under plain concatenation both of these entries produce
	 * {@code ...ab...} and hash identically, so a principal named to look like the start of the
	 * next field would let one entry stand in for another. With a length in front of every
	 * field the boundary is stated before the content is read.
	 *
	 * <p>Built by hand rather than appended, because the point is a property of the encoding
	 * and the database would reject the forged row on
	 * {@code ck_custody_event_artifact_hash_before} long before the digest mattered.
	 */
	@Test
	@DisplayName("Free text cannot forge a field boundary in the canonical form")
	void freeTextCannotForgeAFieldBoundary() {
		CustodyEvent honest = unsavedEntry("ab", "");
		CustodyEvent forged = unsavedEntry("a", "b");

		assertThat(service.canonicalV1(honest)).isNotEqualTo(service.canonicalV1(forged));
		assertThat(service.entryHash(CustodyChainService.GENESIS_HASH, honest))
				.isNotEqualTo(service.entryHash(CustodyChainService.GENESIS_HASH, forged));
	}

	/**
	 * A version this build does not implement is refused rather than verified under the rules
	 * of a different one. Reporting a chain intact on the strength of the wrong canonical form
	 * would be a false assurance, which is worse than an error.
	 */
	@Test
	@DisplayName("An entry written under an unknown canonical version is refused, not passed")
	void unknownCanonicalVersionIsRefused() {
		service.recordCreation(item, PRINCIPAL, "Preserved on streamed ingest.");
		entityManager.flush();
		entityManager.clear();

		execute("UPDATE custody_event SET canonical_version = 99 "
				+ "WHERE evidence_item_id = :itemId AND \"sequence\" = 0");

		assertThatThrownBy(() -> service.verify(item.getId()))
				.isInstanceOf(IllegalStateException.class)
				.hasMessageContaining("canonical version 99");
	}

	@Test
	@DisplayName("Appending to an artifact that does not exist is rejected")
	void appendToUnknownItemIsRejected() {
		assertThatThrownBy(() -> service.append(
				UUID.randomUUID(), CustodyAction.CREATED, PRINCIPAL, OCCURRED_AT, null, null, null))
				.isInstanceOf(ResourceNotFoundException.class);
	}

	private CustodyEvent append(int minutesLater, String detail) {
		return service.append(
				item.getId(),
				CustodyAction.CREATED,
				PRINCIPAL,
				OCCURRED_AT.plusMinutes(minutesLater),
				null,
				null,
				detail);
	}

	/**
	 * An entry that is never persisted, for the cases that are about the canonical form itself
	 * rather than about the ledger.
	 */
	private CustodyEvent unsavedEntry(String performedBy, String artifactHashBefore) {
		CustodyEvent entry = new CustodyEvent();
		entry.setEvidenceItem(item);
		entry.setSequence(0L);
		entry.setAction(CustodyAction.CREATED);
		entry.setPerformedBy(performedBy);
		entry.setOccurredAt(OCCURRED_AT);
		entry.setArtifactHashBefore(artifactHashBefore);
		entry.setCanonicalVersion(CustodyChainService.CANONICAL_VERSION_1);
		return entry;
	}

	/**
	 * Native SQL, scoped to this test's item, because every column on the entity is
	 * {@code updatable = false} — an edit through Hibernate is ignored rather than written, so
	 * the only way to produce a tampered row is the way an attacker would.
	 */
	private void execute(String sql) {
		entityManager.getEntityManager()
				.createNativeQuery(sql)
				.setParameter("itemId", item.getId())
				.executeUpdate();
		entityManager.clear();
	}

	private EvidenceItem newItem(String storageRef) {
		EvidenceItem evidenceItem = new EvidenceItem();
		evidenceItem.setWorkGroup(workGroup);
		evidenceItem.setStorageRef(storageRef);
		evidenceItem.setCurrentHash(SHA_256_OF_EMPTY_STRING);
		evidenceItem.setStatus(EvidenceStatus.PRESERVED);
		evidenceItem.setEventStart(OffsetDateTime.parse("2026-01-01T14:00:00Z"));
		evidenceItem.setEventEnd(OffsetDateTime.parse("2026-01-01T15:00:00Z"));
		return evidenceItem;
	}
}
