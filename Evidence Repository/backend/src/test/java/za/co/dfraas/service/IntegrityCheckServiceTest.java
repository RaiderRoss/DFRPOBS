package za.co.dfraas.service;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
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
import za.co.dfraas.dto.EvidenceExport;
import za.co.dfraas.dto.IntegrityCheckResult;
import za.co.dfraas.entity.CustodyAction;
import za.co.dfraas.entity.CustodyEvent;
import za.co.dfraas.entity.EvidenceItem;
import za.co.dfraas.entity.EvidenceStatus;
import za.co.dfraas.entity.WorkGroup;
import za.co.dfraas.exception.EvidenceStorageException;
import za.co.dfraas.exception.ResourceNotFoundException;
import za.co.dfraas.mapper.CustodyEventMapper;
import za.co.dfraas.repository.CustodyEventRepository;
import za.co.dfraas.repository.EvidenceItemRepository;
import za.co.dfraas.repository.WorkGroupRepository;

/**
 * What a re-verification records, and what it changes.
 *
 * <p>A {@code @DataJpaTest} for the same reason {@code CustodyChainServiceTest} is one: the
 * entry this service appends has to survive a round trip through Postgres and still verify,
 * and the status transition has to be accepted by {@code ck_evidence_item_status} and the
 * new action by {@code ck_custody_event_action} (changeset {@code 0007}) — neither of which
 * a mocked repository would check. Only the object store is mocked, because it is the one
 * thing whose contents the test needs to control: a stored object that still hashes
 * correctly, and one that does not.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import(TestcontainersConfiguration.class)
class IntegrityCheckServiceTest {

	private static final byte[] CONTENT = "hello".getBytes(UTF_8);
	private static final byte[] OTHER_CONTENT = "goodbye".getBytes(UTF_8);

	/** SHA-256 of "hello" — a real digest, so a broken hasher cannot pass by agreeing with itself. */
	private static final String CONTENT_SHA256 =
			"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

	/** SHA-256 of "goodbye". */
	private static final String OTHER_SHA256 =
			"82e35a63ceba37e9646434c5dd412ea577147f1e4a41ccde1614253187e3dbf9";

	private static final String ARTIFACT_ID = "firewall_20260905143000";
	private static final String STORAGE_REF = "pde-sim-ufw-01/" + ARTIFACT_ID;
	private static final String PRINCIPAL = "j.mokoena";

	/** Pinned, so the test can assert on exactly what was stamped into the entry and hashed. */
	private static final Instant CHECKED_AT = Instant.parse("2026-09-06T09:15:00.123456Z");

	@Autowired
	private CustodyEventRepository custodyEventRepository;

	@Autowired
	private EvidenceItemRepository evidenceItemRepository;

	@Autowired
	private WorkGroupRepository workGroupRepository;

	@Autowired
	private TestEntityManager entityManager;

	private EvidenceStorageService storageService;
	private CustodyChainService custodyChainService;
	private IntegrityCheckService service;
	private EvidenceItem item;

	@BeforeEach
	void setUp() {
		storageService = mock(EvidenceStorageService.class);
		HashingService hashingService = new HashingService();
		custodyChainService = new CustodyChainService(custodyEventRepository, evidenceItemRepository, hashingService);
		service = new IntegrityCheckService(
				evidenceItemRepository,
				storageService,
				hashingService,
				custodyChainService,
				new CustodyEventMapper(),
				Clock.fixed(CHECKED_AT, ZoneOffset.UTC));

		WorkGroup workGroup = workGroupRepository.findByClassificationCode("ONLINE_BANKING").orElseThrow();
		item = evidenceItemRepository.saveAndFlush(newItem(workGroup, EvidenceStatus.PRESERVED));
		// Every real item has an opening entry; the check appends after it.
		custodyChainService.recordCreation(item, PRINCIPAL, "Preserved on streamed ingest.");
	}

	@Test
	@DisplayName("An intact object is recorded as HASH_VERIFIED and changes nothing on the item")
	void intactObjectIsRecordedAsVerified() {
		given(storageService.read(STORAGE_REF)).willReturn(CONTENT);

		IntegrityCheckResult result = service.check(item.getId(), PRINCIPAL);

		assertThat(result.intact()).isTrue();
		assertThat(result.expectedHash()).isEqualTo(CONTENT_SHA256);
		assertThat(result.observedHash()).isEqualTo(CONTENT_SHA256);
		assertThat(result.status()).isEqualTo(EvidenceStatus.PRESERVED);

		CustodyEvent entry = headOfChain();
		assertThat(entry.getSequence()).isEqualTo(1L);
		assertThat(entry.getAction()).isEqualTo(CustodyAction.HASH_VERIFIED);
		assertThat(entry.getPerformedBy()).isEqualTo(PRINCIPAL);
		// Expected and observed, both carried, so a reader need not infer the comparison from
		// whichever CREATED entry happens to be at the top of the chain.
		assertThat(entry.getArtifactHashBefore()).isEqualTo(CONTENT_SHA256);
		assertThat(entry.getArtifactHashAfter()).isEqualTo(CONTENT_SHA256);
		assertThat(entry.getOccurredAt()).isEqualTo(OffsetDateTime.ofInstant(CHECKED_AT, ZoneOffset.UTC));
		assertThat(entry.getDetail()).contains("matches").contains("PRESERVED is unchanged");

		assertThat(reloadedItem().getStatus()).isEqualTo(EvidenceStatus.PRESERVED);
		assertThat(reloadedItem().getCurrentHash()).isEqualTo(CONTENT_SHA256);
	}

	@Test
	@DisplayName("A mismatch is recorded as HASH_MISMATCH and moves the item to COMPROMISED")
	void mismatchIsRecordedAndMarksTheItemCompromised() {
		given(storageService.read(STORAGE_REF)).willReturn(OTHER_CONTENT);

		IntegrityCheckResult result = service.check(item.getId(), PRINCIPAL);

		assertThat(result.intact()).isFalse();
		assertThat(result.expectedHash()).isEqualTo(CONTENT_SHA256);
		assertThat(result.observedHash()).isEqualTo(OTHER_SHA256);
		assertThat(result.status()).isEqualTo(EvidenceStatus.COMPROMISED);

		CustodyEvent entry = headOfChain();
		assertThat(entry.getAction()).isEqualTo(CustodyAction.HASH_MISMATCH);
		assertThat(entry.getArtifactHashBefore()).isEqualTo(CONTENT_SHA256);
		assertThat(entry.getArtifactHashAfter()).isEqualTo(OTHER_SHA256);
		assertThat(entry.getDetail()).contains("does not match").contains("from PRESERVED to COMPROMISED");

		EvidenceItem reloaded = reloadedItem();
		assertThat(reloaded.getStatus()).isEqualTo(EvidenceStatus.COMPROMISED);
		// The expectation is kept. Overwriting it with the observation would erase the
		// discrepancy just recorded and make the next check pass.
		assertThat(reloaded.getCurrentHash()).isEqualTo(CONTENT_SHA256);
	}

	/**
	 * The entry the check writes is a link in the chain like any other, and the chain must
	 * still verify with it in place — after a round trip, under the same canonical form.
	 */
	@Test
	@DisplayName("The chain still verifies after either outcome has been appended")
	void chainVerifiesAfterChecks() {
		given(storageService.read(STORAGE_REF)).willReturn(CONTENT, OTHER_CONTENT);

		service.check(item.getId(), PRINCIPAL);
		service.check(item.getId(), PRINCIPAL);
		entityManager.flush();
		entityManager.clear();

		List<CustodyEvent> chain = custodyEventRepository.findByEvidenceItemIdOrderBySequenceAsc(item.getId());
		assertThat(chain).extracting(CustodyEvent::getAction)
				.containsExactly(CustodyAction.CREATED, CustodyAction.HASH_VERIFIED, CustodyAction.HASH_MISMATCH);
		assertThat(custodyChainService.verify(item.getId()).intact()).isTrue();
	}

	@Test
	@DisplayName("A repeated mismatch on a compromised item is recorded again and leaves the status alone")
	void repeatedMismatchOnCompromisedItemIsRecorded() {
		given(storageService.read(STORAGE_REF)).willReturn(OTHER_CONTENT);
		service.check(item.getId(), PRINCIPAL);

		IntegrityCheckResult second = service.check(item.getId(), PRINCIPAL);

		assertThat(second.status()).isEqualTo(EvidenceStatus.COMPROMISED);
		assertThat(headOfChain().getSequence()).isEqualTo(2L);
		assertThat(headOfChain().getAction()).isEqualTo(CustodyAction.HASH_MISMATCH);
		assertThat(headOfChain().getDetail()).contains("already COMPROMISED");
	}

	/**
	 * {@code COMPROMISED} is never cleared. An object that hashes correctly again after a
	 * mismatch is a fact for the chain to record and an investigator to interpret, not a
	 * recovery the system declares on its own.
	 */
	@Test
	@DisplayName("A match after a mismatch is recorded as HASH_VERIFIED but does not clear COMPROMISED")
	void matchAfterMismatchDoesNotClearCompromised() {
		given(storageService.read(STORAGE_REF)).willReturn(OTHER_CONTENT, CONTENT);
		service.check(item.getId(), PRINCIPAL);

		IntegrityCheckResult recovered = service.check(item.getId(), PRINCIPAL);

		assertThat(recovered.intact()).isTrue();
		assertThat(recovered.status()).isEqualTo(EvidenceStatus.COMPROMISED);
		assertThat(headOfChain().getAction()).isEqualTo(CustodyAction.HASH_VERIFIED);
		assertThat(headOfChain().getDetail()).contains("remains so");
		assertThat(reloadedItem().getStatus()).isEqualTo(EvidenceStatus.COMPROMISED);
	}

	@Test
	@DisplayName("A mismatch on an archived item makes it COMPROMISED, and the entry names the prior state")
	void mismatchOnArchivedItemBecomesCompromised() {
		item.setStatus(EvidenceStatus.ARCHIVED);
		evidenceItemRepository.saveAndFlush(item);
		given(storageService.read(STORAGE_REF)).willReturn(OTHER_CONTENT);

		service.check(item.getId(), PRINCIPAL);

		assertThat(reloadedItem().getStatus()).isEqualTo(EvidenceStatus.COMPROMISED);
		assertThat(headOfChain().getDetail()).contains("from ARCHIVED to COMPROMISED");
	}

	/**
	 * An unreachable store is a fact about infrastructure, not about the evidence. Nothing is
	 * recorded, so that a 503 never becomes a HASH_MISMATCH in the ledger.
	 */
	@Test
	@DisplayName("A storage failure records nothing and changes nothing")
	void storageFailureRecordsNothing() {
		given(storageService.read(STORAGE_REF))
				.willThrow(new EvidenceStorageException("Could not read evidence object " + STORAGE_REF, null));

		assertThatThrownBy(() -> service.check(item.getId(), PRINCIPAL))
				.isInstanceOf(EvidenceStorageException.class);

		assertThat(custodyEventRepository.findByEvidenceItemIdOrderBySequenceAsc(item.getId())).hasSize(1);
		assertThat(reloadedItem().getStatus()).isEqualTo(EvidenceStatus.PRESERVED);
	}

	@Test
	@DisplayName("The result carries the appended entry, with the database's own timestamp on it")
	void resultCarriesTheAppendedEntry() {
		given(storageService.read(STORAGE_REF)).willReturn(CONTENT);

		IntegrityCheckResult result = service.check(item.getId(), PRINCIPAL);

		assertThat(result.custodyEvent().evidenceItemId()).isEqualTo(item.getId());
		assertThat(result.custodyEvent().sequence()).isEqualTo(1L);
		assertThat(result.custodyEvent().action()).isEqualTo(CustodyAction.HASH_VERIFIED);
		assertThat(result.custodyEvent().entryHash()).isEqualTo(headOfChain().getEntryHash());
		// recordedAt is stamped by the column default; the saveAndFlush inside append reads it
		// back, so the caller sees both clocks without a second query.
		assertThat(result.custodyEvent().recordedAt()).isNotNull();
	}

	@Test
	@DisplayName("Checking an artifact that does not exist is a not-found")
	void unknownItemIsNotFound() {
		assertThatThrownBy(() -> service.check(UUID.randomUUID(), PRINCIPAL))
				.isInstanceOf(ResourceNotFoundException.class);
	}

	@Test
	@DisplayName("Export releases intact bytes and records EXPORTED with the digest of what was released")
	void exportReleasesIntactBytesAndRecordsExported() {
		given(storageService.read(STORAGE_REF)).willReturn(CONTENT);

		EvidenceExport export = service.export(item.getId(), PRINCIPAL);

		assertThat(export.released()).isTrue();
		assertThat(export.content()).isEqualTo(CONTENT);
		assertThat(export.sha256()).isEqualTo(CONTENT_SHA256);
		// A manually built item, with no source behind it and so no producer artifact id.
		assertThat(export.sourceArtifactId()).isNull();
		assertThat(export.status()).isEqualTo(EvidenceStatus.PRESERVED);
		assertThat(export.custodyEvent().action()).isEqualTo(CustodyAction.EXPORTED);

		CustodyEvent entry = headOfChain();
		assertThat(entry.getSequence()).isEqualTo(1L);
		assertThat(entry.getAction()).isEqualTo(CustodyAction.EXPORTED);
		assertThat(entry.getPerformedBy()).isEqualTo(PRINCIPAL);
		assertThat(entry.getArtifactHashBefore()).isEqualTo(CONTENT_SHA256);
		assertThat(entry.getArtifactHashAfter()).isEqualTo(CONTENT_SHA256);
		assertThat(entry.getOccurredAt()).isEqualTo(OffsetDateTime.ofInstant(CHECKED_AT, ZoneOffset.UTC));
		assertThat(entry.getDetail()).contains("before export").contains("Released 5 bytes");

		assertThat(reloadedItem().getStatus()).isEqualTo(EvidenceStatus.PRESERVED);
	}

	/**
	 * The point of verifying on export: bytes that no longer match are never handed over, and
	 * the finding is recorded exactly as an on-demand check would record it.
	 */
	@Test
	@DisplayName("Export of a mismatched object releases nothing, records HASH_MISMATCH and marks COMPROMISED")
	void exportOfMismatchedObjectReleasesNothing() {
		given(storageService.read(STORAGE_REF)).willReturn(OTHER_CONTENT);

		EvidenceExport export = service.export(item.getId(), PRINCIPAL);

		assertThat(export.released()).isFalse();
		assertThat(export.content()).isNull();
		assertThat(export.sha256()).isEqualTo(OTHER_SHA256);
		assertThat(export.status()).isEqualTo(EvidenceStatus.COMPROMISED);

		CustodyEvent entry = headOfChain();
		assertThat(entry.getAction()).isEqualTo(CustodyAction.HASH_MISMATCH);
		assertThat(entry.getArtifactHashBefore()).isEqualTo(CONTENT_SHA256);
		assertThat(entry.getArtifactHashAfter()).isEqualTo(OTHER_SHA256);
		assertThat(entry.getDetail())
				.contains("before export")
				.contains("from PRESERVED to COMPROMISED")
				.contains("Export refused");
		// No EXPORTED entry: the chain must never claim a release that did not happen.
		assertThat(custodyEventRepository.findByEvidenceItemIdOrderBySequenceAsc(item.getId()))
				.extracting(CustodyEvent::getAction)
				.doesNotContain(CustodyAction.EXPORTED);

		EvidenceItem reloaded = reloadedItem();
		assertThat(reloaded.getStatus()).isEqualTo(EvidenceStatus.COMPROMISED);
		assertThat(reloaded.getCurrentHash()).isEqualTo(CONTENT_SHA256);
	}

	/**
	 * EXPORTED has to be accepted by {@code ck_custody_event_action} (changeset {@code 0010})
	 * and hash into the chain like any other entry. Each download is its own entry.
	 */
	@Test
	@DisplayName("Repeated exports are separate entries and the chain still verifies")
	void repeatedExportsAreSeparateEntriesAndChainVerifies() {
		given(storageService.read(STORAGE_REF)).willReturn(CONTENT, CONTENT, OTHER_CONTENT);

		service.export(item.getId(), PRINCIPAL);
		service.export(item.getId(), "a.naidoo");
		service.export(item.getId(), PRINCIPAL);
		entityManager.flush();
		entityManager.clear();

		List<CustodyEvent> chain = custodyEventRepository.findByEvidenceItemIdOrderBySequenceAsc(item.getId());
		assertThat(chain).extracting(CustodyEvent::getAction).containsExactly(
				CustodyAction.CREATED, CustodyAction.EXPORTED, CustodyAction.EXPORTED, CustodyAction.HASH_MISMATCH);
		assertThat(chain).extracting(CustodyEvent::getPerformedBy)
				.containsExactly(PRINCIPAL, PRINCIPAL, "a.naidoo", PRINCIPAL);
		assertThat(custodyChainService.verify(item.getId()).intact()).isTrue();
	}

	/**
	 * The gate is the digest, not the status: bytes that match the recorded digest are the
	 * ones preserved, whatever happened in between, and the entry says what the status is.
	 */
	@Test
	@DisplayName("A compromised item whose object matches again is released, and stays COMPROMISED")
	void compromisedItemThatMatchesIsReleased() {
		given(storageService.read(STORAGE_REF)).willReturn(OTHER_CONTENT, CONTENT);
		service.check(item.getId(), PRINCIPAL);

		EvidenceExport export = service.export(item.getId(), PRINCIPAL);

		assertThat(export.released()).isTrue();
		assertThat(export.status()).isEqualTo(EvidenceStatus.COMPROMISED);
		assertThat(headOfChain().getAction()).isEqualTo(CustodyAction.EXPORTED);
		assertThat(headOfChain().getDetail()).contains("COMPROMISED from an earlier mismatch");
		assertThat(reloadedItem().getStatus()).isEqualTo(EvidenceStatus.COMPROMISED);
	}

	@Test
	@DisplayName("A storage failure on export releases nothing and records nothing")
	void exportStorageFailureRecordsNothing() {
		given(storageService.read(STORAGE_REF))
				.willThrow(new EvidenceStorageException("Could not read evidence object " + STORAGE_REF, null));

		assertThatThrownBy(() -> service.export(item.getId(), PRINCIPAL))
				.isInstanceOf(EvidenceStorageException.class);

		assertThat(custodyEventRepository.findByEvidenceItemIdOrderBySequenceAsc(item.getId())).hasSize(1);
		assertThat(reloadedItem().getStatus()).isEqualTo(EvidenceStatus.PRESERVED);
	}

	@Test
	@DisplayName("Exporting an artifact that does not exist is a not-found")
	void exportOfUnknownItemIsNotFound() {
		assertThatThrownBy(() -> service.export(UUID.randomUUID(), PRINCIPAL))
				.isInstanceOf(ResourceNotFoundException.class);
	}

	private CustodyEvent headOfChain() {
		return custodyEventRepository.findTopByEvidenceItemIdOrderBySequenceDesc(item.getId()).orElseThrow();
	}

	private EvidenceItem reloadedItem() {
		entityManager.flush();
		entityManager.clear();
		return evidenceItemRepository.findById(item.getId()).orElseThrow();
	}

	private static EvidenceItem newItem(WorkGroup workGroup, EvidenceStatus status) {
		EvidenceItem evidenceItem = new EvidenceItem();
		evidenceItem.setWorkGroup(workGroup);
		evidenceItem.setStorageRef(STORAGE_REF);
		evidenceItem.setCurrentHash(CONTENT_SHA256);
		evidenceItem.setStatus(status);
		evidenceItem.setEventStart(OffsetDateTime.parse("2026-09-05T14:30:00Z"));
		evidenceItem.setEventEnd(OffsetDateTime.parse("2026-09-05T14:30:30Z"));
		return evidenceItem;
	}
}
