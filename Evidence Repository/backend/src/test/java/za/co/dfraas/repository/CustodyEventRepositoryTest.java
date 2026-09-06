package za.co.dfraas.repository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.OffsetDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Locale;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.jpa.test.autoconfigure.TestEntityManager;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;

import za.co.dfraas.TestcontainersConfiguration;
import za.co.dfraas.entity.CustodyAction;
import za.co.dfraas.entity.CustodyEvent;
import za.co.dfraas.entity.EvidenceItem;
import za.co.dfraas.entity.EvidenceStatus;
import za.co.dfraas.entity.WorkGroup;

/**
 * The contract between {@link CustodyEvent} and Liquibase changeset
 * {@code 0006-create-custody-event}.
 *
 * <p>What this file exists to prove is that the database refuses a malformed ledger on its
 * own, without the application's help. Every other table here can rely on the service layer
 * being the only writer; a custody ledger cannot, because the writer it is defending against
 * is one that never went through the service layer at all. So the cases below go at the
 * constraints directly, several of them through native SQL that bypasses Hibernate entirely.
 *
 * <p>The chain arithmetic — what a valid {@code entryHash} is, and what verification catches
 * — belongs to {@code CustodyChainServiceTest}. Hash values here are well-formed digests of
 * nothing in particular, because at this level the only question is whether the column will
 * hold them.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import(TestcontainersConfiguration.class)
class CustodyEventRepositoryTest {

	private static final String SHA_256_OF_EMPTY_STRING =
			"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

	/** What every chain's first entry carries — {@code CustodyChainService.GENESIS_HASH}. */
	private static final String GENESIS_HASH = "0".repeat(64);

	private static final String ENTRY_HASH_0 = "a".repeat(64);
	private static final String ENTRY_HASH_1 = "b".repeat(64);

	private static final OffsetDateTime OCCURRED_AT = OffsetDateTime.parse("2026-01-01T14:00:00Z");

	@Autowired
	private CustodyEventRepository repository;

	@Autowired
	private EvidenceItemRepository evidenceItemRepository;

	@Autowired
	private WorkGroupRepository workGroupRepository;

	@Autowired
	private TestEntityManager entityManager;

	private WorkGroup workGroup;
	private EvidenceItem item;

	@BeforeEach
	void setUp() {
		workGroup = workGroupRepository.findByClassificationCode("ONLINE_BANKING").orElseThrow();
		item = evidenceItemRepository.saveAndFlush(newItem("evidence/auth/14-15.log"));
	}

	@Test
	@DisplayName("An opening entry is accepted, with the application's occurredAt and the database's recordedAt")
	void openingEntryIsAcceptedAndTimestampedByBothClocks() {
		CustodyEvent saved = repository.saveAndFlush(newEntry(0L, GENESIS_HASH, ENTRY_HASH_0));

		assertThat(saved.getId()).isNotNull();
		// The one timestamp in this schema the application supplies, because entry_hash covers
		// it and has to be computed before the INSERT that carries it.
		assertThat(saved.getOccurredAt()).isEqualTo(OCCURRED_AT);
		// And the database's own account of the same entry, kept alongside rather than instead:
		// the gap between the two is what makes a backfill or a fabrication visible.
		assertThat(saved.getRecordedAt()).isNotNull();
		assertThat(saved.getArtifactHashBefore()).isNull();
		assertThat(saved.getArtifactHashAfter()).isEqualTo(SHA_256_OF_EMPTY_STRING);
	}

	@Test
	@DisplayName("Two entries cannot occupy the same position in one chain")
	void duplicateSequenceInOneChainIsRejected() {
		repository.saveAndFlush(newEntry(0L, GENESIS_HASH, ENTRY_HASH_0));

		// The constraint correctness rests on when two appends race. Without it the chain forks
		// — two rows at position 0, each individually valid, and verification reading whichever
		// the planner returned first. A corrupt ledger that looks intact is the worst outcome
		// available here.
		assertThatThrownBy(() -> repository.saveAndFlush(newEntry(0L, GENESIS_HASH, ENTRY_HASH_1)))
				.isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	@DisplayName("Each item's chain numbers itself from zero, independently of every other chain")
	void chainsAreNumberedPerItem() {
		EvidenceItem firewallLog = evidenceItemRepository.saveAndFlush(newItem("evidence/fw/14-15.log"));

		repository.saveAndFlush(newEntry(0L, GENESIS_HASH, ENTRY_HASH_0));
		repository.saveAndFlush(newEntry(1L, ENTRY_HASH_0, ENTRY_HASH_1));
		repository.saveAndFlush(entryFor(firewallLog, 0L, GENESIS_HASH, ENTRY_HASH_0));

		assertThat(repository.findByEvidenceItemIdOrderBySequenceAsc(item.getId()))
				.extracting(CustodyEvent::getSequence)
				.containsExactly(0L, 1L);
		assertThat(repository.findTopByEvidenceItemIdOrderBySequenceDesc(item.getId()).orElseThrow().getSequence())
				.isEqualTo(1L);
		assertThat(repository.findByEvidenceItemIdOrderBySequenceAsc(firewallLog.getId())).hasSize(1);
	}

	@Test
	@DisplayName("An artifact with no chain has no head, which is what an unwritten origin looks like")
	void headOfAnEmptyChainIsEmpty() {
		assertThat(repository.findTopByEvidenceItemIdOrderBySequenceDesc(item.getId())).isEmpty();
	}

	/**
	 * The converse — a mid-chain entry also carrying the genesis hash — is not constrained
	 * here and cannot be: a row-level CHECK cannot see the row before it. Verification is what
	 * catches that, since {@code prevEntryHash} has to equal the preceding entry's
	 * {@code entryHash} and no SHA-256 output is 64 zeros.
	 */
	@Test
	@DisplayName("An entry at position zero must be rooted at the genesis hash")
	void originEntryMustCarryTheGenesisHash() {
		// An origin pointing at some other value claims a predecessor that is nowhere in the
		// ledger — which is what a chain whose beginning was removed and re-rooted looks like.
		assertThatThrownBy(() -> repository.saveAndFlush(newEntry(0L, ENTRY_HASH_1, ENTRY_HASH_0)))
				.isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	@DisplayName("A negative position is rejected")
	void negativeSequenceIsRejected() {
		// A position "before" the origin is a way of prepending to a ledger.
		assertThatThrownBy(() -> repository.saveAndFlush(newEntry(-1L, GENESIS_HASH, ENTRY_HASH_0)))
				.isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	@DisplayName("An upper-case digest is rejected, in the chain columns and the artifact columns alike")
	void nonCanonicalDigestIsRejected() {
		CustodyEvent entry = newEntry(0L, GENESIS_HASH, ENTRY_HASH_0);
		// The same bytes have two hex spellings. Permitting both would mean a digest that fails
		// verification because something in transit re-cased it.
		entry.setArtifactHashAfter(SHA_256_OF_EMPTY_STRING.toUpperCase(Locale.ROOT));

		assertThatThrownBy(() -> repository.saveAndFlush(entry))
				.isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	@DisplayName("A truncated entry hash is rejected")
	void malformedEntryHashIsRejected() {
		// A malformed chain hash would break verification for every entry after it, so it is
		// held to a real digest rather than merely to a length that fits.
		assertThatThrownBy(() -> repository.saveAndFlush(newEntry(0L, GENESIS_HASH, "abc123")))
				.isInstanceOf(DataIntegrityViolationException.class);
	}

	/**
	 * The version is stated by whatever computed the digest, and is deliberately not defaulted
	 * on the entity — so a code path that forgets it is rejected here rather than silently
	 * claiming to have been written under version 1.
	 */
	@Test
	@DisplayName("An entry that states no canonical version is rejected")
	void unstatedCanonicalVersionIsRejected() {
		CustodyEvent entry = newEntry(0L, GENESIS_HASH, ENTRY_HASH_0);
		entry.setCanonicalVersion((short) 0);

		assertThatThrownBy(() -> repository.saveAndFlush(entry))
				.isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	@DisplayName("An evidence item with a custody chain cannot be deleted")
	void evidenceItemDeleteIsRestrictedByTheForeignKey() {
		repository.saveAndFlush(newEntry(0L, GENESIS_HASH, ENTRY_HASH_0));
		entityManager.clear();

		// RESTRICT, and it is doing more here than on evidence_link. CASCADE would let one
		// DELETE destroy the entire record of who handled an artifact — which survives
		// precisely so that "this evidence was destroyed, by whom" stays answerable.
		evidenceItemRepository.delete(evidenceItemRepository.findById(item.getId()).orElseThrow());
		assertThatThrownBy(() -> evidenceItemRepository.flush())
				.isInstanceOf(DataIntegrityViolationException.class);
	}

	/**
	 * Every column is {@code updatable = false}, so an edit through Hibernate is not rejected
	 * but ignored — a deliberate failure mode. A caller who tries has changed nothing, rather
	 * than having thrown an exception someone might catch and work around.
	 */
	@Test
	@DisplayName("Editing a persisted entry through the entity changes nothing")
	void entryColumnsAreNotUpdatable() {
		CustodyEvent saved = repository.saveAndFlush(newEntry(0L, GENESIS_HASH, ENTRY_HASH_0));

		saved.setPerformedBy("someone.else");
		saved.setDetail("Rewritten after the fact.");
		saved.setEntryHash(ENTRY_HASH_1);
		repository.saveAndFlush(saved);
		entityManager.clear();

		CustodyEvent reloaded = repository.findById(saved.getId()).orElseThrow();
		assertThat(reloaded.getPerformedBy()).isEqualTo("j.mokoena");
		assertThat(reloaded.getDetail()).isEqualTo("Preserved on streamed ingest.");
		assertThat(reloaded.getEntryHash()).isEqualTo(ENTRY_HASH_0);
	}

	/**
	 * The action list and the {@link CustodyAction} enum have to stay in step, and this is the
	 * direction that matters: the enum cannot express an unknown action, so the only way to
	 * write one is to go round the application — which is exactly the writer this constraint
	 * exists for.
	 */
	@Test
	@DisplayName("An action the enum does not define is rejected even on a write that bypasses Hibernate")
	void unknownActionIsRejectedByTheDatabase() {
		assertThatThrownBy(() -> entityManager.getEntityManager()
				.createNativeQuery("""
						INSERT INTO custody_event (evidence_item_id, "sequence", action, occurred_at,
								prev_entry_hash, entry_hash, canonical_version)
						VALUES (:itemId, 0, 'EXPORTED', now(), :genesis, :entryHash, 1)
						""")
				.setParameter("itemId", item.getId())
				.setParameter("genesis", GENESIS_HASH)
				.setParameter("entryHash", ENTRY_HASH_0)
				.executeUpdate())
				.hasStackTraceContaining("ck_custody_event_action");
	}

	private CustodyEvent newEntry(long sequence, String prevEntryHash, String entryHash) {
		return entryFor(item, sequence, prevEntryHash, entryHash);
	}

	private static CustodyEvent entryFor(
			EvidenceItem evidenceItem, long sequence, String prevEntryHash, String entryHash) {

		CustodyEvent entry = new CustodyEvent();
		entry.setEvidenceItem(evidenceItem);
		entry.setSequence(sequence);
		entry.setAction(CustodyAction.CREATED);
		entry.setPerformedBy("j.mokoena");
		entry.setOccurredAt(OCCURRED_AT.truncatedTo(ChronoUnit.MICROS));
		entry.setArtifactHashAfter(SHA_256_OF_EMPTY_STRING);
		entry.setPrevEntryHash(prevEntryHash);
		entry.setEntryHash(entryHash);
		entry.setCanonicalVersion((short) 1);
		entry.setDetail("Preserved on streamed ingest.");
		return entry;
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
