package za.co.dfraas.service;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import za.co.dfraas.dto.CustodyChainVerification;
import za.co.dfraas.entity.CustodyAction;
import za.co.dfraas.entity.CustodyEvent;
import za.co.dfraas.entity.EvidenceItem;
import za.co.dfraas.exception.ResourceNotFoundException;
import za.co.dfraas.repository.CustodyEventRepository;
import za.co.dfraas.repository.EvidenceItemRepository;

/**
 * The chain-of-custody ledger: the only thing that writes {@link CustodyEvent}, and the only
 * thing that can say whether a chain still verifies.
 *
 * <p>One chain per {@link EvidenceItem}, append-only, each entry carrying a digest over its
 * own contents and over the entry before it. Sequence, {@code prevEntryHash} and
 * {@code entryHash} are not three fields a caller sets but one computed unit, which is why
 * {@link #append} exists and why nothing else should construct an entry.
 *
 * <p><strong>What this buys, stated without overclaiming.</strong> Editing an entry in place,
 * moving one between chains or positions, and deleting one from the middle of a chain all
 * become detectable. Truncating the <em>end</em> of a chain does not: nothing inside the
 * ledger can tell "three entries, intact" from "five entries, the last two removed". Closing
 * that needs {@link CustodyChainVerification#headEntryHash()} witnessed somewhere this
 * database cannot reach — an external notarisation or write-once storage — and it is
 * deliberately left as a stated gap rather than a quiet assumption.
 */
@Service
@Transactional(readOnly = true)
public class CustodyChainService {

	private static final Logger log = LoggerFactory.getLogger(CustodyChainService.class);

	private static final String RESOURCE = "EvidenceItem";

	/**
	 * What the first entry in every chain carries in {@code prevEntryHash}: 64 {@code '0'}
	 * characters, the value {@code ck_custody_event_origin} requires at sequence 0.
	 *
	 * <p>A fixed constant rather than null, and that is the whole reason {@link #verify} is a
	 * single uniform loop. With a nullable predecessor, verification needs a branch for the
	 * origin — and a branch for the origin is where a forged origin eventually hides, because
	 * it is the one entry whose predecessor nothing checks. Starting the loop from a constant
	 * means position 0 is verified by exactly the same arithmetic as position 400.
	 *
	 * <p>It is not a digest of anything and cannot collide with one: no SHA-256 output is 64
	 * zeros, so no entry can ever produce a hash that makes a later row look like an origin.
	 */
	public static final String GENESIS_HASH = "0".repeat(64);

	/**
	 * The canonical form {@link #canonicalV1} implements, and the version stamped onto every
	 * entry this application writes.
	 */
	public static final short CANONICAL_VERSION_1 = 1;

	/**
	 * Leads every canonical form, so a digest is bound to the rules it was computed under and
	 * two versions can never produce the same bytes for the same entry.
	 */
	private static final String CANONICAL_V1_FORMAT_TAG = "dfraas.custody.v1";

	/**
	 * Fixed-width UTC with a six-digit fraction — {@code 2026-09-05T14:30:00.000000Z}.
	 *
	 * <p>Explicitly not {@code ISO_OFFSET_DATE_TIME}, which drops a zero fraction and even a
	 * zero seconds field. That is deterministic enough to verify, but it makes the digest
	 * depend on how round the timestamp happens to be, and a canonical form should not have
	 * variable-length fields for no reason. Microseconds because that is Postgres' resolution
	 * — see {@link #normalise}.
	 */
	private static final DateTimeFormatter CANONICAL_TIMESTAMP =
			DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ss.SSSSSS'Z'", Locale.ROOT);

	/** Marks an absent field, and cannot be mistaken for a length. */
	private static final String NULL_FIELD = "-:";

	private final CustodyEventRepository repository;
	private final EvidenceItemRepository evidenceItemRepository;
	private final HashingService hashingService;

	public CustodyChainService(
			CustodyEventRepository repository,
			EvidenceItemRepository evidenceItemRepository,
			HashingService hashingService) {
		this.repository = repository;
		this.evidenceItemRepository = evidenceItemRepository;
		this.hashingService = hashingService;
	}

	/**
	 * Appends one entry to an artifact's chain.
	 *
	 * <p><strong>{@code REQUIRED}, and never {@code REQUIRES_NEW}.</strong> This is the most
	 * load-bearing line in the class. A custody entry has to commit or roll back with the
	 * action it records, in one transaction: a separate transaction would let the entry
	 * survive an action that was rolled back — a ledger asserting something that never
	 * happened — or let the action commit while its entry was lost, which is the same failure
	 * with the blame reversed. Both produce a record that is worse than no record, because it
	 * looks authoritative. {@code REQUIRES_NEW} is exactly the annotation someone reaches for
	 * to "make sure the audit entry is always written", so this is stated rather than left to
	 * the default.
	 *
	 * <p>The caller's transaction is therefore also where the lock lives:
	 * {@link EvidenceItemRepository#findByIdForUpdate} serialises appends against one item so
	 * that reading the head and inserting the next position cannot interleave with another
	 * appender doing the same. {@code uq_custody_event_item_sequence} is still what guarantees
	 * it — the lock only means the second appender waits and then succeeds rather than being
	 * rejected.
	 *
	 * @param evidenceItemId     the artifact being handled; must exist
	 * @param action             what happened
	 * @param performedBy        who did it, or null when the answer is "the pipeline"
	 * @param occurredAt         when it happened, normalised to UTC microseconds before it is
	 *                           hashed or stored
	 * @param artifactHashBefore the artifact's digest before the action, or null if unchanged
	 * @param artifactHashAfter  the artifact's digest after the action, or null if unchanged
	 * @param detail             free-text account of the action, hashed rather than inlined
	 */
	@Transactional(propagation = Propagation.REQUIRED)
	public CustodyEvent append(
			UUID evidenceItemId,
			CustodyAction action,
			String performedBy,
			OffsetDateTime occurredAt,
			String artifactHashBefore,
			String artifactHashAfter,
			String detail) {

		Objects.requireNonNull(action, "action");
		Objects.requireNonNull(occurredAt, "occurredAt");

		EvidenceItem item = evidenceItemRepository.findByIdForUpdate(evidenceItemId)
				.orElseThrow(() -> ResourceNotFoundException.of(RESOURCE, evidenceItemId));

		CustodyEvent head = repository.findTopByEvidenceItemIdOrderBySequenceDesc(evidenceItemId).orElse(null);

		CustodyEvent entry = new CustodyEvent();
		entry.setEvidenceItem(item);
		entry.setSequence(head == null ? 0L : head.getSequence() + 1);
		entry.setPrevEntryHash(head == null ? GENESIS_HASH : head.getEntryHash());
		entry.setAction(action);
		entry.setPerformedBy(performedBy);
		entry.setOccurredAt(normalise(occurredAt));
		entry.setArtifactHashBefore(artifactHashBefore);
		entry.setArtifactHashAfter(artifactHashAfter);
		entry.setDetail(detail);
		entry.setCanonicalVersion(CANONICAL_VERSION_1);
		entry.setEntryHash(entryHash(entry.getPrevEntryHash(), entry));

		// saveAndFlush rather than save, so the INSERT is issued here: a deferred flush would
		// surface a duplicate position or a rejected CHECK at commit, far from the append that
		// caused it and past any handler that could say what went wrong.
		CustodyEvent appended = repository.saveAndFlush(entry);

		log.info("Custody entry appended: itemId={} sequence={} action={} performedBy={} entryHash={}",
				evidenceItemId, appended.getSequence(), action, performedBy, appended.getEntryHash());
		return appended;
	}

	/**
	 * Writes the opening entry of an artifact's chain, for the ingest path.
	 *
	 * <p>Every item gets one, and this is what makes provenance survive
	 * {@code evidence_item.evidence_source_id} being nullable: a manually preserved artifact
	 * has no collector, but it has someone who preserved it.
	 *
	 * <p>{@code occurredAt} is the item's own {@code createdAt}, which means the first link of
	 * every chain carries the database's clock rather than the JVM's — the rule every other
	 * timestamp in this schema follows, and one {@link CustodyEvent#getOccurredAt()} otherwise
	 * cannot. It therefore requires an item that has already been flushed, since that column
	 * is filled by the database on INSERT.
	 *
	 * <p>{@code artifactHashAfter} is the digest verified at ingest and
	 * {@code artifactHashBefore} is null: there was no prior state. That anchors
	 * {@code EvidenceItem.currentHash} — a column that legitimately changes — into a record
	 * that cannot.
	 */
	@Transactional(propagation = Propagation.REQUIRED)
	public CustodyEvent recordCreation(EvidenceItem item, String performedBy, String detail) {
		OffsetDateTime createdAt = Objects.requireNonNull(
				item.getCreatedAt(),
				"createdAt is stamped by the database on insert, so the item must be flushed before its "
						+ "opening custody entry can be written");

		return append(item.getId(), CustodyAction.CREATED, performedBy, createdAt, null, item.getCurrentHash(), detail);
	}

	/**
	 * Walks one artifact's chain from the genesis hash and reports the first place it stops
	 * agreeing with itself.
	 *
	 * <p>Three things are checked per entry, and all three are needed:
	 *
	 * <ul>
	 *   <li><strong>Position.</strong> The entry at index {@code i} must have
	 *       {@code sequence == i}. This is the only check that catches an entry deleted from
	 *       the middle of a chain — the digests cannot, because every surviving row is
	 *       individually valid and each still points at the one before it. What changes is
	 *       that the ledger now claims 0, 1, 3, and a ledger with a hole in it is not a
	 *       complete account of anything.</li>
	 *   <li><strong>The link.</strong> {@code prevEntryHash} must equal the previous entry's
	 *       {@code entryHash}, or the genesis hash at position 0.</li>
	 *   <li><strong>The contents.</strong> A digest recomputed from the entry must equal the
	 *       one stored on it, which is what makes an edit to {@code performedBy} or
	 *       {@code occurredAt} visible.</li>
	 * </ul>
	 *
	 * <p>An empty chain is reported as {@code missingOrigin} rather than as an intact chain of
	 * length zero. That distinction is not pedantry: no artifact
	 * legitimately has no custody entries, because the opening entry is written in the same
	 * transaction as the item, so "nothing to check" is a finding and not a pass.
	 *
	 * <p>Recomputation is dispatched on each row's {@code canonicalVersion}, so entries keep
	 * verifying under the rules they were written under.
	 */
	public CustodyChainVerification verify(UUID evidenceItemId) {
		List<CustodyEvent> chain = repository.findByEvidenceItemIdOrderBySequenceAsc(evidenceItemId);
		if (chain.isEmpty()) {
			log.error("Custody chain has no origin: itemId={}", evidenceItemId);
			return CustodyChainVerification.missingOrigin(evidenceItemId);
		}

		String expectedPrev = GENESIS_HASH;
		for (int position = 0; position < chain.size(); position++) {
			CustodyEvent entry = chain.get(position);

			if (entry.getSequence() != position) {
				// Reported at the expected position, not at entry.getSequence(): the row sitting
				// here carries a higher number than it should, and naming that number would point
				// past the hole rather than at it.
				log.error("Custody chain is not contiguous: itemId={} expectedSequence={} found={}",
						evidenceItemId, position, entry.getSequence());
				return CustodyChainVerification.divergedAt(evidenceItemId, position, chain.size());
			}
			if (!expectedPrev.equals(entry.getPrevEntryHash())) {
				log.error("Custody chain link is broken: itemId={} sequence={}", evidenceItemId, position);
				return CustodyChainVerification.divergedAt(evidenceItemId, position, chain.size());
			}
			if (!entryHash(entry.getPrevEntryHash(), entry).equals(entry.getEntryHash())) {
				log.error("Custody entry does not match its own digest: itemId={} sequence={}",
						evidenceItemId, position);
				return CustodyChainVerification.divergedAt(evidenceItemId, position, chain.size());
			}

			expectedPrev = entry.getEntryHash();
		}

		return CustodyChainVerification.intact(evidenceItemId, chain.size(), expectedPrev);
	}

	/**
	 * The digest stored on an entry: SHA-256 over the previous entry's hash concatenated with
	 * this entry's canonical form.
	 *
	 * <p>Taking {@code prev} as a parameter rather than reading {@code entry.prevEntryHash} is
	 * what lets {@link #append} compute a hash for an entry it is still assembling, and it
	 * keeps the two uses honest: {@link #verify} passes the value it has independently
	 * confirmed against the preceding entry, so a row cannot vouch for its own position in the
	 * chain.
	 *
	 * <p>The canonical form is selected by the entry's {@code canonicalVersion}. A version
	 * this build does not implement is refused outright rather than verified under the rules
	 * of a different one — reporting a chain as intact on the strength of the wrong canonical
	 * form would be a false assurance, which is worse than an error.
	 */
	public String entryHash(String prev, CustodyEvent entry) {
		String canonical = switch (entry.getCanonicalVersion()) {
			case CANONICAL_VERSION_1 -> canonicalV1(entry);
			default -> throw new IllegalStateException(
					"Custody entry was written under canonical version " + entry.getCanonicalVersion()
							+ ", which this build cannot verify");
		};
		return hashingService.sha256Hex(prev + canonical);
	}

	/**
	 * Canonical form, version 1 — the exact bytes {@code entry_hash} is computed over.
	 *
	 * <p><strong>Do not edit this method.</strong> Not "prefer not to": every digest ever
	 * written under version 1 is a digest of what this method produces, so any change to field
	 * order, encoding, inclusion or rendering invalidates the entire ledger's history and
	 * makes honest rows indistinguishable from tampered ones. Changes go in a
	 * {@code canonicalV2} alongside it, stamped onto new rows through
	 * {@code canonical_version} and selected per row by {@link #entryHash}. Existing rows are
	 * never migrated — recomputing a stored digest is forgery, however good the intention.
	 *
	 * <p><strong>Every field is length-prefixed</strong> as {@code <byte-length>:<value>}, and
	 * the lengths are what make the encoding injective. Without them, concatenation is
	 * ambiguous and the ambiguity is reachable: {@code performedBy} is free text, so a
	 * principal named to look like the start of the next field could produce the same byte
	 * string as a different entry and hash identically. With a length in front of every field,
	 * a field's content cannot forge a boundary, because the boundary is stated before the
	 * content is read. Absent is {@code -:} and empty is {@code 0:}, so a null
	 * {@code performedBy} and an empty one are not the same entry. Lengths are UTF-8 bytes,
	 * matching what {@link HashingService} digests.
	 *
	 * <p><strong>{@code occurredAt} is rendered as UTC truncated to microseconds</strong>, and
	 * this is the single most likely way for this class to break. A Postgres
	 * {@code timestamptz} stores an instant at microsecond resolution: it keeps neither the
	 * offset the value was written with nor any nanoseconds below a microsecond. So an entry
	 * hashed from {@code 16:30+02:00} or from a nanosecond-precision clock would verify in
	 * memory, and then stop verifying the moment it was read back — a chain that breaks on
	 * restart, for no reason a reader could see. {@link #append} normalises before storing and
	 * this renders the same way, so the digest is over a value the database can hold exactly.
	 *
	 * <p><strong>{@code evidenceItemId} and {@code sequence} are included</strong> so an entry
	 * is bound to its place. Without the item, a row could be moved to another artifact's
	 * chain and still verify; without the sequence, it could be reordered within one. Both are
	 * the kind of tampering that leaves every individual digest intact.
	 *
	 * <p><strong>{@code detail} is included as its SHA-256, never inlined.</strong> Free text
	 * is the one field an operator writes by hand, and hashing it first keeps its content away
	 * from the boundary logic altogether while keeping the canonical form a fixed size however
	 * much prose it holds.
	 *
	 * <p>Not included: {@code id}, a surrogate key that carries no meaning, and
	 * {@code recordedAt}, which the database generates during the INSERT this digest has to
	 * precede — see {@link CustodyEvent#getOccurredAt()}. The format tag stands in for
	 * {@code canonicalVersion} itself.
	 */
	public String canonicalV1(CustodyEvent entry) {
		StringBuilder canonical = new StringBuilder(256);
		appendField(canonical, CANONICAL_V1_FORMAT_TAG);
		// Read off the lazy proxy: Hibernate answers the id without initialising the item, so
		// hashing an entry does not become a second query.
		appendField(canonical, entry.getEvidenceItem().getId().toString());
		appendField(canonical, Long.toString(entry.getSequence()));
		appendField(canonical, entry.getAction().name());
		appendField(canonical, CANONICAL_TIMESTAMP.format(normalise(entry.getOccurredAt())));
		appendField(canonical, entry.getPerformedBy());
		appendField(canonical, entry.getArtifactHashBefore());
		appendField(canonical, entry.getArtifactHashAfter());
		appendField(canonical, entry.getDetail() == null ? null : hashingService.sha256Hex(entry.getDetail()));
		return canonical.toString();
	}

	/**
	 * UTC, truncated to microseconds — the most precision a Postgres {@code timestamptz} can
	 * hold, so the value hashed and the value stored are the same value.
	 */
	private static OffsetDateTime normalise(OffsetDateTime occurredAt) {
		return occurredAt.withOffsetSameInstant(ZoneOffset.UTC).truncatedTo(ChronoUnit.MICROS);
	}

	private static void appendField(StringBuilder canonical, String value) {
		if (value == null) {
			canonical.append(NULL_FIELD);
			return;
		}
		canonical.append(value.getBytes(UTF_8).length).append(':').append(value);
	}
}
