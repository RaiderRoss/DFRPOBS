package za.co.dfraas.service;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import za.co.dfraas.dto.EvidenceExport;
import za.co.dfraas.dto.IntegrityCheckResult;
import za.co.dfraas.entity.CustodyAction;
import za.co.dfraas.entity.CustodyEvent;
import za.co.dfraas.entity.EvidenceItem;
import za.co.dfraas.entity.EvidenceStatus;
import za.co.dfraas.exception.ResourceNotFoundException;
import za.co.dfraas.mapper.CustodyEventMapper;
import za.co.dfraas.repository.EvidenceItemRepository;

/**
 * Re-verification of a preserved artifact: read the stored object back, hash it, and compare
 * with the digest recorded at ingest — SecureRS's verify-on-read, run either on demand
 * against an artifact nobody is reading ({@link #check}) or as the gate on releasing it
 * ({@link #export}).
 *
 * <p>This is the only writer of {@link CustodyAction#HASH_VERIFIED},
 * {@link CustodyAction#HASH_MISMATCH} and {@link CustodyAction#EXPORTED}, and the only thing
 * that moves an item to {@link EvidenceStatus#COMPROMISED}. Export lives here rather than in
 * a service of its own so that both statements stay true: every route by which bytes leave
 * passes through the same comparison, and a mismatch found on the way out is recorded
 * exactly as one found on demand. It is also what turns the custody chain from a record
 * of arrivals into a record of care: a chain holding only {@code CREATED} entries can show
 * when an artifact was preserved and by whom, but not that anyone has looked at it since.
 *
 * <p><strong>The outcome is recorded either way, and it is recorded in the chain.</strong>
 * There is no separate integrity-check table (changeset {@code 0007} gives the argument):
 * the entry this appends carries the expected and observed digests, the principal who ran
 * the check, and both clocks, and it cannot be edited afterwards without
 * {@link CustodyChainService#verify} showing it. A mismatch is the most consequential thing
 * this system can find, and it belongs in the one table built to be defended.
 */
@Service
@Transactional(readOnly = true)
public class IntegrityCheckService {

	private static final Logger log = LoggerFactory.getLogger(IntegrityCheckService.class);

	private static final String RESOURCE = "EvidenceItem";

	/** How each entry's detail opens, naming which act did the re-hash. */
	private static final String ON_DEMAND = "Re-verified on demand";
	private static final String BEFORE_EXPORT = "Re-verified before export";

	private final EvidenceItemRepository repository;
	private final EvidenceStorageService storageService;
	private final HashingService hashingService;
	private final CustodyChainService custodyChainService;
	private final CustodyEventMapper custodyEventMapper;
	private final Clock clock;

	public IntegrityCheckService(
			EvidenceItemRepository repository,
			EvidenceStorageService storageService,
			HashingService hashingService,
			CustodyChainService custodyChainService,
			CustodyEventMapper custodyEventMapper,
			Clock clock) {
		this.repository = repository;
		this.storageService = storageService;
		this.hashingService = hashingService;
		this.custodyChainService = custodyChainService;
		this.custodyEventMapper = custodyEventMapper;
		this.clock = clock;
	}

	/**
	 * Re-hashes one artifact's stored object and records what it found.
	 *
	 * <p><strong>One transaction, under the item's row lock, from the first read to the last
	 * write.</strong> The lock is taken first — before the object is even fetched — so that
	 * the digest compared against, the status written, and the custody entry appended all
	 * describe the same moment, and two concurrent checks cannot both read
	 * {@code PRESERVED}, both find a mismatch, and both claim to be the one that changed it.
	 * {@link CustodyChainService#append} takes the same lock, re-entrantly, so the entry lands
	 * inside this transaction and rolls back with the status change if either fails — a
	 * ledger saying "marked COMPROMISED" beside a row still reading {@code PRESERVED} is the
	 * inconsistency the whole design exists to rule out.
	 *
	 * <p>Holding a database lock across a MinIO read is the same compromise
	 * {@code EvidenceItemService.preserve} makes across a MinIO write, for the same reason:
	 * at testbed volumes it is milliseconds, and atomicity between what was compared and what
	 * was recorded matters more. The split, if it ever matters, is to hash outside the
	 * transaction and re-check {@code currentHash} inside it.
	 *
	 * <p><strong>A storage failure records nothing.</strong> If the object cannot be read the
	 * {@code EvidenceStorageException} propagates, the transaction rolls back, and the caller
	 * gets a 503 that says "not verified, try again" — which is true. It is deliberately not
	 * recorded as a mismatch: an unreachable store is a fact about infrastructure, a mismatch
	 * is a fact about the evidence, and an entry that conflated them would be read as the
	 * latter. An object that is confirmed <em>gone</em> rather than merely unreachable is a
	 * different finding that this method does not yet distinguish, and is noted as such in
	 * the README rather than guessed at here.
	 *
	 * <p><strong>On a mismatch, {@code currentHash} is left alone and {@code status} moves to
	 * {@code COMPROMISED}.</strong> The column is the expectation; overwriting it with the
	 * observation would erase the discrepancy being recorded and make the next check pass.
	 * The transition happens from whatever state the item was in — an archived artifact that
	 * no longer hashes correctly is compromised, not archived — and the prior state is named
	 * in the entry's detail so it is not lost. An item already {@code COMPROMISED} that
	 * mismatches again gets another {@code HASH_MISMATCH} entry and no status change; one
	 * that somehow matches again gets a {@code HASH_VERIFIED} entry and <em>stays</em>
	 * {@code COMPROMISED}, because {@link EvidenceStatus#COMPROMISED} is never cleared — the
	 * chain shows the history, and an investigator decides what a recovery means.
	 *
	 * @param evidenceItemId the artifact to check; must exist
	 * @param performedBy    the authenticated principal, recorded as the entry's attribution.
	 *                       Passed in rather than read from the security context, as
	 *                       everywhere a custody entry is written
	 */
	@Transactional
	public IntegrityCheckResult check(UUID evidenceItemId, String performedBy) {
		EvidenceItem item = repository.findByIdForUpdate(evidenceItemId)
				.orElseThrow(() -> ResourceNotFoundException.of(RESOURCE, evidenceItemId));

		String expected = item.getCurrentHash();
		String observed = hashingService.sha256Hex(storageService.read(item.getStorageRef()));
		OffsetDateTime checkedAt = OffsetDateTime.now(clock);
		boolean intact = observed.equals(expected);

		EvidenceStatus before = item.getStatus();
		CustodyEvent entry;
		if (intact) {
			entry = custodyChainService.append(
					evidenceItemId, CustodyAction.HASH_VERIFIED, performedBy, checkedAt, expected, observed,
					verifiedDetail(before));
			log.info("Integrity check passed: itemId={} performedBy={} sha256={}",
					evidenceItemId, performedBy, expected);
		} else {
			entry = recordMismatch(item, performedBy, checkedAt, expected, observed, mismatchDetail(ON_DEMAND, before));
		}

		return new IntegrityCheckResult(
				evidenceItemId, intact, expected, observed, item.getStatus(), custodyEventMapper.toDto(entry));
	}

	/**
	 * Releases one artifact's bytes, re-hashed first — verify-on-read in the literal sense,
	 * and the only route by which evidence leaves this system.
	 *
	 * <p>The same check as {@link #check}, under the same lock and in one transaction, with a
	 * different consequence for each outcome:
	 *
	 * <ul>
	 *   <li><strong>Match:</strong> the bytes are returned and an {@code EXPORTED} entry is
	 *       appended, attributed to the caller and carrying the digest of exactly what was
	 *       released. No separate {@code HASH_VERIFIED} entry: the export entry already
	 *       records the comparison, and two entries for one act would make the chain read as
	 *       if two things happened.</li>
	 *   <li><strong>Mismatch:</strong> nothing is released. The finding is recorded exactly as
	 *       {@link #check} records it — {@code HASH_MISMATCH}, status to {@code COMPROMISED},
	 *       {@code currentHash} untouched — and the result says so, for the resource to turn
	 *       into a refusal after this transaction has committed.</li>
	 * </ul>
	 *
	 * <p><strong>The gate is the digest, not the status.</strong> An item that is already
	 * {@code COMPROMISED} but whose stored object hashes correctly again is released, because
	 * the bytes are then provably the ones recorded at preservation; the entry names the
	 * status so the recipient knows the history. Refusing on status alone would withhold
	 * bytes that verify while explaining nothing a re-hash does not.
	 *
	 * <p>A storage failure records nothing and releases nothing, as in {@link #check}.
	 *
	 * @param evidenceItemId the artifact to export; must exist
	 * @param performedBy    the authenticated principal receiving the bytes
	 */
	@Transactional
	public EvidenceExport export(UUID evidenceItemId, String performedBy) {
		EvidenceItem item = repository.findByIdForUpdate(evidenceItemId)
				.orElseThrow(() -> ResourceNotFoundException.of(RESOURCE, evidenceItemId));

		String expected = item.getCurrentHash();
		byte[] content = storageService.read(item.getStorageRef());
		String observed = hashingService.sha256Hex(content);
		OffsetDateTime exportedAt = OffsetDateTime.now(clock);

		EvidenceStatus before = item.getStatus();
		if (!observed.equals(expected)) {
			CustodyEvent entry = recordMismatch(
					item, performedBy, exportedAt, expected, observed, mismatchDetail(BEFORE_EXPORT, before)
							+ " Export refused; nothing was released.");
			return new EvidenceExport(evidenceItemId, item.getSourceArtifactId(), false, null, observed,
					item.getStatus(), custodyEventMapper.toDto(entry));
		}

		CustodyEvent entry = custodyChainService.append(
				evidenceItemId, CustodyAction.EXPORTED, performedBy, exportedAt, expected, observed,
				exportedDetail(before, content.length));
		log.info("Evidence exported: itemId={} performedBy={} sha256={} bytes={}",
				evidenceItemId, performedBy, observed, content.length);
		return new EvidenceExport(evidenceItemId, item.getSourceArtifactId(), true, content, observed,
				item.getStatus(), custodyEventMapper.toDto(entry));
	}

	/**
	 * Appends the {@code HASH_MISMATCH} entry and moves the item to {@code COMPROMISED}, in
	 * the caller's transaction. Shared by {@link #check} and {@link #export} so that a
	 * mismatch is recorded the same way whichever act found it.
	 */
	private CustodyEvent recordMismatch(
			EvidenceItem item, String performedBy, OffsetDateTime at, String expected, String observed, String detail) {
		EvidenceStatus before = item.getStatus();
		CustodyEvent entry = custodyChainService.append(
				item.getId(), CustodyAction.HASH_MISMATCH, performedBy, at, expected, observed, detail);
		// Both digests belong in the log, where an operator can see them; the response
		// carries them too, because this is a result and not an error — see
		// IntegrityCheckResult.
		log.error("Integrity check FAILED: itemId={} performedBy={} expected={} observed={} priorStatus={}",
				item.getId(), performedBy, expected, observed, before);
		if (before != EvidenceStatus.COMPROMISED) {
			item.setStatus(EvidenceStatus.COMPROMISED);
			// Flushed here rather than at commit, so a rejected status lands in this method
			// and not in the transaction interceptor.
			repository.saveAndFlush(item);
		}
		return entry;
	}

	/**
	 * The human-readable half of the entry. Names what was done and what it means for the
	 * item's state; the digests are columns on the entry and are not repeated here.
	 */
	private static String verifiedDetail(EvidenceStatus status) {
		String base = ON_DEMAND + ": the stored object was read back and re-hashed, "
				+ "and the digest matches the one recorded at preservation.";
		if (status == EvidenceStatus.COMPROMISED) {
			return base + " The item was already COMPROMISED and remains so; that status is never cleared.";
		}
		return base + " Status " + status + " is unchanged.";
	}

	private static String mismatchDetail(String trigger, EvidenceStatus before) {
		String base = trigger + ": the stored object was read back and re-hashed, "
				+ "and the digest does not match the one recorded at preservation.";
		if (before == EvidenceStatus.COMPROMISED) {
			return base + " The item was already COMPROMISED.";
		}
		return base + " Status changed from " + before + " to COMPROMISED.";
	}

	private static String exportedDetail(EvidenceStatus status, int length) {
		String base = BEFORE_EXPORT + ": the stored object was read back and re-hashed, "
				+ "and the digest matches the one recorded at preservation. Released " + length
				+ " bytes to the principal named on this entry.";
		if (status == EvidenceStatus.COMPROMISED) {
			return base + " The item is COMPROMISED from an earlier mismatch; these bytes match the recorded digest.";
		}
		return base;
	}
}
