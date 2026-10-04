package za.co.dfraas.service;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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
 * with the digest recorded at ingest — SecureRS's verify-on-read, run on demand against an
 * artifact nobody is reading.
 *
 * <p>This is the only writer of {@link CustodyAction#HASH_VERIFIED} and
 * {@link CustodyAction#HASH_MISMATCH}, and the only thing that moves an item to
 * {@link EvidenceStatus#COMPROMISED}. It is also what turns the custody chain from a record
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
			entry = custodyChainService.append(
					evidenceItemId, CustodyAction.HASH_MISMATCH, performedBy, checkedAt, expected, observed,
					mismatchDetail(before));
			// Both digests belong in the log, where an operator can see them; the response
			// carries them too, because this is a result and not an error — see
			// IntegrityCheckResult.
			log.error("Integrity check FAILED: itemId={} performedBy={} expected={} observed={} priorStatus={}",
					evidenceItemId, performedBy, expected, observed, before);
			if (before != EvidenceStatus.COMPROMISED) {
				item.setStatus(EvidenceStatus.COMPROMISED);
				// Flushed here rather than at commit, so a rejected status lands in this method
				// and not in the transaction interceptor.
				repository.saveAndFlush(item);
			}
		}

		return new IntegrityCheckResult(
				evidenceItemId, intact, expected, observed, item.getStatus(), custodyEventMapper.toDto(entry));
	}

	/**
	 * The human-readable half of the entry. Names what was done and what it means for the
	 * item's state; the digests are columns on the entry and are not repeated here.
	 */
	private static String verifiedDetail(EvidenceStatus status) {
		String base = "Re-verified on demand: the stored object was read back and re-hashed, "
				+ "and the digest matches the one recorded at preservation.";
		if (status == EvidenceStatus.COMPROMISED) {
			return base + " The item was already COMPROMISED and remains so; that status is never cleared.";
		}
		return base + " Status " + status + " is unchanged.";
	}

	private static String mismatchDetail(EvidenceStatus before) {
		String base = "Re-verified on demand: the stored object was read back and re-hashed, "
				+ "and the digest does not match the one recorded at preservation.";
		if (before == EvidenceStatus.COMPROMISED) {
			return base + " The item was already COMPROMISED.";
		}
		return base + " Status changed from " + before + " to COMPROMISED.";
	}
}
