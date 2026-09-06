package za.co.dfraas.service;

import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import za.co.dfraas.dto.EvidenceIngestRequest;
import za.co.dfraas.dto.EvidenceItemDto;
import za.co.dfraas.entity.EvidenceItem;
import za.co.dfraas.entity.EvidenceSource;
import za.co.dfraas.entity.EvidenceStatus;
import za.co.dfraas.exception.DuplicateResourceException;
import za.co.dfraas.exception.IntegrityVerificationException;
import za.co.dfraas.exception.ResourceNotFoundException;
import za.co.dfraas.mapper.EvidenceItemMapper;
import za.co.dfraas.repository.EvidenceItemRepository;
import za.co.dfraas.repository.EvidenceSourceRepository;

/**
 * Business logic for preserved artifacts, and the streamed-ingestion path itself.
 *
 * <p>Read-only at the class level with the one write opting in, matching the other services.
 */
@Service
@Transactional(readOnly = true)
public class EvidenceItemService {

	private static final Logger log = LoggerFactory.getLogger(EvidenceItemService.class);

	private static final String RESOURCE = "EvidenceItem";
	private static final String SOURCE_RESOURCE = "EvidenceSource";

	private final EvidenceItemRepository repository;
	private final EvidenceSourceRepository sourceRepository;
	private final EvidenceItemMapper mapper;
	private final HashingService hashingService;
	private final EvidenceStorageService storageService;

	public EvidenceItemService(
			EvidenceItemRepository repository,
			EvidenceSourceRepository sourceRepository,
			EvidenceItemMapper mapper,
			HashingService hashingService,
			EvidenceStorageService storageService) {
		this.repository = repository;
		this.sourceRepository = sourceRepository;
		this.mapper = mapper;
		this.hashingService = hashingService;
		this.storageService = storageService;
	}

	public EvidenceItemDto findById(UUID id) {
		return repository.findById(id)
				.map(mapper::toDto)
				.orElseThrow(() -> ResourceNotFoundException.of(RESOURCE, id));
	}

	/**
	 * The browse listing, optionally narrowed to one classification.
	 *
	 * <p>Paged and never a {@code List}, which is the rule {@code EvidenceItemRepository}
	 * states for every collection-returning read on this table: under continuous collection it
	 * grows at the rate the whole estate produces, so an unpaged listing is a request to
	 * materialise the entire evidence store into one response body. Note that the resource's
	 * {@code @PageableDefault} sets the default page size and not a ceiling: the ceiling is
	 * Spring's {@code spring.data.web.pageable.max-page-size}, which defaults to 2000 and is
	 * worth lowering here once this endpoint has a real caller.
	 *
	 * <p>{@code includeDeleted} defaults to false at the resource. Soft-deleted items are
	 * withheld from an ordinary browse because presenting them beside live evidence
	 * misrepresents what is currently preserved, but they are never unreachable: the record
	 * that an artifact was destroyed, and when, is itself a finding an investigation may need,
	 * which is why this is a flag and not a filter baked into the query.
	 */
	public Page<EvidenceItemDto> findAll(UUID workGroupId, boolean includeDeleted, Pageable pageable) {
		return findEntities(workGroupId, includeDeleted, pageable).map(mapper::toDto);
	}

	private Page<EvidenceItem> findEntities(UUID workGroupId, boolean includeDeleted, Pageable pageable) {
		if (workGroupId != null) {
			return includeDeleted
					? repository.findByWorkGroupId(workGroupId, pageable)
					: repository.findByWorkGroupIdAndStatusNot(workGroupId, EvidenceStatus.DELETED, pageable);
		}
		// findAll(Pageable) rather than the unpaged findAll() the repository warns against.
		return includeDeleted
				? repository.findAll(pageable)
				: repository.findByStatusNot(EvidenceStatus.DELETED, pageable);
	}

	/**
	 * Preserves one artifact from a registered source: verify, store, verify again, record.
	 *
	 * <p><strong>The order of these steps is the design.</strong> Hashing happens first,
	 * before the source is even resolved, because SecureRS's rule is that the digest is the
	 * first thing that touches an artifact — anything done beforehand is something the digest
	 * cannot account for. The digest the producer sent is then a claim to be checked, never
	 * the value stored: what goes into {@code currentHash} is always what this system
	 * computed from the bytes that actually arrived. That comparison is what closes the gap
	 * between a source hashing a file at capture and this repository holding it, and it is
	 * the only part of the transfer chain that can be verified rather than trusted.
	 *
	 * <p>The artifact is written to storage <em>before</em> the row, and that ordering is
	 * chosen for which failure it leaves behind. Row first means a crash between the two
	 * leaves an {@code EvidenceItem} pointing at nothing — a phantom exhibit that looks
	 * preserved in every listing and is not, which is the worst state this schema can be in.
	 * Object first leaves an orphaned object: bytes in a bucket that no row claims, invisible
	 * to the API, harmless, and re-sent safely because the key is derived deterministically
	 * so a retry rewrites the same bytes to the same place. One is a lie, the other is
	 * litter.
	 *
	 * <p>The stored object is then read back and re-hashed before the row is written. It is
	 * the same verify-on-read rule SecureRS applies to every later access, pulled forward to
	 * the write: the digest recorded against this item is one that has been checked against
	 * the bytes storage is actually holding, not merely against the bytes that arrived at the
	 * HTTP layer.
	 *
	 * <p><strong>Idempotency.</strong> The pre-check on
	 * {@code (evidenceSourceId, sourceArtifactId)} is a fast path that gives a clean 409;
	 * {@code uq_evidence_item_source_artifact} is the guarantee, since two concurrent uploads
	 * can both pass the check before either inserts, and the loser's constraint violation is
	 * translated to the same 409. A re-sent artifact therefore cannot become a second exhibit
	 * for one collection event, no matter how the two attempts interleave.
	 *
	 * <p><strong>One acknowledged compromise.</strong> The object write happens inside this
	 * transaction, so a database connection is held for the duration of an upload to MinIO.
	 * At testbed volumes over a local network that is milliseconds and buys atomicity between
	 * the dedupe check and the insert, which matters more. If artifacts grow to where it does
	 * not, the split is to do the storage work outside the transaction and keep only the
	 * insert inside it.
	 */
	@Transactional
	public EvidenceItemDto preserve(EvidenceIngestRequest request, byte[] content, String contentType) {
		String currentHash = hashingService.sha256Hex(content);
		if (!currentHash.equals(request.sourceSha256())) {
			// Both digests are logged here and named in neither the exception nor the
			// response: an operator diagnosing a mismatch needs them, a caller does not, and
			// ApiExceptionHandler's rule is that messages carry identifiers and nothing else.
			log.error("Integrity check failed on arrival: sourceKey={} artifactId={} asserted={} computed={}",
					request.sourceKey(), request.sourceArtifactId(), request.sourceSha256(), currentHash);
			throw IntegrityVerificationException.digestMismatch(request.sourceArtifactId());
		}

		if (content.length == 0) {
			// Preserved anyway. An empty capture is a real outcome — a window in which a
			// rate-limited collector logged nothing is exactly the failure worth having on
			// record — and the repository's job is to preserve what a source produced, not to
			// decide whether it is interesting. It is worth a log line, because the far more
			// common cause is a collector that is misconfigured rather than a quiet estate.
			log.warn("Preserving an empty artifact: sourceKey={} artifactId={}",
					request.sourceKey(), request.sourceArtifactId());
		}

		EvidenceSource source = sourceRepository.findBySourceKey(request.sourceKey())
				.orElseThrow(() -> ResourceNotFoundException.of(SOURCE_RESOURCE, request.sourceKey()));

		if (repository.existsByEvidenceSourceIdAndSourceArtifactId(source.getId(), request.sourceArtifactId())) {
			log.info("Duplicate artifact ignored: sourceKey={} artifactId={}",
					request.sourceKey(), request.sourceArtifactId());
			throw DuplicateResourceException.of(RESOURCE, "sourceArtifactId", request.sourceArtifactId());
		}

		String storageRef = storageKeyFor(source.getSourceKey(), request.sourceArtifactId());
		storageService.store(storageRef, content, contentType);

		String storedHash = hashingService.sha256Hex(storageService.read(storageRef));
		if (!storedHash.equals(currentHash)) {
			log.error("Integrity check failed after storage: storageRef={} expected={} readBack={}",
					storageRef, currentHash, storedHash);
			throw IntegrityVerificationException.storageMismatch(request.sourceArtifactId());
		}

		EvidenceItem entity = mapper.toEntity(request, source, storageRef, currentHash);
		EvidenceItemDto preserved;
		try {
			// saveAndFlush, so the INSERT is issued inside this try rather than at commit —
			// a deferred flush would throw past the catch and surface as a 500.
			preserved = mapper.toDto(repository.saveAndFlush(entity));
		} catch (DataIntegrityViolationException ex) {
			throw DuplicateResourceException.of(RESOURCE, "sourceArtifactId", request.sourceArtifactId());
		}

		// Last, and only on success: a source is "alive" because it delivered something that
		// was preserved, not because something addressed to it arrived and was rejected.
		sourceRepository.touchLastEvidenceAt(source.getId());

		log.info("Preserved artifact: id={} sourceKey={} artifactId={} bytes={} sha256={}",
				preserved.id(), request.sourceKey(), request.sourceArtifactId(), content.length, currentHash);
		return preserved;
	}

	/**
	 * Derives the object key an artifact is stored under.
	 *
	 * <p>Deterministic, from the two values that identify the artifact — which is what makes
	 * a retry after a failed ingest safe: it re-derives the same key and rewrites the same
	 * bytes rather than accumulating a second copy under a fresh name. A random key would
	 * leave {@code uq_evidence_item_storage_ref} guarding nothing, since every attempt would
	 * satisfy it.
	 *
	 * <p>Both components are constrained where they enter the system — the source key at
	 * registration, the artifact id by the ingest request's pattern — so neither can contain
	 * a separator or a traversal segment and the key stays exactly two levels deep.
	 */
	private static String storageKeyFor(String sourceKey, String sourceArtifactId) {
		return sourceKey + "/" + sourceArtifactId;
	}
}
