package za.co.dfraas.repository;

import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import za.co.dfraas.entity.EvidenceItem;
import za.co.dfraas.entity.EvidenceStatus;

/**
 * Data access for {@link EvidenceItem}.
 *
 * <p>Like {@code trigger_event} and unlike {@code work_group}, this table grows without
 * bound — and since the move to continuous collection it grows at the rate the whole
 * estate produces, not at the rate alerts fire. Every collection-returning method here is
 * therefore paged, without exception: the one method that used to return a {@code List} on
 * the argument that a foreign key bounded it ({@code findByTriggerEventId}) is exactly the
 * one whose bound stopped holding. The unpaged {@code findAll} inherited from
 * {@link JpaRepository} should not be called from the service layer.
 *
 * <p>{@code delete} is likewise inherited and likewise should not be called: evidence is
 * soft-delete only ({@link EvidenceStatus#DELETED}). Nothing in this interface enforces
 * that yet — the same lockdown {@code TriggerEventRepository} needs, and the same one
 * {@code CustodyEvent} will need properly.
 */
@Repository
public interface EvidenceItemRepository extends JpaRepository<EvidenceItem, UUID> {

	/**
	 * Resolves an item from the object key. Backed by
	 * {@code uq_evidence_item_storage_ref}, which is what actually guarantees one item per
	 * stored object; this is the lookup that guarantee makes possible.
	 */
	Optional<EvidenceItem> findByStorageRef(String storageRef);

	boolean existsByStorageRef(String storageRef);

	/**
	 * Everything preserved under one classification. Paged, because a busy work group
	 * accumulates items indefinitely. Served by {@code ix_evidence_item_work_group_id}.
	 */
	Page<EvidenceItem> findByWorkGroupId(UUID workGroupId, Pageable pageable);

	/**
	 * The streamed-ingestion dedupe lookup, and the direct counterpart of
	 * {@code TriggerEventRepository.findBySourceSystemAndExternalEventId}.
	 *
	 * <p>Composite because an artifact id is meaningful only within the source that issued
	 * it. Backed by {@code uq_evidence_item_source_artifact}, which is what actually
	 * guarantees uniqueness; this is only the fast path.
	 */
	Optional<EvidenceItem> findByEvidenceSourceIdAndSourceArtifactId(UUID evidenceSourceId, String sourceArtifactId);

	boolean existsByEvidenceSourceIdAndSourceArtifactId(UUID evidenceSourceId, String sourceArtifactId);

	/**
	 * Everything one collector has produced. Paged, because a streaming source accumulates
	 * items indefinitely — unlike the alert-scoped read this replaced, whose count was
	 * bounded by one incident. Served by {@code ix_evidence_item_evidence_source_id}.
	 */
	Page<EvidenceItem> findByEvidenceSourceId(UUID evidenceSourceId, Pageable pageable);

	/**
	 * The correlation query: evidence whose coverage window overlaps a trigger event's
	 * window, within one classification.
	 *
	 * <p><strong>Native, and deliberately so.</strong> The predicate is a range overlap, and
	 * JPQL has no overlap operator — expressing it as
	 * {@code eventStart <= :windowEnd AND eventEnd >= :windowStart} is logically equivalent
	 * but leaves the planner with two independent inequalities over a table holding every
	 * artifact the estate produces, which is close to a sequential scan. Postgres'
	 * {@code &&} on a range goes straight to {@code ix_evidence_item_coverage}. That is the
	 * difference between correlation being a query and being a batch job.
	 *
	 * <p>Inclusive {@code '[]'} bounds on both ranges, matching the index expression. A
	 * point-in-time artifact has {@code eventStart = eventEnd}, and a half-open range over a
	 * zero-length interval is empty — it would silently overlap nothing at all, quietly
	 * excluding exactly the memory captures and single transaction records an investigation
	 * most wants.
	 *
	 * <p><strong>The work group parameter is not optional, and that is the design.</strong>
	 * Time alone is not a usable predicate under continuous collection: every source is
	 * producing constantly, so a 45-minute window across the whole estate returns tens of
	 * thousands of items, which is not evidence gathering but a more expensive way of
	 * finding nothing. Correlation must be scoped on a second axis, and classification is
	 * the one the schema already carries. Narrower scoping — host, account, session —
	 * belongs with {@code TriggerEvent.correlationScope} and is the next thing to build.
	 *
	 * <p>{@code DELETED} items are excluded: soft-deleted evidence must not be quietly
	 * re-gathered into a new incident. {@code COMPROMISED} ones are deliberately <em>not</em>
	 * excluded — an artifact that failed integrity re-verification is still relevant to an
	 * investigation, and arguably more so.
	 *
	 * <p>Paged, with an explicit count query. An unpaged variant is not offered on purpose:
	 * an over-broad scope is a mistake this method should make survivable rather than fatal.
	 */
	@Query(value = """
			SELECT ei.* FROM evidence_item ei
			WHERE ei.event_start IS NOT NULL
			AND ei.work_group_id = :workGroupId
			AND ei.status <> 'DELETED'
			AND tstzrange(ei.event_start, ei.event_end, '[]')
				&& tstzrange(:windowStart, :windowEnd, '[]')
			""",
			countQuery = """
			SELECT count(*) FROM evidence_item ei
			WHERE ei.event_start IS NOT NULL
			AND ei.work_group_id = :workGroupId
			AND ei.status <> 'DELETED'
			AND tstzrange(ei.event_start, ei.event_end, '[]')
				&& tstzrange(:windowStart, :windowEnd, '[]')
			""",
			nativeQuery = true)
	Page<EvidenceItem> findOverlappingCoverage(
			@Param("workGroupId") UUID workGroupId,
			@Param("windowStart") OffsetDateTime windowStart,
			@Param("windowEnd") OffsetDateTime windowEnd,
			Pageable pageable);

	/**
	 * The readiness-audit query: everything not in the normal state. Served by the partial
	 * index {@code ix_evidence_item_status_exceptional} when {@code status} is anything
	 * other than {@link EvidenceStatus#PRESERVED}.
	 */
	Page<EvidenceItem> findByStatus(EvidenceStatus status, Pageable pageable);

	long countByStatus(EvidenceStatus status);
}
