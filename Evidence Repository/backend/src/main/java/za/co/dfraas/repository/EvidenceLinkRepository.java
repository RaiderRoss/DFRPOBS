package za.co.dfraas.repository;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import za.co.dfraas.entity.EvidenceLink;
import za.co.dfraas.entity.LinkDisposition;

/**
 * Data access for {@link EvidenceLink}.
 *
 * <p>Two directions matter here, and they answer different questions. Reads keyed on the
 * incident build its bundle — the efficient-gathering half of the design.
 * Reads keyed on the evidence item answer "which incidents has this artifact been gathered
 * into", which is what keeps individual review meaningful once one artifact can belong to
 * several bundles.
 *
 * <p>{@code delete} is inherited and should not be called. A link that turns out to be
 * irrelevant is set {@link LinkDisposition#DISMISSED}, because "the system surfaced this
 * and an investigator set it aside" is part of the investigative record. Nothing in this
 * interface enforces that yet — the same lockdown {@code TriggerEventRepository} needs.
 */
@Repository
public interface EvidenceLinkRepository extends JpaRepository<EvidenceLink, UUID> {

	/**
	 * An incident's whole bundle. Paged, unlike the {@code findByTriggerEventId} it
	 * replaces on {@code EvidenceItemRepository}.
	 *
	 * <p>That change is not incidental. The old method returned a {@code List} on the
	 * argument that the count was bounded by how many artifacts one incident collects — a
	 * handful. That was true when an alert caused its own evidence to be collected. It is
	 * not true of a time-window correlation over continuously streamed evidence, where the
	 * bound is however much the estate produced during the window, and an over-broad scope
	 * can return thousands.
	 */
	@EntityGraph(attributePaths = {"evidenceItem", "evidenceItem.evidenceSource"})
	Page<EvidenceLink> findByIncidentId(UUID incidentId, Pageable pageable);

	@EntityGraph(attributePaths = {"evidenceItem", "evidenceItem.evidenceSource"})
	Page<EvidenceLink> findByIncidentIdAndDisposition(
			UUID incidentId, LinkDisposition disposition, Pageable pageable);

	/**
	 * One link with the item it points at, for the review endpoints' responses.
	 *
	 * <p>The entity graph on this and the two bundle reads above is what keeps a page of
	 * links from becoming a query per link: a review screen shows each item's coverage
	 * window and source, and both sit behind lazy associations.
	 */
	@EntityGraph(attributePaths = {"evidenceItem", "evidenceItem.evidenceSource"})
	Optional<EvidenceLink> findWithEvidenceItemById(UUID id);

	/**
	 * Records a review, but only on a link nobody has reviewed yet.
	 *
	 * <p><strong>A conditional update, not a read-check-write.</strong> Two investigators
	 * opening the same bundle can both see a link as {@code PROPOSED}; checking the
	 * disposition in Java and then saving would let the second silently overwrite the first's
	 * ruling, reviewer and reason included. Putting the precondition in the {@code WHERE}
	 * clause makes the database the arbiter: exactly one of them gets a row count of 1.
	 *
	 * <p>Why a reviewed link cannot be reviewed again at all is on
	 * {@code EvidenceLinkService.review}.
	 *
	 * @return 1 if the review was recorded, 0 if the link does not exist or was already
	 *         reviewed — the caller tells the two apart
	 */
	@Modifying(flushAutomatically = true, clearAutomatically = true)
	@Query("""
			update EvidenceLink l
			set l.disposition = :disposition,
				l.reviewedBy = :reviewedBy,
				l.reviewedAt = :reviewedAt,
				l.reviewNote = :reviewNote
			where l.id = :id
			and l.disposition = za.co.dfraas.entity.LinkDisposition.PROPOSED
			""")
	int recordReview(
			@Param("id") UUID id,
			@Param("disposition") LinkDisposition disposition,
			@Param("reviewedBy") String reviewedBy,
			@Param("reviewedAt") OffsetDateTime reviewedAt,
			@Param("reviewNote") String reviewNote);

	/**
	 * Every incident one artifact has been gathered into. Unpaged and a {@code List}: this
	 * really is bounded by how many alerts happened to overlap one artifact's coverage
	 * window, and an artifact appearing in more than a handful of incidents is itself a
	 * finding rather than a paging problem.
	 *
	 * <p>Served by {@code ix_evidence_link_evidence_item_id}.
	 */
	List<EvidenceLink> findByEvidenceItemId(UUID evidenceItemId);

	/**
	 * The idempotency lookup a re-correlation pass performs. Backed by
	 * {@code uq_evidence_link_pair}, which is what actually guarantees one link per pair;
	 * this is only the fast path, exactly as
	 * {@code TriggerEventRepository.findBySourceSystemAndExternalEventId} is for ingestion.
	 */
	Optional<EvidenceLink> findByIncidentIdAndEvidenceItemId(UUID incidentId, UUID evidenceItemId);

	boolean existsByIncidentIdAndEvidenceItemId(UUID incidentId, UUID evidenceItemId);

	/**
	 * How much of a bundle is still unreviewed, or was set aside — the triage counts an
	 * investigator sees before opening anything.
	 */
	long countByIncidentIdAndDisposition(UUID incidentId, LinkDisposition disposition);

	long countByIncidentId(UUID incidentId);
}
