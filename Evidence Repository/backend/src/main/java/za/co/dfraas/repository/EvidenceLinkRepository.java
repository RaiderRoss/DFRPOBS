package za.co.dfraas.repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import za.co.dfraas.entity.EvidenceLink;
import za.co.dfraas.entity.LinkDisposition;

/**
 * Data access for {@link EvidenceLink}.
 *
 * <p>Two directions matter here, and they answer different questions. Reads keyed on the
 * trigger event build an incident's bundle — the efficient-gathering half of the design.
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
	Page<EvidenceLink> findByTriggerEventId(UUID triggerEventId, Pageable pageable);

	Page<EvidenceLink> findByTriggerEventIdAndDisposition(
			UUID triggerEventId, LinkDisposition disposition, Pageable pageable);

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
	Optional<EvidenceLink> findByTriggerEventIdAndEvidenceItemId(UUID triggerEventId, UUID evidenceItemId);

	boolean existsByTriggerEventIdAndEvidenceItemId(UUID triggerEventId, UUID evidenceItemId);

	/**
	 * How much of a bundle is still unreviewed, or was set aside — the triage counts an
	 * investigator sees before opening anything.
	 */
	long countByTriggerEventIdAndDisposition(UUID triggerEventId, LinkDisposition disposition);

	long countByTriggerEventId(UUID triggerEventId);
}
