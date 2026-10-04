package za.co.dfraas.service;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import za.co.dfraas.dto.EvidenceLinkDto;
import za.co.dfraas.entity.EvidenceLink;
import za.co.dfraas.entity.LinkDisposition;
import za.co.dfraas.exception.LinkAlreadyReviewedException;
import za.co.dfraas.exception.ResourceNotFoundException;
import za.co.dfraas.mapper.EvidenceLinkMapper;
import za.co.dfraas.repository.EvidenceLinkRepository;
import za.co.dfraas.repository.IncidentRepository;

/**
 * Reading an incident's bundle and ruling on what is in it — the review half of README open
 * question 4.
 *
 * <p>The correlation pass proposes; this is where a person disposes. Until something here
 * moves a link out of {@code PROPOSED}, a bundle is a list of overlaps the system noticed,
 * not a set of exhibits anyone has stood behind.
 *
 * <p>Read-only at the class level with writes opting in, matching the other services.
 */
@Service
@Transactional(readOnly = true)
public class EvidenceLinkService {

	private static final Logger log = LoggerFactory.getLogger(EvidenceLinkService.class);

	private static final String RESOURCE = "EvidenceLink";

	private final EvidenceLinkRepository repository;
	private final IncidentRepository incidentRepository;
	private final EvidenceLinkMapper mapper;
	private final Clock clock;

	public EvidenceLinkService(
			EvidenceLinkRepository repository,
			IncidentRepository incidentRepository,
			EvidenceLinkMapper mapper,
			Clock clock) {
		this.repository = repository;
		this.incidentRepository = incidentRepository;
		this.mapper = mapper;
		this.clock = clock;
	}

	/**
	 * One incident's bundle, optionally narrowed to one disposition.
	 *
	 * <p>An unknown incident is a 404 rather than an empty page. The two mean very different
	 * things to an investigator — "this incident gathered nothing" is a finding, "there is no
	 * such incident" is a typo — and an empty page would say the first when the truth is the
	 * second.
	 */
	public Page<EvidenceLinkDto> findByIncident(
			UUID incidentId, LinkDisposition disposition, Pageable pageable) {
		if (!incidentRepository.existsById(incidentId)) {
			throw ResourceNotFoundException.of("Incident", incidentId);
		}
		Page<EvidenceLink> page = (disposition == null)
				? repository.findByIncidentId(incidentId, pageable)
				: repository.findByIncidentIdAndDisposition(incidentId, disposition, pageable);
		return page.map(mapper::toDto);
	}

	public EvidenceLinkDto findById(UUID id) {
		return repository.findWithEvidenceItemById(id)
				.map(mapper::toDto)
				.orElseThrow(() -> ResourceNotFoundException.of(RESOURCE, id));
	}

	@Transactional
	public EvidenceLinkDto confirm(UUID id, String reviewer, String reason) {
		return review(id, LinkDisposition.CONFIRMED, reviewer, reason);
	}

	@Transactional
	public EvidenceLinkDto dismiss(UUID id, String reviewer, String reason) {
		return review(id, LinkDisposition.DISMISSED, reviewer, reason);
	}

	/**
	 * Records a ruling on a {@code PROPOSED} link.
	 *
	 * <p><strong>A reviewed link cannot be reviewed again, deliberately.</strong> An
	 * investigator who changes their mind is ordinary, but the row holds one reviewer, one
	 * time and one reason, so a second review here would overwrite the first. "Dismissed by
	 * A, then confirmed by B" would become "confirmed by B", and the dismissal — the part a
	 * defence would most want to see — would be gone. Allowing a change of ruling needs that
	 * history recorded somewhere it cannot be overwritten, which is the custody chain's job;
	 * until it can carry it, the honest behaviour is to refuse.
	 *
	 * <p>The reviewer is stored as given, a username, for want of an {@code app_user} table
	 * to point at — see the TODO on {@link EvidenceLink#getLinkedBy()}.
	 *
	 * <p>{@code reviewedAt} is this server's clock rather than the database's, as the entity
	 * explains: it records a person's decision, not an event in an exhibit's life.
	 */
	private EvidenceLinkDto review(UUID id, LinkDisposition ruling, String reviewer, String reason) {
		OffsetDateTime now = OffsetDateTime.now(clock);
		int updated = repository.recordReview(id, ruling, reviewer, now, reason.strip());
		if (updated == 0) {
			// Either it does not exist or it was already ruled on; the update cannot say
			// which, so ask. The re-read happens after the update for the same reason the
			// update is conditional — anything read before it could be stale by now.
			EvidenceLink existing = repository.findById(id)
					.orElseThrow(() -> ResourceNotFoundException.of(RESOURCE, id));
			throw new LinkAlreadyReviewedException(id, existing.getDisposition());
		}
		log.info("Evidence link reviewed: id={} disposition={} reviewer={}", id, ruling, reviewer);
		return findById(id);
	}
}
