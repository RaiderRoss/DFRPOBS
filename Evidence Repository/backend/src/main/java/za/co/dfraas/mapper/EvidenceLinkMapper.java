package za.co.dfraas.mapper;

import org.springframework.stereotype.Component;

import za.co.dfraas.dto.EvidenceLinkDto;
import za.co.dfraas.entity.EvidenceLink;
import za.co.dfraas.entity.EvidenceSource;

/**
 * Translation from {@link EvidenceLink} to its read model. Hand-written, matching the other
 * mappers, and read-only: links are made by the correlation pass and reviewed through
 * {@code EvidenceLinkRepository.recordReview}, so there is no request to map into one.
 */
@Component
public class EvidenceLinkMapper {

	private final EvidenceItemMapper evidenceItemMapper;

	public EvidenceLinkMapper(EvidenceItemMapper evidenceItemMapper) {
		this.evidenceItemMapper = evidenceItemMapper;
	}

	/**
	 * Expects the item and its source to be loaded already — see the entity graphs on
	 * {@code EvidenceLinkRepository}. The incident is read by id only, which Hibernate
	 * answers from the proxy.
	 */
	public EvidenceLinkDto toDto(EvidenceLink entity) {
		EvidenceSource source = entity.getEvidenceItem().getEvidenceSource();
		return new EvidenceLinkDto(
				entity.getId(),
				entity.getIncident().getId(),
				entity.getLinkMethod(),
				entity.getDisposition(),
				entity.getRationale(),
				entity.getLinkedBy(),
				entity.getLinkedAt(),
				entity.isLateArrival(),
				entity.getReviewedBy(),
				entity.getReviewedAt(),
				entity.getReviewNote(),
				source == null ? null : source.getSourceKey(),
				evidenceItemMapper.toDto(entity.getEvidenceItem()));
	}
}
