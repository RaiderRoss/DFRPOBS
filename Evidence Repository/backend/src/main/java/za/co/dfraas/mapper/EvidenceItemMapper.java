package za.co.dfraas.mapper;

import org.springframework.stereotype.Component;

import za.co.dfraas.dto.EvidenceIngestRequest;
import za.co.dfraas.dto.EvidenceItemDto;
import za.co.dfraas.entity.EvidenceItem;
import za.co.dfraas.entity.EvidenceSource;
import za.co.dfraas.entity.EvidenceStatus;

/**
 * Translation between {@link EvidenceItem} and its DTOs.
 *
 * <p>Hand-written, matching the other mappers. Here the explicitness earns more than it does
 * elsewhere: this is the class where {@code storageRef} would end up in a response body if
 * anyone let a framework decide which fields to copy.
 */
@Component
public class EvidenceItemMapper {

	/**
	 * <p>Reads identifiers off the lazy associations rather than the objects, which Hibernate
	 * answers from the proxy without initialising it — so mapping an item does not quietly
	 * become three queries.
	 */
	public EvidenceItemDto toDto(EvidenceItem entity) {
		return new EvidenceItemDto(
				entity.getId(),
				entity.getWorkGroup().getId(),
				entity.getEvidenceSource() == null ? null : entity.getEvidenceSource().getId(),
				entity.getSourceArtifactId(),
				entity.getEventStart(),
				entity.getEventEnd(),
				entity.getCurrentHash(),
				entity.getStatus(),
				entity.getCreatedAt());
	}

	/**
	 * Builds the entity for a streamed artifact from the metadata the producer sent, the
	 * source it was resolved to, and the two values this system decided for itself.
	 *
	 * <p><strong>The work group is copied off the source, not linked through it.</strong> That
	 * is the snapshot changeset {@code 0004-7} argues for: the classification recorded here is
	 * the one in force at the moment of preservation, and reclassifying the source next year
	 * must not silently reclassify every artifact it ever produced, each of which was retained
	 * and released under the old one.
	 *
	 * <p>{@code currentHash} and {@code storageRef} arrive as parameters rather than being
	 * read off the request, because neither is the producer's to state: one is recomputed here
	 * from the bytes that actually arrived, the other is where this system chose to put them.
	 *
	 * <p>{@code status} is set explicitly rather than defaulted, matching the column, which
	 * deliberately has no default — a row that skipped the decision should not be
	 * indistinguishable from one that made it.
	 */
	public EvidenceItem toEntity(
			EvidenceIngestRequest request,
			EvidenceSource source,
			String storageRef,
			String currentHash) {

		EvidenceItem entity = new EvidenceItem();
		entity.setWorkGroup(source.getWorkGroup());
		entity.setEvidenceSource(source);
		entity.setSourceArtifactId(request.sourceArtifactId());
		entity.setEventStart(request.eventStart());
		entity.setEventEnd(request.eventEnd());
		entity.setStorageRef(storageRef);
		entity.setCurrentHash(currentHash);
		entity.setStatus(EvidenceStatus.PRESERVED);
		return entity;
	}
}
