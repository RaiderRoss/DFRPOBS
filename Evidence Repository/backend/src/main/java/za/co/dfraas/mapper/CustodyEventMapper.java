package za.co.dfraas.mapper;

import java.util.List;

import org.springframework.stereotype.Component;

import za.co.dfraas.dto.CustodyEventDto;
import za.co.dfraas.entity.CustodyEvent;

/**
 * Translation from {@link CustodyEvent} to its read model. One direction only: nothing
 * outside {@code CustodyChainService.append} assembles an entry, so there is no
 * {@code toEntity} for a request body to arrive through.
 *
 * <p>Hand-written, matching the other mappers. Every column is copied, and that is the
 * point of writing it out — see {@link CustodyEventDto} on why a custody entry publishes its
 * digests where an evidence item hides its storage key.
 */
@Component
public class CustodyEventMapper {

	/**
	 * Reads the item id off the lazy association, which Hibernate answers from the proxy
	 * without initialising it — so mapping a chain of forty entries is one query, not
	 * forty-one.
	 */
	public CustodyEventDto toDto(CustodyEvent entity) {
		return new CustodyEventDto(
				entity.getId(),
				entity.getEvidenceItem().getId(),
				entity.getSequence(),
				entity.getAction(),
				entity.getPerformedBy(),
				entity.getOccurredAt(),
				entity.getRecordedAt(),
				entity.getArtifactHashBefore(),
				entity.getArtifactHashAfter(),
				entity.getPrevEntryHash(),
				entity.getEntryHash(),
				entity.getCanonicalVersion(),
				entity.getDetail());
	}

	public List<CustodyEventDto> toDtoList(List<CustodyEvent> entities) {
		return entities.stream().map(this::toDto).toList();
	}
}
