package za.co.dfraas.mapper;

import java.util.List;

import org.springframework.stereotype.Component;

import za.co.dfraas.dto.EvidenceSourceCreateRequest;
import za.co.dfraas.dto.EvidenceSourceDto;
import za.co.dfraas.entity.EvidenceSource;
import za.co.dfraas.entity.WorkGroup;

/**
 * Translation between {@link EvidenceSource} and its DTOs.
 *
 * <p>Hand-written, matching {@link WorkGroupMapper}: at this size a mapping framework adds
 * a build step without removing meaningful work, and the explicit version makes it obvious
 * which fields are deliberately not exposed.
 */
@Component
public class EvidenceSourceMapper {

	/**
	 * <p>Reads the work group's identifier off the association rather than the object.
	 * Hibernate answers {@code getId()} from the proxy without initialising it, so this
	 * stays a single query even though the association is {@code LAZY} — which is the
	 * reason {@link EvidenceSourceDto} carries an id in the first place.
	 */
	public EvidenceSourceDto toDto(EvidenceSource entity) {
		return new EvidenceSourceDto(
				entity.getId(),
				entity.getSourceKey(),
				entity.getDisplayName(),
				entity.getWorkGroup().getId(),
				entity.getSourceType(),
				entity.getStatus(),
				entity.getExpectedIntervalSeconds(),
				entity.getLastEvidenceAt(),
				entity.getRegisteredAt());
	}

	public List<EvidenceSourceDto> toDtoList(List<EvidenceSource> entities) {
		return entities.stream().map(this::toDto).toList();
	}

	/**
	 * Builds the entity from the registration body and the work group the service resolved.
	 *
	 * <p>Takes the {@link WorkGroup} as a parameter rather than looking it up: a mapper that
	 * reaches for a repository stops being a translation and starts being a second service
	 * layer with no transaction of its own.
	 *
	 * <p>{@code status} is left at the field default ({@code ACTIVE}) and {@code id},
	 * {@code registeredAt} and {@code lastEvidenceAt} are left unset, so Hibernate, the
	 * column default and the first ingest respectively assign them.
	 */
	public EvidenceSource toEntity(EvidenceSourceCreateRequest request, WorkGroup workGroup) {
		EvidenceSource entity = new EvidenceSource();
		entity.setSourceKey(request.sourceKey());
		entity.setDisplayName(request.displayName());
		entity.setWorkGroup(workGroup);
		entity.setSourceType(request.sourceType());
		entity.setExpectedIntervalSeconds(request.expectedIntervalSeconds());
		return entity;
	}
}
