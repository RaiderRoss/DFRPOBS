package za.co.dfraas.mapper;

import java.util.List;

import org.springframework.stereotype.Component;

import za.co.dfraas.dto.TriggerEventDto;
import za.co.dfraas.dto.TriggerEventIngestRequest;
import za.co.dfraas.entity.TriggerEvent;

/**
 * Translation between {@link TriggerEvent} and its DTOs. Hand-written, matching
 * {@link WorkGroupMapper}.
 */
@Component
public class TriggerEventMapper {

	public TriggerEventDto toDto(TriggerEvent entity) {
		return new TriggerEventDto(
				entity.getId(),
				entity.getExternalEventId(),
				entity.getSourceSystem(),
				entity.getTriggerType(),
				entity.getFiredAt(),
				entity.getReceivedAt(),
				entity.getPayloadSha256(),
				entity.getIncident().getId());
	}

	public List<TriggerEventDto> toDtoList(List<TriggerEvent> entities) {
		return entities.stream().map(this::toDto).toList();
	}

	/**
	 * Maps the sender-supplied fields only. {@code id} is Hibernate's, {@code receivedAt}
	 * the database default's, and {@code payloadSha256} is set by the service after it
	 * computes the digest — a mapper is the wrong place to do cryptography.
	 *
	 * <p>The incident is likewise absent: {@code TriggerEventService} files the alert,
	 * because finding or opening an incident is a lookup, not a translation.
	 */
	public TriggerEvent toEntity(TriggerEventIngestRequest request) {
		TriggerEvent entity = new TriggerEvent();
		entity.setExternalEventId(request.externalEventId());
		entity.setSourceSystem(request.sourceSystem());
		entity.setTriggerType(request.triggerType());
		entity.setFiredAt(request.firedAt());
		entity.setPayload(request.payload());
		return entity;
	}
}
