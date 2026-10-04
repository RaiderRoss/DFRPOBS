package za.co.dfraas.mapper;

import org.springframework.stereotype.Component;

import za.co.dfraas.dto.IncidentDto;
import za.co.dfraas.entity.Incident;

/**
 * Translation from {@link Incident} to its read model. Hand-written, matching the other
 * mappers, and read-only: incidents are opened by ingestion, never by a request.
 */
@Component
public class IncidentMapper {

	/**
	 * The alert count is passed in rather than read off the entity, which holds no collection
	 * of its alerts: {@code IncidentService} counts a whole page of incidents in one query.
	 */
	public IncidentDto toDto(Incident entity, long alertCount) {
		return new IncidentDto(
				entity.getId(),
				entity.getSourceSystem(),
				entity.getIncidentKey(),
				alertCount,
				entity.getFirstFiredAt(),
				entity.getLastFiredAt(),
				entity.getOpenedAt(),
				entity.getCorrelationStatus(),
				entity.getCorrelatedAt(),
				entity.windowStart(),
				entity.windowEnd());
	}
}
