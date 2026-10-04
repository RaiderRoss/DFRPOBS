package za.co.dfraas.service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import za.co.dfraas.dto.IncidentDto;
import za.co.dfraas.dto.TriggerEventDto;
import za.co.dfraas.entity.Incident;
import za.co.dfraas.exception.ResourceNotFoundException;
import za.co.dfraas.mapper.IncidentMapper;
import za.co.dfraas.mapper.TriggerEventMapper;
import za.co.dfraas.repository.IncidentRepository;
import za.co.dfraas.repository.TriggerEventRepository;

/**
 * Reading incidents and their member alerts. Read-only: an incident is opened and extended
 * by {@code TriggerEventService} as alerts arrive, and correlated by
 * {@code CorrelationService}; nothing here writes.
 */
@Service
@Transactional(readOnly = true)
public class IncidentService {

	private static final String RESOURCE = "Incident";

	private final IncidentRepository repository;
	private final TriggerEventRepository triggerEventRepository;
	private final IncidentMapper mapper;
	private final TriggerEventMapper triggerEventMapper;

	public IncidentService(
			IncidentRepository repository,
			TriggerEventRepository triggerEventRepository,
			IncidentMapper mapper,
			TriggerEventMapper triggerEventMapper) {
		this.repository = repository;
		this.triggerEventRepository = triggerEventRepository;
		this.mapper = mapper;
		this.triggerEventMapper = triggerEventMapper;
	}

	/** Paged, with no unpaged variant, for the reason {@code TriggerEventService.findAll} gives. */
	public Page<IncidentDto> findAll(String sourceSystem, Pageable pageable) {
		Page<Incident> page = (sourceSystem == null)
				? repository.findAll(pageable)
				: repository.findBySourceSystem(sourceSystem, pageable);
		Map<UUID, Long> counts = alertCounts(page.getContent());
		return page.map(incident -> mapper.toDto(incident, counts.getOrDefault(incident.getId(), 0L)));
	}

	public IncidentDto findById(UUID id) {
		Incident incident = repository.findById(id).orElseThrow(() -> ResourceNotFoundException.of(RESOURCE, id));
		return mapper.toDto(incident, alertCounts(List.of(incident)).getOrDefault(id, 0L));
	}

	/**
	 * An incident's member alerts. An unknown incident is a 404 rather than an empty page —
	 * every incident has at least one alert, so an empty page would be a lie about one that
	 * does not exist.
	 */
	public Page<TriggerEventDto> findAlerts(UUID incidentId, Pageable pageable) {
		if (!repository.existsById(incidentId)) {
			throw ResourceNotFoundException.of(RESOURCE, incidentId);
		}
		return triggerEventRepository.findByIncidentId(incidentId, pageable).map(triggerEventMapper::toDto);
	}

	private Map<UUID, Long> alertCounts(List<Incident> incidents) {
		Map<UUID, Long> counts = new HashMap<>();
		if (incidents.isEmpty()) {
			return counts;
		}
		List<UUID> ids = incidents.stream().map(Incident::getId).toList();
		for (Object[] row : triggerEventRepository.countByIncidentIds(ids)) {
			counts.put((UUID) row[0], (Long) row[1]);
		}
		return counts;
	}
}
