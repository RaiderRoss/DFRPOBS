package za.co.dfraas.repository;

import java.util.Collection;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import za.co.dfraas.entity.CorrelationStatus;
import za.co.dfraas.entity.Incident;

/**
 * Data access for {@link Incident}.
 *
 * <p>{@code delete} is inherited and should not be called, for the reason it should not be
 * called on {@code TriggerEventRepository}: an incident is part of the investigative record,
 * and {@code fk_trigger_event_incident} and {@code fk_evidence_link_incident} (both
 * {@code RESTRICT}) refuse it once anything points at it.
 */
public interface IncidentRepository extends JpaRepository<Incident, UUID> {

	/**
	 * The lookup ingestion uses to file an alert. Backed by {@code uq_incident_source_key},
	 * which is the actual guarantee of one incident per key; this is only the fast path, as
	 * {@code TriggerEventRepository.findBySourceSystemAndExternalEventId} is for alerts.
	 */
	Optional<Incident> findBySourceSystemAndIncidentKey(String sourceSystem, String incidentKey);

	Page<Incident> findBySourceSystem(String sourceSystem, Pageable pageable);

	/**
	 * The correlation work queue, oldest opened first. {@code PENDING}/{@code FAILED} is
	 * served by the partial index {@code ix_incident_correlation_pending}.
	 */
	Page<Incident> findByCorrelationStatusInOrderByOpenedAtAsc(
			Collection<CorrelationStatus> statuses, Pageable pageable);

	long countByCorrelationStatus(CorrelationStatus correlationStatus);
}
