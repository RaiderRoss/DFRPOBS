package za.co.dfraas.repository;

import java.time.OffsetDateTime;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import za.co.dfraas.entity.CorrelationStatus;
import za.co.dfraas.entity.TriggerEvent;

/**
 * Data access for {@link TriggerEvent}.
 *
 * <p>Unlike {@code work_group}, this table grows without bound — one row per alert, for
 * as long as the SIEM keeps emitting them. Every read here is therefore paged or bounded;
 * an unpaged {@code findAll} is still inherited from {@link JpaRepository} but should not
 * be called from the service layer.
 */
@Repository
public interface TriggerEventRepository extends JpaRepository<TriggerEvent, UUID> {

	/**
	 * The idempotency lookup the ingestion consumer performs before doing any work.
	 *
	 * <p>Composite because an external id is only meaningful within the system that
	 * issued it — two SIEMs can both emit alert {@code 12345}. Backed by
	 * {@code uq_trigger_event_source_external}, which is what actually guarantees
	 * uniqueness; this method only provides the fast path.
	 */
	Optional<TriggerEvent> findBySourceSystemAndExternalEventId(String sourceSystem, String externalEventId);

	boolean existsBySourceSystemAndExternalEventId(String sourceSystem, String externalEventId);

	/**
	 * Returns a {@link Page}, not a {@code List}. The original signature returned
	 * {@code Optional<TriggerEvent>}, which cannot hold: a source system emits many
	 * events, and Spring Data throws {@code IncorrectResultSizeDataAccessException} the
	 * moment a second row exists for that source.
	 */
	Page<TriggerEvent> findBySourceSystem(String sourceSystem, Pageable pageable);

	/**
	 * Events whose source-reported fire time falls in a half-open window. Served by
	 * {@code ix_trigger_event_fired_at}.
	 */
	List<TriggerEvent> findByFiredAtBetween(OffsetDateTime from, OffsetDateTime to);

	/**
	 * The correlation work queue: alerts recorded but not yet correlated, oldest first.
	 *
	 * <p>This is what README open question 3 was reaching for. The original bug was that
	 * ingestion could commit a trigger event and then die before preserving anything, with
	 * no way to tell afterwards; the schema could not answer "which alerts were received and
	 * produced nothing". Once collection is continuous the gap moves to correlation, but the
	 * question is the same one and this method is its answer.
	 *
	 * <p>Pass {@code PENDING} and {@link CorrelationStatus#FAILED} together to drive a sweep
	 * — both need the same work done, and the partial index
	 * {@code ix_trigger_event_correlation_pending} covers exactly that pair. Query them
	 * separately when reporting, because an alert never attempted and one whose attempt
	 * broke say entirely different things about the system.
	 *
	 * <p>Ordered by {@code receivedAt} rather than {@code firedAt}: a source with a wrong
	 * clock must not be able to push its alerts to the front of the queue.
	 */
	Page<TriggerEvent> findByCorrelationStatusInOrderByReceivedAtAsc(
			Collection<CorrelationStatus> statuses, Pageable pageable);

	long countByCorrelationStatus(CorrelationStatus correlationStatus);
}
