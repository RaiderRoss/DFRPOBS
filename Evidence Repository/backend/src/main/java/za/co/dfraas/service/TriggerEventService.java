package za.co.dfraas.service;

import java.util.UUID;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import za.co.dfraas.dto.TriggerEventDto;
import za.co.dfraas.dto.TriggerEventIngestRequest;
import za.co.dfraas.dto.TriggerEventIngestResult;
import za.co.dfraas.entity.TriggerEvent;
import za.co.dfraas.exception.ResourceNotFoundException;
import za.co.dfraas.mapper.TriggerEventMapper;
import za.co.dfraas.repository.TriggerEventRepository;

/**
 * Business logic for trigger events.
 *
 * <p>Read-only at the class level with writes opting in individually, matching
 * {@link WorkGroupService}. There is exactly one write path — {@link #recordIfAbsent} —
 * and it is called by {@code EvidenceEventConsumer}, not by any HTTP endpoint.
 */
@Service
@Transactional(readOnly = true)
public class TriggerEventService {

	private static final String RESOURCE = "TriggerEvent";

	private final TriggerEventRepository repository;
	private final TriggerEventMapper mapper;
	private final HashingService hashingService;

	public TriggerEventService(
			TriggerEventRepository repository,
			TriggerEventMapper mapper,
			HashingService hashingService) {
		this.repository = repository;
		this.mapper = mapper;
		this.hashingService = hashingService;
	}

	/**
	 * Records a trigger event, or reports that it was already recorded.
	 *
	 * <p>This is the idempotency barrier for the whole ingestion pipeline. Kafka delivers
	 * at-least-once, so the same alert arriving twice is normal operation: a rebalance, a
	 * retry, or a consumer restart before the offset was committed. Ingesting it twice
	 * would create a second {@code EvidenceItem} for one real-world event and put a
	 * phantom entry in the custody ledger — a defect that is invisible until someone tries
	 * to rely on the ledger.
	 *
	 * <p>The digest is computed <em>before</em> the insert and never supplied by the
	 * caller, per SecureRS: hashing is the first thing that happens to a payload, and a
	 * sender does not get to assert what its own content hashes to.
	 *
	 * <p><strong>On the concurrent case.</strong> The lookup below is a fast path, not the
	 * guarantee — two consumers on different partitions can both pass it before either
	 * inserts. {@code uq_trigger_event_source_external} is what actually holds, and the
	 * loser's {@code DataIntegrityViolationException} is deliberately allowed to propagate
	 * rather than being caught and turned into a re-read. Two reasons:
	 *
	 * <ul>
	 *   <li>Postgres marks the transaction aborted once a constraint fires, so a re-query
	 *       in this same transaction would fail anyway — the re-read has to happen in a
	 *       new transaction, and that complexity buys nothing here.</li>
	 *   <li>The listener runs with {@code enable-auto-commit=false} and
	 *       {@code ack-mode=record}, so a throw leaves the offset uncommitted and the
	 *       record is redelivered. On redelivery the row exists and the fast path returns
	 *       {@code created=false}. The race resolves itself correctly.</li>
	 * </ul>
	 *
	 * @return the stored event, with {@code created=false} when this was a duplicate
	 *         delivery and no new row was written
	 */
	@Transactional
	public TriggerEventIngestResult recordIfAbsent(TriggerEventIngestRequest request) {
		return repository
				.findBySourceSystemAndExternalEventId(request.sourceSystem(), request.externalEventId())
				.map(existing -> new TriggerEventIngestResult(mapper.toDto(existing), false))
				.orElseGet(() -> {
					TriggerEvent entity = mapper.toEntity(request);
					entity.setPayloadSha256(hashingService.sha256Hex(request.payload()));
					// saveAndFlush, so the INSERT is issued here rather than at commit —
					// a deferred flush would surface the constraint violation outside this
					// method, where the context that explains it is gone.
					return new TriggerEventIngestResult(mapper.toDto(repository.saveAndFlush(entity)), true);
				});
	}

	public TriggerEventDto findById(UUID id) {
		return repository.findById(id)
				.map(mapper::toDto)
				.orElseThrow(() -> ResourceNotFoundException.of(RESOURCE, id));
	}

	/**
	 * Resolves the source's own identifier back to a stored event — the lookup an
	 * investigator performs when starting from a SIEM console rather than from this system.
	 */
	public TriggerEventDto findBySourceSystemAndExternalEventId(String sourceSystem, String externalEventId) {
		return repository.findBySourceSystemAndExternalEventId(sourceSystem, externalEventId)
				.map(mapper::toDto)
				.orElseThrow(() -> ResourceNotFoundException.of(RESOURCE, sourceSystem + "/" + externalEventId));
	}

	/**
	 * Paged deliberately, with no unpaged variant offered. This table has one row per alert
	 * and no natural ceiling, so an endpoint that loads all of it is a denial-of-service
	 * waiting for the first busy week.
	 */
	public Page<TriggerEventDto> findAll(Pageable pageable) {
		return repository.findAll(pageable).map(mapper::toDto);
	}

	public Page<TriggerEventDto> findBySourceSystem(String sourceSystem, Pageable pageable) {
		return repository.findBySourceSystem(sourceSystem, pageable).map(mapper::toDto);
	}
}
