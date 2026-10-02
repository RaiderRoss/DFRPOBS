package za.co.dfraas.service;

import java.util.List;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import za.co.dfraas.config.CorrelationProperties;
import za.co.dfraas.entity.CorrelationStatus;

/**
 * Drives {@link CorrelationService} on a fixed delay.
 *
 * <p>Deliberately separate from the Kafka listener that records alerts. Correlation is a
 * query over evidence that arrived independently of the alert, so running it inside the
 * listener would stall the alert partition behind a slow or over-broad search — and the
 * evidence covering an alert's window may not have been preserved yet when the alert
 * arrives.
 *
 * <p>Not transactional itself: each alert is handed to the service in its own transaction,
 * so one alert failing records that alert {@code FAILED} and the sweep moves on.
 *
 * <p><strong>Assumes a single running instance.</strong> Two instances sweeping the same
 * queue would both try to link the same pairs; {@code uq_evidence_link_pair} stops a
 * duplicate, but the loser's whole pass rolls back and is recorded {@code FAILED} until its
 * next retry. Set {@code dfraas.correlation.enabled=false} on every instance but one.
 */
@Component
@ConditionalOnProperty(prefix = "dfraas.correlation", name = "enabled", havingValue = "true")
public class CorrelationScheduler {

	private static final Logger log = LoggerFactory.getLogger(CorrelationScheduler.class);

	/** Never attempted, or broke last time — both need the same work done. */
	private static final List<CorrelationStatus> UNCORRELATED =
			List.of(CorrelationStatus.PENDING, CorrelationStatus.FAILED);

	/** Correlated, but not yet settled — still collecting late arrivals. */
	private static final List<CorrelationStatus> OPEN = List.of(CorrelationStatus.CORRELATED);

	private final CorrelationService correlationService;
	private final CorrelationProperties properties;

	public CorrelationScheduler(CorrelationService correlationService, CorrelationProperties properties) {
		this.correlationService = correlationService;
		this.properties = properties;
	}

	/**
	 * One sweep: new and failed alerts first, then a re-run over open ones for late
	 * arrivals, closing each once its bundle has settled.
	 *
	 * <p>Both queues are taken oldest-first and capped at {@code batchSize}, so a backlog is
	 * worked through across several sweeps rather than in one unbounded run. Open alerts
	 * beyond the cap wait for a later sweep; nothing is lost by that, because every alert is
	 * re-run once more before it closes.
	 */
	@Scheduled(
			initialDelayString = "${dfraas.correlation.sweep-interval}",
			fixedDelayString = "${dfraas.correlation.sweep-interval}")
	public void sweep() {
		int correlated = run(correlationService.queue(UNCORRELATED, properties.batchSize()));
		int reopened = run(correlationService.queue(OPEN, properties.batchSize()));
		if (correlated + reopened > 0) {
			log.debug("Correlation sweep finished: uncorrelated={} open={}", correlated, reopened);
		}
	}

	private int run(List<UUID> triggerEventIds) {
		for (UUID id : triggerEventIds) {
			try {
				correlationService.correlate(id);
			}
			catch (RuntimeException e) {
				// Logged at WARN, not ERROR: an alert from an unregistered source fails here
				// on every sweep until the source is registered, which is a configuration gap
				// rather than a fault. The FAILED status is what an audit should look for.
				log.warn("Correlation failed for trigger event {}: {}", id, e.getMessage());
				correlationService.markFailed(id);
			}
		}
		return triggerEventIds.size();
	}
}
