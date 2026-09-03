package za.co.dfraas.service;

import java.util.Set;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.support.KafkaHeaders;
import org.springframework.messaging.handler.annotation.Header;
import org.springframework.messaging.handler.annotation.Payload;
import org.springframework.stereotype.Service;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;
import za.co.dfraas.dto.EvidenceEventMessage;
import za.co.dfraas.dto.TriggerEventIngestRequest;
import za.co.dfraas.dto.TriggerEventIngestResult;

/**
 * Ingestion entry point: consumes SIEM/IDS trigger events from the {@code evidence-events}
 * topic and drives the preservation pipeline.
 *
 * <p>The first two rules this class exists to enforce are now in place. Idempotency lives
 * in {@link TriggerEventService#recordIfAbsent}, which dedupes on the source's own event
 * id inside a single transaction backed by a unique constraint; hashing happens in that
 * same call, before the payload is written anywhere. What remains is the storage half —
 * see TODO 3.
 *
 * <p>Payload is consumed as {@code String} until the schema decision (Avro/Protobuf +
 * schema registry) is made; swap the deserializer in application.properties at that point,
 * and replace {@link EvidenceEventMessage}.
 */
@Service
public class EvidenceEventConsumer {

	private static final Logger log = LoggerFactory.getLogger(EvidenceEventConsumer.class);

	private final TriggerEventService triggerEventService;
	private final ObjectMapper objectMapper;
	private final Validator validator;

	public EvidenceEventConsumer(
			TriggerEventService triggerEventService,
			ObjectMapper objectMapper,
			Validator validator) {
		this.triggerEventService = triggerEventService;
		this.objectMapper = objectMapper;
		this.validator = validator;
	}

	@KafkaListener(topics = "${dfraas.kafka.evidence-events-topic}")
	public void onEvidenceEvent(
			@Payload String payload,
			@Header(name = KafkaHeaders.RECEIVED_KEY, required = false) String key,
			@Header(KafkaHeaders.RECEIVED_PARTITION) int partition,
			@Header(KafkaHeaders.OFFSET) long offset) {

		log.info("Received evidence event: key={} partition={} offset={} bytes={}",
				key, partition, offset, payload.length());

		TriggerEventIngestRequest request = parse(payload, partition, offset);
		if (request == null) {
			return;
		}

		// Records the alert and computes its digest in one transaction. A duplicate
		// delivery — normal under at-least-once — stops the pipeline here rather than
		// producing a second EvidenceItem for one real-world event.
		TriggerEventIngestResult result = triggerEventService.recordIfAbsent(request);
		if (!result.created()) {
			log.info("Duplicate delivery ignored: source={} externalEventId={} existingId={}",
					request.sourceSystem(), request.externalEventId(), result.triggerEvent().id());
			return;
		}

		log.info("Recorded trigger event: id={} source={} externalEventId={} sha256={}",
				result.triggerEvent().id(), request.sourceSystem(), request.externalEventId(),
				result.triggerEvent().payloadSha256());

		// TODO 3: store the blob in MinIO, persist the EvidenceItem with its storageRef and
		//         currentHash, and append the opening CustodyEvent — all in one transaction.
	}

	/**
	 * Parses and validates a message, returning {@code null} for one that can never
	 * succeed.
	 *
	 * <p><strong>Why this swallows rather than throws.</strong> With
	 * {@code enable-auto-commit=false} and {@code ack-mode=record}, an exception out of the
	 * listener leaves the offset uncommitted and the record is redelivered. That is exactly
	 * what should happen for a transient fault, and exactly the wrong thing for a malformed
	 * message: a payload that fails to parse will fail identically forever, and the retry
	 * loop blocks every later message on that partition behind it. So a poison message is
	 * logged and skipped, while genuine faults from {@code recordIfAbsent} are still
	 * allowed to propagate and be retried.
	 *
	 * <p>Skipping is not free — a dropped alert is a gap in the readiness record, which is
	 * precisely what this system exists to prevent. The log line is a stopgap.
	 *
	 * <p>TODO: route these to a dead-letter topic via {@code DefaultErrorHandler} +
	 * {@code DeadLetterPublishingRecoverer} so a malformed alert is retained for review
	 * rather than surviving only as a log entry.
	 */
	private TriggerEventIngestRequest parse(String payload, int partition, long offset) {
		EvidenceEventMessage message;
		try {
			message = objectMapper.readValue(payload, EvidenceEventMessage.class);
		} catch (JacksonException ex) {
			log.error("Unparseable evidence event skipped: partition={} offset={} reason={}",
					partition, offset, ex.getOriginalMessage());
			return null;
		}

		// The raw payload, not the re-serialised message: the digest has to describe what
		// actually arrived, and a round trip through the parser is free to change it.
		TriggerEventIngestRequest request = new TriggerEventIngestRequest(
				message.eventId(),
				message.sourceSystem(),
				message.triggerType(),
				message.firedAt(),
				payload);

		Set<ConstraintViolation<TriggerEventIngestRequest>> violations = validator.validate(request);
		if (!violations.isEmpty()) {
			log.error("Invalid evidence event skipped: partition={} offset={} violations={}",
					partition, offset,
					violations.stream().map(v -> v.getPropertyPath() + " " + v.getMessage()).toList());
			return null;
		}
		return request;
	}
}
