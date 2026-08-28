package za.co.dfraas.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.support.KafkaHeaders;
import org.springframework.messaging.handler.annotation.Header;
import org.springframework.messaging.handler.annotation.Payload;
import org.springframework.stereotype.Service;

/**
 * Ingestion entry point: consumes SIEM/IDS trigger events from the {@code evidence-events}
 * topic and drives the preservation pipeline.
 *
 * <p><strong>Skeleton only.</strong> The two rules this class exists to enforce are both
 * still TODO, and both are load-bearing:
 *
 * <ol>
 *   <li><em>Idempotency.</em> Kafka delivery is at-least-once, so the same trigger event
 *       will be redelivered on rebalance or retry. Ingesting twice would create duplicate
 *       EvidenceItems and pollute the custody ledger, so the first thing this method must
 *       do is check whether {@code triggerEventId} has already been persisted and return
 *       early if so. The dedupe check and the insert must share one transaction,
 *       otherwise two consumers can both pass the check.</li>
 *   <li><em>Hash before anything else.</em> Per SecureRS, the SHA-256 of the payload is
 *       computed before any other processing touches it — that hash is what every later
 *       IntegrityCheck compares against.</li>
 * </ol>
 *
 * <p>Payload is consumed as String until the schema decision (Avro/Protobuf + schema
 * registry) is made; swap the deserializer in application.properties at that point.
 */
@Service
public class EvidenceEventConsumer {

	private static final Logger log = LoggerFactory.getLogger(EvidenceEventConsumer.class);

	@KafkaListener(topics = "${dfraas.kafka.evidence-events-topic}")
	public void onEvidenceEvent(
			@Payload String payload,
			@Header(name = KafkaHeaders.RECEIVED_KEY, required = false) String key,
			@Header(KafkaHeaders.RECEIVED_PARTITION) int partition,
			@Header(KafkaHeaders.OFFSET) long offset) {

		// The key is the partition key — currently workGroupId, pending the composite-key
		// decision noted in the README.
		log.info("Received evidence event: key={} partition={} offset={} bytes={}",
				key, partition, offset, payload.length());

		// TODO 1: parse into a TriggerEvent, then return early if triggerEventId already exists.
		// TODO 2: hash the payload (SHA-256) before any further processing.
		// TODO 3: store the blob in MinIO, persist the EvidenceItem with its storageRef and
		//         currentHash, and append the opening CustodyEvent — all in one transaction.
	}
}
