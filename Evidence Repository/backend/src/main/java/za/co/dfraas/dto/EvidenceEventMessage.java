package za.co.dfraas.dto;

import java.time.OffsetDateTime;

/**
 * The wire shape of a message on the {@code evidence-events} topic.
 *
 * <p><strong>Provisional.</strong> These field names are an assumption, not a contract —
 * the schema decision (Avro/Protobuf behind a schema registry) is still open, and this
 * record is what should be replaced when it is made. It is kept separate from
 * {@link TriggerEventIngestRequest} for exactly that reason: the wire format belongs to
 * the producer and will change, while the ingest request belongs to this service.
 *
 * <p>Note what a producer is <em>not</em> permitted to send: no digest, and no received
 * timestamp. Both are computed or stamped on this side, because neither is something a
 * sender gets to assert about evidence.
 */
public record EvidenceEventMessage(
		String eventId,
		String sourceSystem,
		String triggerType,
		OffsetDateTime firedAt) {
}
