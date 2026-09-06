package za.co.dfraas.dto;

/**
 * Outcome of recording a trigger event.
 *
 * <p>The {@code created} flag is the whole point. Ingestion is idempotent, so a duplicate
 * delivery is a success, not an error — but the consumer still has to know the difference,
 * because only a genuinely new event should go on to be hashed, stored in MinIO and given
 * an {@code EvidenceItem}. A bare DTO return would make the two cases indistinguishable.
 */
public record TriggerEventIngestResult(TriggerEventDto triggerEvent, boolean created) {
}
