package za.co.dfraas.dto;

import java.time.OffsetDateTime;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

/**
 * What the ingestion consumer extracts from a Kafka message before recording it.
 *
 * <p>Not an HTTP request body: {@code TriggerEventResource} exposes no create endpoint,
 * because a trigger event is something that happened to the system rather than something
 * a client asks for. It is still validated, though — {@code EvidenceEventConsumer} should
 * run it through a {@code Validator} so a malformed alert is rejected at the boundary
 * instead of failing later against a NOT NULL constraint.
 *
 * <p>{@code receivedAt} and {@code payloadSha256} are absent on purpose: the first is the
 * database's to stamp, the second the service's to compute. Neither is something a sender
 * gets to assert.
 *
 * <p>{@code incidentKey} is optional — null or blank files the alert as an incident of its
 * own. Sized to {@code incident.incident_key}, so an over-long key is a validation failure
 * rather than a driver error.
 */
public record TriggerEventIngestRequest(
		@NotBlank @Size(max = 255) String externalEventId,
		@NotBlank @Size(max = 255) String sourceSystem,
		@NotBlank @Size(max = 255) String triggerType,
		@NotNull OffsetDateTime firedAt,
		@NotNull String payload,
		@Size(max = 255) String incidentKey) {
}
/*
	Work Group
	Triggerevent
	User
	EvidenceItems
*/
