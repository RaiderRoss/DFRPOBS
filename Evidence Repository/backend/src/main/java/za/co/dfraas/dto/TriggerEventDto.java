package za.co.dfraas.dto;

import java.time.OffsetDateTime;
import java.util.UUID;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * Read model for {@link za.co.dfraas.entity.TriggerEvent}.
 *
 * <p>Carries {@code payloadSha256} but <em>not</em> {@code payload}. The digest is enough
 * to prove a caller holds the same bytes the system stored, whereas the body itself can
 * contain account numbers, customer identifiers, or the attacker's own input — none of
 * which belongs in a list response. Retrieving the raw alert is a separate, deliberately
 * separate, operation.
 */
@Schema(name = "TriggerEvent",
		description = """
				An alert recorded from a source system. The raw payload is deliberately absent — \
				payloadSha256 is enough to prove a copy obtained elsewhere is the same bytes this \
				system stored, without putting customer identifiers in a list response.
				""")
public record TriggerEventDto(

		@Schema(description = "Identifier assigned by this repository on ingest",
				example = "3f2a1c8e-9b4d-4e57-8a10-2c6f0d5b7e91")
		UUID id,

		@Schema(description = "The issuing system's own identifier for the alert. Unique only within sourceSystem.",
				example = "EVT-100294")
		String externalEventId,

		@Schema(description = "System that raised the alert", example = "fineract")
		String sourceSystem,

		@Schema(description = "Kind of alert the source raised", example = "LOAN_DISBURSEMENT")
		String triggerType,

		@Schema(description = "When the source says the alert fired. Sender-asserted — never used for ordering.",
				example = "2026-09-03T08:14:22Z")
		OffsetDateTime firedAt,

		@Schema(description = "When this system recorded the alert. Stamped here, and what listings sort on.",
				example = "2026-09-03T08:14:23.481Z")
		OffsetDateTime receivedAt,

		@Schema(description = "Lowercase hex SHA-256 of the raw payload, computed on ingest",
				example = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
		String payloadSha256) {
}
