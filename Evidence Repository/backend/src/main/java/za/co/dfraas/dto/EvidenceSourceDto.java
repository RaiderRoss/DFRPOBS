package za.co.dfraas.dto;

import java.time.OffsetDateTime;
import java.util.UUID;

import io.swagger.v3.oas.annotations.media.Schema;
import za.co.dfraas.entity.SourceStatus;

/**
 * Read model for {@link za.co.dfraas.entity.EvidenceSource}.
 *
 * <p>Exposes {@code workGroupId} rather than a nested work group. The association is
 * {@code LAZY} and {@code spring.jpa.open-in-view=false}, so returning the object itself
 * would either force a fetch-join on every read or fail outside the transaction; a caller
 * that needs the classification's name resolves it through {@code /api/work-groups/{id}}.
 *
 * <p>{@code lastEvidenceAt} is included because it is the readable half of the liveness
 * signal, and "when did we last hear from this collector" is the question the entity exists
 * to answer. It is not evidence: it is overwritten on every ingest and keeps no history.
 */
@Schema(name = "EvidenceSource",
		description = "A registered producer that streams evidence into the repository continuously.")
public record EvidenceSourceDto(

		@Schema(description = "Identifier assigned by this system",
				example = "5b9c2e14-7a08-4d63-9f5a-1c3e8b7d2049")
		UUID id,

		@Schema(description = "Stable key the collector puts on the wire", example = "pde-sim-ufw-01")
		String sourceKey,

		@Schema(description = "Human-readable name", example = "PDE testbed firewall (ufw)")
		String displayName,

		@Schema(description = "Work group every artifact from this source is classified under",
				example = "8c1d4f60-5a72-4a3b-9f28-0e6b1d2c4a55")
		UUID workGroupId,

		@Schema(description = "What kind of collector this is", example = "FIREWALL")
		String sourceType,

		@Schema(description = """
				Registration state: ACTIVE (expected to produce, and the only state in which \
				silence is a finding), SUSPENDED (deliberately paused, expected back) or \
				DECOMMISSIONED (retired; the row survives because its evidence still points here).
				""",
				example = "ACTIVE")
		SourceStatus status,

		@Schema(description = "Declared cadence in seconds, or null when the source is event-driven",
				example = "3600")
		Integer expectedIntervalSeconds,

		@Schema(description = """
				When this source last produced an item. Null until it has produced anything, at \
				which point the liveness sweep judges it from its registration instead.
				""",
				example = "2026-09-05T14:30:03Z")
		OffsetDateTime lastEvidenceAt,

		@Schema(description = "When the source was registered", example = "2026-09-01T09:12:44Z")
		OffsetDateTime registeredAt) {
}
