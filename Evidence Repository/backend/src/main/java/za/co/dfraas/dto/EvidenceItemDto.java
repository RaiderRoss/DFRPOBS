package za.co.dfraas.dto;

import java.time.OffsetDateTime;
import java.util.UUID;

import io.swagger.v3.oas.annotations.media.Schema;
import za.co.dfraas.entity.EvidenceStatus;

/**
 * Read model for {@link za.co.dfraas.entity.EvidenceItem}.
 *
 * <p><strong>Carries {@code currentHash} but not {@code storageRef}</strong>, which is the
 * split {@code WorkGroupDto} warned about when it said a single shared DTO is how one or the
 * other reaches a response body by accident. The digest is exactly what a caller needs — it
 * is how the collector confirms that what this system preserved is what it sent, and how
 * anyone holding a copy later proves it is the same bytes, the same role
 * {@code TriggerEventDto.payloadSha256} plays for alerts. The object key is the opposite: it
 * is deployment detail, it is the one pointer from metadata to the bytes themselves, and
 * publishing it invites a reader to go round the API to the bucket, where nothing
 * re-verifies integrity or writes an access log.
 *
 * <p>Nor are the bytes here, in any form. Retrieving evidence is a separate operation behind
 * the OTP step-up {@code SecurityConfiguration} reserves for it.
 */
@Schema(name = "EvidenceItem",
		description = """
				A preserved artifact. Carries the digest this repository computed and holds, so a \
				caller can verify a copy, but never the storage key or the bytes — retrieval is a \
				separate, step-up-authenticated operation.
				""")
public record EvidenceItemDto(

		@Schema(description = "Identifier assigned by this repository on preservation",
				example = "c4d1f7a2-33b8-4e19-9a06-5f2b8e4c1d73")
		UUID id,

		@Schema(description = """
				Classification this artifact was preserved under, snapshotted from the source at \
				ingest. Reclassifying the source later does not change it.
				""",
				example = "8c1d4f60-5a72-4a3b-9f28-0e6b1d2c4a55")
		UUID workGroupId,

		@Schema(description = "The registered collector that produced it, or null if preserved by hand",
				example = "5b9c2e14-7a08-4d63-9f5a-1c3e8b7d2049")
		UUID evidenceSourceId,

		@Schema(description = "The producer's own identifier for this artifact",
				example = "firewall_20260905143000")
		String sourceArtifactId,

		@Schema(description = "Start of the coverage window the source asserted",
				example = "2026-09-05T14:30:00Z")
		OffsetDateTime eventStart,

		@Schema(description = "End of the coverage window the source asserted",
				example = "2026-09-05T14:30:30Z")
		OffsetDateTime eventEnd,

		@Schema(description = """
				Lower-case hex SHA-256 this repository computed from the bytes it received and \
				re-verified after storing them. Compare it against the source's own digest to \
				confirm the artifact arrived intact.
				""",
				example = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
		String currentHash,

		@Schema(description = """
				PRESERVED (stored, hashed and accounted for), COMPROMISED (a re-verification found \
				a mismatch), ARCHIVED, or DELETED (the soft delete — evidence is never removed).
				""",
				example = "PRESERVED")
		EvidenceStatus status,

		@Schema(description = "When this repository preserved the artifact, stamped by the database clock",
				example = "2026-09-05T14:30:34.221Z")
		OffsetDateTime createdAt) {
}
