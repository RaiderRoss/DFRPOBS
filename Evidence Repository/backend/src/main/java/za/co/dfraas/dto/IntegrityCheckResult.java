package za.co.dfraas.dto;

import java.util.UUID;

import io.swagger.v3.oas.annotations.media.Schema;
import za.co.dfraas.entity.EvidenceStatus;

/**
 * The outcome of re-verifying one preserved artifact against the digest recorded for it.
 *
 * <p>Both digests are published, and on a mismatch that is the point: the caller asked
 * whether the bytes in storage are still the bytes that were preserved, and "no" without
 * "what are they now" is a finding nobody can act on. This is a success response for a check
 * that ran, so {@code ApiExceptionHandler}'s rule about digests in <em>error</em> bodies does
 * not apply — and the same values are in the custody entry this check appended, which is
 * readable on its own endpoint.
 *
 * <p>{@code custodyEvent} is the entry the check appended, returned whole rather than by
 * sequence so a caller does not need a second request to see the durable record of what
 * they just did.
 *
 * @param evidenceItemId the artifact that was checked
 * @param intact         true when the recomputed digest equals {@code expectedHash}
 * @param expectedHash   {@code EvidenceItem.currentHash} at the time of the check — what the
 *                       object should have hashed to
 * @param observedHash   what the object read back from storage did hash to
 * @param status         the item's status after the check: unchanged when intact, and
 *                       {@code COMPROMISED} after a mismatch. Carried because the check is
 *                       the one thing in this system that moves an item into that state
 * @param custodyEvent   the {@code HASH_VERIFIED} or {@code HASH_MISMATCH} entry this check
 *                       appended to the item's chain
 */
@Schema(name = "IntegrityCheckResult",
		description = """
				The outcome of re-hashing a preserved artifact's stored object and comparing it with \
				the digest this repository recorded at ingest. Always accompanied by a new custody \
				entry, returned here, recording what was found.
				""")
public record IntegrityCheckResult(

		@Schema(description = "The artifact that was checked", example = "c4d1f7a2-33b8-4e19-9a06-5f2b8e4c1d73")
		UUID evidenceItemId,

		@Schema(description = "True when the stored object still hashes to the recorded digest", example = "true")
		boolean intact,

		@Schema(description = "The digest the artifact was expected to have — currentHash at the time of the check",
				example = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
		String expectedHash,

		@Schema(description = "The digest recomputed from the object as read back from storage",
				example = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
		String observedHash,

		@Schema(description = "The item's status after the check. COMPROMISED after a mismatch, otherwise unchanged.",
				example = "PRESERVED")
		EvidenceStatus status,

		@Schema(description = "The custody entry this check appended")
		CustodyEventDto custodyEvent) {
}
