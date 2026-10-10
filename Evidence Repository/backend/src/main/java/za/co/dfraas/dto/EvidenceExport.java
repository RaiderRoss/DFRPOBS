package za.co.dfraas.dto;

import java.util.UUID;

import za.co.dfraas.entity.EvidenceStatus;

/**
 * The outcome of an export attempt, handed from {@code IntegrityCheckService.export} to the
 * resource. Not a wire type: on release the body is the bytes themselves, and on refusal it
 * is a problem document.
 *
 * <p>A result rather than an exception for the refusal, because a refused export still
 * commits — the {@code HASH_MISMATCH} entry and the move to {@code COMPROMISED} must survive,
 * and throwing inside the transaction would roll them back. The resource turns a refusal into
 * a 422 once the service has returned.
 *
 * @param evidenceItemId   the artifact asked for
 * @param sourceArtifactId the producer's name for it, used as the download's file name; null
 *                         for a manually preserved item
 * @param released         true when the bytes matched the recorded digest and are in
 *                         {@code content}
 * @param content          the released bytes, or null when nothing was released
 * @param sha256           the digest of the bytes as read back from storage
 * @param status           the item's status after the attempt
 * @param custodyEvent     the entry this attempt appended: {@code EXPORTED} or
 *                         {@code HASH_MISMATCH}
 */
public record EvidenceExport(
		UUID evidenceItemId,
		String sourceArtifactId,
		boolean released,
		byte[] content,
		String sha256,
		EvidenceStatus status,
		CustodyEventDto custodyEvent) {
}
