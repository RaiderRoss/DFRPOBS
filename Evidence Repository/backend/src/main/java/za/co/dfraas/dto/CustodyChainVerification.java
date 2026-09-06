package za.co.dfraas.dto;

import java.util.UUID;

/**
 * The outcome of walking one artifact's chain of custody.
 *
 * <p>A boolean return was the obvious shape and the wrong one. "This chain does not verify"
 * is not a usable finding — the questions immediately asked of it are <em>where</em> and
 * <em>what kind</em>, because an artifact whose ledger diverges at entry 14 of 30 has 14
 * entries that still stand, and one with no chain at all has a different problem entirely.
 * A verification that cannot say which it found leaves an investigator with nothing to act
 * on.
 *
 * <p>Two invariants, so callers need no defensive checks: {@code intact} implies
 * {@code firstDivergentSequence} is null, and {@code !intact} implies it is not.
 *
 * @param evidenceItemId        the artifact whose chain was walked
 * @param intact                true when every entry is contiguous and every digest agrees
 * @param missingOrigin         true when the chain is empty — never a legitimate state, since
 *                              every item gets an opening entry in the transaction that
 *                              creates it. Means the item predates changeset {@code 0006}, or
 *                              that its chain was deleted wholesale. Called out separately
 *                              because it is the one failure that is not a divergence between
 *                              two entries but the absence of anything to compare
 * @param firstDivergentSequence the position where the ledger stopped agreeing with itself,
 *                              or null when it never did. This is the <em>expected</em>
 *                              position rather than any value read from a row: for a deleted
 *                              middle entry the row sitting at the divergent position carries
 *                              a higher sequence than it should, and reporting that number
 *                              would point past the hole rather than at it. Zero when
 *                              {@code missingOrigin}, so a caller reporting "diverges at N"
 *                              needs no special case
 * @param length                how many entries were read. Kept even for a failed
 *                              verification: "diverges at 14" means something different in a
 *                              chain of 15 than in a chain of 400
 * @param headEntryHash         the last entry's {@code entryHash} when the chain is intact,
 *                              null otherwise. This is the value that would have to be
 *                              witnessed outside this database to close the one gap the chain
 *                              cannot close for itself — a truncation of its own end
 */
public record CustodyChainVerification(
		UUID evidenceItemId,
		boolean intact,
		boolean missingOrigin,
		Long firstDivergentSequence,
		int length,
		String headEntryHash) {

	public static CustodyChainVerification intact(UUID evidenceItemId, int length, String headEntryHash) {
		return new CustodyChainVerification(evidenceItemId, true, false, null, length, headEntryHash);
	}

	public static CustodyChainVerification missingOrigin(UUID evidenceItemId) {
		return new CustodyChainVerification(evidenceItemId, false, true, 0L, 0, null);
	}

	public static CustodyChainVerification divergedAt(UUID evidenceItemId, long sequence, int length) {
		return new CustodyChainVerification(evidenceItemId, false, false, sequence, length, null);
	}
}
