package za.co.dfraas.dto;

import java.util.UUID;

import io.swagger.v3.oas.annotations.media.Schema;

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
@Schema(name = "CustodyChainVerification",
		description = """
				The result of walking an artifact's chain of custody from its genesis hash. Reports \
				where the ledger stops agreeing with itself, not merely whether it does. Note what an \
				intact result does and does not prove: interior edits, reorderings and deleted middle \
				entries are detected; truncation of the chain's end is not, which is why headEntryHash \
				is returned — it is the value to witness outside this system.
				""")
public record CustodyChainVerification(

		@Schema(description = "The artifact whose chain was walked", example = "c4d1f7a2-33b8-4e19-9a06-5f2b8e4c1d73")
		UUID evidenceItemId,

		@Schema(description = "True when every entry is contiguous from 0 and every digest agrees", example = "true")
		boolean intact,

		@Schema(description = """
				True when the chain is empty. Never a legitimate state — every item gets an opening \
				entry in the transaction that creates it — so this means the item predates the ledger \
				or its chain was deleted wholesale.
				""",
				example = "false")
		boolean missingOrigin,

		@Schema(description = """
				The position at which the ledger stopped agreeing with itself, or null when it never \
				did. The expected position, not a value read from a row, so a deleted middle entry is \
				reported at the hole rather than past it.
				""",
				example = "null", nullable = true)
		Long firstDivergentSequence,

		@Schema(description = "How many entries were read, kept even when verification failed", example = "3")
		int length,

		@Schema(description = """
				The last entry's entryHash when the chain is intact, null otherwise. Witness this \
				outside the repository to detect truncation of the chain's end.
				""",
				example = "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b", nullable = true)
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
