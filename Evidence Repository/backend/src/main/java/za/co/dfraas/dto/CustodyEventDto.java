package za.co.dfraas.dto;

import java.time.OffsetDateTime;
import java.util.UUID;

import io.swagger.v3.oas.annotations.media.Schema;
import za.co.dfraas.entity.CustodyAction;

/**
 * Read model for {@link za.co.dfraas.entity.CustodyEvent} — one link of an artifact's chain
 * of custody, exactly as the ledger holds it.
 *
 * <p><strong>Everything on the row is published, including both chain hashes</strong>, and
 * that is a deliberate contrast with {@link EvidenceItemDto}, which withholds the storage
 * key. A custody entry contains nothing that points round the API to the bytes; what it
 * contains is the material a reader needs to check the ledger for themselves —
 * {@code prevEntryHash} and {@code entryHash} are how an external party recomputes the chain
 * from the canonical form and confirms this system is not simply asserting it verifies, and
 * {@code entryHash} on the last entry is the value that has to be witnessed outside this
 * database to close the truncation gap the README describes. A custody record that hid its
 * own digests would be asking to be trusted, which is the one thing it exists to avoid.
 *
 * <p>Both clocks are carried, for the same reason the schema keeps both:
 * {@code occurredAt} is the application's claim and is inside the digest, {@code recordedAt}
 * is the database's account and is not, and the gap between them is a signal a reader should
 * be able to see.
 */
@Schema(name = "CustodyEvent",
		description = """
				One entry in an artifact's chain of custody. Entries are append-only and hash-chained: \
				entryHash is a digest over this entry's contents and prevEntryHash is the preceding \
				entry's entryHash, so the whole chain can be recomputed and checked by anyone holding \
				it. The first entry is always CREATED, at sequence 0, with a prevEntryHash of 64 zeros.
				""")
public record CustodyEventDto(

		@Schema(description = "Identifier of this ledger entry. Not part of the digest.",
				example = "7d3e9a10-4b2c-4f61-8e5a-9c0d1b2e3f47")
		UUID id,

		@Schema(description = "The artifact whose chain this entry belongs to",
				example = "c4d1f7a2-33b8-4e19-9a06-5f2b8e4c1d73")
		UUID evidenceItemId,

		@Schema(description = "Position within the artifact's chain, contiguous from 0", example = "0")
		long sequence,

		@Schema(description = """
				What happened. CREATED (the opening entry, written when the artifact was preserved), \
				HASH_VERIFIED (a re-verification recomputed the stored object's digest and it matched), \
				or HASH_MISMATCH (it did not, and the item was marked COMPROMISED).
				""",
				example = "CREATED")
		CustodyAction action,

		@Schema(description = "Authenticated principal the action is attributed to, or null for the ingestion pipeline",
				example = "j.mokoena")
		String performedBy,

		@Schema(description = """
				When the action happened, as stated by the application and covered by entryHash. UTC, \
				microsecond precision.
				""",
				example = "2026-09-05T14:30:34.221000Z")
		OffsetDateTime occurredAt,

		@Schema(description = """
				When the database received this entry, stamped by its own clock and outside the digest. \
				A large gap between this and occurredAt is a backfill or a fabrication.
				""",
				example = "2026-09-05T14:30:34.223417Z")
		OffsetDateTime recordedAt,

		@Schema(description = """
				The artifact's digest before the action, or null if the action did not concern the \
				bytes. On HASH_VERIFIED and HASH_MISMATCH this is the digest that was expected.
				""",
				example = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
		String artifactHashBefore,

		@Schema(description = """
				The artifact's digest after the action. On CREATED, the digest computed at ingest; on \
				HASH_VERIFIED and HASH_MISMATCH, the digest observed when the stored object was re-hashed.
				""",
				example = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
		String artifactHashAfter,

		@Schema(description = "The preceding entry's entryHash, or 64 zeros at sequence 0",
				example = "0000000000000000000000000000000000000000000000000000000000000000")
		String prevEntryHash,

		@Schema(description = "SHA-256 over prevEntryHash and this entry's canonical form",
				example = "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b")
		String entryHash,

		@Schema(description = "Which frozen canonical form entryHash was computed under", example = "1")
		short canonicalVersion,

		@Schema(description = "Free-text account of the action, for a person to read",
				example = "Preserved by streamed ingestion from source pde-sim-ufw-01 as artifact firewall_2026")
		String detail) {
}
