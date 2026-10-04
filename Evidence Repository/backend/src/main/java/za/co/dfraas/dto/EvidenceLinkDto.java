package za.co.dfraas.dto;

import java.time.OffsetDateTime;
import java.util.UUID;

import io.swagger.v3.oas.annotations.media.Schema;
import za.co.dfraas.entity.LinkDisposition;
import za.co.dfraas.entity.LinkMethod;

/**
 * Read model for {@link za.co.dfraas.entity.EvidenceLink}: one entry in an incident's
 * bundle.
 *
 * <p>Embeds the evidence item rather than giving only its id, because a reviewer cannot
 * rule on a link without seeing what it points at — its coverage window and source above
 * all — and a bundle screen that needed a request per row to show that would not get used.
 * The item is the same {@link EvidenceItemDto} served elsewhere, so it carries the digest
 * and never the storage key.
 *
 * <p>Method and disposition are both present and separate, for the reason
 * {@link LinkDisposition} gives: an unreviewed machine suggestion must never look like an
 * investigator's finding.
 */
@Schema(name = "EvidenceLink",
		description = """
				An evidence item gathered into an incident's bundle, with how it got there and whether \
				anyone has agreed. linkMethod says what proposed it; disposition says whether a \
				person has since confirmed or dismissed it.
				""")
public record EvidenceLinkDto(

		@Schema(description = "Identifier of the link", example = "7e3b1a90-4c2d-4f8e-b615-9d0a2c3e5f71")
		UUID id,

		@Schema(description = "The incident this link gathers evidence for",
				example = "8d2f4c1a-6b3e-4f70-9a21-5c7e0b9d3f48")
		UUID incidentId,

		@Schema(description = """
				How the link was made: CAUSAL (collected because the alert fired), AUTO_TIME_WINDOW \
				(coverage overlapped the alert's window), AUTO_RULE (a correlation rule matched), \
				or MANUAL (an investigator added it).
				""",
				example = "AUTO_TIME_WINDOW")
		LinkMethod linkMethod,

		@Schema(description = "PROPOSED (not yet reviewed), CONFIRMED, or DISMISSED (kept, never deleted)",
				example = "PROPOSED")
		LinkDisposition disposition,

		@Schema(description = "Why the link was proposed, in the words of whatever proposed it")
		String rationale,

		@Schema(description = "Who made the link. Null when the correlation pass did.", example = "null")
		String linkedBy,

		@Schema(description = "When the link was made, stamped by the database clock",
				example = "2026-09-05T14:31:02.114Z")
		OffsetDateTime linkedAt,

		@Schema(description = """
				True when a later correlation pass added this link, after the alert had already been \
				correlated once — evidence that arrived after the bundle may have been read.
				""")
		boolean lateArrival,

		@Schema(description = "Who ruled on the link. Null until reviewed.", example = "j.mokoena")
		String reviewedBy,

		@Schema(description = "When the ruling was recorded. Null until reviewed.",
				example = "2026-09-05T16:02:44Z")
		OffsetDateTime reviewedAt,

		@Schema(description = "The reviewer's stated reason. Null until reviewed.")
		String reviewNote,

		/*
		 * Flattened onto the link rather than left for the client to resolve from
		 * evidenceItem.evidenceSourceId. The source is the first thing a reviewer reads —
		 * "this is the firewall's log" — and it is fetched with the item anyway.
		 */
		@Schema(description = "Key of the source that produced the item. Null for manually preserved items.",
				example = "pde-sim-ufw-01")
		String evidenceSourceKey,

		@Schema(description = "The evidence item itself — metadata and digest, never the bytes")
		EvidenceItemDto evidenceItem) {
}
