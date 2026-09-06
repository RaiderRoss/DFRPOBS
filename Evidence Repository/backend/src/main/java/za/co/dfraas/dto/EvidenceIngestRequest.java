package za.co.dfraas.dto;

import java.time.OffsetDateTime;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * The metadata half of an evidence upload: everything about an artifact except its bytes.
 *
 * <p>Sent as the {@code metadata} part of a multipart request alongside the file itself.
 * Two parts rather than form fields because this half is a structured document with a
 * schema — a collector generally already has it as a manifest written at capture time — and
 * because a validation failure on a JSON part surfaces as a 400 naming the field, which
 * loose form parameters do not.
 *
 * <p><strong>What a producer is not allowed to assert.</strong> There is no work group here:
 * classification is inherited from the registered source, so a collector cannot file its own
 * output under a classification nobody assigned it. There is no {@code storageRef}, because
 * where bytes land is this system's decision. There is no {@code status}, and no
 * {@code createdAt} — the database's clock stamps that, so a skewed collector cannot
 * backdate an audited row.
 *
 * <p>{@code sourceSha256} looks like an exception to that rule and is not. It is not
 * accepted <em>as</em> the artifact's digest — the digest stored is always recomputed here
 * from the bytes that arrived. It is accepted as a claim to be checked against that
 * recomputation, which is the whole point: the two agreeing is what makes "nothing happened
 * to this file between capture and preservation" a verified statement rather than a hope.
 */
@Schema(name = "EvidenceIngestRequest",
		description = """
				Metadata part of an evidence upload. Carries no work group (classification is \
				inherited from the registered source), no storage reference and no timestamps of \
				its own. sourceSha256 is a claim to be verified against the digest recomputed \
				here, never the digest that gets stored.
				""")
public record EvidenceIngestRequest(

		@Schema(description = "Key of the registered source producing this artifact",
				example = "pde-sim-ufw-01", maxLength = 255)
		@NotBlank @Size(max = 255) String sourceKey,

		/*
		 * Constrained to one safe path segment, because this value is both the dedupe key and
		 * the second half of the derived storage key. A slash would silently reorganise the
		 * bucket, and "../" would aim the write somewhere else entirely; neither is something
		 * a producer gets to decide by naming its artifact.
		 */
		@Schema(description = """
				The producer's own identifier for this artifact, unique within the source. Also \
				the idempotency key: re-sending the same artifact id is rejected as a duplicate \
				rather than preserved twice.
				""",
				example = "firewall_20260905143000", maxLength = 255,
				pattern = "^[A-Za-z0-9][A-Za-z0-9._-]*$")
		@NotBlank @Size(max = 255)
		@Pattern(regexp = "^[A-Za-z0-9][A-Za-z0-9._-]*$",
				message = "must be a single path-safe segment: letters, digits, dot, dash or underscore")
		String sourceArtifactId,

		/*
		 * Mandatory here, though the column is nullable. A null coverage window is legitimate
		 * in the schema — it describes an item that can only ever be linked to an incident by
		 * hand — but it is not legitimate for a *streamed* artifact, which knows perfectly well
		 * what interval it covers and whose whole value is being correlatable. Manual
		 * preservation is a different act and gets its own endpoint; it should not arrive here
		 * disguised as a collector that forgot to say.
		 */
		@Schema(description = """
				Start of the interval of activity this artifact covers, as asserted by the source \
				— not when it was collected. An hourly bundle rolled at 15:00 covers 14:00-15:00, \
				and this is the axis correlation runs along.
				""",
				example = "2026-09-05T14:30:00Z")
		@NotNull OffsetDateTime eventStart,

		@Schema(description = """
				End of the coverage window. Equal to eventStart for a point-in-time artifact such \
				as a memory capture or a single transaction record.
				""",
				example = "2026-09-05T14:30:30Z")
		@NotNull OffsetDateTime eventEnd,

		@Schema(description = """
				Lower-case hex SHA-256 the source computed at capture, before anything else \
				touched the file. Checked against the digest recomputed on arrival; a mismatch is \
				a 422 and nothing is preserved.
				""",
				example = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
				pattern = "^[a-f0-9]{64}$")
		@NotBlank
		@Pattern(regexp = "^[a-f0-9]{64}$", message = "must be a lower-case hex SHA-256 digest")
		String sourceSha256) {

	/**
	 * The coverage window must not end before it starts — the ordering half of
	 * {@code ck_evidence_item_coverage_window}, checked here so it fails as a 400 naming a
	 * field rather than as a 500 out of a database constraint.
	 *
	 * <p>An inverted window is not merely invalid, it is silently unanswerable: the range it
	 * describes is empty, so it would overlap no alert ever fired and the artifact would sit
	 * in the repository looking preserved while being uncorrelatable forever.
	 */
	@AssertTrue(message = "eventEnd must not be before eventStart")
	public boolean isCoverageWindowOrdered() {
		return eventStart == null || eventEnd == null || !eventEnd.isBefore(eventStart);
	}
}
