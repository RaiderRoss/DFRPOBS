package za.co.dfraas.dto;

import java.util.UUID;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * Write model for registering an {@link za.co.dfraas.entity.EvidenceSource}.
 *
 * <p>Registration is a deliberate human act rather than something a collector does for
 * itself on first contact, and this body is shaped to keep it that way. It is where
 * classification is decided (README open question 1): a person who knows which business
 * unit the collected system belongs to names the work group once, and every artifact the
 * source subsequently produces inherits it.
 *
 * <p>Carries no {@code id}, {@code registeredAt} or {@code lastEvidenceAt} — all three are
 * the system's to assign — and no {@code status} either. A source is registered because it
 * is expected to produce, so it starts {@code ACTIVE}; suspending or decommissioning one is
 * a later decision about a source that already exists, and belongs to an endpoint that says
 * so rather than to a field on the registration body.
 *
 * <p>The {@code Size} limits mirror the column widths in changeset {@code 0004}, so an
 * over-long value fails as a 400 naming the field rather than as a 500 out of the driver.
 */
@Schema(name = "EvidenceSourceCreateRequest",
		description = """
				Body for registering an evidence source. No id, registeredAt, lastEvidenceAt or \
				status — all are assigned by the system, and a source is registered ACTIVE because \
				registration is the statement that it is expected to produce.
				""")
public record EvidenceSourceCreateRequest(

		/*
		 * Lower-case, because this value has to match byte for byte what a collector puts on
		 * the wire. "PDE-Sim-UFW-01" registered against "pde-sim-ufw-01" ingesting is a 404 on
		 * every upload rather than an obvious error, and the failure looks like a missing
		 * source instead of a typo. Same reasoning as WorkGroupCreateRequest's
		 * SCREAMING_SNAKE_CASE rule, applied to the other case.
		 */
		@Schema(description = """
				Stable key the collector puts on the wire, assigned here at registration. \
				Lower-case, separated by . - or _, and unique across all sources.
				""",
				example = "pde-sim-ufw-01", maxLength = 255, pattern = "^[a-z0-9]+([._-][a-z0-9]+)*$")
		@NotBlank @Size(max = 255)
		@Pattern(regexp = "^[a-z0-9]+([._-][a-z0-9]+)*$",
				message = "must be lower-case and separated by . - or _, e.g. pde-sim-ufw-01")
		String sourceKey,

		@Schema(description = "Human-readable name, for an investigator reading a bundle",
				example = "PDE testbed firewall (ufw)", maxLength = 255)
		@NotBlank @Size(max = 255) String displayName,

		@Schema(description = """
				Work group every artifact this source produces is classified under. Mandatory: a \
				source whose evidence cannot be classified has no defensible retention or release \
				policy, so registering it would record a promise the system cannot keep.
				""",
				example = "8c1d4f60-5a72-4a3b-9f28-0e6b1d2c4a55")
		@NotNull UUID workGroupId,

		/*
		 * Free-form by design — the set is whatever the institution actually runs, and adding a
		 * collector must not require a migration — but case-constrained, so FIREWALL and
		 * firewall do not become two source types that nothing can group by.
		 */
		@Schema(description = "What kind of collector this is. Free-form, SCREAMING_SNAKE_CASE.",
				example = "FIREWALL", maxLength = 64, pattern = "^[A-Z0-9]+(_[A-Z0-9]+)*$")
		@NotBlank @Size(max = 64)
		@Pattern(regexp = "^[A-Z0-9]+(_[A-Z0-9]+)*$",
				message = "must be SCREAMING_SNAKE_CASE, e.g. FIREWALL or DB_AUDIT")
		String sourceType,

		/*
		 * Null is a meaningful answer here rather than a missing one, which is why there is no
		 * @NotNull: it says "event-driven, silence proves nothing". A source captured by hand —
		 * the PDE console being the example in front of us — has no cadence, and holding it to
		 * one would put it permanently in the silent-sources report.
		 */
		@Schema(description = """
				How often this source is expected to produce, in seconds. Omit it for an \
				event-driven source: null means silence proves nothing, and a source held to a \
				cadence it does not have becomes a permanent entry in the readiness audit.
				""",
				example = "3600", minimum = "1")
		@Positive Integer expectedIntervalSeconds) {
}
