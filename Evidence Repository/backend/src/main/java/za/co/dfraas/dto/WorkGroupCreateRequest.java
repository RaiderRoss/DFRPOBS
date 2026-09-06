package za.co.dfraas.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * Write model for creating a work group.
 *
 * <p>Carries no {@code id} or {@code createdAt}: both are assigned by the system, and
 * accepting either from a client would let a caller choose the primary key or backdate an
 * audited row.
 *
 * <p>The {@code Size} limits mirror the column widths in changeset {@code 0001} so an
 * over-long value fails as a 400 with a field name, rather than as a 500 out of the JDBC
 * driver.
 */
@Schema(name = "WorkGroupCreateRequest",
		description = """
				Body for creating a work group. No id or createdAt — both are assigned by the \
				system, and accepting either would let a caller choose the primary key or \
				backdate an audited row.
				""")
public record WorkGroupCreateRequest(

		@Schema(description = "Human-readable name", example = "Online Banking", maxLength = 255)
		@NotBlank @Size(max = 255) String name,

		/*
		 * Matches the SCREAMING_SNAKE_CASE of the seeded codes (ONLINE_BANKING,
		 * INTERNAL_SYSTEMS). Ensures consistent case to prevent a silent classification failure.
		 */
		@Schema(description = "Stable machine-readable code. SCREAMING_SNAKE_CASE, and unique across work groups.",
				example = "ONLINE_BANKING", maxLength = 64, pattern = "^[A-Z0-9]+(_[A-Z0-9]+)*$")
		@NotBlank @Size(max = 64) @Pattern(regexp = "^[A-Z0-9]+(_[A-Z0-9]+)*$",
				message = "must be SCREAMING_SNAKE_CASE, e.g. ONLINE_BANKING")
		String classificationCode) {
}
