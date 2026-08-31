package za.co.dfraas.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

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
public record WorkGroupCreateRequest(
		@NotBlank @Size(max = 255) String name,

		/*
		 * Matches the SCREAMING_SNAKE_CASE of the seeded codes (ONLINE_BANKING,
		 * INTERNAL_SYSTEMS). Ensures consistent case to prevent a silent classification failure.
		 */
		@NotBlank @Size(max = 64) @Pattern(regexp = "^[A-Z0-9]+(_[A-Z0-9]+)*$",
				message = "must be SCREAMING_SNAKE_CASE, e.g. ONLINE_BANKING")
		String classificationCode) {
}
