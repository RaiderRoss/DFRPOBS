package za.co.dfraas.dto;

import java.time.OffsetDateTime;
import java.util.UUID;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * Read model for {@link za.co.dfraas.entity.WorkGroup}.
 *
 * <p>Separate from {@link WorkGroupCreateRequest} even though the two overlap. WorkGroup
 * has nothing sensitive in it, which is exactly why the split is established here: on
 * {@code EvidenceItem}, a single shared DTO is how {@code currentHash} or {@code storageRef}
 * ends up in a response body by accident.
 */
@Schema(name = "WorkGroup", description = "A classification unit that evidence is filed against.")
public record WorkGroupDto(

		@Schema(description = "Identifier assigned by this system",
				example = "8c1d4f60-5a72-4a3b-9f28-0e6b1d2c4a55")
		UUID id,

		@Schema(description = "Human-readable name", example = "Online Banking")
		String name,

		@Schema(description = "Stable machine-readable code, SCREAMING_SNAKE_CASE", example = "ONLINE_BANKING")
		String classificationCode,

		@Schema(description = "When the work group was created", example = "2026-09-01T10:22:04Z")
		OffsetDateTime createdAt) {
}
