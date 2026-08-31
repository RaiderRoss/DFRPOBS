package za.co.dfraas.dto;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * Read model for {@link za.co.dfraas.entity.WorkGroup}.
 *
 * <p>Separate from {@link WorkGroupCreateRequest} even though the two overlap. WorkGroup
 * has nothing sensitive in it, which is exactly why the split is established here: on
 * {@code EvidenceItem}, a single shared DTO is how {@code currentHash} or {@code storageRef}
 * ends up in a response body by accident.
 */
public record WorkGroupDto(UUID id, String name, String classificationCode, OffsetDateTime createdAt) {
}
