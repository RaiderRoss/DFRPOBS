package za.co.dfraas.mapper;

import java.util.List;

import org.springframework.stereotype.Component;

import za.co.dfraas.dto.WorkGroupCreateRequest;
import za.co.dfraas.dto.WorkGroupDto;
import za.co.dfraas.entity.WorkGroup;

/**
 * Translation between {@link WorkGroup} and its DTOs.
 *
 * <p>Hand-written rather than generated. At this size a mapping framework would add a
 * build step without removing meaningful work, and the explicit version makes it obvious
 * which fields are deliberately not exposed.
 */
@Component
public class WorkGroupMapper {

	public WorkGroupDto toDto(WorkGroup entity) {
		return new WorkGroupDto(
				entity.getId(),
				entity.getName(),
				entity.getClassificationCode(),
				entity.getCreatedAt());
	}

	public List<WorkGroupDto> toDtoList(List<WorkGroup> entities) {
		return entities.stream().map(this::toDto).toList();
	}

	/**
	 * Maps only the two client-supplied fields; {@code id} and {@code createdAt} are left
	 * unset so Hibernate and the database default assign them respectively.
	 */
	public WorkGroup toEntity(WorkGroupCreateRequest request) {
		WorkGroup entity = new WorkGroup();
		entity.setName(request.name());
		entity.setClassificationCode(request.classificationCode());
		return entity;
	}
}
