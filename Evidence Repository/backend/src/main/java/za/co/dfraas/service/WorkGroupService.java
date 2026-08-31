package za.co.dfraas.service;

import java.util.List;
import java.util.UUID;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import za.co.dfraas.dto.WorkGroupCreateRequest;
import za.co.dfraas.dto.WorkGroupDto;
import za.co.dfraas.entity.WorkGroup;
import za.co.dfraas.exception.DuplicateResourceException;
import za.co.dfraas.exception.ResourceNotFoundException;
import za.co.dfraas.mapper.WorkGroupMapper;
import za.co.dfraas.repository.WorkGroupRepository;

/**
 * Business logic for work groups.
 *
 * <p>Read-only by default at the class level, with writes opting in individually. That way
 * a method added later without a {@code @Transactional} of its own cannot silently acquire
 * write access to an audited schema.
 *
 * <p>Returns DTOs, never entities: this is the layer that owns the translation, so a
 * managed entity never escapes an open transaction into the API layer.
 */
@Service
@Transactional(readOnly = true)
public class WorkGroupService {

	private static final String RESOURCE = "WorkGroup";

	private final WorkGroupRepository repository;
	private final WorkGroupMapper mapper;

	public WorkGroupService(WorkGroupRepository repository, WorkGroupMapper mapper) {
		this.repository = repository;
		this.mapper = mapper;
	}

	public List<WorkGroupDto> findAll() {
		return mapper.toDtoList(repository.findAll());
	}

	public WorkGroupDto findById(UUID id) {
		return repository.findById(id)
				.map(mapper::toDto)
				.orElseThrow(() -> ResourceNotFoundException.of(RESOURCE, id));
	}

	/**
	 * Resolves the classification string a SIEM alert carries to a work group.
	 */
	public WorkGroupDto findByClassificationCode(String classificationCode) {
		return repository.findByClassificationCode(classificationCode)
				.map(mapper::toDto)
				.orElseThrow(() -> ResourceNotFoundException.of(RESOURCE, classificationCode));
	}

	/**
	 * Creates a work group, rejecting a duplicate classification code.
	 *
	 * <p>The uniqueness rule is enforced twice, on purpose. The pre-check produces a clean
	 * 409 naming the offending field in the ordinary case; the unique index is what actually
	 * guarantees it, because two concurrent requests can both pass a pre-check before either
	 * inserts. The same check-then-act gap is the one the ingestion consumer will hit when
	 * it dedupes on {@code triggerEventId} — a unique constraint there, not just a lookup,
	 * is what will make it genuinely idempotent.
	 *
	 * <p>{@code saveAndFlush} rather than {@code save} so the INSERT is issued inside this
	 * try block; a deferred flush at commit time would throw past the catch and surface as
	 * a 500.
	 */
	@Transactional
	public WorkGroupDto create(WorkGroupCreateRequest request) {
		if (repository.existsByClassificationCode(request.classificationCode())) {
			throw DuplicateResourceException.of(RESOURCE, "classificationCode", request.classificationCode());
		}
		WorkGroup entity = mapper.toEntity(request);
		try {
			return mapper.toDto(repository.saveAndFlush(entity));
		} catch (DataIntegrityViolationException ex) {
			throw DuplicateResourceException.of(RESOURCE, "classificationCode", request.classificationCode());
		}
	}
}
