package za.co.dfraas.service;

import java.util.List;
import java.util.UUID;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import za.co.dfraas.dto.EvidenceSourceCreateRequest;
import za.co.dfraas.dto.EvidenceSourceDto;
import za.co.dfraas.entity.EvidenceSource;
import za.co.dfraas.entity.WorkGroup;
import za.co.dfraas.exception.DuplicateResourceException;
import za.co.dfraas.exception.ResourceNotFoundException;
import za.co.dfraas.mapper.EvidenceSourceMapper;
import za.co.dfraas.repository.EvidenceSourceRepository;
import za.co.dfraas.repository.WorkGroupRepository;

/**
 * Business logic for evidence sources.
 *
 * <p>Read-only at the class level with writes opting in individually, matching
 * {@link WorkGroupService}: a method added later without a {@code @Transactional} of its own
 * cannot silently acquire write access to an audited schema.
 *
 * <p>Reads here are unpaged, unlike {@code EvidenceItemService}'s. The table is bounded —
 * one row per registered collector — so listing all of it is a fixed cost rather than one
 * that grows with the estate's output.
 */
@Service
@Transactional(readOnly = true)
public class EvidenceSourceService {

	private static final String RESOURCE = "EvidenceSource";
	private static final String WORK_GROUP_RESOURCE = "WorkGroup";

	private final EvidenceSourceRepository repository;
	private final WorkGroupRepository workGroupRepository;
	private final EvidenceSourceMapper mapper;

	/**
	 * Depends on {@link WorkGroupRepository} rather than {@code WorkGroupService} on purpose:
	 * registration needs the managed {@link WorkGroup} entity to hang the association off,
	 * and the service layer deals exclusively in DTOs, which cannot be one.
	 */
	public EvidenceSourceService(
			EvidenceSourceRepository repository,
			WorkGroupRepository workGroupRepository,
			EvidenceSourceMapper mapper) {
		this.repository = repository;
		this.workGroupRepository = workGroupRepository;
		this.mapper = mapper;
	}

	public List<EvidenceSourceDto> findAll() {
		return mapper.toDtoList(repository.findAll());
	}

	public EvidenceSourceDto findById(UUID id) {
		return repository.findById(id)
				.map(mapper::toDto)
				.orElseThrow(() -> ResourceNotFoundException.of(RESOURCE, id));
	}

	/**
	 * Resolves the key a collector puts on the wire to its registration — the same lookup
	 * ingestion performs on every upload, exposed so an operator can check what a config file
	 * is pointed at before it starts failing.
	 */
	public EvidenceSourceDto findBySourceKey(String sourceKey) {
		return repository.findBySourceKey(sourceKey)
				.map(mapper::toDto)
				.orElseThrow(() -> ResourceNotFoundException.of(RESOURCE, sourceKey));
	}

	/**
	 * Registers a source, rejecting a duplicate key and an unknown work group.
	 *
	 * <p>The uniqueness rule is enforced twice for the reason {@link WorkGroupService#create}
	 * gives: the pre-check produces a clean 409 naming the offending field, and
	 * {@code uq_evidence_source_key} is what actually guarantees it, because two concurrent
	 * registrations can both pass a pre-check before either inserts.
	 *
	 * <p>The work group is resolved rather than referenced blindly. {@code getReferenceById}
	 * would defer the check to flush time and surface a missing classification as a foreign
	 * key violation — a 500 mentioning a constraint — where the caller's actual mistake was a
	 * work group id that does not exist, which is a 404.
	 */
	@Transactional
	public EvidenceSourceDto register(EvidenceSourceCreateRequest request) {
		if (repository.existsBySourceKey(request.sourceKey())) {
			throw DuplicateResourceException.of(RESOURCE, "sourceKey", request.sourceKey());
		}
		WorkGroup workGroup = workGroupRepository.findById(request.workGroupId())
				.orElseThrow(() -> ResourceNotFoundException.of(WORK_GROUP_RESOURCE, request.workGroupId()));

		EvidenceSource entity = mapper.toEntity(request, workGroup);
		try {
			// saveAndFlush, so the INSERT is issued inside this try rather than at commit —
			// a deferred flush would throw past the catch and surface as a 500.
			return mapper.toDto(repository.saveAndFlush(entity));
		} catch (DataIntegrityViolationException ex) {
			throw DuplicateResourceException.of(RESOURCE, "sourceKey", request.sourceKey());
		}
	}
}
