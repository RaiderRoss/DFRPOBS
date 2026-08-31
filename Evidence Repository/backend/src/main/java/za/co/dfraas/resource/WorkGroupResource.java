package za.co.dfraas.resource;

import java.net.URI;
import java.util.List;
import java.util.UUID;

import jakarta.validation.Valid;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

import za.co.dfraas.dto.WorkGroupCreateRequest;
import za.co.dfraas.dto.WorkGroupDto;
import za.co.dfraas.service.WorkGroupService;

/**
 * HTTP API for work groups.
 *
 * <p>Speaks DTOs only and delegates straight to {@link WorkGroupService} — no repository or
 * entity is reachable from here. Every endpoint is authenticated by
 * {@code SecurityConfiguration}'s catch-all rule.
 *
 * <p>No update or delete endpoint yet, and that is a design position rather than an
 * omission: a work group is referenced by evidence that may outlive any investigation, so
 * changing or removing one needs the soft-delete and custody semantics the README
 * describes. Adding a naive {@code DELETE} now would be the wrong precedent for the
 * entities that follow.
 */
@RestController
@RequestMapping("/api/work-groups")
public class WorkGroupResource {

	private final WorkGroupService service;

	public WorkGroupResource(WorkGroupService service) {
		this.service = service;
	}

	/**
	 * Lists all work groups, or resolves exactly one when {@code classificationCode} is
	 * supplied. Filtering rather than a second path segment keeps the code out of a URL
	 * path, where it would be a second identifier for the same resource.
	 */
	@GetMapping
	public ResponseEntity<List<WorkGroupDto>> list(
			@RequestParam(name = "classificationCode", required = false) String classificationCode) {
		if (classificationCode != null) {
			return ResponseEntity.ok(List.of(service.findByClassificationCode(classificationCode)));
		}
		return ResponseEntity.ok(service.findAll());
	}

	@GetMapping("/{id}")
	public ResponseEntity<WorkGroupDto> get(@PathVariable("id") UUID id) {
		return ResponseEntity.ok(service.findById(id));
	}

	@PostMapping
	public ResponseEntity<WorkGroupDto> create(
			@Valid @RequestBody WorkGroupCreateRequest request,
			UriComponentsBuilder uriBuilder) {

		WorkGroupDto created = service.create(request);
		URI location = uriBuilder.path("/api/work-groups/{id}").buildAndExpand(created.id()).toUri();
		return ResponseEntity.created(location).body(created);
	}
}
