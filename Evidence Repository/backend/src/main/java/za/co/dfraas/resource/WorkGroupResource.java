package za.co.dfraas.resource;

import java.net.URI;
import java.util.List;
import java.util.UUID;

import jakarta.validation.Valid;

import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
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
@Tag(name = "Work groups",
		description = """
				Classification units that evidence is filed against. Create and read only — a \
				work group is referenced by evidence that may outlive the investigation, so \
				update and delete wait on the soft-delete and custody semantics.
				""")
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
	@Operation(
			summary = "List work groups, or resolve one by classification code",
			description = """
					With no parameter, returns every work group. With classificationCode, returns \
					a single-element list containing that one — the code is a filter rather than a \
					second path segment, so it does not become a second identifier for the same \
					resource.
					""")
	@ApiResponse(responseCode = "200", description = "Matching work groups")
	@ApiResponse(responseCode = "401", description = "Missing or invalid credentials", content = @Content)
	@ApiResponse(responseCode = "404", description = "No work group carries that classification code",
			content = @Content(mediaType = "application/problem+json",
					schema = @Schema(implementation = ProblemDetail.class)))
	@GetMapping
	public ResponseEntity<List<WorkGroupDto>> list(
			@Parameter(description = "Return only the work group with this code. Omit to list all.",
					example = "ONLINE_BANKING")
			@RequestParam(name = "classificationCode", required = false) String classificationCode) {
		if (classificationCode != null) {
			return ResponseEntity.ok(List.of(service.findByClassificationCode(classificationCode)));
		}
		return ResponseEntity.ok(service.findAll());
	}

	@Operation(summary = "Fetch one work group by id")
	@ApiResponse(responseCode = "200", description = "The work group")
	@ApiResponse(responseCode = "401", description = "Missing or invalid credentials", content = @Content)
	@ApiResponse(responseCode = "404", description = "No work group with that id",
			content = @Content(mediaType = "application/problem+json",
					schema = @Schema(implementation = ProblemDetail.class)))
	@GetMapping("/{id}")
	public ResponseEntity<WorkGroupDto> get(
			@Parameter(description = "Work group id", example = "8c1d4f60-5a72-4a3b-9f28-0e6b1d2c4a55")
			@PathVariable("id") UUID id) {
		return ResponseEntity.ok(service.findById(id));
	}

	@Operation(
			summary = "Create a work group",
			description = """
					The id and createdAt are assigned by the system and must not be supplied — \
					accepting either would let a caller choose the primary key or backdate an \
					audited row. Responds with Location pointing at the new resource.
					""")
	@ApiResponse(responseCode = "201", description = "Created; Location header carries the new resource URI")
	@ApiResponse(responseCode = "400", description = "Validation failed; fieldErrors names the offending fields",
			content = @Content(mediaType = "application/problem+json",
					schema = @Schema(implementation = ProblemDetail.class)))
	@ApiResponse(responseCode = "401", description = "Missing or invalid credentials", content = @Content)
	@ApiResponse(responseCode = "409", description = "That classification code is already taken",
			content = @Content(mediaType = "application/problem+json",
					schema = @Schema(implementation = ProblemDetail.class)))
	@PostMapping
	public ResponseEntity<WorkGroupDto> create(
			@Valid @RequestBody WorkGroupCreateRequest request,

			// Injected by Spring MVC to build the Location header; hidden so springdoc does not
			// advertise it as something the caller supplies.
			@Parameter(hidden = true) UriComponentsBuilder uriBuilder) {

		WorkGroupDto created = service.create(request);
		URI location = uriBuilder.path("/api/work-groups/{id}").buildAndExpand(created.id()).toUri();
		return ResponseEntity.created(location).body(created);
	}
}
