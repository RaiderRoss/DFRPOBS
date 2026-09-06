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
import za.co.dfraas.dto.EvidenceSourceCreateRequest;
import za.co.dfraas.dto.EvidenceSourceDto;
import za.co.dfraas.service.EvidenceSourceService;

/**
 * HTTP API for evidence sources — the registration half of continuous collection, and the
 * first of the two endpoints README open question 4 was waiting on.
 *
 * <p><strong>Create and read only, deliberately.</strong> There is no update endpoint even
 * though the entity has mutable-looking fields, because each of them changes something
 * different and none is a general "edit". Moving a source between work groups rewrites the
 * classification future evidence inherits while leaving every past artifact under the old
 * one; changing the cadence changes what counts as silence; and {@code lastEvidenceAt} is
 * written by ingestion, not by a client. Those are three separate operations with three
 * different audit stories, and a {@code PATCH} that quietly did any of them would be the
 * wrong precedent — the same position {@code WorkGroupResource} takes.
 *
 * <p>No delete either, for a stronger reason: every {@code EvidenceItem} a source produced
 * still points at it, and "what collected this exhibit" must stay answerable years later.
 * Retirement is {@code DECOMMISSIONED}, which is a status change rather than a deletion.
 */
@RestController
@RequestMapping("/api/evidence-sources")
@Tag(name = "Evidence sources",
		description = """
				Registered producers that stream evidence in continuously. Registration is where \
				classification is decided, so every source names a work group and every artifact \
				it produces inherits it. Create and read only — retirement is a status change, \
				never a delete, because preserved evidence still points here.
				""")
public class EvidenceSourceResource {

	private final EvidenceSourceService service;

	public EvidenceSourceResource(EvidenceSourceService service) {
		this.service = service;
	}

	/**
	 * Lists sources, or resolves exactly one when {@code sourceKey} is supplied — the same
	 * filter-rather-than-path-segment shape {@code WorkGroupResource} uses for its
	 * classification code, and for the same reason: the key is a second identifier for a
	 * resource that already has one.
	 */
	@Operation(
			summary = "List evidence sources, or resolve one by source key",
			description = """
					With no parameter, returns every registered source. With sourceKey, returns a \
					single-element list containing that one — useful for checking what a \
					collector's config file is actually pointed at before its uploads start \
					failing as 404s.
					""")
	@ApiResponse(responseCode = "200", description = "Matching sources")
	@ApiResponse(responseCode = "401", description = "Missing or invalid credentials", content = @Content)
	@ApiResponse(responseCode = "404", description = "No source is registered under that key",
			content = @Content(mediaType = "application/problem+json",
					schema = @Schema(implementation = ProblemDetail.class)))
	@GetMapping
	public ResponseEntity<List<EvidenceSourceDto>> list(
			@Parameter(description = "Return only the source registered under this key. Omit to list all.",
					example = "pde-sim-ufw-01")
			@RequestParam(name = "sourceKey", required = false) String sourceKey) {
		if (sourceKey != null) {
			return ResponseEntity.ok(List.of(service.findBySourceKey(sourceKey)));
		}
		return ResponseEntity.ok(service.findAll());
	}

	@Operation(summary = "Fetch one evidence source by id")
	@ApiResponse(responseCode = "200", description = "The evidence source")
	@ApiResponse(responseCode = "401", description = "Missing or invalid credentials", content = @Content)
	@ApiResponse(responseCode = "404", description = "No source with that id",
			content = @Content(mediaType = "application/problem+json",
					schema = @Schema(implementation = ProblemDetail.class)))
	@GetMapping("/{id}")
	public ResponseEntity<EvidenceSourceDto> get(
			@Parameter(description = "Evidence source id", example = "5b9c2e14-7a08-4d63-9f5a-1c3e8b7d2049")
			@PathVariable("id") UUID id) {
		return ResponseEntity.ok(service.findById(id));
	}

	@Operation(
			summary = "Register an evidence source",
			description = """
					One-time registration for a collector, and the point at which classification is \
					decided: the work group named here is inherited by every artifact this source \
					subsequently produces. The source starts ACTIVE. Omit expectedIntervalSeconds \
					for an event-driven source — null means silence proves nothing, and a source \
					held to a cadence it does not have becomes a permanent readiness-audit entry.
					""")
	@ApiResponse(responseCode = "201", description = "Registered; Location header carries the new resource URI")
	@ApiResponse(responseCode = "400", description = "Validation failed; fieldErrors names the offending fields",
			content = @Content(mediaType = "application/problem+json",
					schema = @Schema(implementation = ProblemDetail.class)))
	@ApiResponse(responseCode = "401", description = "Missing or invalid credentials", content = @Content)
	@ApiResponse(responseCode = "404", description = "No work group with the supplied workGroupId",
			content = @Content(mediaType = "application/problem+json",
					schema = @Schema(implementation = ProblemDetail.class)))
	@ApiResponse(responseCode = "409", description = "That source key is already registered",
			content = @Content(mediaType = "application/problem+json",
					schema = @Schema(implementation = ProblemDetail.class)))
	@PostMapping
	public ResponseEntity<EvidenceSourceDto> register(
			@Valid @RequestBody EvidenceSourceCreateRequest request,
			@Parameter(hidden = true) UriComponentsBuilder uriBuilder) {

		EvidenceSourceDto created = service.register(request);
		URI location = uriBuilder.path("/api/evidence-sources/{id}").buildAndExpand(created.id()).toUri();
		return ResponseEntity.created(location).body(created);
	}
}
