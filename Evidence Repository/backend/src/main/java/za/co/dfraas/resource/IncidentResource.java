package za.co.dfraas.resource;

import java.util.UUID;

import org.springdoc.core.annotations.ParameterObject;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.data.web.PagedModel;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import za.co.dfraas.dto.IncidentDto;
import za.co.dfraas.dto.TriggerEventDto;
import za.co.dfraas.service.IncidentService;

/**
 * HTTP API for incidents — what an investigator works from.
 *
 * <p>Read-only, like {@code TriggerEventResource} and for the same reason: an incident is
 * opened by alerts arriving, not by a client asking. The evidence bundle is served by
 * {@code EvidenceLinkResource} at {@code /api/incidents/{id}/links}, beside the review
 * endpoints that act on it.
 */
@RestController
@RequestMapping("/api/incidents")
@Tag(name = "Incidents",
		description = """
				Alerts grouped by the source that raised them — one incident per attack rather than \
				one per re-alert — each with one evidence bundle and one correlation state. \
				Read-only: incidents are opened by alerts arriving over Kafka.
				""")
public class IncidentResource {

	private final IncidentService service;

	public IncidentResource(IncidentService service) {
		this.service = service;
	}

	/**
	 * Newest first by {@code openedAt}, this system's clock — not the sender-asserted fire
	 * times, for the reason {@code TriggerEventResource.list} gives.
	 */
	@Operation(summary = "List incidents",
			description = "Newest first by openedAt, the time this system opened the incident.")
	@ApiResponse(responseCode = "200", description = "A page of incidents")
	@ApiResponse(responseCode = "401", description = "Missing or invalid credentials", content = @Content)
	@GetMapping
	public ResponseEntity<PagedModel<IncidentDto>> list(
			@Parameter(description = "Return only incidents from this source system. Omit for all.",
					example = "pde-sim-slips-01")
			@RequestParam(name = "sourceSystem", required = false) String sourceSystem,

			@ParameterObject
			@PageableDefault(size = 50, sort = "openedAt", direction = Sort.Direction.DESC)
			Pageable pageable) {
		return ResponseEntity.ok(new PagedModel<>(service.findAll(sourceSystem, pageable)));
	}

	@Operation(summary = "Fetch one incident by id")
	@ApiResponse(responseCode = "200", description = "The incident")
	@ApiResponse(responseCode = "401", description = "Missing or invalid credentials", content = @Content)
	@ApiResponse(responseCode = "404", description = "No incident with that id",
			content = @Content(mediaType = "application/problem+json",
					schema = @Schema(implementation = ProblemDetail.class)))
	@GetMapping("/{id}")
	public ResponseEntity<IncidentDto> get(
			@Parameter(description = "Incident id") @PathVariable("id") UUID id) {
		return ResponseEntity.ok(service.findById(id));
	}

	@Operation(summary = "List an incident's alerts",
			description = "Oldest first by receivedAt — the order this system recorded them in.")
	@ApiResponse(responseCode = "200", description = "A page of the incident's trigger events")
	@ApiResponse(responseCode = "401", description = "Missing or invalid credentials", content = @Content)
	@ApiResponse(responseCode = "404", description = "No incident with that id",
			content = @Content(mediaType = "application/problem+json",
					schema = @Schema(implementation = ProblemDetail.class)))
	@GetMapping("/{id}/trigger-events")
	public ResponseEntity<PagedModel<TriggerEventDto>> alerts(
			@Parameter(description = "Incident id") @PathVariable("id") UUID id,

			@ParameterObject
			@PageableDefault(size = 50, sort = "receivedAt", direction = Sort.Direction.ASC)
			Pageable pageable) {
		return ResponseEntity.ok(new PagedModel<>(service.findAlerts(id, pageable)));
	}
}
