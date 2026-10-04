package za.co.dfraas.resource;

import java.security.Principal;
import java.util.UUID;

import jakarta.validation.Valid;

import org.springdoc.core.annotations.ParameterObject;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.data.web.PagedModel;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import za.co.dfraas.dto.EvidenceLinkDto;
import za.co.dfraas.dto.LinkReviewRequest;
import za.co.dfraas.entity.LinkDisposition;
import za.co.dfraas.service.EvidenceLinkService;

/**
 * HTTP API for an incident's bundle and the review of what is in it.
 *
 * <p>Mapped at {@code /api} rather than one collection root, because the bundle is read
 * through its incident ({@code /incidents/{id}/links}) while a review acts on one link
 * ({@code /evidence-links/{id}/...}).
 *
 * <p><strong>There is no endpoint that creates or deletes a link.</strong> Links are made
 * by the correlation pass; manual linking is a separate provenance story (README open
 * question 4) and gets its own endpoint when it is built. Deletion does not exist by
 * design — an irrelevant link is dismissed, and stays.
 *
 * <p>Confirm and dismiss are two {@code POST}s rather than a {@code PATCH} of
 * {@code disposition}. They are acts with preconditions, not field edits: each succeeds only
 * on a {@code PROPOSED} link, records who did it, and cannot be undone through this API.
 */
@RestController
@RequestMapping("/api")
@Tag(name = "Evidence links",
		description = """
				The evidence gathered into each incident's bundle, and the investigator's ruling on \
				each item. The correlation pass proposes links; a person confirms or dismisses \
				them, once, with a reason. Dismissed links are kept as part of the record.
				""")
public class EvidenceLinkResource {

	private final EvidenceLinkService service;

	public EvidenceLinkResource(EvidenceLinkService service) {
		this.service = service;
	}

	/**
	 * An incident's bundle.
	 *
	 * <p><strong>Sorted on {@code linkedAt}, oldest first</strong> — the time this system
	 * made the link, not the source-asserted coverage window, for the same reason listings
	 * elsewhere avoid sender clocks. It also does something useful: late arrivals sort to
	 * the end, so an investigator returning to a bundle finds what appeared since last time
	 * where they would look for it.
	 */
	@Operation(
			summary = "List the evidence linked to an incident",
			description = """
					Oldest link first, by linkedAt — when this system made the link — so late \
					arrivals sort to the end. Each entry embeds the evidence item and its source key. \
					Filter on disposition to see what is still unreviewed.
					""")
	@ApiResponse(responseCode = "200", description = "A page of links")
	@ApiResponse(responseCode = "401", description = "Missing or invalid credentials", content = @Content)
	@ApiResponse(responseCode = "404", description = "No incident with that id",
			content = @Content(mediaType = "application/problem+json",
					schema = @Schema(implementation = ProblemDetail.class)))
	@GetMapping("/incidents/{incidentId}/links")
	public ResponseEntity<PagedModel<EvidenceLinkDto>> listForIncident(
			@Parameter(description = "Repository id of the incident",
					example = "8d2f4c1a-6b3e-4f70-9a21-5c7e0b9d3f48")
			@PathVariable("incidentId") UUID incidentId,

			@Parameter(description = "Return only links in this state. Omit for all.", example = "PROPOSED")
			@RequestParam(name = "disposition", required = false) LinkDisposition disposition,

			// Without @ParameterObject springdoc flattens Pageable's bean properties into the
			// docs instead of the three query params a caller actually sends.
			@ParameterObject
			@PageableDefault(size = 50, sort = {"linkedAt", "id"}, direction = Sort.Direction.ASC)
			Pageable pageable) {
		return ResponseEntity.ok(new PagedModel<>(service.findByIncident(incidentId, disposition, pageable)));
	}

	@Operation(summary = "Fetch one evidence link by id")
	@ApiResponse(responseCode = "200", description = "The link")
	@ApiResponse(responseCode = "401", description = "Missing or invalid credentials", content = @Content)
	@ApiResponse(responseCode = "404", description = "No link with that id",
			content = @Content(mediaType = "application/problem+json",
					schema = @Schema(implementation = ProblemDetail.class)))
	@GetMapping("/evidence-links/{id}")
	public ResponseEntity<EvidenceLinkDto> get(
			@Parameter(description = "Evidence link id") @PathVariable("id") UUID id) {
		return ResponseEntity.ok(service.findById(id));
	}

	@Operation(
			summary = "Confirm a proposed link",
			description = """
					The reviewer agrees the item belongs to this incident. Only a PROPOSED link can be \
					confirmed, and only once; the reviewer is the authenticated user.
					""")
	@ApiResponse(responseCode = "200", description = "The link, now CONFIRMED")
	@ApiResponse(responseCode = "400", description = "No reason given; fieldErrors names it",
			content = @Content(mediaType = "application/problem+json",
					schema = @Schema(implementation = ProblemDetail.class)))
	@ApiResponse(responseCode = "401", description = "Missing or invalid credentials", content = @Content)
	@ApiResponse(responseCode = "404", description = "No link with that id",
			content = @Content(mediaType = "application/problem+json",
					schema = @Schema(implementation = ProblemDetail.class)))
	@ApiResponse(responseCode = "409", description = "The link has already been reviewed",
			content = @Content(mediaType = "application/problem+json",
					schema = @Schema(implementation = ProblemDetail.class)))
	@PostMapping("/evidence-links/{id}/confirm")
	public ResponseEntity<EvidenceLinkDto> confirm(
			@Parameter(description = "Evidence link id") @PathVariable("id") UUID id,
			@Valid @RequestBody LinkReviewRequest request,
			@Parameter(hidden = true) Principal principal) {
		return ResponseEntity.ok(service.confirm(id, principal.getName(), request.reason()));
	}

	@Operation(
			summary = "Dismiss a proposed link",
			description = """
					The reviewer judges the item irrelevant to this incident. The link is kept, \
					marked DISMISSED with who, when and why — "considered and set aside" is part of \
					the investigative record. Only a PROPOSED link can be dismissed, and only once.
					""")
	@ApiResponse(responseCode = "200", description = "The link, now DISMISSED")
	@ApiResponse(responseCode = "400", description = "No reason given; fieldErrors names it",
			content = @Content(mediaType = "application/problem+json",
					schema = @Schema(implementation = ProblemDetail.class)))
	@ApiResponse(responseCode = "401", description = "Missing or invalid credentials", content = @Content)
	@ApiResponse(responseCode = "404", description = "No link with that id",
			content = @Content(mediaType = "application/problem+json",
					schema = @Schema(implementation = ProblemDetail.class)))
	@ApiResponse(responseCode = "409", description = "The link has already been reviewed",
			content = @Content(mediaType = "application/problem+json",
					schema = @Schema(implementation = ProblemDetail.class)))
	@PostMapping("/evidence-links/{id}/dismiss")
	public ResponseEntity<EvidenceLinkDto> dismiss(
			@Parameter(description = "Evidence link id") @PathVariable("id") UUID id,
			@Valid @RequestBody LinkReviewRequest request,
			@Parameter(hidden = true) Principal principal) {
		return ResponseEntity.ok(service.dismiss(id, principal.getName(), request.reason()));
	}
}
