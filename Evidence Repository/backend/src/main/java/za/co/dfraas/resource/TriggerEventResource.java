package za.co.dfraas.resource;

import java.util.UUID;

import org.springdoc.core.annotations.ParameterObject;
import org.springframework.data.domain.Page;
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
import za.co.dfraas.dto.TriggerEventDto;
import za.co.dfraas.service.TriggerEventService;

/**
 * HTTP API for trigger events.
 *
 * <p><strong>Read-only, and that is the design.</strong> A trigger event records something
 * that happened to the system; it is not something a client asks for. The only write path
 * is {@code EvidenceEventConsumer} via
 * {@link TriggerEventService#recordIfAbsent}. Offering a {@code POST} here would let a
 * caller fabricate an alert that never fired, in a table whose entire purpose is to say
 * what really did — and it would bypass the Kafka offset semantics that make ingestion
 * idempotent.
 *
 * <p>There is also no endpoint returning the raw {@code payload}. That is a gap rather
 * than an oversight: the alert body can carry customer identifiers and the attacker's own
 * input, so retrieving it belongs behind the same OTP step-up that
 * {@code SecurityConfiguration} already reserves for evidence download. Responses here
 * carry {@code payloadSha256} instead, which is enough to verify a copy obtained through
 * that gated route.
 */
@RestController
@RequestMapping("/api/trigger-events")
@Tag(name = "Trigger events",
		description = """
				Alerts recorded from the evidence-events topic. Read-only by design: the only \
				write path is the Kafka consumer, so there is no create endpoint, and the raw \
				alert payload is never returned — responses carry its SHA-256 digest instead.
				""")
public class TriggerEventResource {

	private final TriggerEventService service;

	public TriggerEventResource(TriggerEventService service) {
		this.service = service;
	}

	/**
	 * Lists trigger events, newest first, optionally narrowed to one source system.
	 *
	 * <p>Wrapped in {@link PagedModel} rather than returning the {@code Page} directly.
	 * Serialising {@code Page} exposes Spring Data's internal structure as a public wire
	 * contract and draws a startup warning for exactly that reason; {@code PagedModel} is
	 * the stable representation.
	 *
	 * <p>Sorted on {@code receivedAt}, not {@code firedAt}. Ordering by a timestamp the
	 * sender controls would let a source with a wrong clock — or a deliberately wrong one —
	 * decide where its alerts appear in an investigator's list.
	 */
	@Operation(
			summary = "List trigger events",
			description = """
					Newest first, ordered by receivedAt — the timestamp this system stamps, not \
					the firedAt the sender asserts, so a source with a wrong clock cannot decide \
					where its alerts appear in an investigator's list.
					""")
	@ApiResponse(responseCode = "200", description = "A page of trigger events, newest first")
	@ApiResponse(responseCode = "401", description = "Missing or invalid credentials", content = @Content)
	@GetMapping
	public ResponseEntity<PagedModel<TriggerEventDto>> list(
			@Parameter(description = "Return only events issued by this source system. Omit for all sources.",
					example = "fineract")
			@RequestParam(name = "sourceSystem", required = false) String sourceSystem,

			// Without @ParameterObject springdoc flattens Pageable's bean properties into the
			// docs (offset, paged, unpaged, sort.sorted...) instead of the three query params
			// a caller actually sends.
			@ParameterObject
			@PageableDefault(size = 50, sort = "receivedAt", direction = Sort.Direction.DESC)
			Pageable pageable) {

		Page<TriggerEventDto> page = (sourceSystem != null)
				? service.findBySourceSystem(sourceSystem, pageable)
				: service.findAll(pageable);
		return ResponseEntity.ok(new PagedModel<>(page));
	}

	@Operation(
			summary = "Fetch one trigger event by its repository id",
			description = "The id assigned by this system on ingest, not the identifier the source sent.")
	@ApiResponse(responseCode = "200", description = "The trigger event")
	@ApiResponse(responseCode = "401", description = "Missing or invalid credentials", content = @Content)
	@ApiResponse(responseCode = "404", description = "No trigger event with that id",
			content = @Content(mediaType = "application/problem+json",
					schema = @Schema(implementation = ProblemDetail.class)))
	@GetMapping("/{id}")
	public ResponseEntity<TriggerEventDto> get(
			@Parameter(description = "Repository id of the trigger event",
					example = "3f2a1c8e-9b4d-4e57-8a10-2c6f0d5b7e91")
			@PathVariable("id") UUID id) {
		return ResponseEntity.ok(service.findById(id));
	}

	/**
	 * Resolves a source's own alert identifier to the stored event.
	 *
	 * <p>Both parameters are required together, because {@code externalEventId} is only
	 * unique within its issuing system — see {@code uq_trigger_event_source_external}.
	 * A lookup by external id alone has no single correct answer.
	 */
	@Operation(
			summary = "Resolve a source's own alert id to the stored event",
			description = """
					Both parameters are required together: externalEventId is unique only within \
					its issuing system, so a lookup by external id alone has no single correct \
					answer. Use this to correlate an alert in the source system with what this \
					repository recorded for it.
					""")
	@ApiResponse(responseCode = "200", description = "The trigger event")
	@ApiResponse(responseCode = "401", description = "Missing or invalid credentials", content = @Content)
	@ApiResponse(responseCode = "404", description = "That source has no event with that external id",
			content = @Content(mediaType = "application/problem+json",
					schema = @Schema(implementation = ProblemDetail.class)))
	@GetMapping("/by-external-id")
	public ResponseEntity<TriggerEventDto> getByExternalId(
			@Parameter(description = "System that issued the alert", required = true, example = "fineract")
			@RequestParam("sourceSystem") String sourceSystem,

			@Parameter(description = "The issuing system's own identifier for the alert",
					required = true, example = "EVT-100294")
			@RequestParam("externalEventId") String externalEventId) {
		return ResponseEntity.ok(service.findBySourceSystemAndExternalEventId(sourceSystem, externalEventId));
	}
}
