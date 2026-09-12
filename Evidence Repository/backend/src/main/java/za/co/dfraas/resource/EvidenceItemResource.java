package za.co.dfraas.resource;

import java.io.IOException;
import java.net.URI;
import java.util.UUID;

import jakarta.validation.Valid;

import org.springdoc.core.annotations.ParameterObject;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.data.web.PagedModel;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.util.UriComponentsBuilder;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import za.co.dfraas.dto.EvidenceIngestRequest;
import za.co.dfraas.dto.EvidenceItemDto;
import za.co.dfraas.service.EvidenceItemService;

/**
 * HTTP API for preserved artifacts — the ingestion half of README open question 4.
 *
 * <p><strong>Why this one accepts a write and {@code TriggerEventResource} does not.</strong>
 * An alert is something that happened to the system, so a client offering one is claiming an
 * event fired that may not have. An artifact is the opposite: it is something a registered
 * collector <em>has</em>, and preserving it is the entire purpose of a readiness system. The
 * check that matters is therefore not "may this caller assert this" but "are these the bytes
 * they say they are", which is what the service performs before anything is stored.
 *
 * <p><strong>This is the streamed path, not the manual one.</strong> Every upload names a
 * registered source and inherits that source's classification, which is what keeps a
 * producer from filing its own output under a work group nobody assigned it. Manual
 * preservation — an investigator's own copy, with no collector behind it and often no
 * coverage window — is a different act with a different provenance story, and belongs in an
 * endpoint that says so rather than in this one with fields left blank.
 *
 * <p><strong>No download endpoint here.</strong> {@code SecurityConfiguration} reserves
 * {@code /api/evidence/*&#47;download} for the OTP step-up it does not yet implement, and
 * adding a retrieval route before that exists would put evidence bytes behind nothing but a
 * password. Responses carry the digest instead, which is enough to verify a copy obtained
 * through whatever gated route lands later.
 */
@RestController
@RequestMapping("/api/evidence-items")
@Tag(name = "Evidence items",
		description = """
				Artifacts preserved from registered sources. Uploads are verified on arrival — the \
				digest the source computed at capture is checked against one recomputed here, and \
				again after storage — and deduped on the producer's own artifact id, so a re-sent \
				artifact is never preserved twice. Responses carry the digest, never the bytes or \
				the storage key.
				""")
public class EvidenceItemResource {

	private static final String DEFAULT_CONTENT_TYPE = MediaType.APPLICATION_OCTET_STREAM_VALUE;

	private final EvidenceItemService service;

	public EvidenceItemResource(EvidenceItemService service) {
		this.service = service;
	}

	/**
	 * Lists preserved artifacts, newest first, optionally narrowed to one classification.
	 *
	 * <p>Wrapped in {@link PagedModel} rather than returning the {@code Page} directly, for
	 * the reason {@code TriggerEventResource.list} gives: serialising {@code Page} publishes
	 * Spring Data's internal structure as a wire contract and draws a startup warning saying
	 * so.
	 *
	 * <p><strong>Sorted on {@code createdAt}, not {@code eventStart}.</strong> The same rule
	 * that makes trigger events order by {@code receivedAt}: {@code createdAt} is stamped by
	 * the database when this system preserved the artifact, while {@code eventStart} is the
	 * coverage window the <em>source</em> asserted. Ordering a list by a sender-controlled
	 * timestamp lets a collector with a wrong clock — or a deliberately wrong one — decide
	 * where its artifacts appear in an investigator's view.
	 */
	@Operation(
			summary = "List preserved artifacts",
			description = """
					Newest first by createdAt — the timestamp this system stamps on preservation, \
					not the eventStart the source asserts, so a collector with a wrong clock cannot \
					decide where its artifacts appear in an investigator's list. Soft-deleted items \
					are omitted unless includeDeleted is set.
					""")
	@ApiResponse(responseCode = "200", description = "A page of evidence items, newest first")
	@ApiResponse(responseCode = "401", description = "Missing or invalid credentials", content = @Content)
	@GetMapping
	public ResponseEntity<PagedModel<EvidenceItemDto>> list(
			@Parameter(description = "Return only artifacts preserved under this classification. Omit for all.",
					example = "8c1d4f60-5a72-4a3b-9f28-0e6b1d2c4a55")
			@RequestParam(name = "workGroupId", required = false) UUID workGroupId,

			@Parameter(description = """
					Include soft-deleted artifacts. Off by default, because showing them beside live \
					evidence misrepresents what is currently preserved; set it when the question is \
					what was destroyed rather than what is held.
					""")
			@RequestParam(name = "includeDeleted", defaultValue = "false") boolean includeDeleted,

			// Without @ParameterObject springdoc flattens Pageable's bean properties into the
			// docs (offset, paged, unpaged, sort.sorted...) instead of the three query params
			// a caller actually sends.
			@ParameterObject
			@PageableDefault(size = 50, sort = "createdAt", direction = Sort.Direction.DESC)
			Pageable pageable) {

		Page<EvidenceItemDto> page = service.findAll(workGroupId, includeDeleted, pageable);
		return ResponseEntity.ok(new PagedModel<>(page));
	}

	@Operation(summary = "Fetch one preserved artifact by id",
			description = "Metadata and the stored digest. The bytes are not served here.")
	@ApiResponse(responseCode = "200", description = "The evidence item")
	@ApiResponse(responseCode = "401", description = "Missing or invalid credentials", content = @Content)
	@ApiResponse(responseCode = "404", description = "No evidence item with that id",
			content = @Content(mediaType = "application/problem+json",
					schema = @Schema(implementation = ProblemDetail.class)))
	@GetMapping("/{id}")
	public ResponseEntity<EvidenceItemDto> get(
			@Parameter(description = "Evidence item id", example = "c4d1f7a2-33b8-4e19-9a06-5f2b8e4c1d73")
			@PathVariable("id") UUID id) {
		return ResponseEntity.ok(service.findById(id));
	}

	/**
	 * Preserves one artifact: two parts, a JSON {@code metadata} document and the
	 * {@code file} itself.
	 *
	 * <p>Two parts rather than form fields because the metadata is a structured document a
	 * collector usually already holds — a manifest written at capture time — and because a
	 * validation failure on a JSON part comes back naming the field that failed.
	 */
	@Operation(
			summary = "Preserve an artifact from a registered source",
			description = """
					Multipart upload with two parts: `metadata`, a JSON document typed \
					application/json, and `file`, the artifact itself. The source's own SHA-256 in \
					the metadata is checked against a digest recomputed from the received bytes \
					before anything is stored, and against the object read back afterwards; only \
					the recomputed digest is kept. Classification is inherited from the registered \
					source, so no work group is supplied.

					curl -u admin:admin http://localhost:8080/api/evidence-items \\
					-F 'metadata={"sourceKey":"pde-sim-ufw-01","sourceArtifactId":"firewall_20260905143000",\\
					"eventStart":"2026-09-05T14:30:00Z","eventEnd":"2026-09-05T14:30:30Z",\\
					"sourceSha256":"<sha256>"};type=application/json' \\
					-F 'file=@firewall_20260905143000.log'
					""")
	@ApiResponse(responseCode = "201", description = "Preserved; Location header carries the new resource URI")
	@ApiResponse(responseCode = "400", description = "Validation failed; fieldErrors names the offending fields",
			content = @Content(mediaType = "application/problem+json",
					schema = @Schema(implementation = ProblemDetail.class)))
	@ApiResponse(responseCode = "401", description = "Missing or invalid credentials", content = @Content)
	@ApiResponse(responseCode = "404", description = "No source is registered under that sourceKey",
			content = @Content(mediaType = "application/problem+json",
					schema = @Schema(implementation = ProblemDetail.class)))
	@ApiResponse(responseCode = "409", description = "That source has already delivered this artifact id",
			content = @Content(mediaType = "application/problem+json",
					schema = @Schema(implementation = ProblemDetail.class)))
	@ApiResponse(responseCode = "422",
			description = "Integrity check failed — the bytes do not match the digest the source asserted",
			content = @Content(mediaType = "application/problem+json",
					schema = @Schema(implementation = ProblemDetail.class)))
	@ApiResponse(responseCode = "503", description = "The evidence store is unreachable; the artifact was not stored",
			content = @Content(mediaType = "application/problem+json",
					schema = @Schema(implementation = ProblemDetail.class)))
	@PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
	public ResponseEntity<EvidenceItemDto> preserve(
			@Valid @RequestPart("metadata") EvidenceIngestRequest metadata,

			@Parameter(description = "The artifact itself. Sent as bytes; never interpreted here.")
			@RequestPart("file") MultipartFile file,

			// Both injected by Spring MVC and hidden so springdoc does not advertise them as
			// something the caller supplies: one builds the Location header, the other is who
			// the request authenticated as.
			@Parameter(hidden = true) UriComponentsBuilder uriBuilder,
			@Parameter(hidden = true) Authentication authentication) throws IOException {

		EvidenceItemDto preserved = service.preserve(
				metadata, file.getBytes(), contentTypeOf(file), principalOf(authentication));
		URI location = uriBuilder.path("/api/evidence-items/{id}").buildAndExpand(preserved.id()).toUri();
		return ResponseEntity.created(location).body(preserved);
	}

	/**
	 * Who this upload is attributed to in the custody chain.
	 *
	 * <p>Null-tolerant rather than asserted, matching a column that is nullable on purpose:
	 * {@code custody_event.performed_by} is null when the honest answer is "the ingestion
	 * pipeline". No route here can currently be reached unauthenticated —
	 * {@code SecurityConfiguration} ends in {@code anyRequest().authenticated()} — so this
	 * returns a principal in practice; what it refuses to do is invent one if that ever
	 * changes.
	 *
	 * <p>A username rather than a user id, because {@code AppUser} does not exist yet. It
	 * becomes a foreign key with that entity, alongside {@code EvidenceLink.linkedBy}.
	 */
	private static String principalOf(Authentication authentication) {
		return authentication == null ? null : authentication.getName();
	}

	/**
	 * The content type is recorded on the stored object for a reader's convenience and is
	 * deliberately not trusted for anything else — nothing in this system parses an artifact
	 * by it. A client that sends none gets the honest default rather than a guess made from
	 * the file's name.
	 */
	private static String contentTypeOf(MultipartFile file) {
		String contentType = file.getContentType();
		return (contentType == null || contentType.isBlank()) ? DEFAULT_CONTENT_TYPE : contentType;
	}
}
