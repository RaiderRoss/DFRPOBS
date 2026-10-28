package za.co.dfraas.resource;

import java.util.List;
import java.util.UUID;

import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import za.co.dfraas.dto.CustodyChainVerification;
import za.co.dfraas.dto.CustodyEventDto;
import za.co.dfraas.mapper.CustodyEventMapper;
import za.co.dfraas.service.CustodyChainService;

/**
 * HTTP API for reading an artifact's chain of custody — the ledger itself, and whether it
 * still agrees with itself.
 *
 * <p><strong>Read-only, and deliberately so.</strong> Nothing here appends: a custody entry
 * is written by the action it records, in that action's transaction, and an endpoint that
 * accepted one directly would be a way of asserting that something happened to an exhibit
 * without it having happened. The writers that exist are the ingest path ({@code CREATED}),
 * the integrity check ({@code HASH_VERIFIED} / {@code HASH_MISMATCH}) and the verified
 * export ({@code EXPORTED}, or {@code HASH_MISMATCH} when it refuses); each lives beside the
 * operation it describes.
 *
 * <p><strong>Two endpoints, not one.</strong> The chain and its verification are separate
 * answers and are kept in separate responses, so that what the ledger says and whether it
 * can be believed are never blended. A listing annotated with "this entry does not verify"
 * would be making a judgement that belongs with the reader, and a listing that refused to
 * show a broken chain would hide the rows an investigation most needs. The chain comes back
 * whole; verification is asked for on its own.
 *
 * <p>Nested under the item rather than at {@code /api/custody-events}, because a custody
 * entry has no meaning apart from the artifact it belongs to and no legitimate cross-item
 * query exists yet.
 */
@RestController
@RequestMapping("/api/evidence-items/{id}/custody")
@Tag(name = "Chain of custody",
		description = """
				The append-only, hash-chained ledger of everything done to a preserved artifact, and \
				the verification that walks it. Read-only: entries are written by the actions they \
				record, never posted here. Publishes every entry's digests so the chain can be \
				recomputed and checked independently of this system.
				""")
public class CustodyResource {

	private final CustodyChainService service;
	private final CustodyEventMapper mapper;

	public CustodyResource(CustodyChainService service, CustodyEventMapper mapper) {
		this.service = service;
		this.mapper = mapper;
	}

	/**
	 * The chain in ledger order. A plain list rather than a page, for the reason the
	 * repository gives: a chain is bounded by how often one artifact is handled, and a
	 * verification-grade record cannot be read with gaps between pages taken on trust.
	 */
	@Operation(
			summary = "Read an artifact's chain of custody",
			description = """
					Every custody entry for the artifact, in sequence order from the opening CREATED \
					entry. Returned exactly as the ledger holds it, unverified — call /verification \
					for whether the chain still agrees with itself. An artifact with no entries at \
					all returns an empty list, which is a finding, not a normal state.
					""")
	@ApiResponse(responseCode = "200", description = "The artifact's custody entries, in sequence order")
	@ApiResponse(responseCode = "401", description = "Missing or invalid credentials", content = @Content)
	@ApiResponse(responseCode = "404", description = "No evidence item with that id",
			content = @Content(mediaType = "application/problem+json",
					schema = @Schema(implementation = ProblemDetail.class)))
	@GetMapping
	public ResponseEntity<List<CustodyEventDto>> chain(
			@Parameter(description = "Evidence item id", example = "c4d1f7a2-33b8-4e19-9a06-5f2b8e4c1d73")
			@PathVariable("id") UUID id) {
		return ResponseEntity.ok(mapper.toDtoList(service.chainOf(id)));
	}

	/**
	 * Walks the chain from the genesis hash and reports the first place it stops agreeing
	 * with itself.
	 *
	 * <p>Always 200, whatever the chain looks like. A broken chain is a successful
	 * verification with a negative finding, and the body says where; a 4xx would tell an
	 * HTTP client the <em>request</em> failed, which it did not. The one 404 is for an id that
	 * names no item at all — which is distinct from an item with no chain, and the service
	 * keeps the two apart on purpose.
	 */
	@Operation(
			summary = "Verify an artifact's chain of custody",
			description = """
					Recomputes every entry's digest from its stored contents and checks each link \
					against the one before it, from a fixed genesis value. Reports intact or the \
					first divergent position. Detects interior edits, reorderings and deleted middle \
					entries; does not detect truncation of the chain's end — witness headEntryHash \
					outside this system for that. Always 200; the finding is in the body.
					""")
	@ApiResponse(responseCode = "200", description = "The verification result, intact or not")
	@ApiResponse(responseCode = "401", description = "Missing or invalid credentials", content = @Content)
	@ApiResponse(responseCode = "404", description = "No evidence item with that id",
			content = @Content(mediaType = "application/problem+json",
					schema = @Schema(implementation = ProblemDetail.class)))
	@GetMapping("/verification")
	public ResponseEntity<CustodyChainVerification> verify(
			@Parameter(description = "Evidence item id", example = "c4d1f7a2-33b8-4e19-9a06-5f2b8e4c1d73")
			@PathVariable("id") UUID id) {
		return ResponseEntity.ok(service.verify(id));
	}
}
