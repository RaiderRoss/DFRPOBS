package za.co.dfraas.resource;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.startsWith;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.BDDMockito.willThrow;
import static org.mockito.Mockito.never;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.head;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMultipartHttpServletRequestBuilder;

import za.co.dfraas.config.SecurityConfiguration;
import za.co.dfraas.dto.CustodyEventDto;
import za.co.dfraas.dto.EvidenceExport;
import za.co.dfraas.dto.EvidenceItemDto;
import za.co.dfraas.dto.IntegrityCheckResult;
import za.co.dfraas.entity.CustodyAction;
import za.co.dfraas.entity.EvidenceStatus;
import za.co.dfraas.exception.DuplicateResourceException;
import za.co.dfraas.exception.EvidenceStorageException;
import za.co.dfraas.exception.IntegrityVerificationException;
import za.co.dfraas.exception.ResourceNotFoundException;
import za.co.dfraas.service.EvidenceItemService;
import za.co.dfraas.service.IntegrityCheckService;

/**
 * Web-layer contract for {@link EvidenceItemResource}: the multipart upload shape, and the
 * status codes that let a collector tell the four failures apart — a malformed request
 * (400), an unregistered source (404), an artifact already preserved (409) and bytes that
 * did not survive the trip (422). The service is mocked; what it actually verifies is
 * covered by {@code EvidenceItemServiceTest}.
 *
 * <p>Also the integrity-check endpoint's contract: a mismatch is a 200 with the finding in
 * the body, because the check ran and the evidence is what failed; only an unreachable store
 * is an error. What the check records is covered by {@code IntegrityCheckServiceTest}.
 */
@WebMvcTest(EvidenceItemResource.class)
@Import({SecurityConfiguration.class, ApiExceptionHandler.class})
@WithMockUser(roles = "INVESTIGATOR")
class EvidenceItemResourceTest {

	private static final UUID ITEM_ID = UUID.fromString("33333333-3333-3333-3333-333333333333");
	private static final UUID SOURCE_ID = UUID.fromString("22222222-2222-2222-2222-222222222222");
	private static final UUID WORK_GROUP_ID = UUID.fromString("11111111-1111-1111-1111-111111111111");
	private static final String ARTIFACT_ID = "firewall_20260905143000";

	/** SHA-256 of "hello" — a real digest, so the fixture cannot drift into nonsense. */
	private static final String CONTENT_SHA256 =
			"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

	/** SHA-256 of "goodbye" — a valid digest of the wrong bytes. */
	private static final String OTHER_SHA256 =
			"82e35a63ceba37e9646434c5dd412ea577147f1e4a41ccde1614253187e3dbf9";

	@Autowired
	private MockMvc mockMvc;

	@MockitoBean
	private EvidenceItemService service;

	@MockitoBean
	private IntegrityCheckService integrityCheckService;

	@Test
	@DisplayName("GET lists preserved artifacts as a page, not a bare array")
	void listReturnsAPageOfItems() throws Exception {
		given(service.findAll(any(), anyBoolean(), any()))
				.willReturn(new PageImpl<>(List.of(sampleDto()), PageRequest.of(0, 50), 1));

		mockMvc.perform(get("/api/evidence-items"))
				.andExpect(status().isOk())
				// PagedModel's shape, not Spring Data's Page — content plus a page descriptor.
				.andExpect(jsonPath("$.content[0].id").value(ITEM_ID.toString()))
				.andExpect(jsonPath("$.content[0].currentHash").value(CONTENT_SHA256))
				.andExpect(jsonPath("$.page.totalElements").value(1));
	}

	@Test
	@DisplayName("The listing carries the digest but never the storage reference")
	void listResponseOmitsTheStorageReference() throws Exception {
		given(service.findAll(any(), anyBoolean(), any()))
				.willReturn(new PageImpl<>(List.of(sampleDto()), PageRequest.of(0, 50), 1));

		String body = mockMvc.perform(get("/api/evidence-items"))
				.andExpect(status().isOk())
				.andReturn().getResponse().getContentAsString();

		// The same guarantee the single-item response makes. A listing is the easier place to
		// leak the object key, because it leaks one per row.
		assertThat(body.toLowerCase(Locale.ROOT)).doesNotContain("storageref");
	}

	@Test
	@DisplayName("Soft-deleted items are omitted unless the caller asks for them")
	void includeDeletedDefaultsToFalse() throws Exception {
		given(service.findAll(any(), anyBoolean(), any()))
				.willReturn(new PageImpl<>(List.of(), PageRequest.of(0, 50), 0));

		mockMvc.perform(get("/api/evidence-items")).andExpect(status().isOk());
		then(service).should().findAll(eq(null), eq(false), any());

		mockMvc.perform(get("/api/evidence-items").param("includeDeleted", "true"))
				.andExpect(status().isOk());
		then(service).should().findAll(eq(null), eq(true), any());
	}

	@Test
	@DisplayName("workGroupId narrows the listing to one classification")
	void listPassesTheWorkGroupFilterThrough() throws Exception {
		given(service.findAll(any(), anyBoolean(), any()))
				.willReturn(new PageImpl<>(List.of(), PageRequest.of(0, 50), 0));

		mockMvc.perform(get("/api/evidence-items").param("workGroupId", WORK_GROUP_ID.toString()))
				.andExpect(status().isOk());

		then(service).should().findAll(eq(WORK_GROUP_ID), eq(false), any());
	}

	@Test
	@DisplayName("The default ordering is newest-first on createdAt, not the source-asserted eventStart")
	void listDefaultsToNewestFirstByCreatedAt() throws Exception {
		given(service.findAll(any(), anyBoolean(), any()))
				.willReturn(new PageImpl<>(List.of(), PageRequest.of(0, 50), 0));

		mockMvc.perform(get("/api/evidence-items")).andExpect(status().isOk());

		ArgumentCaptor<Pageable> pageable = ArgumentCaptor.forClass(Pageable.class);
		then(service).should().findAll(any(), anyBoolean(), pageable.capture());

		// eventStart is asserted by the collector. Ordering on it would let a source with a
		// wrong clock decide where its artifacts sit in an investigator's list.
		assertThat(pageable.getValue().getSort().getOrderFor("createdAt"))
				.isNotNull()
				.satisfies(order -> assertThat(order.getDirection()).isEqualTo(Sort.Direction.DESC));
		assertThat(pageable.getValue().getPageSize()).isEqualTo(50);
	}

	@Test
	@DisplayName("POST preserves the artifact and returns 201 with a Location header")
	void preserveReturnsCreatedWithLocation() throws Exception {
		given(service.preserve(any(), any(), any(), any())).willReturn(sampleDto());

		mockMvc.perform(upload(metadataJson(CONTENT_SHA256, "2026-09-05T14:30:00Z", "2026-09-05T14:30:30Z")))
				.andExpect(status().isCreated())
				.andExpect(header().string("Location", "http://localhost/api/evidence-items/" + ITEM_ID))
				.andExpect(jsonPath("$.currentHash").value(CONTENT_SHA256))
				.andExpect(jsonPath("$.status").value("PRESERVED"));
	}

	/**
	 * The response must not leak the object key. Publishing it invites a reader round the API
	 * to the bucket, where nothing re-verifies integrity or writes an access log.
	 */
	@Test
	@DisplayName("The response carries the digest but never the storage reference")
	void preserveResponseOmitsStorageRef() throws Exception {
		given(service.preserve(any(), any(), any(), any())).willReturn(sampleDto());

		mockMvc.perform(upload(metadataJson(CONTENT_SHA256, "2026-09-05T14:30:00Z", "2026-09-05T14:30:30Z")))
				.andExpect(status().isCreated())
				.andExpect(jsonPath("$.storageRef").doesNotExist());
	}

	/**
	 * The attribution the custody chain records is taken from the authenticated request, not
	 * from anything the caller can state in the metadata part. An upload that could name its
	 * own preserver would make {@code custody_event.performed_by} worthless.
	 */
	@Test
	@DisplayName("The authenticated principal is passed through as the custody attribution")
	void preservePassesAuthenticatedPrincipalToTheService() throws Exception {
		given(service.preserve(any(), any(), any(), any())).willReturn(sampleDto());

		mockMvc.perform(upload(metadataJson(CONTENT_SHA256, "2026-09-05T14:30:00Z", "2026-09-05T14:30:30Z")))
				.andExpect(status().isCreated());

		then(service).should().preserve(any(), any(), any(), eq("user"));
	}

	@Test
	@DisplayName("An integrity failure is translated to 422, not 400")
	void integrityFailureIsUnprocessableEntity() throws Exception {
		willThrow(IntegrityVerificationException.digestMismatch(ARTIFACT_ID))
				.given(service).preserve(any(), any(), any(), any());

		mockMvc.perform(upload(metadataJson(CONTENT_SHA256, "2026-09-05T14:30:00Z", "2026-09-05T14:30:30Z")))
				.andExpect(status().isUnprocessableEntity())
				.andExpect(header().string("Content-Type", MediaType.APPLICATION_PROBLEM_JSON_VALUE))
				.andExpect(jsonPath("$.title").value("Evidence integrity check failed"));
	}

	/**
	 * Neither digest may appear in the body — the handler's rule is identifiers only, and a
	 * digest in an error response is a hash this system never agreed to publish.
	 */
	@Test
	@DisplayName("An integrity failure names the artifact and no digests")
	void integrityFailureDetailCarriesNoDigests() throws Exception {
		willThrow(IntegrityVerificationException.digestMismatch(ARTIFACT_ID))
				.given(service).preserve(any(), any(), any(), any());

		String body = mockMvc
				.perform(upload(metadataJson(CONTENT_SHA256, "2026-09-05T14:30:00Z", "2026-09-05T14:30:30Z")))
				.andExpect(status().isUnprocessableEntity())
				.andReturn()
				.getResponse()
				.getContentAsString();

		assertThat(body).contains(ARTIFACT_ID).doesNotContain(CONTENT_SHA256);
	}

	@Test
	@DisplayName("A re-sent artifact is translated to 409")
	void duplicateArtifactIsConflict() throws Exception {
		willThrow(DuplicateResourceException.of("EvidenceItem", "sourceArtifactId", ARTIFACT_ID))
				.given(service).preserve(any(), any(), any(), any());

		mockMvc.perform(upload(metadataJson(CONTENT_SHA256, "2026-09-05T14:30:00Z", "2026-09-05T14:30:30Z")))
				.andExpect(status().isConflict())
				.andExpect(jsonPath("$.title").value("Resource already exists"));
	}

	@Test
	@DisplayName("An unregistered source key is translated to 404")
	void unknownSourceIsNotFound() throws Exception {
		willThrow(ResourceNotFoundException.of("EvidenceSource", "pde-sim-ufw-01"))
				.given(service).preserve(any(), any(), any(), any());

		mockMvc.perform(upload(metadataJson(CONTENT_SHA256, "2026-09-05T14:30:00Z", "2026-09-05T14:30:30Z")))
				.andExpect(status().isNotFound())
				.andExpect(jsonPath("$.title").value("Resource not found"));
	}

	/**
	 * An inverted window describes an empty range: it would overlap no alert ever fired, so
	 * the artifact would sit in the repository looking preserved and be uncorrelatable
	 * forever. Rejected at the boundary rather than stored and puzzled over later.
	 */
	@Test
	@DisplayName("A coverage window that ends before it starts is rejected as 400")
	void invertedCoverageWindowIsBadRequest() throws Exception {
		mockMvc.perform(upload(metadataJson(CONTENT_SHA256, "2026-09-05T14:30:30Z", "2026-09-05T14:30:00Z")))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.fieldErrors.coverageWindowOrdered").exists());
	}

	@Test
	@DisplayName("An upper-case digest is rejected as 400 naming the field")
	void nonCanonicalDigestIsBadRequest() throws Exception {
		mockMvc.perform(upload(metadataJson(
						CONTENT_SHA256.toUpperCase(Locale.ROOT),
						"2026-09-05T14:30:00Z",
						"2026-09-05T14:30:30Z")))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.fieldErrors.sourceSha256").exists());
	}

	@Test
	@DisplayName("POST integrity-checks runs the check as the authenticated principal and returns the result")
	void integrityCheckReturnsTheResultAttributedToTheCaller() throws Exception {
		given(integrityCheckService.check(eq(ITEM_ID), eq("user")))
				.willReturn(checkResult(true, CONTENT_SHA256, EvidenceStatus.PRESERVED, CustodyAction.HASH_VERIFIED));

		mockMvc.perform(post("/api/evidence-items/{id}/integrity-checks", ITEM_ID))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.intact").value(true))
				.andExpect(jsonPath("$.expectedHash").value(CONTENT_SHA256))
				.andExpect(jsonPath("$.observedHash").value(CONTENT_SHA256))
				.andExpect(jsonPath("$.status").value("PRESERVED"))
				.andExpect(jsonPath("$.custodyEvent.action").value("HASH_VERIFIED"))
				.andExpect(jsonPath("$.custodyEvent.sequence").value(1));

		then(integrityCheckService).should().check(ITEM_ID, "user");
	}

	/**
	 * The ingest path's 422 means "rejected, resend". A re-verification that finds a mismatch
	 * is the opposite: the finding was recorded and the item marked, and the request did
	 * exactly what was asked. The evidence failed; the request did not.
	 */
	@Test
	@DisplayName("A mismatch is a 200 with the finding in the body, not a 4xx")
	void integrityMismatchIsOkWithTheFindingInTheBody() throws Exception {
		given(integrityCheckService.check(any(), any()))
				.willReturn(checkResult(false, OTHER_SHA256, EvidenceStatus.COMPROMISED, CustodyAction.HASH_MISMATCH));

		mockMvc.perform(post("/api/evidence-items/{id}/integrity-checks", ITEM_ID))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.intact").value(false))
				.andExpect(jsonPath("$.expectedHash").value(CONTENT_SHA256))
				.andExpect(jsonPath("$.observedHash").value(OTHER_SHA256))
				.andExpect(jsonPath("$.status").value("COMPROMISED"))
				.andExpect(jsonPath("$.custodyEvent.action").value("HASH_MISMATCH"))
				.andExpect(jsonPath("$.custodyEvent.artifactHashBefore").value(CONTENT_SHA256))
				.andExpect(jsonPath("$.custodyEvent.artifactHashAfter").value(OTHER_SHA256));
	}

	@Test
	@DisplayName("An integrity check on an unknown item is 404")
	void integrityCheckOnUnknownItemIsNotFound() throws Exception {
		willThrow(ResourceNotFoundException.of("EvidenceItem", ITEM_ID))
				.given(integrityCheckService).check(any(), any());

		mockMvc.perform(post("/api/evidence-items/{id}/integrity-checks", ITEM_ID))
				.andExpect(status().isNotFound())
				.andExpect(jsonPath("$.title").value("Resource not found"));
	}

	/**
	 * An unreachable store is the one outcome that is an error rather than a finding, and the
	 * response must not carry the object key the exception's own message names.
	 */
	@Test
	@DisplayName("An unreachable store is 503 and the body does not name the storage key")
	void integrityCheckStorageFailureIsServiceUnavailable() throws Exception {
		willThrow(new EvidenceStorageException("Could not read evidence object pde-sim-ufw-01/" + ARTIFACT_ID, null))
				.given(integrityCheckService).check(any(), any());

		String body = mockMvc.perform(post("/api/evidence-items/{id}/integrity-checks", ITEM_ID))
				.andExpect(status().isServiceUnavailable())
				.andExpect(jsonPath("$.title").value("Evidence store unavailable"))
				.andReturn().getResponse().getContentAsString();

		assertThat(body).doesNotContain("pde-sim-ufw-01/");
	}

	@Test
	@DisplayName("GET content releases the bytes as an attachment, with their digest, exported as the caller")
	void contentReleasesBytesAsAnAttachmentWithTheirDigest() throws Exception {
		given(integrityCheckService.export(eq(ITEM_ID), eq("user")))
				.willReturn(export(true, "hello".getBytes(UTF_8), CONTENT_SHA256, CustodyAction.EXPORTED));

		mockMvc.perform(get("/api/evidence-items/{id}/content", ITEM_ID))
				.andExpect(status().isOk())
				.andExpect(header().string("Content-Type", MediaType.APPLICATION_OCTET_STREAM_VALUE))
				.andExpect(header().string("Content-Length", "5"))
				.andExpect(header().string("Content-Disposition",
						allOf(
								startsWith("attachment"),
								containsString(ARTIFACT_ID))))
				// RFC 9530: the SHA-256 of "hello", base64 between colons.
				.andExpect(header().string("Repr-Digest", "sha-256=:LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=:"))
				.andExpect(header().string("Cache-Control", containsString("no-store")))
				.andExpect(content().bytes("hello".getBytes(UTF_8)));

		then(integrityCheckService).should().export(ITEM_ID, "user");
	}

	/**
	 * The finding has been committed by the service by the time this is thrown, so the
	 * problem document can say so; what it must not do is carry the digests or the bytes.
	 */
	@Test
	@DisplayName("A mismatched object is refused with 422, no bytes and no digests")
	void contentOfMismatchedObjectIsRefused() throws Exception {
		given(integrityCheckService.export(any(), any()))
				.willReturn(export(false, null, OTHER_SHA256, CustodyAction.HASH_MISMATCH));

		String body = mockMvc.perform(get("/api/evidence-items/{id}/content", ITEM_ID))
				.andExpect(status().isUnprocessableEntity())
				.andExpect(jsonPath("$.title").value("Evidence integrity check failed"))
				.andExpect(jsonPath("$.detail").value(containsString("COMPROMISED")))
				.andReturn().getResponse().getContentAsString();

		assertThat(body).doesNotContain(CONTENT_SHA256).doesNotContain(OTHER_SHA256);
	}

	@Test
	@DisplayName("Downloading an unknown item is 404")
	void contentOfUnknownItemIsNotFound() throws Exception {
		willThrow(ResourceNotFoundException.of("EvidenceItem", ITEM_ID))
				.given(integrityCheckService).export(any(), any());

		mockMvc.perform(get("/api/evidence-items/{id}/content", ITEM_ID))
				.andExpect(status().isNotFound());
	}

	@Test
	@DisplayName("An unreachable store on download is 503 and names no storage key")
	void contentStorageFailureIsServiceUnavailable() throws Exception {
		willThrow(new EvidenceStorageException("Could not read evidence object pde-sim-ufw-01/" + ARTIFACT_ID, null))
				.given(integrityCheckService).export(any(), any());

		String body = mockMvc.perform(get("/api/evidence-items/{id}/content", ITEM_ID))
				.andExpect(status().isServiceUnavailable())
				.andReturn().getResponse().getContentAsString();

		assertThat(body).doesNotContain("pde-sim-ufw-01/");
	}

	/**
	 * Spring answers HEAD on a GET route by running the handler and dropping the body, which
	 * here would append an EXPORTED entry for a release that never happened.
	 */
	@Test
	@DisplayName("HEAD on content is refused and never reaches the export")
	void headOnContentIsRefusedWithoutExporting() throws Exception {
		mockMvc.perform(head("/api/evidence-items/{id}/content", ITEM_ID))
				.andExpect(status().isMethodNotAllowed())
				.andExpect(header().string("Allow", "GET"));

		then(integrityCheckService).should(never()).export(any(), any());
	}

	@Test
	@DisplayName("Downloading without credentials is 401 and never reaches the export")
	@WithAnonymousUser
	void contentRequiresAuthentication() throws Exception {
		mockMvc.perform(get("/api/evidence-items/{id}/content", ITEM_ID))
				.andExpect(status().isUnauthorized());

		then(integrityCheckService).should(never()).export(any(), any());
	}

	private static EvidenceExport export(boolean released, byte[] content, String sha256, CustodyAction action) {
		CustodyEventDto entry = new CustodyEventDto(
				UUID.fromString("55555555-5555-5555-5555-555555555555"),
				ITEM_ID,
				1L,
				action,
				"user",
				OffsetDateTime.parse("2026-09-06T09:15:00.123456Z"),
				OffsetDateTime.parse("2026-09-06T09:15:00.125000Z"),
				CONTENT_SHA256,
				sha256,
				"3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b",
				"b1f5a6d7c8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f6071829",
				(short) 1,
				"Re-verified before export.");
		return new EvidenceExport(ITEM_ID, ARTIFACT_ID, released, content, sha256,
				released ? EvidenceStatus.PRESERVED : EvidenceStatus.COMPROMISED, entry);
	}

	private static IntegrityCheckResult checkResult(
			boolean intact, String observed, EvidenceStatus status, CustodyAction action) {
		CustodyEventDto entry = new CustodyEventDto(
				UUID.fromString("44444444-4444-4444-4444-444444444444"),
				ITEM_ID,
				1L,
				action,
				"user",
				OffsetDateTime.parse("2026-09-06T09:15:00.123456Z"),
				OffsetDateTime.parse("2026-09-06T09:15:00.125000Z"),
				CONTENT_SHA256,
				observed,
				"3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b",
				"b1f5a6d7c8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f6071829",
				(short) 1,
				"Re-verified on demand.");
		return new IntegrityCheckResult(ITEM_ID, intact, CONTENT_SHA256, observed, status, entry);
	}

	private static MockMultipartHttpServletRequestBuilder upload(String metadata) {
		return multipart("/api/evidence-items")
				.file(new MockMultipartFile(
						"metadata", "", MediaType.APPLICATION_JSON_VALUE, metadata.getBytes(UTF_8)))
				.file(new MockMultipartFile(
						"file", "firewall.log", MediaType.TEXT_PLAIN_VALUE, "hello".getBytes(UTF_8)));
	}

	private static String metadataJson(String sha256, String eventStart, String eventEnd) {
		return """
				{"sourceKey": "pde-sim-ufw-01", "sourceArtifactId": "%s", \
				"eventStart": "%s", "eventEnd": "%s", "sourceSha256": "%s"}
				""".formatted(ARTIFACT_ID, eventStart, eventEnd, sha256);
	}

	private static EvidenceItemDto sampleDto() {
		return new EvidenceItemDto(
				ITEM_ID,
				WORK_GROUP_ID,
				SOURCE_ID,
				ARTIFACT_ID,
				OffsetDateTime.parse("2026-09-05T14:30:00Z"),
				OffsetDateTime.parse("2026-09-05T14:30:30Z"),
				CONTENT_SHA256,
				EvidenceStatus.PRESERVED,
				OffsetDateTime.parse("2026-09-05T14:30:34.221Z"));
	}
}
