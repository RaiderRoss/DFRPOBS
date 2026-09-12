package za.co.dfraas.resource;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.BDDMockito.willThrow;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
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
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMultipartHttpServletRequestBuilder;

import za.co.dfraas.config.SecurityConfiguration;
import za.co.dfraas.dto.EvidenceItemDto;
import za.co.dfraas.entity.EvidenceStatus;
import za.co.dfraas.exception.DuplicateResourceException;
import za.co.dfraas.exception.IntegrityVerificationException;
import za.co.dfraas.exception.ResourceNotFoundException;
import za.co.dfraas.service.EvidenceItemService;

/**
 * Web-layer contract for {@link EvidenceItemResource}: the multipart upload shape, and the
 * status codes that let a collector tell the four failures apart — a malformed request
 * (400), an unregistered source (404), an artifact already preserved (409) and bytes that
 * did not survive the trip (422). The service is mocked; what it actually verifies is
 * covered by {@code EvidenceItemServiceTest}.
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

	@Autowired
	private MockMvc mockMvc;

	@MockitoBean
	private EvidenceItemService service;

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
