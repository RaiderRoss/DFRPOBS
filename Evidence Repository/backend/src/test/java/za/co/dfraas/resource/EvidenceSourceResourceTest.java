package za.co.dfraas.resource;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willThrow;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.OffsetDateTime;
import java.util.UUID;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import za.co.dfraas.config.SecurityConfiguration;
import za.co.dfraas.dto.EvidenceSourceCreateRequest;
import za.co.dfraas.dto.EvidenceSourceDto;
import za.co.dfraas.entity.SourceStatus;
import za.co.dfraas.exception.DuplicateResourceException;
import za.co.dfraas.exception.ResourceNotFoundException;
import za.co.dfraas.service.EvidenceSourceService;

/**
 * Web-layer contract for {@link EvidenceSourceResource}, matching
 * {@code WorkGroupResourceTest}: status codes, response shape and the
 * {@link ApiExceptionHandler} translations, with the service mocked.
 */
@WebMvcTest(EvidenceSourceResource.class)
@Import({SecurityConfiguration.class, ApiExceptionHandler.class})
@WithMockUser(roles = "INVESTIGATOR")
class EvidenceSourceResourceTest {

	private static final UUID SOURCE_ID = UUID.fromString("22222222-2222-2222-2222-222222222222");
	private static final UUID WORK_GROUP_ID = UUID.fromString("11111111-1111-1111-1111-111111111111");
	private static final String SOURCE_KEY = "pde-sim-ufw-01";

	@Autowired
	private MockMvc mockMvc;

	@MockitoBean
	private EvidenceSourceService service;

	@Test
	@DisplayName("POST registers a source and returns 201 with a Location header")
	void registerReturnsCreatedWithLocation() throws Exception {
		given(service.register(any(EvidenceSourceCreateRequest.class))).willReturn(sampleDto());

		mockMvc.perform(post("/api/evidence-sources")
						.contentType(MediaType.APPLICATION_JSON)
						.content(registrationJson(SOURCE_KEY, "FIREWALL")))
				.andExpect(status().isCreated())
				.andExpect(header().string("Location", "http://localhost/api/evidence-sources/" + SOURCE_ID))
				.andExpect(jsonPath("$.sourceKey").value(SOURCE_KEY))
				.andExpect(jsonPath("$.status").value("ACTIVE"));
	}

	/**
	 * The case rule is not cosmetic: a key registered in one case and sent in another is a
	 * 404 on every upload that follows, which looks like a missing source rather than a typo.
	 */
	@Test
	@DisplayName("POST with an upper-case source key is rejected as 400 naming the field")
	void registerRejectsUpperCaseSourceKey() throws Exception {
		mockMvc.perform(post("/api/evidence-sources")
						.contentType(MediaType.APPLICATION_JSON)
						.content(registrationJson("PDE-Sim-UFW-01", "FIREWALL")))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.fieldErrors.sourceKey").exists());
	}

	@Test
	@DisplayName("POST with a lower-case source type is rejected as 400 naming the field")
	void registerRejectsLowerCaseSourceType() throws Exception {
		mockMvc.perform(post("/api/evidence-sources")
						.contentType(MediaType.APPLICATION_JSON)
						.content(registrationJson(SOURCE_KEY, "firewall")))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.fieldErrors.sourceType").exists());
	}

	@Test
	@DisplayName("POST naming an unknown work group is translated to 404")
	void registerRejectsUnknownWorkGroup() throws Exception {
		willThrow(ResourceNotFoundException.of("WorkGroup", WORK_GROUP_ID))
				.given(service).register(any(EvidenceSourceCreateRequest.class));

		mockMvc.perform(post("/api/evidence-sources")
						.contentType(MediaType.APPLICATION_JSON)
						.content(registrationJson(SOURCE_KEY, "FIREWALL")))
				.andExpect(status().isNotFound())
				.andExpect(jsonPath("$.title").value("Resource not found"));
	}

	@Test
	@DisplayName("POST with an already-registered key is translated to 409")
	void registerRejectsDuplicateSourceKey() throws Exception {
		willThrow(DuplicateResourceException.of("EvidenceSource", "sourceKey", SOURCE_KEY))
				.given(service).register(any(EvidenceSourceCreateRequest.class));

		mockMvc.perform(post("/api/evidence-sources")
						.contentType(MediaType.APPLICATION_JSON)
						.content(registrationJson(SOURCE_KEY, "FIREWALL")))
				.andExpect(status().isConflict())
				.andExpect(jsonPath("$.title").value("Resource already exists"));
	}

	@Test
	@DisplayName("GET with sourceKey resolves the single registration")
	void listBySourceKeyReturnsOne() throws Exception {
		given(service.findBySourceKey(SOURCE_KEY)).willReturn(sampleDto());

		mockMvc.perform(get("/api/evidence-sources").param("sourceKey", SOURCE_KEY))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$[0].id").value(SOURCE_ID.toString()))
				.andExpect(jsonPath("$[0].workGroupId").value(WORK_GROUP_ID.toString()));
	}

	/**
	 * Literal JSON rather than a serialised record, so these assert against the exact wire
	 * format a collector's operator sends and stay valid if the DTO is refactored.
	 */
	private static String registrationJson(String sourceKey, String sourceType) {
		return """
				{"sourceKey": "%s", "displayName": "PDE testbed firewall (ufw)", \
				"workGroupId": "%s", "sourceType": "%s"}
				""".formatted(sourceKey, WORK_GROUP_ID, sourceType);
	}

	private static EvidenceSourceDto sampleDto() {
		return new EvidenceSourceDto(
				SOURCE_ID,
				SOURCE_KEY,
				"PDE testbed firewall (ufw)",
				WORK_GROUP_ID,
				"FIREWALL",
				SourceStatus.ACTIVE,
				null,
				null,
				OffsetDateTime.parse("2026-09-01T09:12:44Z"));
	}
}
