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
import java.util.List;
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
import za.co.dfraas.dto.WorkGroupCreateRequest;
import za.co.dfraas.dto.WorkGroupDto;
import za.co.dfraas.exception.DuplicateResourceException;
import za.co.dfraas.exception.ResourceNotFoundException;
import za.co.dfraas.service.WorkGroupService;

/**
 * Web-layer contract for {@link WorkGroupResource}: status codes, response shape and the
 * {@link ApiExceptionHandler} translations. The service is mocked — persistence is covered
 * by {@code WorkGroupRepositoryTest}.
 *
 * <p>The real {@link SecurityConfiguration} is imported rather than left to the test
 * defaults, so these tests fail if the filter chain ever starts rejecting the API's own
 * endpoints.
 */
@WebMvcTest(WorkGroupResource.class)
@Import({SecurityConfiguration.class, ApiExceptionHandler.class})
@WithMockUser(roles = "INVESTIGATOR")
class WorkGroupResourceTest {

	private static final UUID WORK_GROUP_ID = UUID.fromString("11111111-1111-1111-1111-111111111111");

	@Autowired
	private MockMvc mockMvc;

	@MockitoBean
	private WorkGroupService service;

	@Test
	@DisplayName("GET /api/work-groups returns the collection")
	void listReturnsWorkGroups() throws Exception {
		given(service.findAll()).willReturn(List.of(sampleDto()));

		mockMvc.perform(get("/api/work-groups"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$[0].classificationCode").value("ONLINE_BANKING"))
				.andExpect(jsonPath("$[0].id").value(WORK_GROUP_ID.toString()));
	}

	@Test
	@DisplayName("GET /api/work-groups/{id} returns 404 as problem+json when absent")
	void getUnknownIdReturnsProblemDetail() throws Exception {
		given(service.findById(WORK_GROUP_ID))
				.willThrow(ResourceNotFoundException.of("WorkGroup", WORK_GROUP_ID));

		mockMvc.perform(get("/api/work-groups/{id}", WORK_GROUP_ID))
				.andExpect(status().isNotFound())
				.andExpect(header().string("Content-Type", MediaType.APPLICATION_PROBLEM_JSON_VALUE))
				.andExpect(jsonPath("$.title").value("Resource not found"));
	}

	@Test
	@DisplayName("POST returns 201 with a Location header pointing at the new resource")
	void createReturnsCreatedWithLocation() throws Exception {
		given(service.create(any(WorkGroupCreateRequest.class))).willReturn(sampleDto());

		mockMvc.perform(post("/api/work-groups")
						.contentType(MediaType.APPLICATION_JSON)
						.content(createRequestJson("Online Banking", "ONLINE_BANKING")))
				.andExpect(status().isCreated())
				.andExpect(header().string("Location", "http://localhost/api/work-groups/" + WORK_GROUP_ID))
				.andExpect(jsonPath("$.classificationCode").value("ONLINE_BANKING"));
	}

	@Test
	@DisplayName("POST with a lower-case code is rejected as 400 naming the field")
	void createRejectsMalformedClassificationCode() throws Exception {
		mockMvc.perform(post("/api/work-groups")
						.contentType(MediaType.APPLICATION_JSON)
						.content(createRequestJson("Online Banking", "online banking")))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.fieldErrors.classificationCode").exists());
	}

	@Test
	@DisplayName("POST with a duplicate code is translated to 409")
	void createRejectsDuplicateClassificationCode() throws Exception {
		willThrow(DuplicateResourceException.of("WorkGroup", "classificationCode", "ONLINE_BANKING"))
				.given(service).create(any(WorkGroupCreateRequest.class));

		mockMvc.perform(post("/api/work-groups")
						.contentType(MediaType.APPLICATION_JSON)
						.content(createRequestJson("Online Banking", "ONLINE_BANKING")))
				.andExpect(status().isConflict())
				.andExpect(jsonPath("$.title").value("Resource already exists"));
	}

	/**
	 * Literal JSON rather than a serialised record, so these tests assert against the exact
	 * wire format a client sends and stay valid if the DTO is refactored.
	 */
	private static String createRequestJson(String name, String classificationCode) {
		return """
				{"name": "%s", "classificationCode": "%s"}
				""".formatted(name, classificationCode);
	}

	private static WorkGroupDto sampleDto() {
		return new WorkGroupDto(
				WORK_GROUP_ID,
				"Online Banking",
				"ONLINE_BANKING",
				OffsetDateTime.parse("2026-01-01T00:00:00Z"));
	}
}
