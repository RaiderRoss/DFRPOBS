package za.co.dfraas.resource;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
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
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import za.co.dfraas.config.SecurityConfiguration;
import za.co.dfraas.dto.TriggerEventDto;
import za.co.dfraas.entity.CorrelationStatus;
import za.co.dfraas.exception.ResourceNotFoundException;
import za.co.dfraas.service.TriggerEventService;

/**
 * Web-layer contract for {@link TriggerEventResource}. The service is mocked; persistence
 * and idempotency are covered by {@code TriggerEventRepositoryTest} and
 * {@code TriggerEventServiceTest}.
 *
 * <p>Imports the real {@link SecurityConfiguration} for the same reason the WorkGroup test
 * does — so these fail if the filter chain starts rejecting the API's own endpoints.
 */
@WebMvcTest(TriggerEventResource.class)
@Import({SecurityConfiguration.class, ApiExceptionHandler.class})
@WithMockUser(roles = "INVESTIGATOR")
class TriggerEventResourceTest {

	private static final UUID EVENT_ID = UUID.fromString("22222222-2222-2222-2222-222222222222");
	private static final String DIGEST =
			"c82fb88239e96ae95bfdc7fc1b17a9ef3015a8ac3135bc8955850e0da4398ae8";

	@Autowired
	private MockMvc mockMvc;

	@MockitoBean
	private TriggerEventService service;

	@Test
	@DisplayName("GET /api/trigger-events returns a paged collection")
	void listReturnsPagedTriggerEvents() throws Exception {
		given(service.findAll(any(Pageable.class))).willReturn(pageOf(sampleDto()));

		mockMvc.perform(get("/api/trigger-events"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.content[0].id").value(EVENT_ID.toString()))
				.andExpect(jsonPath("$.content[0].sourceSystem").value("splunk"))
				// PagedModel's stable envelope, rather than a serialised Spring Data Page.
				.andExpect(jsonPath("$.page.totalElements").value(1));
	}

	@Test
	@DisplayName("The raw payload is never in a response body, only its digest")
	void listOmitsTheRawPayload() throws Exception {
		given(service.findAll(any(Pageable.class))).willReturn(pageOf(sampleDto()));

		// The alert body can carry customer identifiers and attacker-controlled input, so
		// it is gated behind the OTP step-up rather than served here. This test is what
		// stops a payload field being added to TriggerEventDto without that conversation.
		mockMvc.perform(get("/api/trigger-events"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.content[0].payload").doesNotExist())
				.andExpect(jsonPath("$.content[0].payloadSha256").value(DIGEST));
	}

	@Test
	@DisplayName("GET /api/trigger-events?sourceSystem= narrows to one source")
	void listFiltersBySourceSystem() throws Exception {
		given(service.findBySourceSystem(eq("splunk"), any(Pageable.class))).willReturn(pageOf(sampleDto()));

		mockMvc.perform(get("/api/trigger-events").param("sourceSystem", "splunk"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.content[0].sourceSystem").value("splunk"));
	}

	@Test
	@DisplayName("GET /api/trigger-events/{id} returns 404 as problem+json when absent")
	void getUnknownIdReturnsProblemDetail() throws Exception {
		given(service.findById(EVENT_ID)).willThrow(ResourceNotFoundException.of("TriggerEvent", EVENT_ID));

		mockMvc.perform(get("/api/trigger-events/{id}", EVENT_ID))
				.andExpect(status().isNotFound())
				.andExpect(header().string("Content-Type", MediaType.APPLICATION_PROBLEM_JSON_VALUE))
				.andExpect(jsonPath("$.title").value("Resource not found"));
	}

	@Test
	@DisplayName("GET /by-external-id resolves the source's own alert identifier")
	void getByExternalIdResolvesTheEvent() throws Exception {
		given(service.findBySourceSystemAndExternalEventId("splunk", "EVT-1")).willReturn(sampleDto());

		mockMvc.perform(get("/api/trigger-events/by-external-id")
						.param("sourceSystem", "splunk")
						.param("externalEventId", "EVT-1"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.externalEventId").value("EVT-1"));
	}

	@Test
	@DisplayName("There is no create endpoint — trigger events arrive over Kafka only")
	void postIsNotAllowed() throws Exception {
		// Asserted rather than merely documented. A POST added later for convenience would
		// let a caller fabricate an alert that never fired, and bypass the Kafka offset
		// semantics that make ingestion idempotent.
		mockMvc.perform(post("/api/trigger-events")
						.contentType(MediaType.APPLICATION_JSON)
						.content("{}"))
				.andExpect(status().isMethodNotAllowed());
	}

	private static Page<TriggerEventDto> pageOf(TriggerEventDto... events) {
		return new PageImpl<>(List.of(events), PageRequest.of(0, 50), events.length);
	}

	private static TriggerEventDto sampleDto() {
		return new TriggerEventDto(
				EVENT_ID,
				"EVT-1",
				"splunk",
				"BRUTE_FORCE_LOGIN",
				OffsetDateTime.parse("2026-01-01T09:00:00Z"),
				OffsetDateTime.parse("2026-01-01T09:00:05Z"),
				DIGEST,
				CorrelationStatus.CORRELATED,
				OffsetDateTime.parse("2026-01-01T09:01:00Z"));
	}
}
