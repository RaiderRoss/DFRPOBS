package za.co.dfraas.resource;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
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
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import za.co.dfraas.config.SecurityConfiguration;
import za.co.dfraas.dto.IncidentDto;
import za.co.dfraas.dto.TriggerEventDto;
import za.co.dfraas.entity.CorrelationStatus;
import za.co.dfraas.exception.ResourceNotFoundException;
import za.co.dfraas.service.IncidentService;

/**
 * Web-layer contract for {@link IncidentResource}. The service is mocked; grouping and
 * correlation are covered against Postgres by {@code TriggerEventServiceTest} and
 * {@code CorrelationServiceTest}.
 */
@WebMvcTest(IncidentResource.class)
@Import({SecurityConfiguration.class, ApiExceptionHandler.class})
@WithMockUser(roles = "INVESTIGATOR")
class IncidentResourceTest {

	private static final UUID INCIDENT_ID = UUID.fromString("55555555-5555-5555-5555-555555555555");
	private static final OffsetDateTime FIRED_AT = OffsetDateTime.parse("2026-10-04T11:25:00Z");

	@Autowired
	private MockMvc mockMvc;

	@MockitoBean
	private IncidentService service;

	@Test
	@DisplayName("GET /api/incidents lists incidents with their alert counts and correlation state")
	void listReturnsIncidents() throws Exception {
		given(service.findAll(eq(null), any(Pageable.class))).willReturn(new PageImpl<>(List.of(sample())));

		mockMvc.perform(get("/api/incidents"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.content[0].id").value(INCIDENT_ID.toString()))
				.andExpect(jsonPath("$.content[0].alertCount").value(6))
				.andExpect(jsonPath("$.content[0].correlationStatus").value("CORRELATED"))
				// Deployment detail, and nothing a reader acts on.
				.andExpect(jsonPath("$.content[0].correlationScope").doesNotExist());
	}

	@Test
	@DisplayName("GET /api/incidents/{id}/trigger-events lists the member alerts")
	void alertsAreListed() throws Exception {
		TriggerEventDto alert = new TriggerEventDto(UUID.randomUUID(), "A1", "slips", "SLIPS_ALERT",
				FIRED_AT, FIRED_AT.plusSeconds(2),
				"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", INCIDENT_ID);
		given(service.findAlerts(eq(INCIDENT_ID), any(Pageable.class))).willReturn(new PageImpl<>(List.of(alert)));

		mockMvc.perform(get("/api/incidents/{id}/trigger-events", INCIDENT_ID))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.content[0].incidentId").value(INCIDENT_ID.toString()));
	}

	@Test
	@DisplayName("An unknown incident is a 404")
	void unknownIncidentIsNotFound() throws Exception {
		given(service.findById(INCIDENT_ID)).willThrow(ResourceNotFoundException.of("Incident", INCIDENT_ID));

		mockMvc.perform(get("/api/incidents/{id}", INCIDENT_ID)).andExpect(status().isNotFound());
	}

	@Test
	@DisplayName("There is no create endpoint — incidents are opened by alerts arriving")
	void postIsNotAllowed() throws Exception {
		mockMvc.perform(post("/api/incidents").contentType(MediaType.APPLICATION_JSON).content("{}"))
				.andExpect(status().isMethodNotAllowed());
	}

	private static IncidentDto sample() {
		return new IncidentDto(INCIDENT_ID, "pde-sim-slips-01", "ids-1/10.99.0.20/tw1", 6,
				FIRED_AT, FIRED_AT.plusSeconds(30), FIRED_AT.plusSeconds(2),
				CorrelationStatus.CORRELATED, FIRED_AT.plusMinutes(1),
				FIRED_AT.minusSeconds(1800), FIRED_AT.plusSeconds(930));
	}
}
