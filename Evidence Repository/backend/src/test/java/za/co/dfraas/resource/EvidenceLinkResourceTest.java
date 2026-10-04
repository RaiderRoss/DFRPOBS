package za.co.dfraas.resource;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.Mockito.never;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
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
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import za.co.dfraas.config.SecurityConfiguration;
import za.co.dfraas.dto.EvidenceItemDto;
import za.co.dfraas.dto.EvidenceLinkDto;
import za.co.dfraas.entity.EvidenceStatus;
import za.co.dfraas.entity.LinkDisposition;
import za.co.dfraas.entity.LinkMethod;
import za.co.dfraas.exception.LinkAlreadyReviewedException;
import za.co.dfraas.exception.ResourceNotFoundException;
import za.co.dfraas.service.EvidenceLinkService;

/**
 * Web-layer contract for {@link EvidenceLinkResource}. The service is mocked; the review
 * rules themselves are covered against Postgres by {@code EvidenceLinkServiceTest}.
 */
@WebMvcTest(EvidenceLinkResource.class)
@Import({SecurityConfiguration.class, ApiExceptionHandler.class})
@WithMockUser(username = "j.mokoena", roles = "INVESTIGATOR")
class EvidenceLinkResourceTest {

	private static final UUID EVENT_ID = UUID.fromString("22222222-2222-2222-2222-222222222222");
	private static final UUID LINK_ID = UUID.fromString("33333333-3333-3333-3333-333333333333");
	private static final UUID ITEM_ID = UUID.fromString("44444444-4444-4444-4444-444444444444");

	@Autowired
	private MockMvc mockMvc;

	@MockitoBean
	private EvidenceLinkService service;

	@Test
	@DisplayName("GET /api/incidents/{id}/links returns the bundle with each item embedded")
	void listReturnsTheBundle() throws Exception {
		given(service.findByIncident(eq(EVENT_ID), eq(null), any(Pageable.class)))
				.willReturn(new PageImpl<>(List.of(sample(LinkDisposition.PROPOSED)), PageRequest.of(0, 50), 1));

		mockMvc.perform(get("/api/incidents/{id}/links", EVENT_ID))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.content[0].id").value(LINK_ID.toString()))
				.andExpect(jsonPath("$.content[0].evidenceSourceKey").value("pde-sim-ufw-01"))
				.andExpect(jsonPath("$.content[0].evidenceItem.id").value(ITEM_ID.toString()))
				// The item is the shared read model: digest yes, storage key never.
				.andExpect(jsonPath("$.content[0].evidenceItem.storageRef").doesNotExist())
				.andExpect(jsonPath("$.page.totalElements").value(1));
	}

	@Test
	@DisplayName("?disposition= narrows the bundle")
	void listFiltersByDisposition() throws Exception {
		given(service.findByIncident(eq(EVENT_ID), eq(LinkDisposition.PROPOSED), any(Pageable.class)))
				.willReturn(new PageImpl<>(List.of(sample(LinkDisposition.PROPOSED))));

		mockMvc.perform(get("/api/incidents/{id}/links", EVENT_ID).param("disposition", "PROPOSED"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.content[0].disposition").value("PROPOSED"));
	}

	@Test
	@DisplayName("Confirming takes the reviewer from the authenticated user, not the body")
	void confirmUsesTheAuthenticatedReviewer() throws Exception {
		given(service.confirm(LINK_ID, "j.mokoena", "Same source IP."))
				.willReturn(sample(LinkDisposition.CONFIRMED));

		// A reviewedBy in the body is ignored. Letting a caller type in whose judgement a
		// review was would make the attribution worthless.
		mockMvc.perform(post("/api/evidence-links/{id}/confirm", LINK_ID)
						.contentType(MediaType.APPLICATION_JSON)
						.content("{\"reason\":\"Same source IP.\",\"reviewedBy\":\"someone.else\"}"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.disposition").value("CONFIRMED"));

		then(service).should().confirm(LINK_ID, "j.mokoena", "Same source IP.");
	}

	@Test
	@DisplayName("A review without a reason is a 400 naming the field, and never reaches the service")
	void reviewRequiresAReason() throws Exception {
		mockMvc.perform(post("/api/evidence-links/{id}/dismiss", LINK_ID)
						.contentType(MediaType.APPLICATION_JSON)
						.content("{\"reason\":\"  \"}"))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.fieldErrors.reason").exists());

		then(service).should(never()).dismiss(any(), anyString(), anyString());
	}

	@Test
	@DisplayName("Reviewing an already-reviewed link is a 409 that names the ruling that stands")
	void secondReviewIsAConflict() throws Exception {
		given(service.dismiss(LINK_ID, "j.mokoena", "Irrelevant."))
				.willThrow(new LinkAlreadyReviewedException(LINK_ID, LinkDisposition.CONFIRMED));

		mockMvc.perform(post("/api/evidence-links/{id}/dismiss", LINK_ID)
						.contentType(MediaType.APPLICATION_JSON)
						.content("{\"reason\":\"Irrelevant.\"}"))
				.andExpect(status().isConflict())
				.andExpect(jsonPath("$.title").value("Link already reviewed"))
				.andExpect(jsonPath("$.detail").value(org.hamcrest.Matchers.containsString("CONFIRMED")));
	}

	@Test
	@DisplayName("An unknown link is a 404")
	void unknownLinkIsNotFound() throws Exception {
		given(service.findById(LINK_ID)).willThrow(ResourceNotFoundException.of("EvidenceLink", LINK_ID));

		mockMvc.perform(get("/api/evidence-links/{id}", LINK_ID))
				.andExpect(status().isNotFound());
	}

	@Test
	@DisplayName("There is no delete — an irrelevant link is dismissed, and stays")
	void deleteIsNotAllowed() throws Exception {
		mockMvc.perform(delete("/api/evidence-links/{id}", LINK_ID))
				.andExpect(status().isMethodNotAllowed());
	}

	private static EvidenceLinkDto sample(LinkDisposition disposition) {
		boolean reviewed = disposition != LinkDisposition.PROPOSED;
		EvidenceItemDto item = new EvidenceItemDto(
				ITEM_ID,
				UUID.randomUUID(),
				UUID.randomUUID(),
				"firewall_20260101143000",
				OffsetDateTime.parse("2026-01-01T14:30:00Z"),
				OffsetDateTime.parse("2026-01-01T14:30:30Z"),
				"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				EvidenceStatus.PRESERVED,
				OffsetDateTime.parse("2026-01-01T14:31:00Z"));
		return new EvidenceLinkDto(
				LINK_ID,
				EVENT_ID,
				LinkMethod.AUTO_TIME_WINDOW,
				disposition,
				"overlap",
				null,
				OffsetDateTime.parse("2026-01-01T14:46:00Z"),
				false,
				reviewed ? "j.mokoena" : null,
				reviewed ? OffsetDateTime.parse("2026-01-01T16:00:00Z") : null,
				reviewed ? "Same source IP." : null,
				"pde-sim-ufw-01",
				item);
	}
}
