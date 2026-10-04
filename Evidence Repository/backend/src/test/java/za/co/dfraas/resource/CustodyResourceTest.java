package za.co.dfraas.resource;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willThrow;
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
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import za.co.dfraas.config.SecurityConfiguration;
import za.co.dfraas.dto.CustodyChainVerification;
import za.co.dfraas.entity.CustodyAction;
import za.co.dfraas.entity.CustodyEvent;
import za.co.dfraas.entity.EvidenceItem;
import za.co.dfraas.exception.ResourceNotFoundException;
import za.co.dfraas.mapper.CustodyEventMapper;
import za.co.dfraas.service.CustodyChainService;

/**
 * Web-layer contract for {@link CustodyResource}: the chain comes back whole and in order
 * with its digests published, verification is a separate answer that is always 200, and an
 * unknown item is 404 on both. The service is mocked; what the chain detects is covered by
 * {@code CustodyChainServiceTest}.
 */
@WebMvcTest(CustodyResource.class)
@Import({SecurityConfiguration.class, ApiExceptionHandler.class, CustodyEventMapper.class})
@WithMockUser(roles = "INVESTIGATOR")
class CustodyResourceTest {

	private static final UUID ITEM_ID = UUID.fromString("33333333-3333-3333-3333-333333333333");

	private static final String GENESIS_HASH = "0".repeat(64);
	private static final String ENTRY_HASH_0 = "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b";
	private static final String ENTRY_HASH_1 = "b1f5a6d7c8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f6071829";
	private static final String CONTENT_SHA256 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

	@Autowired
	private MockMvc mockMvc;

	@MockitoBean
	private CustodyChainService service;

	/**
	 * The digests are the point of publishing the chain: they are what lets a reader
	 * recompute it rather than take this system's word, and the head hash is what has to be
	 * witnessed elsewhere. A response that withheld them would be a custody record asking to
	 * be trusted.
	 */
	@Test
	@DisplayName("GET returns the chain in sequence order with both chain hashes on every entry")
	void chainIsReturnedInOrderWithItsDigests() throws Exception {
		given(service.chainOf(ITEM_ID)).willReturn(List.of(
				entry(0L, CustodyAction.CREATED, GENESIS_HASH, ENTRY_HASH_0, null, CONTENT_SHA256),
				entry(1L, CustodyAction.HASH_VERIFIED, ENTRY_HASH_0, ENTRY_HASH_1, CONTENT_SHA256, CONTENT_SHA256)));

		mockMvc.perform(get("/api/evidence-items/{id}/custody", ITEM_ID))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.length()").value(2))
				.andExpect(jsonPath("$[0].sequence").value(0))
				.andExpect(jsonPath("$[0].action").value("CREATED"))
				.andExpect(jsonPath("$[0].evidenceItemId").value(ITEM_ID.toString()))
				.andExpect(jsonPath("$[0].prevEntryHash").value(GENESIS_HASH))
				.andExpect(jsonPath("$[0].entryHash").value(ENTRY_HASH_0))
				.andExpect(jsonPath("$[0].artifactHashBefore").doesNotExist())
				.andExpect(jsonPath("$[0].artifactHashAfter").value(CONTENT_SHA256))
				.andExpect(jsonPath("$[0].canonicalVersion").value(1))
				.andExpect(jsonPath("$[1].sequence").value(1))
				.andExpect(jsonPath("$[1].action").value("HASH_VERIFIED"))
				.andExpect(jsonPath("$[1].prevEntryHash").value(ENTRY_HASH_0))
				.andExpect(jsonPath("$[1].entryHash").value(ENTRY_HASH_1))
				.andExpect(jsonPath("$[1].performedBy").value("j.mokoena"));
	}

	@Test
	@DisplayName("An artifact with no entries returns an empty list, not an error")
	void emptyChainIsAnEmptyList() throws Exception {
		given(service.chainOf(ITEM_ID)).willReturn(List.of());

		mockMvc.perform(get("/api/evidence-items/{id}/custody", ITEM_ID))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.length()").value(0));
	}

	@Test
	@DisplayName("Reading the chain of an unknown item is 404")
	void chainOfUnknownItemIsNotFound() throws Exception {
		willThrow(ResourceNotFoundException.of("EvidenceItem", ITEM_ID)).given(service).chainOf(any());

		mockMvc.perform(get("/api/evidence-items/{id}/custody", ITEM_ID))
				.andExpect(status().isNotFound())
				.andExpect(jsonPath("$.title").value("Resource not found"));
	}

	@Test
	@DisplayName("Verification of an intact chain reports its length and head hash")
	void intactVerificationIsReported() throws Exception {
		given(service.verify(ITEM_ID)).willReturn(CustodyChainVerification.intact(ITEM_ID, 2, ENTRY_HASH_1));

		mockMvc.perform(get("/api/evidence-items/{id}/custody/verification", ITEM_ID))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.intact").value(true))
				.andExpect(jsonPath("$.missingOrigin").value(false))
				.andExpect(jsonPath("$.firstDivergentSequence").doesNotExist())
				.andExpect(jsonPath("$.length").value(2))
				.andExpect(jsonPath("$.headEntryHash").value(ENTRY_HASH_1));
	}

	/**
	 * A broken chain is a successful verification with a negative finding. A 4xx would tell
	 * an HTTP client the request failed, which it did not; the body says where the ledger
	 * stopped agreeing with itself.
	 */
	@Test
	@DisplayName("A divergent chain is still 200, with the position in the body")
	void divergentVerificationIsOkWithThePosition() throws Exception {
		given(service.verify(ITEM_ID)).willReturn(CustodyChainVerification.divergedAt(ITEM_ID, 1L, 3));

		mockMvc.perform(get("/api/evidence-items/{id}/custody/verification", ITEM_ID))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.intact").value(false))
				.andExpect(jsonPath("$.missingOrigin").value(false))
				.andExpect(jsonPath("$.firstDivergentSequence").value(1))
				.andExpect(jsonPath("$.length").value(3))
				.andExpect(jsonPath("$.headEntryHash").doesNotExist());
	}

	@Test
	@DisplayName("A missing origin is reported as such, not as an intact empty chain")
	void missingOriginIsReported() throws Exception {
		given(service.verify(ITEM_ID)).willReturn(CustodyChainVerification.missingOrigin(ITEM_ID));

		mockMvc.perform(get("/api/evidence-items/{id}/custody/verification", ITEM_ID))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.intact").value(false))
				.andExpect(jsonPath("$.missingOrigin").value(true))
				.andExpect(jsonPath("$.length").value(0));
	}

	@Test
	@DisplayName("Verifying an unknown item is 404, never a missing origin")
	void verifyUnknownItemIsNotFound() throws Exception {
		willThrow(ResourceNotFoundException.of("EvidenceItem", ITEM_ID)).given(service).verify(any());

		mockMvc.perform(get("/api/evidence-items/{id}/custody/verification", ITEM_ID))
				.andExpect(status().isNotFound());
	}

	/**
	 * A custody entry is written by the action it records, in that action's transaction.
	 * There is no route for posting one directly, and there must not be.
	 */
	@Test
	@DisplayName("The ledger cannot be appended to over HTTP")
	void chainCannotBePostedTo() throws Exception {
		mockMvc.perform(post("/api/evidence-items/{id}/custody", ITEM_ID))
				.andExpect(status().isMethodNotAllowed());
	}

	private static CustodyEvent entry(
			long sequence,
			CustodyAction action,
			String prevEntryHash,
			String entryHash,
			String artifactHashBefore,
			String artifactHashAfter) {
		EvidenceItem item = new EvidenceItem();
		item.setId(ITEM_ID);

		CustodyEvent event = new CustodyEvent();
		event.setId(UUID.randomUUID());
		event.setEvidenceItem(item);
		event.setSequence(sequence);
		event.setAction(action);
		event.setPerformedBy("j.mokoena");
		event.setOccurredAt(OffsetDateTime.parse("2026-09-05T14:30:34.221000Z"));
		event.setRecordedAt(OffsetDateTime.parse("2026-09-05T14:30:34.223417Z"));
		event.setArtifactHashBefore(artifactHashBefore);
		event.setArtifactHashAfter(artifactHashAfter);
		event.setPrevEntryHash(prevEntryHash);
		event.setEntryHash(entryHash);
		event.setCanonicalVersion((short) 1);
		event.setDetail("Preserved on streamed ingest.");
		return event;
	}
}
