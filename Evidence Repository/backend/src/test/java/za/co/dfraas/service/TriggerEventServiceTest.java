package za.co.dfraas.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.OffsetDateTime;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.context.annotation.Import;

import za.co.dfraas.TestcontainersConfiguration;
import za.co.dfraas.dto.TriggerEventIngestRequest;
import za.co.dfraas.dto.TriggerEventIngestResult;
import za.co.dfraas.mapper.TriggerEventMapper;
import za.co.dfraas.repository.TriggerEventRepository;

/**
 * Idempotency behaviour of {@link TriggerEventService#recordIfAbsent}.
 *
 * <p>Run against real Postgres rather than a mocked repository, because the property under
 * test is a claim about what the database ends up holding after a redelivery — exactly the
 * thing a mock would let pass regardless.
 *
 * <p>{@code @DataJpaTest} does not scan {@code @Service} beans, so the three collaborators
 * are imported explicitly. That is a feature here: it makes the slice's real dependencies
 * visible instead of pulling in the whole context.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import({TestcontainersConfiguration.class, TriggerEventService.class, TriggerEventMapper.class,
		HashingService.class})
class TriggerEventServiceTest {

	private static final OffsetDateTime FIRED_AT = OffsetDateTime.parse("2026-01-01T09:00:00Z");

	/** Known-answer digest of {@code {"alert":"x"}}, so the test does not recompute it. */
	private static final String EXPECTED_DIGEST =
			"c82fb88239e96ae95bfdc7fc1b17a9ef3015a8ac3135bc8955850e0da4398ae8";

	@Autowired
	private TriggerEventService service;

	@Autowired
	private TriggerEventRepository repository;

	@Test
	@DisplayName("A first delivery is recorded and reported as created")
	void firstDeliveryIsRecorded() {
		TriggerEventIngestResult result = service.recordIfAbsent(request("splunk", "EVT-100"));

		assertThat(result.created()).isTrue();
		assertThat(result.triggerEvent().id()).isNotNull();
		assertThat(repository.count()).isEqualTo(1);
	}

	@Test
	@DisplayName("Redelivery of the same alert writes no second row and reports created=false")
	void redeliveryIsIdempotent() {
		TriggerEventIngestResult first = service.recordIfAbsent(request("splunk", "EVT-200"));
		TriggerEventIngestResult second = service.recordIfAbsent(request("splunk", "EVT-200"));

		// The flag is what the consumer branches on: only a genuinely new event should go on
		// to be stored in MinIO and given an EvidenceItem.
		assertThat(second.created()).isFalse();

		// And the row it hands back is the original, not a fresh one — so anything already
		// linked to that trigger event still resolves.
		assertThat(second.triggerEvent().id()).isEqualTo(first.triggerEvent().id());
		assertThat(second.triggerEvent().receivedAt()).isEqualTo(first.triggerEvent().receivedAt());
		assertThat(repository.count()).isEqualTo(1);
	}

	@Test
	@DisplayName("The digest is computed by the service, not accepted from the caller")
	void digestIsComputedOnIngest() {
		TriggerEventIngestResult result = service.recordIfAbsent(request("splunk", "EVT-300"));

		// TriggerEventIngestRequest has no digest field at all, so there is no way for a
		// sender to assert what its own payload hashes to.
		assertThat(result.triggerEvent().payloadSha256())
				.isEqualTo(EXPECTED_DIGEST)
				.matches("^[a-f0-9]{64}$");
	}

	@Test
	@DisplayName("The same external id from another source is a distinct event, not a duplicate")
	void differentSourceIsNotADuplicate() {
		service.recordIfAbsent(request("splunk", "12345"));
		TriggerEventIngestResult other = service.recordIfAbsent(request("suricata", "12345"));

		assertThat(other.created()).isTrue();
		assertThat(repository.count()).isEqualTo(2);
	}

	private static TriggerEventIngestRequest request(String sourceSystem, String externalEventId) {
		return new TriggerEventIngestRequest(
				externalEventId, sourceSystem, "BRUTE_FORCE_LOGIN", FIRED_AT, "{\"alert\":\"x\"}");
	}
}
