package za.co.dfraas.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.OffsetDateTime;
import java.util.UUID;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.context.annotation.Import;

import za.co.dfraas.TestcontainersConfiguration;
import za.co.dfraas.dto.TriggerEventIngestRequest;
import za.co.dfraas.dto.TriggerEventIngestResult;
import za.co.dfraas.entity.CorrelationStatus;
import za.co.dfraas.entity.Incident;
import za.co.dfraas.mapper.TriggerEventMapper;
import za.co.dfraas.repository.IncidentRepository;
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

	@Autowired
	private IncidentRepository incidentRepository;

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

	@Test
	@DisplayName("Alerts sharing an incident key are one incident, and its span covers them all")
	void alertsWithTheSameKeyShareAnIncident() {
		String key = "ids-1/10.99.0.20/tw1";
		UUID first = service.recordIfAbsent(request("slips", "A1", FIRED_AT, key)).triggerEvent().incidentId();
		UUID second = service.recordIfAbsent(request("slips", "A2", FIRED_AT.plusMinutes(3), key))
				.triggerEvent().incidentId();
		UUID earlier = service.recordIfAbsent(request("slips", "A3", FIRED_AT.minusMinutes(1), key))
				.triggerEvent().incidentId();

		// Every alert is still its own trigger event — nothing the IDS said is dropped.
		assertThat(repository.count()).isEqualTo(3);
		// But one investigation, so one bundle rather than three.
		assertThat(second).isEqualTo(first);
		assertThat(earlier).isEqualTo(first);
		Incident incident = incidentRepository.findById(first).orElseThrow();
		assertThat(incident.getFirstFiredAt()).isEqualTo(FIRED_AT.minusMinutes(1));
		assertThat(incident.getLastFiredAt()).isEqualTo(FIRED_AT.plusMinutes(3));
	}

	@Test
	@DisplayName("An alert without a key is an incident of its own")
	void alertsWithoutAKeyAreNotGrouped() {
		UUID a = service.recordIfAbsent(request("splunk", "EVT-A")).triggerEvent().incidentId();
		UUID b = service.recordIfAbsent(request("splunk", "EVT-B")).triggerEvent().incidentId();

		assertThat(a).isNotEqualTo(b);
		assertThat(incidentRepository.findById(a).orElseThrow().getIncidentKey()).isEqualTo("event:EVT-A");
	}

	@Test
	@DisplayName("The same key from two sources is two incidents")
	void keysAreScopedToTheirSource() {
		UUID slips = service.recordIfAbsent(request("slips", "X", FIRED_AT, "shared")).triggerEvent().incidentId();
		UUID other = service.recordIfAbsent(request("suricata", "X", FIRED_AT, "shared")).triggerEvent().incidentId();

		// The key is sender-asserted; a source must not be able to file into another's incident.
		assertThat(slips).isNotEqualTo(other);
	}

	@Test
	@DisplayName("A redelivered alert does not stretch its incident")
	void redeliveryDoesNotTouchTheIncident() {
		UUID incidentId = service.recordIfAbsent(request("slips", "A1", FIRED_AT, "k")).triggerEvent().incidentId();
		// Same alert id, different (wrong) fired time — a duplicate returns before filing.
		service.recordIfAbsent(request("slips", "A1", FIRED_AT.plusHours(5), "k"));

		assertThat(incidentRepository.findById(incidentId).orElseThrow().getLastFiredAt()).isEqualTo(FIRED_AT);
	}

	@Test
	@DisplayName("A new alert reopens a closed incident")
	void newAlertReopensAClosedIncident() {
		UUID incidentId = service.recordIfAbsent(request("slips", "A1", FIRED_AT, "k")).triggerEvent().incidentId();
		Incident incident = incidentRepository.findById(incidentId).orElseThrow();
		incident.setCorrelationStatus(CorrelationStatus.CLOSED);
		incident.setCorrelatedAt(FIRED_AT.plusMinutes(5));
		incidentRepository.saveAndFlush(incident);

		service.recordIfAbsent(request("slips", "A2", FIRED_AT.plusHours(2), "k"));

		assertThat(incidentRepository.findById(incidentId).orElseThrow().getCorrelationStatus())
				.isEqualTo(CorrelationStatus.CORRELATED);
	}

	private static TriggerEventIngestRequest request(String sourceSystem, String externalEventId) {
		return request(sourceSystem, externalEventId, FIRED_AT, null);
	}

	private static TriggerEventIngestRequest request(
			String sourceSystem, String externalEventId, OffsetDateTime firedAt, String incidentKey) {
		return new TriggerEventIngestRequest(
				externalEventId, sourceSystem, "BRUTE_FORCE_LOGIN", firedAt, "{\"alert\":\"x\"}", incidentKey);
	}
}
