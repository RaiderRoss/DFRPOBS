package za.co.dfraas.repository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.PageRequest;

import za.co.dfraas.TestcontainersConfiguration;
import za.co.dfraas.entity.CorrelationStatus;
import za.co.dfraas.entity.TriggerEvent;

/**
 * The contract between {@link TriggerEvent} and Liquibase changeset
 * {@code 0002-create-trigger-event-table}.
 *
 * <p>As with {@code WorkGroupRepositoryTest}, {@code ddl-auto=validate} means the context
 * fails to start on any column-level disagreement, so every method here implicitly asserts
 * that. The explicit assertions cover the three things validation cannot see: the
 * composite dedupe constraint, the hash-format CHECK, and the {@code received_at} default.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import(TestcontainersConfiguration.class)
class TriggerEventRepositoryTest {

	private static final String SHA_256_OF_EMPTY_STRING =
			"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

	@Autowired
	private TriggerEventRepository repository;

	@Test
	@DisplayName("Hibernate assigns the id, and the column default populates receivedAt")
	void generatedFieldsArePopulatedOnInsert() {
		OffsetDateTime firedAt = OffsetDateTime.parse("2026-01-01T09:00:00Z");
		TriggerEvent saved = repository.saveAndFlush(newEvent("splunk", "EVT-1", firedAt));

		assertThat(saved.getId()).isNotNull();

		// Populated by the now() default and read back via @Generated(INSERT); this is the
		// assertion that fails if that annotation is ever dropped.
		assertThat(saved.getReceivedAt()).isNotNull();

		// The two timestamps must stay independent. receivedAt is the database's account of
		// when we saw the alert; firedAt is the sender's claim about when it happened.
		assertThat(saved.getFiredAt()).isEqualTo(firedAt);
		assertThat(saved.getReceivedAt()).isAfter(firedAt);
	}

	@Test
	@DisplayName("The same external id from the same source is rejected by the database")
	void duplicateSourceAndExternalIdIsRejected() {
		repository.saveAndFlush(newEvent("splunk", "EVT-DUP", OffsetDateTime.parse("2026-01-01T09:00:00Z")));

		// This is the constraint the whole idempotency story rests on. The service's lookup
		// is only a fast path; two consumers racing are stopped here or not at all.
		assertThatThrownBy(() -> repository
				.saveAndFlush(newEvent("splunk", "EVT-DUP", OffsetDateTime.parse("2026-01-01T10:00:00Z"))))
				.isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	@DisplayName("The same external id from a different source is allowed")
	void sameExternalIdFromAnotherSourceIsAccepted() {
		OffsetDateTime firedAt = OffsetDateTime.parse("2026-01-01T09:00:00Z");
		repository.saveAndFlush(newEvent("splunk", "12345", firedAt));

		// The reason the constraint is composite. Alert numbering is per-vendor, so a bare
		// unique index on external_event_id would silently drop this second, unrelated alert.
		TriggerEvent other = repository.saveAndFlush(newEvent("suricata", "12345", firedAt));

		assertThat(other.getId()).isNotNull();
		assertThat(repository.count()).isEqualTo(2);
	}

	@Test
	@DisplayName("A payload_sha256 that is not a lowercase hex digest is rejected")
	void malformedDigestIsRejectedByTheCheckConstraint() {
		TriggerEvent event = newEvent("splunk", "EVT-BAD-HASH", OffsetDateTime.parse("2026-01-01T09:00:00Z"));
		event.setPayloadSha256("not-a-sha-256");

		assertThatThrownBy(() -> repository.saveAndFlush(event))
				.isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	@DisplayName("findBySourceSystemAndExternalEventId resolves the dedupe lookup")
	void findsByCompositeDedupeKey() {
		repository.saveAndFlush(newEvent("splunk", "EVT-FIND", OffsetDateTime.parse("2026-01-01T09:00:00Z")));

		Optional<TriggerEvent> found = repository.findBySourceSystemAndExternalEventId("splunk", "EVT-FIND");

		assertThat(found).isPresent();
		assertThat(found.get().getTriggerType()).isEqualTo("BRUTE_FORCE_LOGIN");
		assertThat(repository.findBySourceSystemAndExternalEventId("splunk", "NO-SUCH-EVENT")).isEmpty();
	}

	@Test
	@DisplayName("findBySourceSystem pages rather than assuming a single result")
	void findsAllEventsForOneSource() {
		OffsetDateTime firedAt = OffsetDateTime.parse("2026-01-01T09:00:00Z");
		repository.saveAndFlush(newEvent("qradar", "EVT-A", firedAt));
		repository.saveAndFlush(newEvent("qradar", "EVT-B", firedAt));

		// The original Optional-returning signature would have thrown here. A source system
		// emits many events; only the composite key identifies one.
		assertThat(repository.findBySourceSystem("qradar", PageRequest.of(0, 10)))
				.hasSize(2)
				.extracting(TriggerEvent::getExternalEventId)
				.containsExactlyInAnyOrder("EVT-A", "EVT-B");
	}

	@Test
	@DisplayName("A recorded alert starts PENDING, with the default correlation window frozen onto it")
	void correlationDefaultsAreRecordedOnInsert() {
		TriggerEvent saved = repository.saveAndFlush(
				newEvent("splunk", "EVT-PENDING", OffsetDateTime.parse("2026-01-01T09:00:00Z")));

		assertThat(saved.getCorrelationStatus()).isEqualTo(CorrelationStatus.PENDING);
		assertThat(saved.getCorrelatedAt()).isNull();

		// The parameters are written onto the row rather than read from configuration when a
		// correlation runs. Configuration changes; a bundle that cannot say what the system
		// was asked to look for cannot be reproduced or defended.
		assertThat(saved.getCorrelationLookbackSeconds()).isEqualTo(TriggerEvent.DEFAULT_LOOKBACK_SECONDS);
		assertThat(saved.getCorrelationLookaheadSeconds()).isEqualTo(TriggerEvent.DEFAULT_LOOKAHEAD_SECONDS);

		// Asymmetric on purpose: reconnaissance, initial access and staging precede
		// detection, so reaching back matters more than reaching forward. Gathering only
		// from the moment of detection is the blind spot continuous collection exists to fix.
		assertThat(saved.getCorrelationLookbackSeconds())
				.isGreaterThan(saved.getCorrelationLookaheadSeconds());
	}

	@Test
	@DisplayName("The correlation work queue returns pending and failed alerts, oldest first")
	void correlationQueueReturnsWhatStillNeedsDoing() {
		OffsetDateTime firedAt = OffsetDateTime.parse("2026-01-01T09:00:00Z");
		repository.saveAndFlush(newEvent("splunk", "EVT-PENDING", firedAt));

		TriggerEvent failed = newEvent("splunk", "EVT-FAILED", firedAt);
		failed.setCorrelationStatus(CorrelationStatus.FAILED);
		repository.saveAndFlush(failed);

		TriggerEvent done = newEvent("splunk", "EVT-DONE", firedAt);
		done.setCorrelationStatus(CorrelationStatus.CORRELATED);
		done.setCorrelatedAt(OffsetDateTime.parse("2026-01-01T09:05:00Z"));
		repository.saveAndFlush(done);

		// PENDING and FAILED need the same work done, which is why the partial index covers
		// exactly that pair. They are still distinct states: an alert never attempted and one
		// whose attempt broke say entirely different things about the system.
		assertThat(repository.findByCorrelationStatusInOrderByReceivedAtAsc(
				List.of(CorrelationStatus.PENDING, CorrelationStatus.FAILED), PageRequest.of(0, 10)))
				.extracting(TriggerEvent::getExternalEventId)
				.containsExactly("EVT-PENDING", "EVT-FAILED");

		assertThat(repository.countByCorrelationStatus(CorrelationStatus.CORRELATED)).isEqualTo(1);
	}

	@Test
	@DisplayName("An alert cannot claim to be correlated without saying when")
	void correlatedWithoutTimestampIsRejected() {
		TriggerEvent event = newEvent("splunk", "EVT-INCONSISTENT", OffsetDateTime.parse("2026-01-01T09:00:00Z"));
		event.setCorrelationStatus(CorrelationStatus.CORRELATED);
		// correlatedAt deliberately left null.

		// Either the status or the missing timestamp is lying, and nothing in the row says
		// which — so the database refuses the combination outright.
		assertThatThrownBy(() -> repository.saveAndFlush(event))
				.isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	@DisplayName("A pending alert cannot carry a completion timestamp")
	void pendingWithTimestampIsRejected() {
		TriggerEvent event = newEvent("splunk", "EVT-BACKDATED", OffsetDateTime.parse("2026-01-01T09:00:00Z"));
		event.setCorrelatedAt(OffsetDateTime.parse("2026-01-01T09:05:00Z"));

		assertThatThrownBy(() -> repository.saveAndFlush(event))
				.isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	@DisplayName("A failed alert may or may not have been correlated before")
	void failedIsTheOneStatusTheTimestampSaysNothingAbout() {
		OffsetDateTime firedAt = OffsetDateTime.parse("2026-01-01T09:00:00Z");

		// Failed on the first attempt: nothing was ever completed.
		TriggerEvent neverCorrelated = newEvent("splunk", "EVT-FAILED-FIRST", firedAt);
		neverCorrelated.setCorrelationStatus(CorrelationStatus.FAILED);
		repository.saveAndFlush(neverCorrelated);

		// Failed on a re-correlation: last week's pass succeeded and its bundle is still
		// valid, so the timestamp must survive the later failure.
		TriggerEvent reCorrelationFailed = newEvent("splunk", "EVT-FAILED-LATER", firedAt);
		reCorrelationFailed.setCorrelationStatus(CorrelationStatus.FAILED);
		reCorrelationFailed.setCorrelatedAt(OffsetDateTime.parse("2026-01-01T09:05:00Z"));
		repository.saveAndFlush(reCorrelationFailed);

		assertThat(repository.countByCorrelationStatus(CorrelationStatus.FAILED)).isEqualTo(2);
	}

	@Test
	@DisplayName("A negative correlation window is rejected")
	void negativeCorrelationWindowIsRejected() {
		TriggerEvent event = newEvent("splunk", "EVT-NEGATIVE", OffsetDateTime.parse("2026-01-01T09:00:00Z"));
		// Zero is legitimate — an alert type whose evidence is strictly contemporaneous —
		// but a negative window inverts the range and silently matches nothing.
		event.setCorrelationLookbackSeconds(-1);

		assertThatThrownBy(() -> repository.saveAndFlush(event))
				.isInstanceOf(DataIntegrityViolationException.class);
	}

	private static TriggerEvent newEvent(String sourceSystem, String externalEventId, OffsetDateTime firedAt) {
		TriggerEvent event = new TriggerEvent();
		event.setSourceSystem(sourceSystem);
		event.setExternalEventId(externalEventId);
		event.setTriggerType("BRUTE_FORCE_LOGIN");
		event.setFiredAt(firedAt);
		event.setPayload("");
		event.setPayloadSha256(SHA_256_OF_EMPTY_STRING);
		return event;
	}
}
