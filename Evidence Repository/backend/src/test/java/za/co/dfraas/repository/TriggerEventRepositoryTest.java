package za.co.dfraas.repository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.OffsetDateTime;
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
