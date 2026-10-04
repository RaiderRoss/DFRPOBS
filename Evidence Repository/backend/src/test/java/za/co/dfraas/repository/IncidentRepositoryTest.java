package za.co.dfraas.repository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.OffsetDateTime;
import java.util.List;

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
import za.co.dfraas.entity.Incident;

/**
 * The contract between {@link Incident} and Liquibase changeset {@code 0007-create-incident}.
 *
 * <p>The correlation-state tests moved here from {@code TriggerEventRepositoryTest} along
 * with the columns, and assert the same rules on their new table.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import(TestcontainersConfiguration.class)
class IncidentRepositoryTest {

	private static final OffsetDateTime FIRED_AT = OffsetDateTime.parse("2026-01-01T09:00:00Z");

	@Autowired
	private IncidentRepository repository;

	@Test
	@DisplayName("An incident starts PENDING, with the default correlation window frozen onto it")
	void correlationDefaultsAreRecordedOnInsert() {
		Incident saved = repository.saveAndFlush(newIncident("slips", "k1"));

		assertThat(saved.getCorrelationStatus()).isEqualTo(CorrelationStatus.PENDING);
		assertThat(saved.getCorrelatedAt()).isNull();
		assertThat(saved.getOpenedAt()).isNotNull();

		// Written onto the row rather than read from configuration when a correlation runs:
		// a bundle that cannot say what the system was asked to look for cannot be defended.
		assertThat(saved.getCorrelationLookbackSeconds()).isEqualTo(Incident.DEFAULT_LOOKBACK_SECONDS);
		assertThat(saved.getCorrelationLookaheadSeconds()).isEqualTo(Incident.DEFAULT_LOOKAHEAD_SECONDS);
		// Asymmetric on purpose: what matters precedes detection.
		assertThat(saved.getCorrelationLookbackSeconds()).isGreaterThan(saved.getCorrelationLookaheadSeconds());
	}

	@Test
	@DisplayName("One incident per key per source — the same key from another source is a different incident")
	void keyIsUniqueWithinItsSourceOnly() {
		repository.saveAndFlush(newIncident("slips", "10.99.0.20/tw1"));

		// The key is sender-asserted; scoping it to the source is what stops one source from
		// filing its alerts into another source's incident.
		assertThat(repository.saveAndFlush(newIncident("suricata", "10.99.0.20/tw1")).getId()).isNotNull();
		assertThatThrownBy(() -> repository.saveAndFlush(newIncident("slips", "10.99.0.20/tw1")))
				.isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	@DisplayName("The window spans every member alert, and a closed incident reopens when one joins")
	void absorbWidensTheWindowAndReopens() {
		Incident incident = newIncident("slips", "k-span");
		incident.absorb(FIRED_AT.plusMinutes(10));
		incident.absorb(FIRED_AT.minusMinutes(5));

		assertThat(incident.getFirstFiredAt()).isEqualTo(FIRED_AT.minusMinutes(5));
		assertThat(incident.getLastFiredAt()).isEqualTo(FIRED_AT.plusMinutes(10));
		assertThat(incident.windowStart()).isEqualTo(FIRED_AT.minusMinutes(5).minusSeconds(1800));
		assertThat(incident.windowEnd()).isEqualTo(FIRED_AT.plusMinutes(10).plusSeconds(900));

		incident.setCorrelationStatus(CorrelationStatus.CLOSED);
		incident.setCorrelatedAt(FIRED_AT.plusHours(2));
		incident.absorb(FIRED_AT.plusHours(3));

		// A new alert is new information: back to CORRELATED (not PENDING — correlatedAt still
		// says when it was first correlated, so what the next pass finds is flagged late).
		assertThat(incident.getCorrelationStatus()).isEqualTo(CorrelationStatus.CORRELATED);
		assertThat(repository.saveAndFlush(incident).getLastFiredAt()).isEqualTo(FIRED_AT.plusHours(3));
	}

	@Test
	@DisplayName("A span that ends before it starts is rejected")
	void invertedSpanIsRejected() {
		Incident incident = newIncident("slips", "k-inverted");
		incident.setLastFiredAt(FIRED_AT.minusMinutes(1));

		assertThatThrownBy(() -> repository.saveAndFlush(incident))
				.isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	@DisplayName("The correlation work queue returns pending and failed incidents, oldest first")
	void correlationQueueReturnsWhatStillNeedsDoing() {
		repository.saveAndFlush(newIncident("slips", "pending"));

		Incident failed = newIncident("slips", "failed");
		failed.setCorrelationStatus(CorrelationStatus.FAILED);
		repository.saveAndFlush(failed);

		Incident done = newIncident("slips", "done");
		done.setCorrelationStatus(CorrelationStatus.CORRELATED);
		done.setCorrelatedAt(FIRED_AT.plusMinutes(5));
		repository.saveAndFlush(done);

		assertThat(repository.findByCorrelationStatusInOrderByOpenedAtAsc(
				List.of(CorrelationStatus.PENDING, CorrelationStatus.FAILED), PageRequest.of(0, 10)))
				.extracting(Incident::getIncidentKey)
				.containsExactly("pending", "failed");
		assertThat(repository.countByCorrelationStatus(CorrelationStatus.CORRELATED)).isEqualTo(1);
	}

	@Test
	@DisplayName("An incident cannot claim to be correlated without saying when")
	void correlatedWithoutTimestampIsRejected() {
		Incident incident = newIncident("slips", "inconsistent");
		incident.setCorrelationStatus(CorrelationStatus.CORRELATED);

		assertThatThrownBy(() -> repository.saveAndFlush(incident))
				.isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	@DisplayName("A pending incident cannot carry a completion timestamp")
	void pendingWithTimestampIsRejected() {
		Incident incident = newIncident("slips", "backdated");
		incident.setCorrelatedAt(FIRED_AT.plusMinutes(5));

		assertThatThrownBy(() -> repository.saveAndFlush(incident))
				.isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	@DisplayName("A failed incident may or may not have been correlated before")
	void failedIsTheOneStatusTheTimestampSaysNothingAbout() {
		Incident neverCorrelated = newIncident("slips", "failed-first");
		neverCorrelated.setCorrelationStatus(CorrelationStatus.FAILED);
		repository.saveAndFlush(neverCorrelated);

		// Failed on a re-correlation: the earlier pass's bundle is still valid, so the
		// timestamp must survive the later failure.
		Incident reCorrelationFailed = newIncident("slips", "failed-later");
		reCorrelationFailed.setCorrelationStatus(CorrelationStatus.FAILED);
		reCorrelationFailed.setCorrelatedAt(FIRED_AT.plusMinutes(5));
		repository.saveAndFlush(reCorrelationFailed);

		assertThat(repository.countByCorrelationStatus(CorrelationStatus.FAILED)).isEqualTo(2);
	}

	@Test
	@DisplayName("A negative correlation window is rejected")
	void negativeCorrelationWindowIsRejected() {
		Incident incident = newIncident("slips", "negative");
		// Zero is legitimate; a negative window inverts the range and silently matches nothing.
		incident.setCorrelationLookbackSeconds(-1);

		assertThatThrownBy(() -> repository.saveAndFlush(incident))
				.isInstanceOf(DataIntegrityViolationException.class);
	}

	private static Incident newIncident(String sourceSystem, String key) {
		Incident incident = new Incident();
		incident.setSourceSystem(sourceSystem);
		incident.setIncidentKey(key);
		incident.absorb(FIRED_AT);
		return incident;
	}
}
