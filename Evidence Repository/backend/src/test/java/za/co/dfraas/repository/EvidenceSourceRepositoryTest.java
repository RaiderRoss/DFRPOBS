package za.co.dfraas.repository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.OffsetDateTime;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;

import za.co.dfraas.TestcontainersConfiguration;
import za.co.dfraas.entity.EvidenceSource;
import za.co.dfraas.entity.SourceStatus;
import za.co.dfraas.entity.WorkGroup;

/**
 * The contract between {@link EvidenceSource} and Liquibase changeset
 * {@code 0004-create-evidence-source-and-coverage-window}.
 *
 * <p>Most of this file is about {@link EvidenceSourceRepository#findSilentSources}, which
 * is the point of the entity. Continuous collection introduces a failure mode the reactive
 * design did not have: a collector that stops produces exactly what a collector with
 * nothing to report produces, and nobody is waiting for the difference. These cases pin
 * down which silences are findings and which are not.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import(TestcontainersConfiguration.class)
class EvidenceSourceRepositoryTest {

	/**
	 * Every liveness assertion is made at an explicit instant rather than against the wall
	 * clock. {@code registeredAt} is stamped by the database on insert, so "now" during a
	 * test is effectively registration time; judging from an hour later is what makes an
	 * overdue source overdue, deterministically.
	 */
	private static final OffsetDateTime AN_HOUR_FROM_NOW = OffsetDateTime.now().plusHours(1);

	@Autowired
	private EvidenceSourceRepository repository;

	@Autowired
	private WorkGroupRepository workGroupRepository;

	private WorkGroup workGroup;

	@BeforeEach
	void setUp() {
		workGroup = workGroupRepository.findByClassificationCode("ONLINE_BANKING").orElseThrow();
	}

	@Test
	@DisplayName("Hibernate assigns the id, the column default stamps registeredAt, and status defaults to ACTIVE")
	void generatedFieldsArePopulatedOnInsert() {
		EvidenceSource saved = repository.saveAndFlush(newSource("auth-syslog"));

		assertThat(saved.getId()).isNotNull();
		assertThat(saved.getRegisteredAt()).isNotNull();
		assertThat(saved.getStatus()).isEqualTo(SourceStatus.ACTIVE);
		assertThat(saved.getLastEvidenceAt()).isNull();
	}

	@Test
	@DisplayName("findBySourceKey resolves the identifier a producer puts on the wire")
	void resolvesBySourceKey() {
		repository.saveAndFlush(newSource("auth-syslog"));

		assertThat(repository.findBySourceKey("auth-syslog"))
				.get()
				.extracting(EvidenceSource::getDisplayName)
				.isEqualTo("Authentication syslog forwarder");
		assertThat(repository.existsBySourceKey("not-registered")).isFalse();
	}

	@Test
	@DisplayName("Two sources cannot share a source key")
	void duplicateSourceKeyIsRejected() {
		repository.saveAndFlush(newSource("auth-syslog"));

		// Unlike an external event id, this key is assigned by us at registration, so it can
		// and should be unique outright rather than only within some issuing system.
		assertThatThrownBy(() -> repository.saveAndFlush(newSource("auth-syslog")))
				.isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	@DisplayName("A zero or negative cadence is rejected")
	void nonPositiveCadenceIsRejected() {
		EvidenceSource source = newSource("broken-cadence");
		source.setExpectedIntervalSeconds(0);

		// An always-overdue source would put a permanent entry in the liveness report, and
		// an alarm that is always on is an alarm nobody reads.
		assertThatThrownBy(() -> repository.saveAndFlush(source))
				.isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	@DisplayName("A source that has produced nothing since registration is reported silent")
	void sourceThatNeverProducedIsSilent() {
		// The case worth catching most: a collector misconfigured on the day it was
		// onboarded, quietly delivering nothing ever since. COALESCE(last_evidence_at,
		// registered_at) is what makes registration the deadline when there is no delivery
		// to measure from.
		repository.saveAndFlush(withCadence(newSource("never-delivered"), 300));

		assertThat(repository.findSilentSources(AN_HOUR_FROM_NOW))
				.extracting(EvidenceSource::getSourceKey)
				.containsExactly("never-delivered");
	}

	@Test
	@DisplayName("A source that delivered within its cadence is not silent")
	void recentlyDeliveredSourceIsNotSilent() {
		EvidenceSource source = withCadence(newSource("healthy"), 3600);
		source.setLastEvidenceAt(AN_HOUR_FROM_NOW.minusMinutes(5));
		repository.saveAndFlush(source);

		assertThat(repository.findSilentSources(AN_HOUR_FROM_NOW)).isEmpty();
	}

	@Test
	@DisplayName("A source past its cadence is reported silent")
	void overdueSourceIsSilent() {
		EvidenceSource source = withCadence(newSource("stalled"), 300);
		source.setLastEvidenceAt(AN_HOUR_FROM_NOW.minusMinutes(30));
		repository.saveAndFlush(source);

		assertThat(repository.findSilentSources(AN_HOUR_FROM_NOW))
				.extracting(EvidenceSource::getSourceKey)
				.containsExactly("stalled");
	}

	@Test
	@DisplayName("Silence is not a finding for event-driven, suspended or decommissioned sources")
	void silenceIsOnlyAFindingForActiveSourcesWithACadence() {
		// No declared cadence: event-driven, so silence proves nothing and holding it to an
		// interval would manufacture a permanent false alarm.
		repository.saveAndFlush(newSource("event-driven"));

		// Deliberately paused and permanently retired. Both are silent, and in both cases
		// somebody already knows why — which is the whole reason SourceStatus exists.
		EvidenceSource suspended = withCadence(newSource("suspended"), 60);
		suspended.setStatus(SourceStatus.SUSPENDED);
		repository.saveAndFlush(suspended);

		EvidenceSource retired = withCadence(newSource("retired"), 60);
		retired.setStatus(SourceStatus.DECOMMISSIONED);
		repository.saveAndFlush(retired);

		assertThat(repository.findSilentSources(AN_HOUR_FROM_NOW)).isEmpty();
	}

	@Test
	@DisplayName("Silent sources are reported longest-silent first")
	void silentSourcesAreOrderedByHowLongTheyHaveBeenQuiet() {
		EvidenceSource quietForAges = withCadence(newSource("quiet-for-ages"), 60);
		quietForAges.setLastEvidenceAt(AN_HOUR_FROM_NOW.minusDays(2));
		repository.saveAndFlush(quietForAges);

		EvidenceSource quietRecently = withCadence(newSource("quiet-recently"), 60);
		quietRecently.setLastEvidenceAt(AN_HOUR_FROM_NOW.minusMinutes(10));
		repository.saveAndFlush(quietRecently);

		assertThat(repository.findSilentSources(AN_HOUR_FROM_NOW))
				.extracting(EvidenceSource::getSourceKey)
				.containsExactly("quiet-for-ages", "quiet-recently");
	}

	@Test
	@DisplayName("A non-default status round-trips, and the CHECK constraint forces name storage")
	void statusRoundTripsByName() {
		EvidenceSource source = newSource("named-status");
		source.setStatus(SourceStatus.DECOMMISSIONED);
		repository.saveAndFlush(source);

		// This insert succeeding is itself the guard on @Enumerated(EnumType.STRING): an
		// ordinal mapping would write "2" into a VARCHAR column that ck_evidence_source_status
		// only permits the three names in, so the row would be rejected outright rather than
		// silently stored as a number nobody can read.
		assertThat(repository.findByStatus(SourceStatus.DECOMMISSIONED))
				.extracting(EvidenceSource::getSourceKey)
				.containsExactly("named-status");
	}

	private EvidenceSource newSource(String sourceKey) {
		EvidenceSource source = new EvidenceSource();
		source.setSourceKey(sourceKey);
		source.setDisplayName("Authentication syslog forwarder");
		source.setSourceType("SYSLOG");
		source.setWorkGroup(workGroup);
		return source;
	}

	private static EvidenceSource withCadence(EvidenceSource source, int seconds) {
		source.setExpectedIntervalSeconds(seconds);
		return source;
	}
}
