package za.co.dfraas.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Clock;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.jpa.test.autoconfigure.TestEntityManager;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.PageRequest;

import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import za.co.dfraas.TestcontainersConfiguration;
import za.co.dfraas.config.CorrelationProperties;
import za.co.dfraas.entity.CorrelationStatus;
import za.co.dfraas.entity.EvidenceItem;
import za.co.dfraas.entity.EvidenceLink;
import za.co.dfraas.entity.EvidenceSource;
import za.co.dfraas.entity.EvidenceStatus;
import za.co.dfraas.entity.Incident;
import za.co.dfraas.entity.LinkDisposition;
import za.co.dfraas.entity.LinkMethod;
import za.co.dfraas.entity.TriggerEvent;
import za.co.dfraas.entity.WorkGroup;
import za.co.dfraas.exception.CorrelationException;
import za.co.dfraas.repository.EvidenceItemIndicatorRepository;
import za.co.dfraas.repository.EvidenceItemRepository;
import za.co.dfraas.repository.EvidenceLinkRepository;
import za.co.dfraas.repository.EvidenceSourceRepository;
import za.co.dfraas.repository.IncidentRepository;
import za.co.dfraas.repository.TriggerEventRepository;
import za.co.dfraas.repository.WorkGroupRepository;

/**
 * Behaviour of {@link CorrelationService} against Postgres.
 *
 * <p>A real database rather than mocks, because the pass is mostly a query: the overlap
 * test is a native {@code tstzrange} predicate, and the constraints on {@code evidence_link}
 * and {@code trigger_event} are what reject a link or a status the pass should never write.
 *
 * <p>The clock is fixed at 15:00 and the default alert fires at 14:30, so its window is
 * 14:00–14:45 and its bundle settles at 15:45 — open for every test that does not move
 * the alert into the past on purpose.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import({TestcontainersConfiguration.class, CorrelationService.class, IndicatorExtractor.class,
		EvidenceItemIndicatorRepository.class, CorrelationServiceTest.Config.class})
class CorrelationServiceTest {

	private static final String SHA_256_OF_EMPTY_STRING =
			"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

	private static final OffsetDateTime NOW = OffsetDateTime.parse("2026-01-01T15:00:00Z");
	private static final OffsetDateTime FIRED_AT = OffsetDateTime.parse("2026-01-01T14:30:00Z");

	/** Small, so the paging test needs only a handful of items to cross a page boundary. */
	private static final int PAGE_SIZE = 2;

	@TestConfiguration(proxyBeanMethods = false)
	static class Config {

		@Bean
		Clock clock() {
			return Clock.fixed(NOW.toInstant(), ZoneOffset.UTC);
		}

		@Bean
		ObjectMapper objectMapper() {
			return JsonMapper.builder().build();
		}

		@Bean
		CorrelationProperties correlationProperties() {
			return new CorrelationProperties(false, Duration.ofMinutes(1), 100, PAGE_SIZE, Duration.ofHours(1));
		}
	}

	@Autowired
	private CorrelationService service;

	@Autowired
	private IncidentRepository incidentRepository;

	@Autowired
	private EvidenceItemRepository evidenceItemRepository;

	@Autowired
	private EvidenceLinkRepository evidenceLinkRepository;

	@Autowired
	private EvidenceSourceRepository evidenceSourceRepository;

	@Autowired
	private WorkGroupRepository workGroupRepository;

	@Autowired
	private TriggerEventRepository triggerEventRepository;

	@Autowired
	private EvidenceItemIndicatorRepository indicatorRepository;

	@Autowired
	private TestEntityManager entityManager;

	private WorkGroup onlineBanking;
	private WorkGroup internalSystems;
	private EvidenceSource ids;
	private EvidenceSource firewall;
	private int artifactCounter;

	@BeforeEach
	void setUp() {
		// Both seeded by changeset 0001-2.
		onlineBanking = workGroupRepository.findByClassificationCode("ONLINE_BANKING").orElseThrow();
		internalSystems = workGroupRepository.findByClassificationCode("INTERNAL_SYSTEMS").orElseThrow();
		ids = evidenceSourceRepository.saveAndFlush(newSource("slips-ids", onlineBanking));
		firewall = evidenceSourceRepository.saveAndFlush(newSource("edge-firewall", onlineBanking));
	}

	@Test
	@DisplayName("Overlapping evidence in the alert's work group is proposed, and nothing else is")
	void linksOnlyOverlappingItemsInScope() {
		EvidenceItem inside = item(firewall, at("14:00"), at("15:00"));
		EvidenceItem pointInTime = item(firewall, at("14:45"), at("14:45"));
		EvidenceItem tooEarly = item(firewall, at("13:00"), at("13:59"));
		EvidenceItem otherGroup = item(newSourceSaved("hr-syslog", internalSystems), at("14:10"), at("14:20"));
		Incident alert = alert("slips-ids", FIRED_AT);

		var result = service.correlate(alert.getId());

		assertThat(result.linksAdded()).isEqualTo(2);
		assertThat(linkedItemIds(alert)).containsExactlyInAnyOrder(inside.getId(), pointInTime.getId())
				.doesNotContain(tooEarly.getId(), otherGroup.getId());

		EvidenceLink link = links(alert).get(0);
		assertThat(link.getLinkMethod()).isEqualTo(LinkMethod.AUTO_TIME_WINDOW);
		// An overlap is a reason to look, not a finding.
		assertThat(link.getDisposition()).isEqualTo(LinkDisposition.PROPOSED);
		assertThat(link.getLinkedBy()).isNull();
		assertThat(link.isLateArrival()).isFalse();
		assertThat(link.getRationale()).contains("ONLINE_BANKING").contains("lookback 1800s");
	}

	@Test
	@DisplayName("An item covering the instant an alert fired is proposed by rule, its neighbours by time")
	void alertInstantRule() {
		EvidenceItem covering = item(firewall, at("14:25"), at("14:35"));
		EvidenceItem before = item(firewall, at("14:00"), at("14:20"));
		Incident scan = alertWithPayload(FIRED_AT, "{}");

		service.correlate(scan.getId());

		assertThat(link(scan, covering).getLinkMethod()).isEqualTo(LinkMethod.AUTO_RULE);
		assertThat(link(scan, covering).getRationale()).startsWith("Matched alert-instant")
				.contains(FIRED_AT.toString());
		assertThat(link(scan, before).getLinkMethod()).isEqualTo(LinkMethod.AUTO_TIME_WINDOW);
		// A rule changes how a link is graded, never whether it is a finding.
		assertThat(links(scan)).allSatisfy(link ->
				assertThat(link.getDisposition()).isEqualTo(LinkDisposition.PROPOSED));
	}

	@Test
	@DisplayName("An item mentioning the address the alert names is proposed by rule; a shared server address is not")
	void sharedIndicatorRule() {
		EvidenceItem attacker = item(firewall, at("14:00"), at("14:10"));
		EvidenceItem serverOnly = item(firewall, at("14:10"), at("14:20"));
		indicatorRepository.saveIpv4(attacker.getId(), List.of("10.98.0.1", "10.99.0.20"));
		indicatorRepository.saveIpv4(serverOnly.getId(), List.of("10.98.0.1", "10.99.0.11"));
		// The server appears in the payload's evidence, but only indicators.ip is the subject.
		Incident scan = alertWithPayload(FIRED_AT,
				"{\"indicators\":{\"ip\":[\"10.99.0.20\"]},\"slips\":{\"line\":\"from 10.99.0.20 to 10.98.0.1\"}}");

		service.correlate(scan.getId());

		assertThat(link(scan, attacker).getLinkMethod()).isEqualTo(LinkMethod.AUTO_RULE);
		assertThat(link(scan, attacker).getRationale()).contains("shared-indicator").contains("10.99.0.20")
				.doesNotContain("10.98.0.1");
		assertThat(link(scan, serverOnly).getLinkMethod()).isEqualTo(LinkMethod.AUTO_TIME_WINDOW);
	}

	@Test
	@DisplayName("An alert whose payload is not JSON is still correlated on time and on its instant")
	void unreadablePayloadStillCorrelates() {
		EvidenceItem covering = item(firewall, at("14:25"), at("14:35"));
		item(firewall, at("14:00"), at("14:10"));
		Incident alert = alertWithPayload(FIRED_AT, "not json");

		assertThat(service.correlate(alert.getId()).linksAdded()).isEqualTo(2);
		assertThat(link(alert, covering).getLinkMethod()).isEqualTo(LinkMethod.AUTO_RULE);
	}

	@Test
	@DisplayName("A first pass marks the alert correlated and freezes the scope it searched")
	void firstPassRecordsStatusAndScope() {
		Incident alert = alert("slips-ids", FIRED_AT);

		service.correlate(alert.getId());

		Incident reloaded = reload(alert);
		assertThat(reloaded.getCorrelationStatus()).isEqualTo(CorrelationStatus.CORRELATED);
		assertThat(reloaded.getCorrelatedAt()).isAtSameInstantAs(NOW);
		assertThat(reloaded.getCorrelationScope())
				.contains(onlineBanking.getId().toString())
				.contains("slips-ids");
	}

	@Test
	@DisplayName("An alert with nothing overlapping is still correlated — an empty window is an answer")
	void emptyWindowIsStillCorrelated() {
		Incident alert = alert("slips-ids", FIRED_AT);

		var result = service.correlate(alert.getId());

		assertThat(result.linksAdded()).isZero();
		assertThat(reload(alert).getCorrelationStatus()).isEqualTo(CorrelationStatus.CORRELATED);
	}

	@Test
	@DisplayName("A re-run adds nothing twice, and flags evidence that arrived since as late")
	void rerunIsIdempotentAndFlagsLateArrivals() {
		EvidenceItem early = item(firewall, at("14:00"), at("14:30"));
		Incident alert = alert("slips-ids", FIRED_AT);
		service.correlate(alert.getId());

		assertThat(service.correlate(alert.getId()).linksAdded()).isZero();

		EvidenceItem late = item(firewall, at("14:30"), at("15:00"));
		assertThat(service.correlate(alert.getId()).linksAdded()).isEqualTo(1);

		assertThat(links(alert)).hasSize(2).allSatisfy(link -> assertThat(link.isLateArrival())
				.isEqualTo(link.getEvidenceItem().getId().equals(late.getId())));
		assertThat(linkedItemIds(alert)).contains(early.getId());
		// The first completion time survives every later pass.
		assertThat(reload(alert).getCorrelatedAt()).isAtSameInstantAs(NOW);
	}

	@Test
	@DisplayName("Every overlapping item is linked, however many pages the search spans")
	void linksAcrossPages() {
		for (int i = 0; i < PAGE_SIZE * 2 + 1; i++) {
			item(firewall, at("14:00"), at("14:40"));
		}
		Incident alert = alert("slips-ids", FIRED_AT);

		assertThat(service.correlate(alert.getId()).linksAdded()).isEqualTo(PAGE_SIZE * 2 + 1);
		assertThat(links(alert)).hasSize(PAGE_SIZE * 2 + 1);
	}

	@Test
	@DisplayName("An alert whose window ended longer ago than the settle period is closed, and stays closed")
	void settledAlertIsClosed() {
		// Window 10:00-10:45, settled at 11:45, well before the 15:00 clock.
		item(firewall, at("10:00"), at("10:30"));
		Incident alert = alert("slips-ids", at("10:30"));

		var result = service.correlate(alert.getId());

		assertThat(result.status()).isEqualTo(CorrelationStatus.CLOSED);
		assertThat(result.linksAdded()).isEqualTo(1);

		// Closing stops the machine: evidence arriving now is not linked automatically.
		item(firewall, at("10:00"), at("10:30"));
		assertThat(service.correlate(alert.getId()).linksAdded()).isZero();
		assertThat(links(alert)).hasSize(1);
	}

	@Test
	@DisplayName("A grouped incident searches from its first alert's lookback to its last alert's lookahead")
	void groupedIncidentWindowSpansEveryAlert() {
		// Alerts at 14:30 and 15:30: the window is 14:00-15:45. A lone 14:30 alert would stop at
		// 14:45 and miss the second item; a lone 15:30 alert would start at 15:00 and miss the first.
		EvidenceItem duringFirst = item(firewall, at("14:05"), at("14:10"));
		EvidenceItem duringSecond = item(firewall, at("15:35"), at("15:40"));
		item(firewall, at("15:50"), at("15:55"));
		Incident scan = incident("slips-ids", at("14:30"), at("15:30"));

		assertThat(service.correlate(scan.getId()).linksAdded()).isEqualTo(2);
		assertThat(linkedItemIds(scan)).containsExactlyInAnyOrder(duringFirst.getId(), duringSecond.getId());
		assertThat(links(scan).get(0).getRationale()).contains("alerts fired");
	}

	@Test
	@DisplayName("An alert from an unregistered source cannot be correlated")
	void unregisteredSourceIsRejected() {
		item(firewall, at("14:00"), at("15:00"));
		Incident alert = alert("unknown-siem", FIRED_AT);

		assertThatThrownBy(() -> service.correlate(alert.getId()))
				.isInstanceOf(CorrelationException.class)
				.hasMessageContaining("unknown-siem");
		assertThat(links(alert)).isEmpty();
	}

	@Test
	@DisplayName("Reclassifying the source does not change what an already-correlated alert searches")
	void frozenScopeOutlivesReclassification() {
		Incident alert = alert("slips-ids", FIRED_AT);
		service.correlate(alert.getId());

		ids.setWorkGroup(internalSystems);
		evidenceSourceRepository.saveAndFlush(ids);
		item(newSourceSaved("hr-syslog", internalSystems), at("14:10"), at("14:20"));

		assertThat(service.correlate(alert.getId()).linksAdded()).isZero();
	}

	@Test
	@DisplayName("A failure after a completed pass keeps the first completion time")
	void markFailedKeepsCorrelatedAt() {
		Incident alert = alert("slips-ids", FIRED_AT);
		service.correlate(alert.getId());

		service.markFailed(alert.getId());

		Incident reloaded = reload(alert);
		assertThat(reloaded.getCorrelationStatus()).isEqualTo(CorrelationStatus.FAILED);
		assertThat(reloaded.getCorrelatedAt()).isAtSameInstantAs(NOW);
	}

	@Test
	@DisplayName("The work queue holds pending and failed alerts, oldest first")
	void queueReturnsUncorrelatedAlerts() {
		Incident pending = alert("slips-ids", FIRED_AT);
		Incident correlated = alert("slips-ids", FIRED_AT);
		service.correlate(correlated.getId());

		List<UUID> queue = service.queue(List.of(CorrelationStatus.PENDING, CorrelationStatus.FAILED), 10);

		assertThat(queue).contains(pending.getId()).doesNotContain(correlated.getId());
	}

	/**
	 * A one-alert incident — what an alert sent without a group key becomes. Correlation reads
	 * only the incident, so the member trigger events themselves are not needed here.
	 */
	private Incident alert(String sourceSystem, OffsetDateTime firedAt) {
		return incident(sourceSystem, firedAt);
	}

	private Incident incident(String sourceSystem, OffsetDateTime... firedAts) {
		Incident incident = new Incident();
		incident.setSourceSystem(sourceSystem);
		incident.setIncidentKey(Incident.keyForUngrouped(UUID.randomUUID().toString()));
		for (OffsetDateTime firedAt : firedAts) {
			incident.absorb(firedAt);
		}
		return incidentRepository.saveAndFlush(incident);
	}

	/** A one-alert incident whose member trigger event exists, carrying {@code payload}. */
	private Incident alertWithPayload(OffsetDateTime firedAt, String payload) {
		Incident incident = incident("slips-ids", firedAt);
		TriggerEvent event = new TriggerEvent();
		event.setIncident(incident);
		event.setSourceSystem("slips-ids");
		event.setExternalEventId(UUID.randomUUID().toString());
		event.setTriggerType("SLIPS_ALERT");
		event.setFiredAt(firedAt);
		event.setPayload(payload);
		event.setPayloadSha256(SHA_256_OF_EMPTY_STRING);
		triggerEventRepository.saveAndFlush(event);
		return incident;
	}

	private EvidenceLink link(Incident incident, EvidenceItem item) {
		return links(incident).stream()
				.filter(link -> link.getEvidenceItem().getId().equals(item.getId()))
				.findFirst().orElseThrow();
	}

	private EvidenceItem item(EvidenceSource source, OffsetDateTime start, OffsetDateTime end) {
		String artifactId = "artifact-" + artifactCounter++;
		EvidenceItem item = new EvidenceItem();
		item.setWorkGroup(source.getWorkGroup());
		item.setEvidenceSource(source);
		item.setSourceArtifactId(artifactId);
		item.setStorageRef("evidence/" + source.getSourceKey() + "/" + artifactId);
		item.setCurrentHash(SHA_256_OF_EMPTY_STRING);
		item.setStatus(EvidenceStatus.PRESERVED);
		item.setEventStart(start);
		item.setEventEnd(end);
		return evidenceItemRepository.saveAndFlush(item);
	}

	private EvidenceSource newSourceSaved(String sourceKey, WorkGroup workGroup) {
		return evidenceSourceRepository.saveAndFlush(newSource(sourceKey, workGroup));
	}

	private static EvidenceSource newSource(String sourceKey, WorkGroup workGroup) {
		EvidenceSource source = new EvidenceSource();
		source.setSourceKey(sourceKey);
		source.setDisplayName(sourceKey);
		source.setSourceType("SYSLOG");
		source.setWorkGroup(workGroup);
		return source;
	}

	/** Flushes the pass's writes and reads the alert back as the database holds it. */
	private Incident reload(Incident alert) {
		entityManager.flush();
		entityManager.clear();
		return incidentRepository.findById(alert.getId()).orElseThrow();
	}

	private List<EvidenceLink> links(Incident alert) {
		entityManager.flush();
		return evidenceLinkRepository.findByIncidentId(alert.getId(), PageRequest.of(0, 100)).getContent();
	}

	private List<UUID> linkedItemIds(Incident alert) {
		return links(alert).stream().map(link -> link.getEvidenceItem().getId()).toList();
	}

	private static OffsetDateTime at(String time) {
		return OffsetDateTime.parse("2026-01-01T" + time + ":00Z");
	}
}
