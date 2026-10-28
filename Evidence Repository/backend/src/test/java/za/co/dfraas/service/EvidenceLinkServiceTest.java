package za.co.dfraas.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Clock;
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
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import za.co.dfraas.TestcontainersConfiguration;
import za.co.dfraas.dto.EvidenceLinkDto;
import za.co.dfraas.entity.EvidenceItem;
import za.co.dfraas.entity.EvidenceLink;
import za.co.dfraas.entity.EvidenceSource;
import za.co.dfraas.entity.EvidenceStatus;
import za.co.dfraas.entity.Incident;
import za.co.dfraas.entity.LinkDisposition;
import za.co.dfraas.entity.LinkMethod;
import za.co.dfraas.entity.WorkGroup;
import za.co.dfraas.exception.LinkAlreadyReviewedException;
import za.co.dfraas.exception.ResourceNotFoundException;
import za.co.dfraas.mapper.EvidenceItemMapper;
import za.co.dfraas.mapper.EvidenceLinkMapper;
import za.co.dfraas.repository.EvidenceItemRepository;
import za.co.dfraas.repository.EvidenceLinkRepository;
import za.co.dfraas.repository.EvidenceSourceRepository;
import za.co.dfraas.repository.IncidentRepository;
import za.co.dfraas.repository.WorkGroupRepository;

/**
 * Behaviour of {@link EvidenceLinkService} against Postgres.
 *
 * <p>A real database, because the property that matters most — a link is reviewed once and
 * the first ruling stands — is enforced by the conditional update's {@code WHERE} clause and
 * by {@code ck_evidence_link_review_complete}, neither of which a mock would exercise.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import({
	TestcontainersConfiguration.class,
	EvidenceLinkService.class,
	EvidenceLinkMapper.class,
	EvidenceItemMapper.class,
	EvidenceLinkServiceTest.Config.class})
class EvidenceLinkServiceTest {

	private static final String SHA_256_OF_EMPTY_STRING =
			"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

	private static final OffsetDateTime NOW = OffsetDateTime.parse("2026-01-01T16:00:00Z");

	@TestConfiguration(proxyBeanMethods = false)
	static class Config {

		@Bean
		Clock clock() {
			return Clock.fixed(NOW.toInstant(), ZoneOffset.UTC);
		}
	}

	@Autowired
	private EvidenceLinkService service;

	@Autowired
	private EvidenceLinkRepository linkRepository;

	@Autowired
	private IncidentRepository incidentRepository;

	@Autowired
	private EvidenceItemRepository evidenceItemRepository;

	@Autowired
	private EvidenceSourceRepository evidenceSourceRepository;

	@Autowired
	private WorkGroupRepository workGroupRepository;

	private EvidenceSource firewall;
	private Incident alert;
	private int artifactCounter;

	@BeforeEach
	void setUp() {
		WorkGroup onlineBanking = workGroupRepository.findByClassificationCode("ONLINE_BANKING").orElseThrow();
		EvidenceSource source = new EvidenceSource();
		source.setSourceKey("edge-firewall");
		source.setDisplayName("Edge firewall");
		source.setSourceType("SYSLOG");
		source.setWorkGroup(onlineBanking);
		firewall = evidenceSourceRepository.saveAndFlush(source);
		alert = alert();
	}

	@Test
	@DisplayName("Confirming records who, when and why, and the response shows what was confirmed")
	void confirmRecordsTheReview() {
		EvidenceLink link = link(LinkMethod.AUTO_TIME_WINDOW);

		EvidenceLinkDto confirmed = service.confirm(link.getId(), "j.mokoena", "  Same source IP probing.  ");

		assertThat(confirmed.disposition()).isEqualTo(LinkDisposition.CONFIRMED);
		assertThat(confirmed.reviewedBy()).isEqualTo("j.mokoena");
		assertThat(confirmed.reviewedAt()).isAtSameInstantAs(NOW);
		assertThat(confirmed.reviewNote()).isEqualTo("Same source IP probing.");
		// The reviewer has to see what they ruled on, not just an id.
		assertThat(confirmed.evidenceSourceKey()).isEqualTo("edge-firewall");
		assertThat(confirmed.evidenceItem().id()).isEqualTo(link.getEvidenceItem().getId());
		// The proposal's own reasoning is untouched by the review.
		assertThat(confirmed.rationale()).isEqualTo("overlap");
	}

	@Test
	@DisplayName("Dismissing keeps the link, marked dismissed, rather than removing it")
	void dismissKeepsTheLink() {
		EvidenceLink link = link(LinkMethod.AUTO_TIME_WINDOW);

		EvidenceLinkDto dismissed = service.dismiss(link.getId(), "j.mokoena", "Covers the wrong host.");

		assertThat(dismissed.disposition()).isEqualTo(LinkDisposition.DISMISSED);
		assertThat(linkRepository.countByIncidentId(alert.getId())).isEqualTo(1);
	}

	@Test
	@DisplayName("A reviewed link cannot be reviewed again, and the first ruling stands")
	void secondReviewIsRefused() {
		EvidenceLink link = link(LinkMethod.AUTO_TIME_WINDOW);
		service.dismiss(link.getId(), "j.mokoena", "Covers the wrong host.");

		// Overwriting would turn "dismissed by A, then confirmed by B" into "confirmed by B"
		// and lose the dismissal — the part of the record a defence would most want.
		assertThatThrownBy(() -> service.confirm(link.getId(), "a.pillay", "Actually relevant."))
				.isInstanceOf(LinkAlreadyReviewedException.class)
				.hasMessageContaining("DISMISSED");

		EvidenceLinkDto stored = service.findById(link.getId());
		assertThat(stored.disposition()).isEqualTo(LinkDisposition.DISMISSED);
		assertThat(stored.reviewedBy()).isEqualTo("j.mokoena");
		assertThat(stored.reviewNote()).isEqualTo("Covers the wrong host.");
	}

	@Test
	@DisplayName("A causal link, confirmed by observation at ingest, is not open to review")
	void causalLinkIsNotReviewable() {
		EvidenceLink link = link(LinkMethod.CAUSAL);
		link.setDisposition(LinkDisposition.CONFIRMED);
		linkRepository.saveAndFlush(link);

		assertThatThrownBy(() -> service.dismiss(link.getId(), "j.mokoena", "Not relevant."))
				.isInstanceOf(LinkAlreadyReviewedException.class);
	}

	@Test
	@DisplayName("Reviewing a link that does not exist is a 404, not a conflict")
	void unknownLinkIsNotFound() {
		assertThatThrownBy(() -> service.confirm(UUID.randomUUID(), "j.mokoena", "Relevant."))
				.isInstanceOf(ResourceNotFoundException.class);
	}

	@Test
	@DisplayName("A bulk dismissal records the reviewer, time and reason on every link, once each")
	void bulkDismissalRecordsEachLink() {
		EvidenceLink first = link(LinkMethod.AUTO_TIME_WINDOW);
		EvidenceLink second = link(LinkMethod.AUTO_TIME_WINDOW);

		List<EvidenceLinkDto> dismissed = service.dismissAll(
				List.of(first.getId(), second.getId(), first.getId()), "j.mokoena", "Different host.");

		assertThat(dismissed).extracting(EvidenceLinkDto::id).containsExactly(first.getId(), second.getId());
		assertThat(dismissed).allSatisfy(link -> {
			assertThat(link.disposition()).isEqualTo(LinkDisposition.DISMISSED);
			assertThat(link.reviewedBy()).isEqualTo("j.mokoena");
			assertThat(link.reviewedAt()).isAtSameInstantAs(NOW);
			assertThat(link.reviewNote()).isEqualTo("Different host.");
		});
	}

	/**
	 * Outside the test transaction, so that the service's own transaction commits or rolls
	 * back for real; inside one, a rollback would only mark the test's transaction and the
	 * partial dismissal would still be visible. What it commits is removed afterwards.
	 */
	@Test
	@Transactional(propagation = Propagation.NOT_SUPPORTED)
	@DisplayName("A bulk ruling that reaches an already-reviewed link records nothing at all")
	void bulkRulingIsAllOrNone() {
		EvidenceLink pending = link(LinkMethod.AUTO_TIME_WINDOW);
		EvidenceLink reviewed = link(LinkMethod.AUTO_TIME_WINDOW);
		try {
			service.confirm(reviewed.getId(), "a.pillay", "Relevant.");

			assertThatThrownBy(() -> service.dismissAll(
					List.of(pending.getId(), reviewed.getId()), "j.mokoena", "Different host."))
					.isInstanceOf(LinkAlreadyReviewedException.class);

			// pending was dismissed first in the call, and that dismissal did not survive it.
			assertThat(service.findById(pending.getId()).disposition()).isEqualTo(LinkDisposition.PROPOSED);
			assertThat(service.findById(reviewed.getId()).reviewedBy()).isEqualTo("a.pillay");
		} finally {
			linkRepository.deleteAllById(List.of(pending.getId(), reviewed.getId()));
			evidenceItemRepository.deleteAllById(
					List.of(pending.getEvidenceItem().getId(), reviewed.getEvidenceItem().getId()));
			incidentRepository.deleteById(alert.getId());
			evidenceSourceRepository.deleteById(firewall.getId());
		}
	}

	@Test
	@DisplayName("A bundle can be narrowed to what is still unreviewed")
	void bundleFiltersByDisposition() {
		EvidenceLink reviewed = link(LinkMethod.AUTO_TIME_WINDOW);
		EvidenceLink pending = link(LinkMethod.AUTO_TIME_WINDOW);
		service.confirm(reviewed.getId(), "j.mokoena", "Relevant.");

		var page = PageRequest.of(0, 10, Sort.by("linkedAt", "id"));
		assertThat(service.findByIncident(alert.getId(), null, page)).hasSize(2);
		assertThat(service.findByIncident(alert.getId(), LinkDisposition.PROPOSED, page))
				.extracting(EvidenceLinkDto::id)
				.containsExactly(pending.getId());
	}

	@Test
	@DisplayName("The bundle of an incident that does not exist is a 404, not an empty page")
	void bundleOfUnknownIncidentIsNotFound() {
		// "This incident gathered nothing" is a finding; "there is no such incident" is a typo.
		assertThatThrownBy(() -> service.findByIncident(UUID.randomUUID(), null, PageRequest.of(0, 10)))
				.isInstanceOf(ResourceNotFoundException.class);
	}

	/** A one-alert incident; links and their review belong to the incident. */
	private Incident alert() {
		Incident incident = new Incident();
		incident.setSourceSystem("slips-ids");
		incident.setIncidentKey(Incident.keyForUngrouped(UUID.randomUUID().toString()));
		incident.absorb(OffsetDateTime.parse("2026-01-01T14:30:00Z"));
		return incidentRepository.saveAndFlush(incident);
	}

	private EvidenceLink link(LinkMethod method) {
		String artifactId = "artifact-" + artifactCounter++;
		EvidenceItem item = new EvidenceItem();
		item.setWorkGroup(firewall.getWorkGroup());
		item.setEvidenceSource(firewall);
		item.setSourceArtifactId(artifactId);
		item.setStorageRef("evidence/edge-firewall/" + artifactId);
		item.setCurrentHash(SHA_256_OF_EMPTY_STRING);
		item.setStatus(EvidenceStatus.PRESERVED);
		item.setEventStart(OffsetDateTime.parse("2026-01-01T14:00:00Z"));
		item.setEventEnd(OffsetDateTime.parse("2026-01-01T15:00:00Z"));
		evidenceItemRepository.saveAndFlush(item);

		EvidenceLink link = new EvidenceLink();
		link.setIncident(alert);
		link.setEvidenceItem(item);
		link.setLinkMethod(method);
		link.setRationale("overlap");
		return linkRepository.saveAndFlush(link);
	}
}
