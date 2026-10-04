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
import org.springframework.boot.jpa.test.autoconfigure.TestEntityManager;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.PageRequest;

import za.co.dfraas.TestcontainersConfiguration;
import za.co.dfraas.entity.EvidenceItem;
import za.co.dfraas.entity.EvidenceLink;
import za.co.dfraas.entity.EvidenceStatus;
import za.co.dfraas.entity.Incident;
import za.co.dfraas.entity.LinkDisposition;
import za.co.dfraas.entity.LinkMethod;
import za.co.dfraas.entity.WorkGroup;

/**
 * The contract between {@link EvidenceLink} and Liquibase changeset
 * {@code 0005-create-evidence-link-and-correlation-state}.
 *
 * <p>What this file exists to prove is that the schema can hold the two claims apart. A
 * correlation and a causation are not the same statement about an exhibit, and neither is
 * a machine's suggestion and an investigator's finding — the cases below pin down every
 * constraint that stops those collapsing into each other.
 *
 * <p>It also covers the many-to-many the old {@code evidence_item.trigger_event_id} could
 * not express, in both directions: an alert gathering several artifacts, and an artifact
 * gathered into several incidents.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import(TestcontainersConfiguration.class)
class EvidenceLinkRepositoryTest {

	private static final String SHA_256_OF_EMPTY_STRING =
			"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

	@Autowired
	private EvidenceLinkRepository repository;

	@Autowired
	private EvidenceItemRepository evidenceItemRepository;

	@Autowired
	private IncidentRepository incidentRepository;

	@Autowired
	private WorkGroupRepository workGroupRepository;

	@Autowired
	private TestEntityManager entityManager;

	private WorkGroup workGroup;
	private Incident alert;
	private EvidenceItem item;

	@BeforeEach
	void setUp() {
		workGroup = workGroupRepository.findByClassificationCode("ONLINE_BANKING").orElseThrow();
		alert = incidentRepository.saveAndFlush(newIncident("EVT-1"));
		item = evidenceItemRepository.saveAndFlush(newItem("evidence/auth/14-15.log"));
	}

	@Test
	@DisplayName("An automatic link is created PROPOSED, with the database stamping linkedAt")
	void automaticLinkIsProposedAndTimestamped() {
		EvidenceLink saved = repository.saveAndFlush(newLink(alert, item, LinkMethod.AUTO_TIME_WINDOW));

		assertThat(saved.getId()).isNotNull();
		assertThat(saved.getLinkedAt()).isNotNull();
		// PROPOSED is the honest default for anything automated: the system found an
		// overlap, which is a reason to look, not a finding.
		assertThat(saved.getDisposition()).isEqualTo(LinkDisposition.PROPOSED);
		assertThat(saved.getLinkedBy()).isNull();
		assertThat(saved.isLateArrival()).isFalse();
	}

	@Test
	@DisplayName("One alert gathers many artifacts, and one artifact belongs to many alerts")
	void theRelationshipIsManyToManyInBothDirections() {
		EvidenceItem firewallLog = evidenceItemRepository.saveAndFlush(newItem("evidence/fw/14-15.log"));
		Incident secondAlert = incidentRepository.saveAndFlush(newIncident("EVT-2"));

		repository.saveAndFlush(newLink(alert, item, LinkMethod.AUTO_TIME_WINDOW));
		repository.saveAndFlush(newLink(alert, firewallLog, LinkMethod.AUTO_TIME_WINDOW));
		// The direction the old foreign key on evidence_item could not express at all: a log
		// bundle covering 14:00-15:00 overlaps every alert that fired in that hour.
		repository.saveAndFlush(newLink(secondAlert, item, LinkMethod.AUTO_RULE));

		assertThat(repository.findByIncidentId(alert.getId(), PageRequest.of(0, 10))).hasSize(2);
		assertThat(repository.findByEvidenceItemId(item.getId()))
				.extracting(EvidenceLink::getLinkMethod)
				.containsExactlyInAnyOrder(LinkMethod.AUTO_TIME_WINDOW, LinkMethod.AUTO_RULE);
	}

	@Test
	@DisplayName("The same alert and item cannot be linked twice")
	void duplicateLinkIsRejected() {
		repository.saveAndFlush(newLink(alert, item, LinkMethod.AUTO_TIME_WINDOW));

		// What makes a re-correlation pass safely idempotent: it can insert unconditionally
		// and let the constraint reject what it already recorded, exactly as trigger event
		// ingestion does. Without this a bundle would grow duplicates in proportion to how
		// often it was swept.
		assertThatThrownBy(() -> repository.saveAndFlush(newLink(alert, item, LinkMethod.AUTO_RULE)))
				.isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	@DisplayName("A manual link must name who made it")
	void manualLinkWithoutAttributionIsRejected() {
		EvidenceLink link = newLink(alert, item, LinkMethod.MANUAL);

		// A manual link is an investigator's assertion, and an unattributed assertion is not
		// admissible as anything.
		assertThatThrownBy(() -> repository.saveAndFlush(link))
				.isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	@DisplayName("A manual link with attribution is accepted")
	void manualLinkWithAttributionIsAccepted() {
		EvidenceLink link = newLink(alert, item, LinkMethod.MANUAL);
		link.setLinkedBy("j.mokoena");
		link.setRationale("Same customer account as the alerting transaction.");

		assertThat(repository.saveAndFlush(link).getLinkedBy()).isEqualTo("j.mokoena");
	}

	@Test
	@DisplayName("A dismissal must name a reviewer")
	void dismissalWithoutReviewerIsRejected() {
		EvidenceLink link = newLink(alert, item, LinkMethod.AUTO_TIME_WINDOW);
		link.setDisposition(LinkDisposition.DISMISSED);

		// Nothing automated may decide that evidence is irrelevant. Dismissal is always a
		// human judgement, and the database is where that is enforced.
		assertThatThrownBy(() -> repository.saveAndFlush(link))
				.isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	@DisplayName("A dismissed link survives as a record of what was considered and set aside")
	void dismissedLinkIsRetainedRatherThanDeleted() {
		EvidenceLink link = repository.saveAndFlush(newLink(alert, item, LinkMethod.AUTO_TIME_WINDOW));

		link.setDisposition(LinkDisposition.DISMISSED);
		link.setReviewedBy("j.mokoena");
		link.setReviewedAt(OffsetDateTime.parse("2026-01-01T16:00:00Z"));
		link.setReviewNote("Covers the wrong host; the alert concerns 10.99.0.12.");
		repository.saveAndFlush(link);

		// Deleting the row would leave the bundle looking as though the item had never been
		// surfaced — a different and less defensible claim than "it was considered and
		// rejected", which is precisely what a defence would probe.
		assertThat(repository.countByIncidentId(alert.getId())).isEqualTo(1);
		assertThat(repository.countByIncidentIdAndDisposition(alert.getId(), LinkDisposition.PROPOSED))
				.isZero();
		assertThat(repository.findByIncidentIdAndDisposition(
				alert.getId(), LinkDisposition.DISMISSED, PageRequest.of(0, 10))).hasSize(1);
	}

	@Test
	@DisplayName("A CAUSAL link may be CONFIRMED with no reviewer, unlike every other method")
	void causalLinkIsConfirmedWithoutReview() {
		EvidenceLink link = newLink(alert, item, LinkMethod.CAUSAL);
		link.setDisposition(LinkDisposition.CONFIRMED);

		// The deliberate asymmetry in ck_evidence_link_dismissal_attribution. A causal link
		// is an observation — the system watched the collection happen — rather than an
		// inference drawn afterwards, so requiring a reviewer would force the ingestion path
		// to invent one.
		EvidenceLink saved = repository.saveAndFlush(link);

		assertThat(saved.getDisposition()).isEqualTo(LinkDisposition.CONFIRMED);
		assertThat(saved.getReviewedBy()).isNull();
	}

	@Test
	@DisplayName("A half-completed review is rejected")
	void reviewerWithoutTimestampIsRejected() {
		EvidenceLink link = newLink(alert, item, LinkMethod.AUTO_TIME_WINDOW);
		link.setDisposition(LinkDisposition.CONFIRMED);
		link.setReviewedBy("j.mokoena");
		// reviewedAt deliberately left null.

		assertThatThrownBy(() -> repository.saveAndFlush(link))
				.isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	@DisplayName("A review must state its reason, and a blank one does not count")
	void reviewWithBlankNoteIsRejected() {
		EvidenceLink link = newLink(alert, item, LinkMethod.AUTO_TIME_WINDOW);
		link.setDisposition(LinkDisposition.CONFIRMED);
		link.setReviewedBy("j.mokoena");
		link.setReviewedAt(OffsetDateTime.parse("2026-01-01T16:00:00Z"));
		link.setReviewNote("   ");

		// "Set aside by j.mokoena" without a why is the half of the record a defence probes
		// and the half the row could not answer — ck_evidence_link_review_complete.
		assertThatThrownBy(() -> repository.saveAndFlush(link))
				.isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	@DisplayName("A late-arriving link is flagged as such")
	void lateArrivalIsRecorded() {
		// Normal rather than exceptional once collection is decoupled from alerting:
		// evidence covering 14:00-15:00 may not reach us until 15:02, by which time an alert
		// that fired at 14:30 has been correlated and possibly already reviewed.
		EvidenceLink link = newLink(alert, item, LinkMethod.AUTO_TIME_WINDOW);
		link.setLateArrival(true);

		assertThat(repository.saveAndFlush(link).isLateArrival()).isTrue();
	}

	@Test
	@DisplayName("An evidence item that has been linked cannot be deleted")
	void evidenceItemDeleteIsRestrictedByTheForeignKey() {
		repository.saveAndFlush(newLink(alert, item, LinkMethod.AUTO_TIME_WINDOW));
		entityManager.clear();

		// RESTRICT, not CASCADE. A hard delete must not quietly remove an exhibit from every
		// bundle it belongs to — evidence is soft-delete only, and this table inherits that.
		evidenceItemRepository.delete(evidenceItemRepository.findById(item.getId()).orElseThrow());
		assertThatThrownBy(() -> evidenceItemRepository.flush())
				.isInstanceOf(DataIntegrityViolationException.class);
	}

	private EvidenceLink newLink(Incident incident, EvidenceItem evidenceItem, LinkMethod method) {
		EvidenceLink link = new EvidenceLink();
		link.setIncident(incident);
		link.setEvidenceItem(evidenceItem);
		link.setLinkMethod(method);
		return link;
	}

	private EvidenceItem newItem(String storageRef) {
		EvidenceItem evidenceItem = new EvidenceItem();
		evidenceItem.setWorkGroup(workGroup);
		evidenceItem.setStorageRef(storageRef);
		evidenceItem.setCurrentHash(SHA_256_OF_EMPTY_STRING);
		evidenceItem.setStatus(EvidenceStatus.PRESERVED);
		evidenceItem.setEventStart(OffsetDateTime.parse("2026-01-01T14:00:00Z"));
		evidenceItem.setEventEnd(OffsetDateTime.parse("2026-01-01T15:00:00Z"));
		return evidenceItem;
	}

	/**
	 * Links belong to incidents since {@code 0007}. The variables keep the name "alert" because
	 * each test is about one alert's bundle, and an ungrouped alert is an incident of its own.
	 */
	private static Incident newIncident(String externalEventId) {
		Incident incident = new Incident();
		incident.setSourceSystem("splunk");
		incident.setIncidentKey(Incident.keyForUngrouped(externalEventId));
		incident.absorb(OffsetDateTime.parse("2026-01-01T14:30:00Z"));
		return incident;
	}
}
