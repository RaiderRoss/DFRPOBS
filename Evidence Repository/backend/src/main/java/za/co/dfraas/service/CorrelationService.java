package za.co.dfraas.service;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;
import za.co.dfraas.config.CorrelationProperties;
import za.co.dfraas.entity.CorrelationStatus;
import za.co.dfraas.entity.EvidenceItem;
import za.co.dfraas.entity.EvidenceLink;
import za.co.dfraas.entity.EvidenceSource;
import za.co.dfraas.entity.Incident;
import za.co.dfraas.entity.LinkDisposition;
import za.co.dfraas.entity.LinkMethod;
import za.co.dfraas.entity.TriggerEvent;
import za.co.dfraas.entity.WorkGroup;
import za.co.dfraas.exception.CorrelationException;
import za.co.dfraas.exception.ResourceNotFoundException;
import za.co.dfraas.repository.EvidenceItemIndicatorRepository;
import za.co.dfraas.repository.EvidenceItemRepository;
import za.co.dfraas.repository.EvidenceLinkRepository;
import za.co.dfraas.repository.EvidenceSourceRepository;
import za.co.dfraas.repository.IncidentRepository;
import za.co.dfraas.repository.TriggerEventRepository;
import za.co.dfraas.repository.WorkGroupRepository;

/**
 * The correlation pass: gathers the evidence already preserved around an {@link Incident}
 * into {@link EvidenceLink}s, and moves the incident through {@link CorrelationStatus}.
 *
 * <p><strong>Incidents, not alerts.</strong> Since {@code 0007} the unit correlated is the
 * incident — the alerts a source says belong together — so a source re-alerting about one
 * attack gets one bundle. Its window runs from the first member alert minus the lookback to
 * the last plus the lookahead, so an incident that keeps alerting keeps widening its search.
 *
 * <p><strong>One incident per transaction.</strong> {@link #correlate} is the unit of work
 * and is called once per incident by {@link CorrelationScheduler}, never in a loop inside
 * one transaction. An over-broad incident, or one whose scope cannot be resolved, then fails
 * on its own and is recorded {@code FAILED}, instead of rolling back every other incident in
 * the sweep with it.
 *
 * <p><strong>Re-running is the design, not a recovery path.</strong> Under continuous
 * collection, evidence covering an incident can arrive after it has been correlated, so a
 * {@code CORRELATED} incident is correlated again on every sweep until its bundle settles.
 * Each pass inserts only the links it has not made before ({@code uq_evidence_link_pair}
 * backs that up), and flags them {@link EvidenceLink#isLateArrival() late}. First
 * correlation, retry after failure and late arrival are therefore one code path.
 *
 * <p><strong>Scope.</strong> Time alone is not a usable predicate here, so every incident is
 * searched within one classification. It does not carry one, so it is taken from the
 * {@link EvidenceSource} registered under the incident's {@code sourceSystem} — the two
 * fields are documented as the same identifier — and frozen onto
 * {@link Incident#getCorrelationScope()} on the first attempt. Later passes read the frozen
 * scope back rather than resolving it again, so reclassifying a source cannot change what an
 * incident that has already been correlated was searched against.
 *
 * <p><strong>Rules, on top of the overlap.</strong> Within that scope every overlapping item
 * is still proposed — recall is the point of a bundle — but an item that also matches a
 * named rule is proposed as {@link LinkMethod#AUTO_RULE}, so an investigator can open those
 * first and deal with the rest together. Two rules, each named in the link's rationale:
 * <ul>
 *   <li>{@code alert-instant}: the item's coverage contains the moment a member alert fired.
 *       It recorded the activity the alert is about, not merely activity nearby. Of a source
 *       that collects continuously, exactly one item does.</li>
 *   <li>{@code shared-indicator}: the item mentions an address the alert names as its
 *       subject, in the payload's {@code indicators.ip} list. The item's addresses were
 *       extracted from its bytes at ingest; see {@link IndicatorExtractor}.</li>
 * </ul>
 * Rules are evaluated when a link is made. A later alert joining the incident does not
 * re-grade links that already exist, because a link's method and rationale are its record of
 * why it was proposed, and are not rewritten.
 */
@Service
@Transactional(readOnly = true)
public class CorrelationService {

	private static final Logger log = LoggerFactory.getLogger(CorrelationService.class);

	/**
	 * Version of the {@code correlationScope} document. Stamped into every scope this class
	 * writes, so a later change to its shape can still read the scopes already frozen.
	 */
	static final int SCOPE_VERSION = 1;

	private final IncidentRepository incidentRepository;
	private final EvidenceItemRepository evidenceItemRepository;
	private final EvidenceLinkRepository evidenceLinkRepository;
	private final EvidenceSourceRepository evidenceSourceRepository;
	private final WorkGroupRepository workGroupRepository;
	private final TriggerEventRepository triggerEventRepository;
	private final EvidenceItemIndicatorRepository indicatorRepository;
	private final IndicatorExtractor indicatorExtractor;
	private final ObjectMapper objectMapper;
	private final CorrelationProperties properties;
	private final Clock clock;

	public CorrelationService(
			IncidentRepository incidentRepository,
			EvidenceItemRepository evidenceItemRepository,
			EvidenceLinkRepository evidenceLinkRepository,
			EvidenceSourceRepository evidenceSourceRepository,
			WorkGroupRepository workGroupRepository,
			TriggerEventRepository triggerEventRepository,
			EvidenceItemIndicatorRepository indicatorRepository,
			IndicatorExtractor indicatorExtractor,
			ObjectMapper objectMapper,
			CorrelationProperties properties,
			Clock clock) {
		this.incidentRepository = incidentRepository;
		this.evidenceItemRepository = evidenceItemRepository;
		this.evidenceLinkRepository = evidenceLinkRepository;
		this.evidenceSourceRepository = evidenceSourceRepository;
		this.workGroupRepository = workGroupRepository;
		this.triggerEventRepository = triggerEventRepository;
		this.indicatorRepository = indicatorRepository;
		this.indicatorExtractor = indicatorExtractor;
		this.objectMapper = objectMapper;
		this.properties = properties;
		this.clock = clock;
	}

	/**
	 * The ids of up to {@code limit} incidents in the given states, oldest opened first.
	 *
	 * <p>Ids rather than entities, and collected before any of them is processed: each
	 * incident is then correlated in its own transaction, and correlating one moves it out of
	 * the queue being read. Paging through the queue while changing it would skip rows.
	 */
	public List<UUID> queue(Collection<CorrelationStatus> statuses, int limit) {
		return incidentRepository
				.findByCorrelationStatusInOrderByOpenedAtAsc(statuses, PageRequest.of(0, limit))
				.map(Incident::getId)
				.getContent();
	}

	/**
	 * Correlates one incident: links every overlapping item not already linked, marks the
	 * incident {@code CORRELATED}, and closes it once its bundle has settled.
	 *
	 * @throws CorrelationException when the incident's scope cannot be resolved
	 */
	@Transactional
	public CorrelationResult correlate(UUID incidentId) {
		Incident incident = incidentRepository.findById(incidentId)
				.orElseThrow(() -> ResourceNotFoundException.of("Incident", incidentId));

		if (incident.getCorrelationStatus() == CorrelationStatus.CLOSED) {
			// Closing stops the machine. A person may still add a MANUAL link; this may not.
			// A new member alert reopens it — see Incident.absorb.
			return new CorrelationResult(incidentId, CorrelationStatus.CLOSED, 0);
		}

		WorkGroup workGroup = resolveScope(incident);
		OffsetDateTime windowStart = incident.windowStart();
		OffsetDateTime windowEnd = incident.windowEnd();

		// Judged before this pass touches the status. A link is late if the incident had
		// already been through a completed pass — including one that later failed on a re-run,
		// and including evidence only reached because a new alert widened the window.
		boolean lateArrival = incident.getCorrelatedAt() != null;
		AlertSubject subject = alertSubject(incident);
		int linksAdded = linkOverlapping(incident, workGroup, windowStart, windowEnd, subject, lateArrival);

		OffsetDateTime now = OffsetDateTime.now(clock);
		if (incident.getCorrelatedAt() == null) {
			incident.setCorrelatedAt(now);
		}
		boolean settled = !now.isBefore(windowEnd.plus(properties.settleAfter()));
		incident.setCorrelationStatus(settled ? CorrelationStatus.CLOSED : CorrelationStatus.CORRELATED);

		if (linksAdded > 0 || settled) {
			log.info("Correlated incident: id={} workGroup={} linksAdded={} lateArrival={} status={}",
					incident.getId(), workGroup.getClassificationCode(), linksAdded, lateArrival,
					incident.getCorrelationStatus());
		}
		return new CorrelationResult(incidentId, incident.getCorrelationStatus(), linksAdded);
	}

	/**
	 * Records that an attempt to correlate this incident broke.
	 *
	 * <p>Its own transaction, called after {@link #correlate} has rolled back, so the
	 * failure is recorded even though nothing the failed pass did was kept. A
	 * {@code correlatedAt} from an earlier successful pass is left in place: it still says
	 * when the incident was first correlated, and it is what makes a later retry flag its new
	 * links as late.
	 */
	@Transactional
	public void markFailed(UUID incidentId) {
		incidentRepository.findById(incidentId).ifPresent(incident -> {
			if (incident.getCorrelationStatus() != CorrelationStatus.CLOSED) {
				incident.setCorrelationStatus(CorrelationStatus.FAILED);
			}
		});
	}

	private int linkOverlapping(
			Incident incident, WorkGroup workGroup,
			OffsetDateTime windowStart, OffsetDateTime windowEnd, AlertSubject subject, boolean lateArrival) {
		String windowText = "correlation window [" + windowStart + ", " + windowEnd + "] (alerts fired "
				+ incident.getFirstFiredAt() + " to " + incident.getLastFiredAt()
				+ ", lookback " + incident.getCorrelationLookbackSeconds()
				+ "s, lookahead " + incident.getCorrelationLookaheadSeconds() + "s) within work group "
				+ workGroup.getClassificationCode();

		// Ordered by id so that offset paging is stable: without an ORDER BY, Postgres may
		// return the same rows on two pages and never return others. Inserting links does
		// not change which items overlap, so the result set itself holds still.
		Pageable pageable = PageRequest.of(0, properties.pageSize(), Sort.by("id"));
		int linksAdded = 0;
		Page<EvidenceItem> page;
		do {
			page = evidenceItemRepository.findOverlappingCoverage(
					workGroup.getId(), windowStart, windowEnd, pageable);
			List<EvidenceItem> unlinked = page.stream()
					.filter(item -> evidenceLinkRepository
							.findByIncidentIdAndEvidenceItemId(incident.getId(), item.getId()).isEmpty())
					.toList();
			// One query per page for the indicator rule, not one per item.
			Map<UUID, Set<String>> sharedIps = indicatorRepository.findIpv4Matches(
					unlinked.stream().map(EvidenceItem::getId).toList(), subject.ips());
			List<EvidenceLink> links = new ArrayList<>();
			for (EvidenceItem item : unlinked) {
				links.add(newLink(incident, item, windowText, lateArrival,
						subject.firedAtsWithin(item.getEventStart(), item.getEventEnd()),
						sharedIps.getOrDefault(item.getId(), Set.of())));
			}
			evidenceLinkRepository.saveAll(links);
			linksAdded += links.size();
			pageable = pageable.next();
		} while (page.hasNext());
		return linksAdded;
	}

	private static EvidenceLink newLink(
			Incident incident, EvidenceItem item, String windowText, boolean lateArrival,
			List<OffsetDateTime> alertInstants, Set<String> sharedIps) {
		List<String> rules = new ArrayList<>();
		if (!alertInstants.isEmpty()) {
			rules.add("alert-instant (coverage contains the alert fired at " + alertInstants.get(0)
					+ (alertInstants.size() > 1 ? " and " + (alertInstants.size() - 1) + " more" : "") + ")");
		}
		if (!sharedIps.isEmpty()) {
			rules.add("shared-indicator (artifact mentions " + String.join(", ", sharedIps)
					+ ", named by the alert)");
		}

		EvidenceLink link = new EvidenceLink();
		link.setIncident(incident);
		link.setEvidenceItem(item);
		link.setLinkMethod(rules.isEmpty() ? LinkMethod.AUTO_TIME_WINDOW : LinkMethod.AUTO_RULE);
		// An overlap or a rule is a reason to look, not a finding. Only a person moves this on.
		link.setDisposition(LinkDisposition.PROPOSED);
		// linkedBy stays null: the honest author of an automated link is the pass itself.
		link.setLateArrival(lateArrival);
		link.setRationale((rules.isEmpty() ? "" : "Matched " + String.join("; ", rules) + ". ")
				+ "Coverage window [" + item.getEventStart() + ", " + item.getEventEnd()
				+ "] overlaps " + windowText + "."
				+ (lateArrival ? " Added by a later pass, after the incident was first correlated." : ""));
		return link;
	}

	/**
	 * What the incident's member alerts say it is about: when each fired, and the addresses
	 * they name.
	 *
	 * <p>Addresses come only from the payload's {@code indicators.ip} list — what the
	 * producer declares the alert's subject to be — and never from anything else in the
	 * payload. A Slips alert's evidence lines also name the bank's own server, which appears
	 * in every artifact, and matching on it would mark everything as relevant.
	 */
	private AlertSubject alertSubject(Incident incident) {
		List<OffsetDateTime> firedAts = new ArrayList<>();
		Set<String> ips = new TreeSet<>();
		Pageable pageable = PageRequest.of(0, properties.pageSize(), Sort.by("id"));
		Page<TriggerEvent> page;
		do {
			page = triggerEventRepository.findByIncidentId(incident.getId(), pageable);
			for (TriggerEvent alert : page) {
				firedAts.add(alert.getFiredAt());
				ips.addAll(declaredIps(alert));
			}
			pageable = pageable.next();
		} while (page.hasNext());
		firedAts.sort(null);
		return new AlertSubject(firedAts, ips);
	}

	private Set<String> declaredIps(TriggerEvent alert) {
		JsonNode declared;
		try {
			declared = objectMapper.readTree(alert.getPayload()).path("indicators").path("ip");
		} catch (RuntimeException ex) {
			// Not JSON: the alert names no subject, and is still correlated on time and on
			// the instant it fired.
			return Set.of();
		}
		Set<String> ips = new TreeSet<>();
		for (JsonNode value : declared) {
			if (value.isString()) {
				// Through the extractor, so the address is spelled exactly as the items' are.
				ips.addAll(indicatorExtractor.ipv4(value.asString().getBytes(StandardCharsets.UTF_8)));
			}
		}
		return ips;
	}

	/**
	 * @param firedAts when each member alert fired, sorted
	 * @param ips      the addresses the member alerts name as their subject
	 */
	private record AlertSubject(List<OffsetDateTime> firedAts, Set<String> ips) {

		/** The alert instants inside {@code [start, end]}, inclusive like the overlap query. */
		List<OffsetDateTime> firedAtsWithin(OffsetDateTime start, OffsetDateTime end) {
			return firedAts.stream().filter(at -> !at.isBefore(start) && !at.isAfter(end)).toList();
		}
	}

	/**
	 * The classification this incident is searched within — read from the frozen scope if
	 * there is one, otherwise resolved from the incident's source and frozen.
	 */
	private WorkGroup resolveScope(Incident incident) {
		if (incident.getCorrelationScope() != null) {
			return workGroupFromScope(incident);
		}

		EvidenceSource source = evidenceSourceRepository.findBySourceKey(incident.getSourceSystem())
				.orElseThrow(() -> new CorrelationException(
						"No evidence source is registered under '" + incident.getSourceSystem()
								+ "', so incident " + incident.getId()
								+ " has no classification to correlate within"));
		WorkGroup workGroup = source.getWorkGroup();

		ObjectNode scope = objectMapper.createObjectNode();
		scope.put("version", SCOPE_VERSION);
		scope.putArray("workGroupIds").add(workGroup.getId().toString());
		scope.put("resolvedFromSourceKey", source.getSourceKey());
		incident.setCorrelationScope(objectMapper.writeValueAsString(scope));
		return workGroup;
	}

	private WorkGroup workGroupFromScope(Incident incident) {
		JsonNode workGroupIds = objectMapper.readTree(incident.getCorrelationScope()).path("workGroupIds");
		if (workGroupIds.size() != 1) {
			// Version 1 always writes exactly one. Anything else was not written by this
			// class, and guessing which group was meant would correlate against the wrong one.
			throw new CorrelationException("Incident " + incident.getId()
					+ " has a correlation scope this pass cannot read: " + incident.getCorrelationScope());
		}
		UUID workGroupId = UUID.fromString(workGroupIds.get(0).asString());
		return workGroupRepository.findById(workGroupId)
				.orElseThrow(() -> new CorrelationException("Incident " + incident.getId()
						+ " is scoped to work group " + workGroupId + ", which does not exist"));
	}

	/**
	 * What one pass did to one incident.
	 *
	 * @param linksAdded links this pass created; zero on a re-run with nothing new
	 */
	public record CorrelationResult(UUID incidentId, CorrelationStatus status, int linksAdded) {
	}
}
