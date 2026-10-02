package za.co.dfraas.service;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
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
import za.co.dfraas.entity.LinkDisposition;
import za.co.dfraas.entity.LinkMethod;
import za.co.dfraas.entity.TriggerEvent;
import za.co.dfraas.entity.WorkGroup;
import za.co.dfraas.exception.CorrelationException;
import za.co.dfraas.exception.ResourceNotFoundException;
import za.co.dfraas.repository.EvidenceItemRepository;
import za.co.dfraas.repository.EvidenceLinkRepository;
import za.co.dfraas.repository.EvidenceSourceRepository;
import za.co.dfraas.repository.TriggerEventRepository;
import za.co.dfraas.repository.WorkGroupRepository;

/**
 * The correlation pass: gathers the evidence already preserved around an alert into
 * {@link EvidenceLink}s, and moves the alert through {@link CorrelationStatus}.
 *
 * <p><strong>One alert per transaction.</strong> {@link #correlate} is the unit of work and
 * is called once per alert by {@link CorrelationScheduler}, never in a loop inside one
 * transaction. An over-broad alert, or one whose scope cannot be resolved, then fails on
 * its own and is recorded {@code FAILED}, instead of rolling back every other alert in the
 * sweep with it.
 *
 * <p><strong>Re-running is the design, not a recovery path.</strong> Under continuous
 * collection, evidence covering an alert can arrive after the alert has been correlated, so
 * a {@code CORRELATED} alert is correlated again on every sweep until its bundle settles.
 * Each pass inserts only the links it has not made before ({@code uq_evidence_link_pair}
 * backs that up), and flags them {@link EvidenceLink#isLateArrival() late}. First
 * correlation, retry after failure and late arrival are therefore one code path.
 *
 * <p><strong>Scope.</strong> Time alone is not a usable predicate here, so every alert is
 * searched within one classification. The alert does not carry one, so it is taken from
 * the {@link EvidenceSource} registered under the alert's {@code sourceSystem} — the two
 * fields are documented as the same identifier — and frozen onto
 * {@link TriggerEvent#getCorrelationScope()} on the first attempt. Later passes read the
 * frozen scope back rather than resolving it again, so reclassifying a source cannot change
 * what an alert that has already been correlated was searched against.
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

	private final TriggerEventRepository triggerEventRepository;
	private final EvidenceItemRepository evidenceItemRepository;
	private final EvidenceLinkRepository evidenceLinkRepository;
	private final EvidenceSourceRepository evidenceSourceRepository;
	private final WorkGroupRepository workGroupRepository;
	private final ObjectMapper objectMapper;
	private final CorrelationProperties properties;
	private final Clock clock;

	public CorrelationService(
			TriggerEventRepository triggerEventRepository,
			EvidenceItemRepository evidenceItemRepository,
			EvidenceLinkRepository evidenceLinkRepository,
			EvidenceSourceRepository evidenceSourceRepository,
			WorkGroupRepository workGroupRepository,
			ObjectMapper objectMapper,
			CorrelationProperties properties,
			Clock clock) {
		this.triggerEventRepository = triggerEventRepository;
		this.evidenceItemRepository = evidenceItemRepository;
		this.evidenceLinkRepository = evidenceLinkRepository;
		this.evidenceSourceRepository = evidenceSourceRepository;
		this.workGroupRepository = workGroupRepository;
		this.objectMapper = objectMapper;
		this.properties = properties;
		this.clock = clock;
	}

	/**
	 * The ids of up to {@code limit} alerts in the given states, oldest received first.
	 *
	 * <p>Ids rather than entities, and collected before any of them is processed: each alert
	 * is then correlated in its own transaction, and correlating one moves it out of the
	 * queue being read. Paging through the queue while changing it would skip rows.
	 */
	public List<UUID> queue(Collection<CorrelationStatus> statuses, int limit) {
		return triggerEventRepository
				.findByCorrelationStatusInOrderByReceivedAtAsc(statuses, PageRequest.of(0, limit))
				.map(TriggerEvent::getId)
				.getContent();
	}

	/**
	 * Correlates one alert: links every overlapping item not already linked, marks the
	 * alert {@code CORRELATED}, and closes it once its bundle has settled.
	 *
	 * @throws CorrelationException when the alert's scope cannot be resolved
	 */
	@Transactional
	public CorrelationResult correlate(UUID triggerEventId) {
		TriggerEvent event = triggerEventRepository.findById(triggerEventId)
				.orElseThrow(() -> new ResourceNotFoundException("TriggerEvent not found: " + triggerEventId));

		if (event.getCorrelationStatus() == CorrelationStatus.CLOSED) {
			// Closing stops the machine. A person may still add a MANUAL link; this may not.
			return new CorrelationResult(triggerEventId, CorrelationStatus.CLOSED, 0);
		}

		WorkGroup workGroup = resolveScope(event);
		OffsetDateTime windowStart = event.getFiredAt().minusSeconds(event.getCorrelationLookbackSeconds());
		OffsetDateTime windowEnd = event.getFiredAt().plusSeconds(event.getCorrelationLookaheadSeconds());

		// Judged before this pass touches the status. A link is late if the alert had already
		// been through a completed pass — including one that later failed on a re-run.
		boolean lateArrival = event.getCorrelatedAt() != null;
		int linksAdded = linkOverlapping(event, workGroup, windowStart, windowEnd, lateArrival);

		OffsetDateTime now = OffsetDateTime.now(clock);
		if (event.getCorrelatedAt() == null) {
			event.setCorrelatedAt(now);
		}
		boolean settled = !now.isBefore(windowEnd.plus(properties.settleAfter()));
		event.setCorrelationStatus(settled ? CorrelationStatus.CLOSED : CorrelationStatus.CORRELATED);

		if (linksAdded > 0 || settled) {
			log.info("Correlated trigger event: id={} workGroup={} linksAdded={} lateArrival={} status={}",
					event.getId(), workGroup.getClassificationCode(), linksAdded, lateArrival,
					event.getCorrelationStatus());
		}
		return new CorrelationResult(triggerEventId, event.getCorrelationStatus(), linksAdded);
	}

	/**
	 * Records that an attempt to correlate this alert broke.
	 *
	 * <p>Its own transaction, called after {@link #correlate} has rolled back, so the
	 * failure is recorded even though nothing the failed pass did was kept. A
	 * {@code correlatedAt} from an earlier successful pass is left in place: it still says
	 * when the alert was first correlated, and it is what makes a later retry flag its new
	 * links as late.
	 */
	@Transactional
	public void markFailed(UUID triggerEventId) {
		triggerEventRepository.findById(triggerEventId).ifPresent(event -> {
			if (event.getCorrelationStatus() != CorrelationStatus.CLOSED) {
				event.setCorrelationStatus(CorrelationStatus.FAILED);
			}
		});
	}

	private int linkOverlapping(
			TriggerEvent event, WorkGroup workGroup,
			OffsetDateTime windowStart, OffsetDateTime windowEnd, boolean lateArrival) {
		String windowText = "correlation window [" + windowStart + ", " + windowEnd + "] (fired_at "
				+ event.getFiredAt() + ", lookback " + event.getCorrelationLookbackSeconds()
				+ "s, lookahead " + event.getCorrelationLookaheadSeconds() + "s) within work group "
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
			List<EvidenceLink> links = new ArrayList<>();
			for (EvidenceItem item : page) {
				if (evidenceLinkRepository.findByTriggerEventIdAndEvidenceItemId(event.getId(), item.getId())
						.isEmpty()) {
					links.add(newLink(event, item, windowText, lateArrival));
				}
			}
			evidenceLinkRepository.saveAll(links);
			linksAdded += links.size();
			pageable = pageable.next();
		} while (page.hasNext());
		return linksAdded;
	}

	private static EvidenceLink newLink(
			TriggerEvent event, EvidenceItem item, String windowText, boolean lateArrival) {
		EvidenceLink link = new EvidenceLink();
		link.setTriggerEvent(event);
		link.setEvidenceItem(item);
		link.setLinkMethod(LinkMethod.AUTO_TIME_WINDOW);
		// An overlap is a reason to look, not a finding. Only a person moves this on.
		link.setDisposition(LinkDisposition.PROPOSED);
		// linkedBy stays null: the honest author of an automated link is the pass itself.
		link.setLateArrival(lateArrival);
		link.setRationale("Coverage window [" + item.getEventStart() + ", " + item.getEventEnd()
				+ "] overlaps " + windowText + "."
				+ (lateArrival ? " Added by a later pass, after the alert was first correlated." : ""));
		return link;
	}

	/**
	 * The classification this alert is searched within — read from the frozen scope if
	 * there is one, otherwise resolved from the alert's source and frozen.
	 */
	private WorkGroup resolveScope(TriggerEvent event) {
		if (event.getCorrelationScope() != null) {
			return workGroupFromScope(event);
		}

		EvidenceSource source = evidenceSourceRepository.findBySourceKey(event.getSourceSystem())
				.orElseThrow(() -> new CorrelationException(
						"No evidence source is registered under '" + event.getSourceSystem()
								+ "', so trigger event " + event.getId()
								+ " has no classification to correlate within"));
		WorkGroup workGroup = source.getWorkGroup();

		ObjectNode scope = objectMapper.createObjectNode();
		scope.put("version", SCOPE_VERSION);
		scope.putArray("workGroupIds").add(workGroup.getId().toString());
		scope.put("resolvedFromSourceKey", source.getSourceKey());
		event.setCorrelationScope(objectMapper.writeValueAsString(scope));
		return workGroup;
	}

	private WorkGroup workGroupFromScope(TriggerEvent event) {
		JsonNode workGroupIds = objectMapper.readTree(event.getCorrelationScope()).path("workGroupIds");
		if (workGroupIds.size() != 1) {
			// Version 1 always writes exactly one. Anything else was not written by this
			// class, and guessing which group was meant would correlate against the wrong one.
			throw new CorrelationException("Trigger event " + event.getId()
					+ " has a correlation scope this pass cannot read: " + event.getCorrelationScope());
		}
		UUID workGroupId = UUID.fromString(workGroupIds.get(0).asString());
		return workGroupRepository.findById(workGroupId)
				.orElseThrow(() -> new CorrelationException("Trigger event " + event.getId()
						+ " is scoped to work group " + workGroupId + ", which does not exist"));
	}

	/**
	 * What one pass did to one alert.
	 *
	 * @param linksAdded links this pass created; zero on a re-run with nothing new
	 */
	public record CorrelationResult(UUID triggerEventId, CorrelationStatus status, int linksAdded) {
	}
}
