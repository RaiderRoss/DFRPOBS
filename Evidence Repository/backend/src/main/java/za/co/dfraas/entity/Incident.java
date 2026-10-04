package za.co.dfraas.entity;

import java.time.OffsetDateTime;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;

import org.hibernate.annotations.Generated;
import org.hibernate.generator.EventType;

import lombok.Getter;
import lombok.Setter;

/**
 * What an investigation is about: one or more {@link TriggerEvent}s a source says belong
 * together, and the evidence gathered for them.
 *
 * <p><strong>Why alerts are not enough on their own.</strong> An IDS does not alert once per
 * attack. Slips raises an alert every time an attacker's evidence crosses its threshold
 * again inside the same timewindow, so one scan is several alerts — and when each alert
 * owned its own bundle, the same firewall log was proposed and reviewed once per alert. The
 * alert was doing two jobs. {@link TriggerEvent} keeps the first, an immutable record of
 * what the source said, every one of them kept. This class takes the second: it owns the
 * correlation state and the {@link EvidenceLink}s.
 *
 * <p><strong>Grouping is the source's assertion.</strong> Alerts join an incident by
 * {@link #incidentKey}, which the producer sends (the Slips forwarder sends session, attacker
 * IP and timewindow). Only the source knows which of its alerts are one finding, so this is
 * sender-asserted like {@code firedAt} — and scoped the same way, by
 * {@code uq_incident_source_key}, so a source can group its own alerts and never another's.
 * An alert sent without a key is an incident of its own.
 *
 * <p>Mirrors Liquibase changeset {@code 0007-create-incident}; with
 * {@code ddl-auto=validate}, drift between the two fails startup.
 */
@Entity
@Table(
		name = "incident",
		uniqueConstraints = @UniqueConstraint(
				name = "uq_incident_source_key",
				columnNames = {"source_system", "incident_key"}))
@Getter
@Setter
public class Incident {

	/**
	 * Default seconds of lookback applied when nothing more specific is known.
	 *
	 * <p>Much larger than {@link #DEFAULT_LOOKAHEAD_SECONDS}, and the asymmetry is the whole
	 * point of continuous collection: the activity that matters — reconnaissance, initial
	 * access, staging — precedes detection, and gathering only from the moment of detection
	 * reproduces the blind spot the reactive design had.
	 *
	 * <p>A constant rather than a configuration property because it is a schema-level
	 * default, matched by the column default in {@code 0007-1}, and because the real answer
	 * is per-trigger-type policy rather than one global number.
	 */
	public static final int DEFAULT_LOOKBACK_SECONDS = 1800;

	/** Default seconds of lookahead — the immediate aftermath, plus the collection lag of
	 *  sources that batch their output. */
	public static final int DEFAULT_LOOKAHEAD_SECONDS = 900;

	/** The key an alert sent without one is filed under, making it an incident of its own. */
	public static String keyForUngrouped(String externalEventId) {
		return "event:" + externalEventId;
	}

	@Id
	@GeneratedValue(strategy = GenerationType.UUID)
	@Column(name = "id", nullable = false, updatable = false)
	private UUID id;

	@Column(name = "source_system", nullable = false, updatable = false, length = 255)
	private String sourceSystem;

	@Column(name = "incident_key", nullable = false, updatable = false, length = 255)
	private String incidentKey;

	/**
	 * The earliest and latest {@code firedAt} of the member alerts, widened as alerts join.
	 * Correlation searches from {@code firstFiredAt - lookback} to
	 * {@code lastFiredAt + lookahead}, so an incident that keeps alerting keeps extending its
	 * own window. Sender-asserted, as {@code firedAt} is.
	 */
	@Column(name = "first_fired_at", nullable = false)
	private OffsetDateTime firstFiredAt;

	@Column(name = "last_fired_at", nullable = false)
	private OffsetDateTime lastFiredAt;

	/** When this system opened the incident — its own clock, and what listings sort on. */
	@Generated(event = EventType.INSERT)
	@Column(name = "opened_at", nullable = false, insertable = false, updatable = false)
	private OffsetDateTime openedAt;

	/**
	 * How far correlation has got. See {@link CorrelationStatus}, which carries the argument
	 * for why this exists and why it is not a native Postgres enum.
	 */
	@Enumerated(EnumType.STRING)
	@Column(name = "correlation_status", nullable = false, length = 32)
	private CorrelationStatus correlationStatus = CorrelationStatus.PENDING;

	/**
	 * Seconds before {@link #firstFiredAt} that correlation reaches back, frozen onto the row
	 * rather than read from configuration when a query runs.
	 *
	 * <p>Recording it is what makes a correlation <em>reproducible</em>. Configuration
	 * changes; if the parameters lived only in {@code application.properties} then re-running
	 * a correlation next year would produce a different bundle with nothing to explain the
	 * difference. {@code updatable = false} for the same reason — the parameters an incident
	 * was correlated under are history, not settings.
	 *
	 * <p>Also absorbs clock skew between sources, since {@code EvidenceItem.eventStart} and
	 * {@code eventEnd} are sender-asserted.
	 */
	@Column(name = "correlation_lookback_seconds", nullable = false, updatable = false)
	private int correlationLookbackSeconds = DEFAULT_LOOKBACK_SECONDS;

	@Column(name = "correlation_lookahead_seconds", nullable = false, updatable = false)
	private int correlationLookaheadSeconds = DEFAULT_LOOKAHEAD_SECONDS;

	/**
	 * When the first correlation pass completed, or {@code null} while
	 * {@link CorrelationStatus#PENDING}. What {@link EvidenceLink#isLateArrival()} is judged
	 * against. Kept consistent with {@link #correlationStatus} by
	 * {@code ck_incident_correlated_at}.
	 */
	@Column(name = "correlated_at")
	private OffsetDateTime correlatedAt;

	/**
	 * The non-time half of the correlation rule, as a JSON document — currently the work
	 * group the incident is searched within.
	 *
	 * <p>Time alone is not a usable predicate: under continuous collection a 45-minute window
	 * across the whole estate returns tens of thousands of items. Written once, by the first
	 * pass, and treated as frozen afterwards — a convention rather than a constraint, since it
	 * is not known at insert time.
	 */
	@Column(name = "correlation_scope", columnDefinition = "text")
	private String correlationScope;

	/**
	 * Takes in one more member alert's {@code firedAt}, widening the span if it falls outside.
	 *
	 * <p>A {@link CorrelationStatus#CLOSED} incident is reopened: a new alert in a settled
	 * incident is new information, and its widened window may cover evidence the closed
	 * bundle never searched. It goes back to {@code CORRELATED}, not {@code PENDING} — it was
	 * correlated, and {@link #correlatedAt} still says when, so anything the next pass finds
	 * is correctly flagged as a late arrival.
	 */
	public void absorb(OffsetDateTime firedAt) {
		if (firstFiredAt == null || firedAt.isBefore(firstFiredAt)) {
			firstFiredAt = firedAt;
		}
		if (lastFiredAt == null || firedAt.isAfter(lastFiredAt)) {
			lastFiredAt = firedAt;
		}
		if (correlationStatus == CorrelationStatus.CLOSED) {
			correlationStatus = CorrelationStatus.CORRELATED;
		}
	}

	/** The start of the window correlation searches. */
	public OffsetDateTime windowStart() {
		return firstFiredAt.minusSeconds(correlationLookbackSeconds);
	}

	/** The end of the window correlation searches. */
	public OffsetDateTime windowEnd() {
		return lastFiredAt.plusSeconds(correlationLookaheadSeconds);
	}

	/** Identity by primary key once assigned, matching the other entities. */
	@Override
	public boolean equals(Object other) {
		if (this == other) {
			return true;
		}
		if (!(other instanceof Incident that)) {
			return false;
		}
		return id != null && id.equals(that.id);
	}

	/** Constant per type, so an instance is not stranded in a hash bucket once persisted. */
	@Override
	public int hashCode() {
		return Incident.class.hashCode();
	}

	@Override
	public String toString() {
		return "Incident{id=" + id
				+ ", sourceSystem='" + sourceSystem + '\''
				+ ", incidentKey='" + incidentKey + '\''
				+ ", status=" + correlationStatus + '}';
	}
}
