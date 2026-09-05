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
 * The SIEM/IDS alert an investigation starts from.
 *
 * <p><strong>No longer the cause of ingestion.</strong> Before changeset {@code 0004},
 * evidence existed because an alert fired, which made the system purely reactive: by the
 * time an IDS notices an intrusion, the reconnaissance and initial access that preceded it
 * happened hours ago and were never preserved. Evidence now streams in continuously from
 * registered {@link EvidenceSource}s, and an alert's job is to <em>gather</em> what was
 * already preserved — everything whose coverage window overlaps the window this alert
 * defines. A trigger event is therefore an anchor for retrospective correlation rather
 * than an ingestion command, and the association it produces lives in {@link EvidenceLink}.
 *
 * <p>Mirrors Liquibase changesets {@code 0002-create-trigger-event-table} and
 * {@code 0005-create-evidence-link-and-correlation-state}. Because
 * {@code spring.jpa.hibernate.ddl-auto=validate}, any drift between this class and that
 * changeset fails application startup, so the two must be edited together.
 *
 * <p>Treat rows here as append-only. A trigger event records that an alert was received
 * at a point in time; editing or deleting one rewrites history in a system whose whole
 * value proposition is that history was not rewritten. Nothing in this class enforces
 * that yet — {@link za.co.dfraas.repository.TriggerEventRepository} still inherits
 * {@code delete}, and locking that down is the same job that {@code CustodyEvent} will
 * need doing properly.
 */
@Entity
@Table(
		name = "trigger_event",
		uniqueConstraints = @UniqueConstraint(
				name = "uq_trigger_event_source_external",
				columnNames = {"source_system", "external_event_id"}))
@Getter
@Setter
public class TriggerEvent {

	@Id
	@GeneratedValue(strategy = GenerationType.UUID)
	@Column(name = "id", nullable = false, updatable = false)
	private UUID id;

	/**
	 * The identifier the emitting system assigned to this alert, and the field ingestion
	 * actually dedupes on.
	 *
	 * <p>{@code id} cannot serve that purpose: it is generated here at insert time, so a
	 * redelivered Kafka message would produce a fresh UUID and sail straight past any
	 * check. Kafka's delivery guarantee is at-least-once, so redelivery is normal
	 * operation rather than an error case.
	 *
	 * <p>Unique only in combination with {@link #sourceSystem} — see the table's composite
	 * constraint.
	 */
	@Column(name = "external_event_id", nullable = false, updatable = false, length = 255)
	private String externalEventId;

	@Column(name = "source_system", nullable = false, updatable = false, length = 255)
	private String sourceSystem;

	/**
	 * Free-form on purpose. Detection rule names are vendor-defined and open-ended, so a
	 * native enum here would mean a migration every time someone writes a new SIEM rule.
	 */
	@Column(name = "trigger_type", nullable = false, updatable = false, length = 255)
	private String triggerType;

	/**
	 * When the source says the alert fired. Reported by the sender, so it inherits that
	 * host's clock — useful, but not evidence of anything on its own.
	 */
	@Column(name = "fired_at", nullable = false, updatable = false)
	private OffsetDateTime firedAt;

	/**
	 * When this service received it, stamped by the database clock via the column default.
	 *
	 * <p>{@code @Generated(INSERT)} is what makes the default fire: without it Hibernate
	 * would include the field in the INSERT as {@code null} and the NOT NULL constraint
	 * would reject the row.
	 *
	 * <p>Kept distinct from {@link #firedAt} deliberately. The gap between the two is
	 * itself diagnostic — a large one means delayed delivery or a skewed source clock, and
	 * collapsing them into one column would hide that.
	 */
	@Generated(event = EventType.INSERT)
	@Column(name = "received_at", nullable = false, insertable = false, updatable = false)
	private OffsetDateTime receivedAt;

	/**
	 * The original alert, byte for byte. Retained rather than discarded after parsing:
	 * the alert is part of the evidentiary record, and the typed columns above are an
	 * interpretation of it, not a replacement for it.
	 */
	@Column(name = "payload", nullable = false, updatable = false, columnDefinition = "text")
	private String payload;

	/**
	 * Lowercase hex SHA-256 of {@link #payload}, computed before any other processing
	 * touches it, per SecureRS. A database CHECK constraint enforces the format, so a
	 * malformed digest is rejected even on a write that bypasses this application.
	 */
	@Column(name = "payload_sha256", nullable = false, updatable = false, length = 64)
	private String payloadSha256;

	/**
	 * Default seconds of lookback applied when nothing more specific is known.
	 *
	 * <p>Much larger than {@link #DEFAULT_LOOKAHEAD_SECONDS}, and the asymmetry is the
	 * whole point of the refactor: the activity that matters — reconnaissance, initial
	 * access, staging — precedes detection, and gathering only from the moment of detection
	 * reproduces the blind spot the reactive design had.
	 *
	 * <p>A constant here rather than a configuration property because it is a schema-level
	 * default, matched by the column default in {@code 0005-8}, and because the real answer
	 * is per-trigger-type policy rather than one global number. See
	 * {@link #getCorrelationLookbackSeconds()}.
	 */
	public static final int DEFAULT_LOOKBACK_SECONDS = 1800;

	/** Default seconds of lookahead — the immediate aftermath, plus the collection lag of
	 *  sources that batch their output. */
	public static final int DEFAULT_LOOKAHEAD_SECONDS = 900;

	/**
	 * How far correlation has got for this alert. See {@link CorrelationStatus}, which
	 * carries the argument for why this exists and why it is not a native Postgres enum.
	 */
	@Enumerated(EnumType.STRING)
	@Column(name = "correlation_status", nullable = false, length = 32)
	private CorrelationStatus correlationStatus = CorrelationStatus.PENDING;

	/**
	 * Seconds before {@link #firedAt} that correlation reaches back, frozen onto the row
	 * rather than read from configuration when a query runs.
	 *
	 * <p>Recording it is what makes a correlation <em>reproducible</em>. Configuration
	 * changes; if the parameters lived only in {@code application.properties} then
	 * re-running a correlation next year would produce a different bundle with nothing to
	 * explain the difference, and an investigator could not state on the record what the
	 * system had been asked to look for. {@code updatable = false} for the same reason —
	 * the parameters an alert was correlated under are history, not settings.
	 *
	 * <p>Also absorbs clock skew between sources, since {@code EvidenceItem.eventStart} and
	 * {@code eventEnd} are sender-asserted and carry none of {@link #receivedAt}'s
	 * authority.
	 *
	 * <p>Per-trigger-type policy — a data-exfiltration alert wants hours of lookback, a
	 * failed-login alert minutes — is the obvious next step and is deliberately not modelled
	 * yet. It belongs with the detection catalogue, not on this table.
	 */
	@Column(name = "correlation_lookback_seconds", nullable = false, updatable = false)
	private int correlationLookbackSeconds = DEFAULT_LOOKBACK_SECONDS;

	@Column(name = "correlation_lookahead_seconds", nullable = false, updatable = false)
	private int correlationLookaheadSeconds = DEFAULT_LOOKAHEAD_SECONDS;

	/**
	 * When the first correlation pass completed, or {@code null} while
	 * {@link CorrelationStatus#PENDING}. What {@link EvidenceLink#isLateArrival()} is judged
	 * against.
	 *
	 * <p>Kept consistent with {@link #correlationStatus} by
	 * {@code ck_trigger_event_correlated_at} — a pending alert carrying a completion
	 * timestamp is unreadable, because either the status or the timestamp is lying and
	 * nothing says which.
	 */
	@Column(name = "correlated_at")
	private OffsetDateTime correlatedAt;

	/**
	 * The non-time half of the correlation rule, as a JSON document — work groups, source
	 * keys, hosts, accounts.
	 *
	 * <p>Time alone is not a usable predicate, and this field is where that is admitted.
	 * Under continuous collection every source produces constantly, so a 45-minute window
	 * across the whole estate returns a bundle measured in tens of thousands of items —
	 * which is not evidence gathering but a more expensive way of finding nothing. A scope
	 * narrows it to what could plausibly bear on the alert.
	 *
	 * <p>Written once, by the pass that correlates the alert, and treated as frozen
	 * afterwards. Not {@code updatable = false}, because it is not known at insert time; the
	 * write-once rule is therefore currently a convention rather than a constraint — the
	 * same gap {@code CustodyEvent}'s append-only requirement will have to close properly.
	 */
	@Column(name = "correlation_scope", columnDefinition = "text")
	private String correlationScope;

	/**
	 * Identity by primary key once assigned, matching {@link WorkGroup}. Two unsaved
	 * instances are never equal, which is the correct answer — they are two separate
	 * objects that have not yet been given an identity.
	 */
	@Override
	public boolean equals(Object other) {
		if (this == other) {
			return true;
		}
		if (!(other instanceof TriggerEvent that)) {
			return false;
		}
		return id != null && id.equals(that.id);
	}

	/**
	 * Constant per type rather than derived from {@code id}, so an instance added to a
	 * {@code HashSet} before persist is not stranded in the wrong bucket once Hibernate
	 * assigns the id.
	 */
	@Override
	public int hashCode() {
		return TriggerEvent.class.hashCode();
	}

	/**
	 * Deliberately omits {@link #payload} — this string reaches logs, and the alert body
	 * can carry account numbers or customer identifiers.
	 */
	@Override
	public String toString() {
		return "TriggerEvent{id=" + id
				+ ", sourceSystem='" + sourceSystem + '\''
				+ ", externalEventId='" + externalEventId + '\''
				+ ", triggerType='" + triggerType + '\'' + '}';
	}
}
