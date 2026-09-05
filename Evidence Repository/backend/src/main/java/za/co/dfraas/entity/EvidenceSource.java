package za.co.dfraas.entity;

import java.time.OffsetDateTime;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.ForeignKey;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

import org.hibernate.annotations.Generated;
import org.hibernate.generator.EventType;

import lombok.Getter;
import lombok.Setter;

/**
 * A registered producer that streams evidence into the repository continuously.
 *
 * <p>Mirrors Liquibase changeset {@code 0004-create-evidence-source-and-coverage-window}.
 * Because {@code spring.jpa.hibernate.ddl-auto=validate}, any drift between this class and
 * that changeset fails application startup, so the two must be edited together.
 *
 * <p><strong>Why this entity exists.</strong> Under the original reactive design a producer
 * was anonymous: anything could publish to the topic, and the alert carried the
 * classification. Continuous collection changes what a producer is. It becomes a
 * long-lived participant that the institution has decided to collect from, whose output is
 * expected on a cadence, and whose registration is where classification is decided —
 * which is the answer to README open question 1.
 *
 * <p><strong>The failure mode it defends against.</strong> A streaming source that silently
 * stops produces exactly what a source with nothing to report produces: nothing. Under the
 * reactive design a missing alert was noticeable because someone was waiting for it; here
 * nobody is, and the gap only surfaces months later when an investigator finds the window
 * they need is empty. {@link #expectedIntervalSeconds} and {@link #lastEvidenceAt} are what
 * turn "which of our sources has gone quiet" into a query — and that question, not the
 * volume of evidence stored, is the readiness audit.
 */
@Entity
@Table(name = "evidence_source")
@Getter
@Setter
public class EvidenceSource {

	@Id
	@GeneratedValue(strategy = GenerationType.UUID)
	@Column(name = "id", nullable = false, updatable = false)
	private UUID id;

	/**
	 * The stable identifier a producer puts on the wire — the same value
	 * {@link TriggerEvent#getSourceSystem()} carries for alerts.
	 *
	 * <p>The natural key rather than {@link #id}, because a collection agent's config file
	 * has to name its source and a human-readable key is what survives being copied into
	 * one. Globally unique, unlike {@code TriggerEvent.externalEventId}: this one is
	 * assigned by us at registration rather than by a vendor we do not control.
	 */
	@Column(name = "source_key", nullable = false, updatable = false, unique = true, length = 255)
	private String sourceKey;

	@Column(name = "display_name", nullable = false, length = 255)
	private String displayName;

	/**
	 * The classification every item this source produces is preserved under.
	 *
	 * <p>Mandatory, for the same reason {@link EvidenceItem#getWorkGroup()} is: evidence
	 * that cannot be classified has no defensible retention or release policy, and
	 * registering a source without one records a promise the system cannot keep.
	 *
	 * <p>Note that {@code EvidenceItem} keeps its own {@code workGroup} rather than
	 * deriving it through here. That is not redundancy — it is a snapshot. Reclassifying a
	 * source next year must not silently reclassify every artifact it ever produced, each
	 * of which was retained and released under the classification in force at the time.
	 */
	@ManyToOne(fetch = FetchType.LAZY, optional = false)
	@JoinColumn(
			name = "work_group_id",
			nullable = false,
			foreignKey = @ForeignKey(name = "fk_evidence_source_work_group"))
	private WorkGroup workGroup;

	/**
	 * What kind of collector this is — {@code SYSLOG}, {@code DB_AUDIT}, {@code NETFLOW},
	 * {@code EDR}. Free-form for the same reason {@link TriggerEvent#getTriggerType()} is:
	 * the set is defined by whatever the institution actually runs, and adding a collector
	 * must not require a migration.
	 */
	@Column(name = "source_type", nullable = false, length = 64)
	private String sourceType;

	@Enumerated(EnumType.STRING)
	@Column(name = "status", nullable = false, length = 32)
	private SourceStatus status = SourceStatus.ACTIVE;

	/**
	 * How often this source is expected to produce, in seconds, or {@code null} when it is
	 * event-driven and silence proves nothing.
	 *
	 * <p>The null is meaningful rather than missing data. A syslog forwarder should have a
	 * cadence; a collector that only emits on a rare condition should not, because holding
	 * it to one produces a permanent false alarm — and an alarm that is always on is an
	 * alarm nobody reads.
	 */
	@Column(name = "expected_interval_seconds")
	private Integer expectedIntervalSeconds;

	/**
	 * When this source last successfully produced an item, stamped on each ingest.
	 *
	 * <p>The one mutable column on the row, and deliberately not evidence: it is
	 * overwritten, so it keeps no history. The history of what a source produced is
	 * {@code evidence_item} itself. This is a liveness signal and nothing more.
	 */
	@Column(name = "last_evidence_at")
	private OffsetDateTime lastEvidenceAt;

	/**
	 * Stamped by the database clock via the column default, as everywhere else in this
	 * schema. {@code @Generated(INSERT)} is what makes the default fire.
	 */
	@Generated(event = EventType.INSERT)
	@Column(name = "registered_at", nullable = false, insertable = false, updatable = false)
	private OffsetDateTime registeredAt;

	/**
	 * Identity by primary key once assigned, matching the other entities. Two unsaved
	 * instances are never equal.
	 */
	@Override
	public boolean equals(Object other) {
		if (this == other) {
			return true;
		}
		if (!(other instanceof EvidenceSource that)) {
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
		return EvidenceSource.class.hashCode();
	}

	/**
	 * Deliberately omits the lazy {@link #workGroup} — touching it here would fire a query
	 * from whatever logging statement interpolated this object, or throw outside a session.
	 */
	@Override
	public String toString() {
		return "EvidenceSource{id=" + id + ", sourceKey='" + sourceKey + "', status=" + status + "}";
	}
}
