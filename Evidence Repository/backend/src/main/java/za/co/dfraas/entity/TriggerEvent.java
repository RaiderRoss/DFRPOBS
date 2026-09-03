package za.co.dfraas.entity;

import java.time.OffsetDateTime;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
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
 * The SIEM/IDS alert that caused an ingestion — the input end of the preservation
 * pipeline.
 *
 * <p>Mirrors Liquibase changeset {@code 0002-create-trigger-event-table}. Because
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
