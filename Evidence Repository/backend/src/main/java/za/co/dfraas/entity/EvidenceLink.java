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
import jakarta.persistence.UniqueConstraint;

import org.hibernate.annotations.Generated;
import org.hibernate.generator.EventType;

import lombok.Getter;
import lombok.Setter;

/**
 * The association between an {@link Incident} and an {@link EvidenceItem} that bears on
 * it — the join that replaced {@code evidence_item.trigger_event_id}, re-pointed from the
 * alert to its incident by {@code 0007}.
 *
 * <p>Mirrors Liquibase changeset {@code 0005-create-evidence-link-and-correlation-state}.
 * Because {@code spring.jpa.hibernate.ddl-auto=validate}, any drift between this class and
 * that changeset fails application startup, so the two must be edited together.
 *
 * <p><strong>Why a join entity and not a {@code @ManyToMany}.</strong> Two reasons, and the
 * second is the important one.
 *
 * <ul>
 *   <li>The cardinality is genuinely many-to-many. A firewall log covering 10:00–11:00
 *       overlaps every alert that fired in that hour, and the old foreign key on
 *       {@code EvidenceItem} capped it at one.</li>
 *   <li>The link is an <em>assertion</em>, not a fact. Under continuous collection the
 *       artifact already existed; what an alert does is gather evidence preserved
 *       independently of it, and a time-overlap match is a hypothesis produced by a rule
 *       with parameters. So the link has to carry how it was made ({@link LinkMethod}), on
 *       what reasoning ({@link #rationale}), and whether a person has since agreed
 *       ({@link LinkDisposition}). A bare {@code @ManyToMany} can carry none of that, and
 *       would present an unreviewed machine suggestion in exactly the same shape as an
 *       investigator's finding.</li>
 * </ul>
 *
 * <p><strong>Treat rows here as append-only apart from the review fields.</strong> Links
 * are added by re-correlation and never removed: silently retracting evidence from a bundle
 * someone has already reviewed would be indefensible, which is why an irrelevant link is
 * {@link LinkDisposition#DISMISSED} rather than deleted. Nothing in this class enforces
 * that yet — the same lockdown {@link TriggerEvent} needs, and the same one
 * {@code CustodyEvent} will need properly.
 */
@Entity
@Table(
		name = "evidence_link",
		uniqueConstraints = @UniqueConstraint(
				name = "uq_evidence_link_pair",
				columnNames = {"incident_id", "evidence_item_id"}))
@Getter
@Setter
public class EvidenceLink {

	@Id
	@GeneratedValue(strategy = GenerationType.UUID)
	@Column(name = "id", nullable = false, updatable = false)
	private UUID id;

	/**
	 * The incident this link gathers evidence for — not an individual alert, since
	 * {@code 0007}: a source that alerts six times about one attack gets one bundle, reviewed
	 * once, rather than the same firewall log proposed six times.
	 *
	 * <p>{@code updatable = false} on both foreign keys: re-pointing a link at a different
	 * incident or a different artifact would silently move an exhibit between investigations
	 * while keeping the reasoning and the reviewer's name attached to it, which is a forgery
	 * in everything but name. A wrong link is dismissed; it is not repaired in place.
	 */
	@ManyToOne(fetch = FetchType.LAZY, optional = false)
	@JoinColumn(
			name = "incident_id",
			nullable = false,
			updatable = false,
			foreignKey = @ForeignKey(name = "fk_evidence_link_incident"))
	private Incident incident;

	@ManyToOne(fetch = FetchType.LAZY, optional = false)
	@JoinColumn(
			name = "evidence_item_id",
			nullable = false,
			updatable = false,
			foreignKey = @ForeignKey(name = "fk_evidence_link_evidence_item"))
	private EvidenceItem evidenceItem;

	@Enumerated(EnumType.STRING)
	@Column(name = "link_method", nullable = false, updatable = false, length = 32)
	private LinkMethod linkMethod;

	@Enumerated(EnumType.STRING)
	@Column(name = "disposition", nullable = false, length = 32)
	private LinkDisposition disposition = LinkDisposition.PROPOSED;

	/**
	 * Why this link exists, in a form a person can read: the overlap that matched, the rule
	 * that fired, or the investigator's stated reason.
	 *
	 * <p>This is what makes "why is this item in this incident's bundle?" answerable a year
	 * later, without re-running a correlation whose parameters may since have changed. It
	 * is the difference between a bundle an investigator can defend and one they can only
	 * present.
	 */
	@Column(name = "rationale", updatable = false, columnDefinition = "text")
	private String rationale;

	/**
	 * Who created the link, or {@code null} for an automated one — where the honest answer
	 * is "the correlation pass", and naming a synthetic user would be worse than saying
	 * nothing. Required for {@link LinkMethod#MANUAL}, enforced by
	 * {@code ck_evidence_link_manual_attribution}.
	 *
	 * <p>TODO: becomes a foreign key to {@code app_user} once that table exists. A
	 * {@code String} in the interim, as {@code CustodyEvent.performedBy} will also have to
	 * be.
	 */
	@Column(name = "linked_by", updatable = false, length = 255)
	private String linkedBy;

	/**
	 * Stamped by the database clock via the column default, as everywhere else here.
	 */
	@Generated(event = EventType.INSERT)
	@Column(name = "linked_at", nullable = false, insertable = false, updatable = false)
	private OffsetDateTime linkedAt;

	/**
	 * Who ruled on the link and when. Both null or both set —
	 * {@code ck_evidence_link_review_complete}, with {@link #reviewNote} — and both mandatory for
	 * {@link LinkDisposition#DISMISSED}.
	 *
	 * <p>Set by the application rather than a column default, unlike every other timestamp
	 * in this schema. That is a real weakening and it is deliberate: this records a human
	 * decision that may be made offline and entered afterwards, so it cannot always be
	 * "now". It is metadata about an investigation rather than about an exhibit, which is
	 * why it does not need the untouchable-clock treatment {@code createdAt} and
	 * {@code receivedAt} get.
	 */
	@Column(name = "reviewed_by", length = 255)
	private String reviewedBy;

	@Column(name = "reviewed_at")
	private OffsetDateTime reviewedAt;

	/**
	 * Why the reviewer ruled as they did. Set with {@link #reviewedBy} and
	 * {@link #reviewedAt} or not at all, and never blank —
	 * {@code ck_evidence_link_review_complete}.
	 *
	 * <p>Separate from {@link #rationale}, which says why the link was <em>proposed</em> and
	 * belongs to whoever made it. This says why a person agreed or set it aside, which is
	 * the part of a dismissal a defence will actually ask about.
	 */
	@Column(name = "review_note", columnDefinition = "text")
	private String reviewNote;

	/**
	 * Whether this link was added by a later correlation pass, after the alert had already
	 * been correlated once.
	 *
	 * <p>Late arrival is normal here rather than exceptional, and that is a direct
	 * consequence of decoupling collection from alerting: evidence covering 14:00–15:00 may
	 * not reach us until 15:02, by which time an alert that fired at 14:30 has been
	 * correlated and possibly already reviewed. Flagging it lets an investigator who looked
	 * at the bundle yesterday see what has appeared since, rather than having to re-read the
	 * whole thing to find out.
	 */
	@Column(name = "late_arrival", nullable = false)
	private boolean lateArrival;

	/**
	 * Identity by primary key once assigned, matching the other entities. Two unsaved
	 * instances are never equal — deliberately not identity by the (trigger event, item)
	 * pair, even though the database treats that as unique: two unsaved links for the same
	 * pair are a bug to be caught by the constraint, not a coincidence to be smoothed over
	 * in memory.
	 */
	@Override
	public boolean equals(Object other) {
		if (this == other) {
			return true;
		}
		if (!(other instanceof EvidenceLink that)) {
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
		return EvidenceLink.class.hashCode();
	}

	/**
	 * Deliberately omits both lazy associations — touching them here would fire a query
	 * from whatever logging statement interpolated this object, or throw outside a session.
	 */
	@Override
	public String toString() {
		return "EvidenceLink{id=" + id
				+ ", method=" + linkMethod
				+ ", disposition=" + disposition
				+ ", lateArrival=" + lateArrival + '}';
	}
}
