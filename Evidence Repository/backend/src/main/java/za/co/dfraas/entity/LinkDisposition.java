package za.co.dfraas.entity;

/**
 * Whether a human has ruled on an {@link EvidenceLink}.
 *
 * <p>Separate from {@link LinkMethod} on purpose: the method says who or what proposed the
 * link, this says whether anyone has since agreed. Collapsing the two would make an
 * unreviewed machine suggestion indistinguishable from an investigator's finding.
 *
 * <p>Persisted by name with a CHECK constraint behind it, matching {@link EvidenceStatus}.
 */
public enum LinkDisposition {

	/**
	 * Proposed and not yet reviewed. The honest default for anything automated: the system
	 * found an overlap, which is a reason to look, not a finding.
	 */
	PROPOSED,

	/**
	 * A person has agreed the item belongs to this incident — or, for a
	 * {@link LinkMethod#CAUSAL} link, no person was needed because the collection was
	 * observed rather than inferred. That exception is why the database requires a reviewer
	 * for {@link #DISMISSED} but not for this state.
	 */
	CONFIRMED,

	/**
	 * An investigator judged the item irrelevant to this incident.
	 *
	 * <p><strong>Dismissed, not deleted</strong> — and that distinction carries real weight.
	 * "The system surfaced this and an investigator considered it and set it aside" is part
	 * of the investigative record, and is precisely what a defence would probe. Deleting the
	 * row would leave the bundle looking as though the item had never been surfaced at all,
	 * which is a different and less defensible claim.
	 *
	 * <p>Always a human judgement: nothing automated may decide evidence is irrelevant, and
	 * a database CHECK enforces that by requiring {@code reviewedBy} and {@code reviewedAt}.
	 */
	DISMISSED
}
