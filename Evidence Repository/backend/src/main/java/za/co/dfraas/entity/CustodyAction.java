package za.co.dfraas.entity;

/**
 * What a {@link CustodyEvent} records having happened to an {@link EvidenceItem}.
 *
 * <p><strong>Persisted as {@code VARCHAR} + a CHECK constraint, not a native Postgres
 * enum</strong>, for the reasons {@link EvidenceStatus} sets out: this list is
 * business-facing, it will be argued over as the readiness process matures, and a CHECK can
 * shrink as well as grow while a native enum cannot lose or rename a value without
 * recreating the type and rewriting every dependent column. Names are the stored values
 * ({@code @Enumerated(EnumType.STRING)}), so renaming a constant is a schema migration
 * rather than a refactor — and here it is worse than that: the name is inside
 * {@code entry_hash}, so a rename invalidates every digest ever written over it.
 *
 * <p><strong>Only actions something can actually emit are defined.</strong> That is the
 * whole of the list below, and the discipline matters more here than anywhere else in this
 * schema. An action list is read as exhaustive — an investigator seeing no {@code EXPORTED}
 * entries against an artifact concludes it was never exported. If the value exists but
 * nothing writes it, what they have actually learned is "never recorded", and the ledger has
 * misled them while appearing complete. A short list makes the gap visible; a speculative
 * one hides it.
 *
 * <p>So, deliberately absent until the code that would emit them exists:
 *
 * <ul>
 *   <li>{@code EXPORTED} / {@code DOWNLOADED} — there is no retrieval route at all.
 *       {@code SecurityConfiguration} reserves {@code /api/evidence/*&#47;download} for an
 *       OTP step-up it does not implement, so nothing in this application can serve
 *       evidence bytes and nothing could write this entry.</li>
 *   <li>{@code STATUS_CHANGED} — no endpoint or scheduled task changes
 *       {@code EvidenceItem.status} after ingest.</li>
 *   <li>{@code HASH_MISMATCH} — needs {@code IntegrityCheck} and the re-verification pass.
 *       Note that the mismatches the ingest path already detects cannot be recorded here:
 *       both abort the transaction, and {@code CustodyChainService.append} joins the caller's
 *       transaction by design, so the entry would roll back with the row it describes. A
 *       failed ingest leaves no artifact and therefore no chain to append to.</li>
 *   <li>{@code ACCESSED} — belongs to {@code AccessLog}, which the README keeps separate
 *       from this table on purpose: reads are high-volume and do not change custody, and
 *       mixing them in would bury the handful of entries that do.</li>
 * </ul>
 *
 * <p>Adding any of them is one {@code ALTER TABLE} against
 * {@code ck_custody_event_action}, in the same changeset as the code that emits it.
 */
public enum CustodyAction {

	/**
	 * The artifact was preserved — the opening entry of every chain, written by
	 * {@code EvidenceItemService.preserve} in the same transaction as the
	 * {@link EvidenceItem} row itself.
	 *
	 * <p>Mandatory rather than merely usual, and it is what makes provenance survive
	 * {@code evidence_item.evidence_source_id} being nullable: a manually preserved item has
	 * no collector behind it, but it still has someone who preserved it, and this is where
	 * that is recorded. An item whose chain has no {@code CREATED} entry at position 0 does
	 * not verify — {@code CustodyChainService.verify} reports it as missing its origin, and
	 * an empty chain is never a legitimate state.
	 *
	 * <p>Carries the digest computed at ingest in {@code artifactHashAfter} and nothing in
	 * {@code artifactHashBefore}: there was no prior state. That is the anchor for every
	 * later change to {@code EvidenceItem.currentHash}, which is mutable by design.
	 */
	CREATED
}
