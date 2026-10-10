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
 *   <li>{@code STATUS_CHANGED} — no endpoint or scheduled task changes
 *       {@code EvidenceItem.status} by operator decision. The one status transition that
 *       does exist, to {@code COMPROMISED}, is a consequence of {@link #HASH_MISMATCH} and
 *       is recorded by that entry rather than by a second one in the same transaction.</li>
 *   <li>{@code ACCESSED} — belongs to {@code AccessLog}, which the README keeps separate
 *       from this table on purpose: reads are high-volume and do not change custody, and
 *       mixing them in would bury the handful of entries that do.</li>
 * </ul>
 *
 * <p>Adding any of them is one {@code ALTER TABLE} against
 * {@code ck_custody_event_action}, in the same changeset as the code that emits it —
 * changesets {@code 0007} and {@code 0010} are what that looks like.
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
	CREATED,

	/**
	 * The stored object was read back, re-hashed, and the digest matched
	 * {@code EvidenceItem.currentHash}. Written by {@code IntegrityCheckService.check}.
	 *
	 * <p><strong>The hash pair reads as expected/observed on this entry</strong>, not
	 * before/after: a verification does not change the bytes, so {@code artifactHashBefore}
	 * is the digest the item was expected to have and {@code artifactHashAfter} is the one
	 * recomputed from storage. They are equal here by definition, and both are carried
	 * rather than one, so a reader does not have to infer what the check compared against
	 * from whichever {@code CREATED} entry happens to be at the top of the chain.
	 *
	 * <p>Recorded even though nothing changed, because "this artifact was re-verified on
	 * this date by this principal and was intact" is a custody fact in its own right — it
	 * is the evidence that the evidence was looked after. A chain that only ever records
	 * failures cannot show that anyone was checking.
	 */
	HASH_VERIFIED,

	/**
	 * The stored object was read back, re-hashed, and the digest did not match
	 * {@code EvidenceItem.currentHash}. Written by {@code IntegrityCheckService.check}, which
	 * moves the item to {@link EvidenceStatus#COMPROMISED} in the same transaction.
	 *
	 * <p>Reads as expected/observed like {@link #HASH_VERIFIED}: {@code artifactHashBefore}
	 * is the digest the item should have produced, {@code artifactHashAfter} is what it did
	 * produce. This entry <em>is</em> the record of what was found — there is no separate
	 * integrity-check table, for the reason changeset {@code 0007} gives — and it is the
	 * most consequential thing the ledger can hold, which is exactly why it sits in the
	 * chain that cannot be edited.
	 *
	 * <p>{@code EvidenceItem.currentHash} is deliberately <em>not</em> updated to the observed
	 * value. That column is the expectation; overwriting it with the observation would erase
	 * the discrepancy this entry exists to preserve, and would make a subsequent check pass.
	 *
	 * <p>Also written by {@code IntegrityCheckService.export} when an artifact fails the
	 * re-hash taken before release; nothing is released, and no {@link #EXPORTED} entry
	 * follows.
	 */
	HASH_MISMATCH,

	/**
	 * The artifact's bytes were released to the principal named on the entry, after being
	 * re-hashed and found to match {@code EvidenceItem.currentHash}. Written by
	 * {@code IntegrityCheckService.export}, in the same transaction as the read.
	 *
	 * <p>Reads as expected/observed like {@link #HASH_VERIFIED}, and the two are equal by
	 * construction: an export that fails the re-hash releases nothing and is recorded as
	 * {@link #HASH_MISMATCH} instead. So {@code artifactHashAfter} on this entry is the digest
	 * of exactly the bytes that left, and a copy held outside the system can be checked
	 * against it.
	 *
	 * <p>Every release is an entry, including a second download by the same principal, since
	 * "how many copies exist and who holds them" is the custody question an export raises.
	 * Reads that release nothing — listings, metadata, the chain itself — are not recorded
	 * here; see {@code ACCESSED} above.
	 */
	EXPORTED
}
