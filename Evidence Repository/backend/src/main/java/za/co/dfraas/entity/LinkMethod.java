package za.co.dfraas.entity;

/**
 * How an {@link EvidenceLink} came to exist.
 *
 * <p>This enum is the reason the link is an entity rather than a bare join table. A
 * correlation and a causation are not the same claim, and a schema that cannot tell them
 * apart invites an investigator to read a proposed match as established provenance — the
 * one misreading this system exists to prevent. Ordering the constants below runs from
 * strongest evidential standing to weakest for exactly that reason.
 *
 * <p>Persisted by name ({@code @Enumerated(EnumType.STRING)}) with a CHECK constraint
 * behind it, matching {@link EvidenceStatus}.
 */
public enum LinkMethod {

	/**
	 * The item was collected <em>because</em> this alert fired — on-demand collection, and
	 * the meaning the old {@code evidence_item.trigger_event_id} column carried before
	 * changeset {@code 0005} migrated it here.
	 *
	 * <p>Still a real case after the move to continuous collection, and worth keeping
	 * distinct: some artifacts (a memory capture, a targeted snapshot) can only be taken in
	 * response to something. This is the only method that is an <em>observation</em> — the
	 * system watched the collection happen — rather than an inference drawn afterwards,
	 * which is why it is the only one legitimately created already
	 * {@link LinkDisposition#CONFIRMED}.
	 */
	CAUSAL,

	/**
	 * Overlapped the window and also matched a named correlation rule, which the link's
	 * rationale names: the item covers the instant an alert fired ({@code alert-instant}), or
	 * mentions an address the alert names as its subject ({@code shared-indicator}). See
	 * {@code CorrelationService}.
	 *
	 * <p>Kept separate from {@link #AUTO_TIME_WINDOW} because it is far stronger evidence of
	 * relevance, and an investigator triaging a large bundle needs to see which links are
	 * which. Both are hypotheses; these are the ones worth opening first.
	 */
	AUTO_RULE,

	/**
	 * The item's coverage window overlaps the alert's correlation window, and nothing
	 * narrower was matched. The default automated path, and the weakest claim in the set:
	 * temporal overlap in a system where every source is producing continuously means only
	 * that this artifact <em>could</em> bear on the alert.
	 */
	AUTO_TIME_WINDOW,

	/**
	 * An investigator added it. Requires attribution — a database CHECK rejects a
	 * {@code MANUAL} link with no {@code linkedBy}, because an unattributed assertion is
	 * not admissible as anything.
	 */
	MANUAL
}
