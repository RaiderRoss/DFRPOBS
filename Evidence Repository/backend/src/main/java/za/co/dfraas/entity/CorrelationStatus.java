package za.co.dfraas.entity;

/**
 * How far correlation has got for a {@link TriggerEvent}.
 *
 * <p>This is README open question 3, arriving in the shape the move to continuous
 * collection gives it. The original bug was that ingestion deduped on "has this alert been
 * recorded" when it needed "has this alert been fully processed", so a crash between
 * committing the trigger event and writing the blob lost the evidence permanently and
 * silently. Once the alert no longer causes ingestion there is no blob write to resume —
 * but the same gap reappears one step along, as <em>"this alert was recorded and never
 * correlated"</em>. The state therefore tracks correlation rather than preservation, and it
 * answers the audit question the original was reaching for: which alerts came in and
 * produced nothing.
 *
 * <p><strong>One documented reversal.</strong> Open question 3 argued for a native Postgres
 * enum here, on the grounds that a processing state is closed and internal. Correlation
 * status is not internal — an investigator sees "correlation still pending" against an
 * incident and will reasonably ask for states this list does not have (awaiting review,
 * superseded, reopened). That puts it in the same category as {@link EvidenceStatus}, so it
 * gets the same treatment: {@code VARCHAR} plus a CHECK constraint, which can shrink as
 * well as grow.
 */
public enum CorrelationStatus {

	/**
	 * Recorded, not yet correlated. The state every alert is created in, and the one a
	 * readiness audit cares about finding rows sitting in long after the fact.
	 */
	PENDING,

	/**
	 * A correlation pass has completed. Not terminal: later passes may still add links for
	 * evidence that arrives after the fact, flagged with
	 * {@link EvidenceLink#isLateArrival()}.
	 */
	CORRELATED,

	/**
	 * The collection lag has elapsed and no further links will be added automatically. The
	 * bundle is settled, which is what lets an investigator rely on having seen all of it —
	 * a distinction {@link #CORRELATED} alone cannot make, since under continuous collection
	 * "correlated" never means "finished" on its own.
	 *
	 * <p>An investigator can still add a {@link LinkMethod#MANUAL} link to a closed event.
	 * Closing stops the machine, not the person.
	 */
	CLOSED,

	/**
	 * A correlation pass errored. Terminal until retried, and deliberately distinct from
	 * {@link #PENDING}: an alert that has never been attempted and one whose attempt broke
	 * need the same work done but tell an operator entirely different things about the
	 * system.
	 */
	FAILED
}
