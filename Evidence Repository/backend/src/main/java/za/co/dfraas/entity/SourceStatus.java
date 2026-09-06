package za.co.dfraas.entity;

/**
 * Registration state of an {@link EvidenceSource}.
 *
 * <p>Persisted as {@code VARCHAR} + a CHECK constraint rather than a native Postgres enum,
 * on the same reasoning as {@link EvidenceStatus}: the set is operational and
 * human-facing, so it must be able to shrink as well as grow.
 *
 * <p>What this enum is really for is telling two kinds of silence apart. A source that
 * stops producing is either broken or switched off, and only one of those is a finding.
 * Without a registration state the liveness sweep cannot distinguish them and every
 * decommissioned collector becomes a permanent alarm.
 */
public enum SourceStatus {

	/**
	 * Registered and expected to produce. The only state in which silence is a finding —
	 * see {@link EvidenceSource#getExpectedIntervalSeconds()}.
	 */
	ACTIVE,

	/**
	 * Deliberately paused — maintenance, an investigation into the collector itself, or a
	 * source quarantined because its output is suspect. Distinct from
	 * {@link #DECOMMISSIONED} because it is expected to come back, and the gap in
	 * collection is a known one rather than a discovered one.
	 */
	SUSPENDED,

	/**
	 * Retired for good. The row survives rather than being deleted, because every
	 * {@code EvidenceItem} this source produced still points at it, and "what collected
	 * this exhibit, and is that collector still in service" is a question an investigation
	 * is entitled to ask years later.
	 */
	DECOMMISSIONED
}
