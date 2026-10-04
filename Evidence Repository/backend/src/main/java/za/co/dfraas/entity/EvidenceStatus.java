package za.co.dfraas.entity;

/**
 * Lifecycle state of an {@link EvidenceItem}.
 *
 * <p><strong>Persisted as {@code VARCHAR} + a CHECK constraint, not a native Postgres
 * enum.</strong> The two are not interchangeable here. A native enum can gain values
 * ({@code ALTER TYPE ... ADD VALUE}) but cannot lose or rename them without recreating the
 * type and rewriting every dependent column — and this set is business-facing, so it will
 * be argued over as the readiness process matures (legal hold, redaction, export
 * embargo). A CHECK constraint is one {@code ALTER TABLE} to change in either direction
 * while still refusing an unknown value on writes that bypass this application. Contrast
 * the processing state planned for {@code TriggerEvent}, which is closed and internal and
 * therefore a safe place for a native enum.
 *
 * <p>Names are the stored values — {@code @Enumerated(EnumType.STRING)} — so renaming a
 * constant is a schema migration, not a refactor.
 */
public enum EvidenceStatus {

	/**
	 * Stored in MinIO, hashed, and accounted for. The normal state, and the only one an
	 * item is created in: an {@code EvidenceItem} row is written only once the blob is
	 * durably stored, so there is no "pending" state here. The gap between "alert
	 * received" and "evidence preserved" is tracked on {@code TriggerEvent} instead,
	 * where the alert exists even when preservation never completed.
	 */
	PRESERVED,

	/**
	 * A re-verification computed a digest that does not match {@link
	 * EvidenceItem#getCurrentHash()}. Set by {@code IntegrityCheckService}, never by an
	 * operator, and never cleared by anyone — the item stays in this state and the
	 * {@link CustodyAction#HASH_MISMATCH} custody entry records what was found, with the
	 * expected and observed digests side by side.
	 *
	 * <p>This is the state the whole system exists to be able to report honestly. It is
	 * deliberately not called {@code FAILED}: the check succeeded, the evidence is what
	 * failed.
	 */
	COMPROMISED,

	/**
	 * Retention period elapsed or the matter closed; moved to cold storage but still
	 * retrievable and still verifiable. Distinct from {@link #DELETED} because an archived
	 * item is intact — retrieval is merely slower.
	 */
	ARCHIVED,

	/**
	 * Soft-deleted. Evidence is never hard-deleted: the row, its hash, its custody chain
	 * and its access log all survive, because "this evidence was destroyed, by whom, and
	 * when" is itself a finding an investigation may need. The blob behind
	 * {@link EvidenceItem#getStorageRef()} may or may not still exist; the record of it
	 * always does.
	 */
	DELETED
}
