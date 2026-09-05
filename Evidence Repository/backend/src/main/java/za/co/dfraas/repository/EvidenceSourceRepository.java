package za.co.dfraas.repository;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import za.co.dfraas.entity.EvidenceSource;
import za.co.dfraas.entity.SourceStatus;

/**
 * Data access for {@link EvidenceSource}.
 *
 * <p>Unlike {@code evidence_item} and {@code trigger_event}, this table is bounded — one
 * row per registered collector, in the hundreds at most — so the unpaged reads here are
 * safe, in the same way {@code WorkGroupRepository}'s are.
 */
@Repository
public interface EvidenceSourceRepository extends JpaRepository<EvidenceSource, UUID> {

	/**
	 * Resolves the identifier a producer puts on the wire to its registration. The lookup
	 * streamed ingestion performs on every message, so it is backed by
	 * {@code uq_evidence_source_key}.
	 */
	Optional<EvidenceSource> findBySourceKey(String sourceKey);

	boolean existsBySourceKey(String sourceKey);

	List<EvidenceSource> findByStatus(SourceStatus status);

	List<EvidenceSource> findByWorkGroupId(UUID workGroupId);

	/**
	 * Sources that should have produced by now and have not — the readiness-audit query for
	 * continuous collection.
	 *
	 * <p><strong>Why this method is the point of the whole entity.</strong> Continuous
	 * collection has a failure mode the reactive design did not: a collector that silently
	 * stops produces exactly what a collector with nothing to report produces. Under the old
	 * model a missing alert was noticed because someone was waiting for it; here nobody is,
	 * and the gap surfaces months later when an investigator finds the window they need is
	 * empty. This turns that into a question the system can answer on a schedule.
	 *
	 * <p>Three conditions, each excluding a source whose silence means nothing. Only
	 * {@link SourceStatus#ACTIVE} sources are expected to produce — a suspended or
	 * decommissioned one cannot be late. Only sources with a declared cadence are held to
	 * one. And a source that has never produced at all is late from its registration, which
	 * is the case worth catching most: a collector misconfigured on the day it was
	 * onboarded, quietly delivering nothing ever since.
	 *
	 * <p>{@code asOf} is passed in rather than read from {@code now()} inside the query, so
	 * the sweep is testable at a fixed instant instead of only against wall-clock time.
	 *
	 * <p>Backed by the partial index {@code ix_evidence_source_liveness}, which covers
	 * exactly the {@code ACTIVE} + declared-cadence rows this predicate looks at.
	 *
	 * <p><strong>Native rather than HQL</strong>, and not by preference. The deadline is
	 * {@code (last seen) + (that source's own cadence)}, so the interval is a value read
	 * from the row rather than a constant — and HQL has no portable way to build an interval
	 * from a column. Postgres does, via {@code make_interval}. The alternative was to fetch
	 * every active source and filter in Java, which pushes a whole-table read into the
	 * application to avoid one function call.
	 *
	 * <p>{@code COALESCE(last_evidence_at, registered_at)} collapses the two cases: a source
	 * that has produced is judged from its last delivery, one that never has is judged from
	 * the moment it was registered.
	 *
	 * <p><strong>The interval is added to the deadline, not subtracted from {@code asOf}.</strong>
	 * That is a correctness requirement, not a stylistic one. Written the other way —
	 * {@code COALESCE(...) < :asOf - make_interval(...)} — the bind parameter arrives
	 * untyped, so Postgres resolves {@code ? - interval} by picking a candidate operator and
	 * settles on {@code interval - interval → interval}, leaving the comparison as
	 * {@code timestamptz < interval} and failing at execution with "operator does not
	 * exist". Adding instead makes the left side unambiguously
	 * {@code timestamptz + interval → timestamptz}, which then types the parameter correctly
	 * with no cast. It also reads as what it is: a deadline, compared against now.
	 */
	@Query(value = """
			SELECT s.* FROM evidence_source s
			WHERE s.status = 'ACTIVE'
			AND s.expected_interval_seconds IS NOT NULL
			AND COALESCE(s.last_evidence_at, s.registered_at)
				+ make_interval(secs => s.expected_interval_seconds) < :asOf
			ORDER BY COALESCE(s.last_evidence_at, s.registered_at)
			""", nativeQuery = true)
	List<EvidenceSource> findSilentSources(@Param("asOf") OffsetDateTime asOf);
}
