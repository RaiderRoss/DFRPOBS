package za.co.dfraas.repository;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

/**
 * Data access for {@code evidence_item_indicator}: the addresses each artifact mentions.
 *
 * <p>JDBC rather than a JPA entity. The rows are a derived index over an artifact's bytes —
 * written once in bulk at ingest and read in bulk by correlation — and nothing ever loads,
 * edits or navigates one on its own, which is all an entity would add.
 *
 * <p>Insert and read only. There is no update or delete, for the same reason the artifact
 * has none: what a preserved file contains does not change.
 */
@Repository
public class EvidenceItemIndicatorRepository {

	private static final String IPV4 = "IPV4";

	private final NamedParameterJdbcTemplate jdbc;

	public EvidenceItemIndicatorRepository(NamedParameterJdbcTemplate jdbc) {
		this.jdbc = jdbc;
	}

	/** Records the IPv4 addresses one artifact mentions. A batch, not a row per round trip. */
	public void saveIpv4(UUID evidenceItemId, Collection<String> addresses) {
		if (addresses.isEmpty()) {
			return;
		}
		MapSqlParameterSource[] rows = addresses.stream()
				.map(address -> new MapSqlParameterSource()
						.addValue("itemId", evidenceItemId)
						.addValue("type", IPV4)
						.addValue("value", address))
				.toArray(MapSqlParameterSource[]::new);
		jdbc.batchUpdate("""
				INSERT INTO evidence_item_indicator (evidence_item_id, indicator_type, indicator_value)
				VALUES (:itemId, :type, :value)
				""", rows);
	}

	/**
	 * Which of the given addresses each of the given artifacts mentions. Artifacts that
	 * mention none of them are absent from the map.
	 *
	 * <p>Both sides bounded by the caller: one page of correlation candidates against one
	 * incident's addresses.
	 */
	public Map<UUID, Set<String>> findIpv4Matches(Collection<UUID> evidenceItemIds, Collection<String> addresses) {
		Map<UUID, Set<String>> matches = new HashMap<>();
		if (evidenceItemIds.isEmpty() || addresses.isEmpty()) {
			return matches;
		}
		List<Map<String, Object>> rows = jdbc.queryForList("""
				SELECT evidence_item_id, indicator_value FROM evidence_item_indicator
				WHERE indicator_type = :type
				AND evidence_item_id IN (:itemIds)
				AND indicator_value IN (:values)
				""", new MapSqlParameterSource()
						.addValue("type", IPV4)
						.addValue("itemIds", evidenceItemIds)
						.addValue("values", addresses));
		for (Map<String, Object> row : rows) {
			matches.computeIfAbsent((UUID) row.get("evidence_item_id"), id -> new TreeSet<>())
					.add((String) row.get("indicator_value"));
		}
		return matches;
	}

	/** Every IPv4 address one artifact mentions, sorted. */
	public List<String> findIpv4(UUID evidenceItemId) {
		return jdbc.queryForList("""
				SELECT indicator_value FROM evidence_item_indicator
				WHERE evidence_item_id = :itemId AND indicator_type = :type
				ORDER BY indicator_value
				""", new MapSqlParameterSource().addValue("itemId", evidenceItemId).addValue("type", IPV4),
				String.class);
	}
}
