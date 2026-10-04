package za.co.dfraas.dto;

import java.time.OffsetDateTime;
import java.util.UUID;

import io.swagger.v3.oas.annotations.media.Schema;
import za.co.dfraas.entity.CorrelationStatus;

/**
 * Read model for {@link za.co.dfraas.entity.Incident}.
 *
 * <p>Carries the correlation state that used to sit on every alert, because an investigator
 * reading a bundle needs to know whether they are looking at everything. Under continuous
 * collection "correlated" does not mean "finished" — evidence covering the window can still
 * be preserved after the pass ran — so a bundle presented without its state invites the
 * reader to assume a completeness the system has not claimed.
 *
 * <p>No correlation scope: it names work groups by id, which is deployment detail, and
 * nothing a reader acts on.
 */
@Schema(name = "Incident",
		description = """
				A group of alerts one source says belong together — for Slips, the same attacker in \
				the same timewindow — with one evidence bundle. Every alert is still recorded as its \
				own trigger event.
				""")
public record IncidentDto(

		@Schema(description = "Identifier assigned by this repository",
				example = "8d2f4c1a-6b3e-4f70-9a21-5c7e0b9d3f48")
		UUID id,

		@Schema(description = "System that raised the alerts", example = "pde-sim-slips-01")
		String sourceSystem,

		@Schema(description = """
				The source's grouping key. Alerts it sent with the same key are one incident; an alert \
				sent without one is filed under "event:" plus its own id.
				""",
				example = "ids-20261004111242/10.99.0.20/tw1")
		String incidentKey,

		@Schema(description = "How many alerts the incident holds", example = "6")
		long alertCount,

		@Schema(description = "When the earliest member alert says it fired. Sender-asserted.",
				example = "2026-10-04T11:24:58Z")
		OffsetDateTime firstFiredAt,

		@Schema(description = "When the latest member alert says it fired. Sender-asserted.",
				example = "2026-10-04T11:25:31Z")
		OffsetDateTime lastFiredAt,

		@Schema(description = "When this system opened the incident. What listings sort on.",
				example = "2026-10-04T11:25:02.311Z")
		OffsetDateTime openedAt,

		@Schema(description = """
				How far correlation has got: PENDING (not yet correlated), CORRELATED (a pass \
				completed; late-arriving evidence may still be linked), CLOSED (the collection lag has \
				elapsed and the bundle is settled — a new alert reopens it), FAILED (a pass errored \
				and will be retried).
				""",
				example = "CORRELATED")
		CorrelationStatus correlationStatus,

		@Schema(description = "When the first correlation pass completed. Null while PENDING.",
				example = "2026-10-04T11:26:02.114Z")
		OffsetDateTime correlatedAt,

		@Schema(description = "Start of the window correlation searches: the first alert minus the lookback",
				example = "2026-10-04T10:54:58Z")
		OffsetDateTime windowStart,

		@Schema(description = "End of the window correlation searches: the last alert plus the lookahead",
				example = "2026-10-04T11:40:31Z")
		OffsetDateTime windowEnd) {
}
