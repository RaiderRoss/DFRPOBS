package za.co.dfraas.config;

import java.time.Duration;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Settings for the correlation pass, bound from {@code dfraas.correlation.*}.
 *
 * <p>None of these decide <em>what</em> an alert is correlated against — the window is
 * frozen onto each {@code TriggerEvent} and the scope onto its {@code correlationScope}, so
 * changing a value here never changes a bundle that has already been gathered. These only
 * govern how often and how much work the sweep does, and when a bundle is declared settled.
 *
 * @param enabled      whether the scheduled sweep runs at all; off lets a second instance
 *                     serve the API without racing the first for the same alerts
 * @param sweepInterval delay between the end of one sweep and the start of the next
 * @param batchSize    most alerts taken from each queue per sweep, so one sweep over a
 *                     large backlog cannot run unbounded
 * @param pageSize     overlapping items read per query while gathering one alert's bundle
 * @param settleAfter  how long after an alert's window closes before its bundle is declared
 *                     {@code CLOSED}. This is the allowance for collection lag: a source
 *                     that batches hourly delivers evidence for 14:00–15:00 at 15:02, and an
 *                     alert closed at 14:46 would never see it
 */
@Validated
@ConfigurationProperties(prefix = "dfraas.correlation")
public record CorrelationProperties(
		boolean enabled,
		@NotNull Duration sweepInterval,
		@Min(1) int batchSize,
		@Min(1) int pageSize,
		@NotNull Duration settleAfter) {
}
