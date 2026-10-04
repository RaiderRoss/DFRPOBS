package za.co.dfraas.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Wiring for the correlation pass: its properties and the scheduler that drives it.
 *
 * <p>The pass reads the application {@link java.time.Clock} from {@link ClockConfiguration}
 * rather than {@code OffsetDateTime.now()} inline, because it makes a time-based decision —
 * whether an alert's bundle has settled — and that decision has to be testable without
 * waiting an hour for it. Link review reads the same clock to stamp {@code reviewedAt}.
 */
@Configuration(proxyBeanMethods = false)
@EnableScheduling
@EnableConfigurationProperties(CorrelationProperties.class)
public class CorrelationConfig {
}
