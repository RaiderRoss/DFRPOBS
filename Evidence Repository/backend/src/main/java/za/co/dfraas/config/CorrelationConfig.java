package za.co.dfraas.config;

import java.time.Clock;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Wiring for the correlation pass: its properties, the scheduler that drives it, and the
 * clock it reads.
 *
 * <p>The clock is a bean rather than {@code OffsetDateTime.now()} inline because the pass
 * makes a time-based decision — whether an alert's bundle has settled — and that decision
 * has to be testable without waiting an hour for it.
 */
@Configuration(proxyBeanMethods = false)
@EnableScheduling
@EnableConfigurationProperties(CorrelationProperties.class)
public class CorrelationConfig {

	@Bean
	Clock clock() {
		return Clock.systemUTC();
	}
}
