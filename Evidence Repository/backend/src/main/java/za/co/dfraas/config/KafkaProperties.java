package za.co.dfraas.config;

import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * DFRaaS-specific Kafka settings, bound from {@code dfraas.kafka.*}.
 *
 * <p>Separate from Spring's own {@code spring.kafka.*} (brokers, deserializers), which
 * stays under Boot's autoconfiguration.
 */
@Validated
@ConfigurationProperties(prefix = "dfraas.kafka")
public record KafkaProperties(@NotBlank String evidenceEventsTopic) {
}
