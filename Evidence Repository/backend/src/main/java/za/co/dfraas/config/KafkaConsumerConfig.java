package za.co.dfraas.config;

import org.apache.kafka.common.errors.SerializationException;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.listener.DefaultErrorHandler;
import org.springframework.util.backoff.FixedBackOff;

/**
 * Error handling for the ingestion consumer.
 *
 * <p>A trigger event that cannot be ingested must not be dropped silently — losing one
 * means evidence that should have been preserved never was. Transient failures are
 * retried with a bounded backoff; a message that is structurally undeserialisable is not
 * retried, because redelivering it would only spin the partition.
 *
 * <p>TODO: route exhausted retries to a dead-letter topic
 * ({@code DeadLetterPublishingRecoverer}) once the evidence-event schema is fixed, so
 * failures are auditable rather than log-only.
 */
@Configuration
public class KafkaConsumerConfig {

	private static final long RETRY_INTERVAL_MS = 2_000L;
	private static final long MAX_RETRIES = 3L;

	@Bean
	public DefaultErrorHandler kafkaErrorHandler() {
		DefaultErrorHandler handler =
				new DefaultErrorHandler(new FixedBackOff(RETRY_INTERVAL_MS, MAX_RETRIES));
		handler.addNotRetryableExceptions(SerializationException.class);
		return handler;
	}
}
