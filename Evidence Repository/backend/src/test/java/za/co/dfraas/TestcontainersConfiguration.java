package za.co.dfraas;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.testcontainers.kafka.KafkaContainer;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * Shared container definitions for integration tests.
 *
 * <p>Public rather than package-private so slice tests in sub-packages
 * (e.g. {@code za.co.dfraas.repository}) can {@code @Import} it.
 */
@TestConfiguration(proxyBeanMethods = false)
public class TestcontainersConfiguration {

	/**
	 * Pinned to match the repo-root docker-compose.yml. Previously {@code :latest}, which
	 * meant tests validated against a different Postgres major version than the one the
	 * stack actually runs — a real risk here, because the native-enum behaviour the README
	 * documents (ALTER TYPE ... ADD VALUE, no DROP VALUE) is version-sensitive.
	 */
	@Bean
	@ServiceConnection
	PostgreSQLContainer postgresContainer() {
		return new PostgreSQLContainer(DockerImageName.parse("postgres:16-alpine"));
	}

	// TODO: also pin this. It drifts twice over — ':latest' against a compose stack that
	// runs Redpanda, not Apache Kafka. Pin to the kafka-native tag closest to the Redpanda
	// Kafka API level once verified against a running Docker daemon.
	@Bean
	@ServiceConnection
	KafkaContainer kafkaContainer() {
		return new KafkaContainer(DockerImageName.parse("apache/kafka-native:latest"));
	}

}
