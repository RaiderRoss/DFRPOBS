package za.co.dfraas.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.minio.MinioClient;

/**
 * Builds the MinIO client used for evidence blob storage.
 *
 * <p>The bucket itself is created by the {@code minio-init} one-shot container in
 * docker-compose, so the application never needs to create or own it.
 */
@Configuration
@EnableConfigurationProperties({StorageProperties.class, KafkaProperties.class})
public class MinioConfig {

	@Bean
	public MinioClient minioClient(StorageProperties properties) {
		return MinioClient.builder()
				.endpoint(properties.endpoint())
				.credentials(properties.accessKey(), properties.secretKey())
				.build();
	}
}
