package za.co.dfraas.config;

import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Object-storage settings for the evidence bucket, bound from {@code dfraas.storage.*}.
 *
 * <p>The access/secret key pair here is a development convenience only. Production must
 * use KMS/HSM-backed envelope encryption rather than static credentials in config — this
 * is the main point where DFRaaS deliberately departs from the SecureRS prototype.
 */
@Validated
@ConfigurationProperties(prefix = "dfraas.storage")
public record StorageProperties(
		@NotBlank String endpoint,
		@NotBlank String accessKey,
		@NotBlank String secretKey,
		@NotBlank String bucket) {
}
