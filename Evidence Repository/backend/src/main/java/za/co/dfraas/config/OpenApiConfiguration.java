package za.co.dfraas.config;

import org.springframework.context.annotation.Configuration;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.annotations.servers.Server;

/**
 * Publishes the OpenAPI 3 description served at {@code /v3/api-docs} and rendered by
 * Swagger UI at {@code /swagger-ui/index.html}.
 *
 * <p>The document is generated from the controllers rather than hand-written, so it cannot
 * drift from the endpoints it describes — which matters more than usual here, since the
 * API surface is deliberately narrow and the reasons for that (no create endpoint for
 * trigger events, no raw payload accessor) are worth stating where a caller will read them.
 *
 * <p>The declared scheme is HTTP Basic because that is what {@link SecurityConfiguration}
 * currently enforces. When Basic is replaced by OAuth2/mTLS for service-to-service calls,
 * this annotation is the single place that has to change for "Authorize" in the UI to keep
 * working — and it should change in the same commit, since a spec that advertises the wrong
 * auth mechanism is worse than one that advertises none.
 */
@Configuration
@OpenAPIDefinition(
		info = @Info(
				title = "DFRaaS Evidence Repository API",
				version = "0.0.1-SNAPSHOT",
				description = """
						Digital Forensic Readiness as a Service — evidence repository backend.

						Trigger events arrive over Kafka and are recorded idempotently; this API \
						reads them back. Every endpoint outside the actuator health probe and these \
						docs requires authentication. Evidence download re-hashes the artifact before \
						releasing it and records each release in its chain of custody; an OTP step-up \
						on download is future work.
						"""),
		servers = @Server(url = "/", description = "This instance"),
		security = @SecurityRequirement(name = OpenApiConfiguration.BASIC_AUTH))
@SecurityScheme(
		name = OpenApiConfiguration.BASIC_AUTH,
		type = SecuritySchemeType.HTTP,
		scheme = "basic",
		in = SecuritySchemeIn.HEADER,
		description = "Dev credentials default to admin/admin — see spring.security.user.* in application.properties.")
public class OpenApiConfiguration {

	/** Name tying the {@code @SecurityScheme} above to the requirement referenced by operations. */
	public static final String BASIC_AUTH = "basicAuth";
}
