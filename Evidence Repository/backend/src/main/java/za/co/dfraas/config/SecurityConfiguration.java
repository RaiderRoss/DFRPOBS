package za.co.dfraas.config;

import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * Entry point for the security model described in the README.
 *
 * <p>Currently the baseline only: stateless HTTP Basic over the whole API, with the
 * actuator health probe left open for docker-compose. Three things are still to be
 * layered on here as their supporting pieces land:
 *
 * <ul>
 *   <li>OTP/2FA step-up gating evidence export ({@code GET /api/evidence-items/{id}/content})
 *       specifically — see the placeholder matcher below. Needs the AppUser entity and its
 *       {@code mfaEnabled} flag first.</li>
 *   <li>OAuth2/mTLS for service-to-service calls, replacing HTTP Basic.</li>
 *   <li>An {@code AppUser}-backed {@code UserDetailsService}, replacing the dev-only
 *       {@code spring.security.user.*} credentials in application.properties.</li>
 * </ul>
 */
@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		return http
				// Picks up the CorsConfigurationSource bean below. This installs a CorsFilter
				// ahead of the authentication filters, which matters: a preflight OPTIONS
				// carries no Authorization header, so if it reached anyRequest().authenticated()
				// it would be answered with a 401 and the browser would block the real request.
				// CorsFilter short-circuits preflights itself, so no OPTIONS permitAll is needed
				// (and adding one would be worse — it would let OPTIONS through to controllers).
				.cors(Customizer.withDefaults())
				// Safe to disable: the API is token/basic authenticated and stateless, so
				// there is no ambient session cookie for a CSRF attack to ride on.
				.csrf(csrf -> csrf.disable())
				.sessionManagement(session ->
						session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.authorizeHttpRequests(auth -> auth
						.requestMatchers("/actuator/health/**").permitAll()
						// Swagger UI and the spec it fetches. Both have to be open together:
						// the page itself loads over a plain GET with no Authorization header,
						// so leaving /v3/api-docs authenticated renders an empty UI and a 401
						// in the console rather than a login prompt. Dev affordance only —
						// see SPRINGDOC in application.properties for switching it off, and
						// close these paths before this service is exposed outside localhost.
						.requestMatchers(
								"/swagger-ui.html",
								"/swagger-ui/**",
								"/v3/api-docs",
								"/v3/api-docs/**",
								"/v3/api-docs.yaml").permitAll()
						// Placeholder for the step-up rule on the one route that releases
						// evidence bytes. Authentication alone is what guards it in the
						// prototype; this matcher is where a verified OTP would be required
						// once a user model exists (out of scope — README, Future work).
						.requestMatchers(HttpMethod.GET, "/api/evidence-items/*/content").authenticated()
						.anyRequest().authenticated())
				.httpBasic(basic -> {})
				.build();
	}

	/**
	 * Browser access for the frontend, bound from {@code dfraas.security.cors.allowed-origins}.
	 *
	 * <p>Kept here rather than in a {@code @ConfigurationProperties} record because it is a
	 * single list that only the filter chain above consumes.
	 *
	 * <p>Origins are an explicit allowlist — never a wildcard. CORS is what stops a page on
	 * some other origin from reading this API's responses in a victim's browser, so this list
	 * must be narrowed for each deployment, not widened. The defaults are the Vite dev server
	 * and {@code vite preview}; see CORS_ALLOWED_ORIGINS in .env.example.
	 */
	@Bean
	public CorsConfigurationSource corsConfigurationSource(
			@Value("${dfraas.security.cors.allowed-origins}") List<String> allowedOrigins) {
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(allowedOrigins);
		configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
		// Authorization is what forces the preflight in the first place — HTTP Basic puts it on
		// every call, and it is not a CORS-safelisted request header.
		configuration.setAllowedHeaders(List.of("Authorization", "Content-Type", "Accept"));
		// The download's file name and digest. Neither is CORS-safelisted, so without this the
		// frontend could fetch the bytes but not name them or check them on receipt.
		configuration.setExposedHeaders(List.of("Content-Disposition", "Repr-Digest"));
		// Deliberately false. The frontend builds the Authorization header in JS rather than
		// relying on a cookie or a browser-managed credential, so it does not need
		// credentialed-mode CORS — and leaving this off keeps the response uncacheable as a
		// credentialed one. Revisit only if session cookies replace HTTP Basic.
		configuration.setAllowCredentials(false);
		// Preflight results are cacheable for an hour, so the browser stops re-asking before
		// every list/detail call.
		configuration.setMaxAge(3600L);

		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/api/**", configuration);
		return source;
	}
}
