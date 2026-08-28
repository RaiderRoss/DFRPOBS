package za.co.dfraas.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Entry point for the security model described in the README.
 *
 * <p>Currently the baseline only: stateless HTTP Basic over the whole API, with the
 * actuator health probe left open for docker-compose. Three things are still to be
 * layered on here as their supporting pieces land:
 *
 * <ul>
 *   <li>OTP/2FA step-up gating evidence export/download specifically — see the
 *       placeholder matcher below. Needs the AppUser entity and its {@code mfaEnabled}
 *       flag first.</li>
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
				// Safe to disable: the API is token/basic authenticated and stateless, so
				// there is no ambient session cookie for a CSRF attack to ride on.
				.csrf(csrf -> csrf.disable())
				.sessionManagement(session ->
						session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.authorizeHttpRequests(auth -> auth
						.requestMatchers("/actuator/health/**").permitAll()
						// Placeholder for the step-up rule. Authentication alone is not
						// enough to download evidence — this matcher must additionally
						// require a verified OTP once 2FA is implemented.
						.requestMatchers(HttpMethod.GET, "/api/evidence/*/download").authenticated()
						.anyRequest().authenticated())
				.httpBasic(basic -> {})
				.build();
	}
}
