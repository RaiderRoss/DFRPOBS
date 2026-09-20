package za.co.dfraas.config;

import java.time.Clock;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * The application clock, for the one place this system stamps a timestamp itself.
 *
 * <p>Every other timestamp in the schema is the database's {@code now()}, and the README
 * explains why. {@code custody_event.occurred_at} is the exception — it is inside the entry's
 * digest, so it has to be known before the INSERT — and {@code IntegrityCheckService} is the
 * first writer that has no database-stamped value to borrow the way the opening entry
 * borrows {@code evidence_item.created_at}. A {@link Clock} bean rather than a static
 * {@code now()} so a test can pin the instant and assert on what was hashed.
 */
@Configuration
public class ClockConfiguration {

	@Bean
	public Clock clock() {
		return Clock.systemUTC();
	}
}
