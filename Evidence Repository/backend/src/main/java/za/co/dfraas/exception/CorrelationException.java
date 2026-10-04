package za.co.dfraas.exception;

/**
 * A trigger event cannot be correlated as it stands — most often because nothing tells the
 * pass which classification to search, since the alert's {@code sourceSystem} matches no
 * registered {@code EvidenceSource}.
 *
 * <p>Thrown rather than handled quietly because the alternative is worse in both
 * directions: searching every work group returns a bundle too large to mean anything, and
 * marking the alert correlated with nothing linked would tell an investigator the window
 * was empty when in fact it was never searched. The sweep records the alert as
 * {@code FAILED} and retries it, so registering the missing source is enough to recover.
 */
public class CorrelationException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	public CorrelationException(String message) {
		super(message);
	}
}
