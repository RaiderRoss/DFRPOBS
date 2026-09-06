package za.co.dfraas.exception;

/**
 * Thrown when a create would violate a uniqueness rule. Translated to 409 by
 * {@code ApiExceptionHandler}.
 */
public class DuplicateResourceException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	public DuplicateResourceException(String message) {
		super(message);
	}

	public static DuplicateResourceException of(String resourceType, String field, Object value) {
		return new DuplicateResourceException(resourceType + " already exists with " + field + " " + value);
	}
}
