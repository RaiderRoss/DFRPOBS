package za.co.dfraas.exception;

/**
 * Thrown when a lookup by identifier finds nothing. Translated to 404 by
 * {@code ApiExceptionHandler}.
 */
public class ResourceNotFoundException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	public ResourceNotFoundException(String message) {
		super(message);
	}

	public static ResourceNotFoundException of(String resourceType, Object identifier) {
		return new ResourceNotFoundException(resourceType + " not found: " + identifier);
	}
}
