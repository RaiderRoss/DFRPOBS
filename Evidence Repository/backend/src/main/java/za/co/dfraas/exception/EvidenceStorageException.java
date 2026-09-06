package za.co.dfraas.exception;

/**
 * Thrown when the object store cannot be read or written. Translated to 503 by
 * {@code ApiExceptionHandler}.
 *
 * <p>503 rather than 500, because the honest answer to a caller whose upload failed here is
 * "this artifact was not preserved, send it again" rather than "something broke". That is
 * safe advice to give: the storage key is derived deterministically from the artifact's
 * identity and ingestion dedupes on {@code (evidenceSourceId, sourceArtifactId)}, so a
 * retry either completes the interrupted preservation or is rejected as a duplicate. It
 * cannot produce a second copy.
 *
 * <p>Wraps the MinIO client's checked exceptions, which arrive as nine unrelated types for
 * what is, to every caller in this system, one condition: the bytes are not safely stored.
 */
public class EvidenceStorageException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	public EvidenceStorageException(String message, Throwable cause) {
		super(message, cause);
	}
}
