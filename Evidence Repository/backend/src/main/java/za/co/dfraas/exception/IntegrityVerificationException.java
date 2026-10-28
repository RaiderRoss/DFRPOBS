package za.co.dfraas.exception;

import java.util.UUID;

/**
 * Thrown when bytes fail to hash to the digest they were expected to. Translated to 422 by
 * {@code ApiExceptionHandler}.
 *
 * <p>Its own type rather than a validation failure, because the two say different things. A
 * 400 means the caller's request was malformed and they should fix it; this means the
 * request was well-formed and the <em>content</em> did not survive intact, which is a
 * finding about the evidence rather than about the message carrying it. That distinction is
 * the one {@code ApiExceptionHandler} was written to preserve — a client that cannot tell
 * "no such evidence" from "integrity check failed" by status code has an audit trail made
 * of prose.
 *
 * <p><strong>Messages name the artifact and nothing else.</strong> Neither digest appears,
 * following the rule the handler states: identifiers the caller already supplied, no
 * hashes, no storage references. The digests are logged server-side, where an operator
 * diagnosing a mismatch can see them and a client cannot.
 */
public class IntegrityVerificationException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	public IntegrityVerificationException(String message) {
		super(message);
	}

	/**
	 * The uploaded bytes do not hash to the digest the source asserted for them — something
	 * changed between the source computing it and this system receiving them.
	 */
	public static IntegrityVerificationException digestMismatch(String sourceArtifactId) {
		return new IntegrityVerificationException(
				"Integrity check failed for artifact " + sourceArtifactId
						+ ": the digest computed on arrival does not match the digest the source asserted");
	}

	/**
	 * The object read back out of storage does not hash to what was written — the write
	 * itself did not land intact, so no row is created for it.
	 */
	public static IntegrityVerificationException storageMismatch(String sourceArtifactId) {
		return new IntegrityVerificationException(
				"Integrity check failed for artifact " + sourceArtifactId
						+ ": the object read back from storage does not match the bytes that arrived");
	}

	/**
	 * The stored object no longer hashes to the digest recorded at preservation, so it was not
	 * released. Unlike the two ingest cases, the finding has already been recorded — thrown
	 * only after the transaction that appended {@code HASH_MISMATCH} and marked the item
	 * {@code COMPROMISED} has committed — so the message says so, and names the item by the
	 * id the caller asked for.
	 */
	public static IntegrityVerificationException exportRefused(UUID evidenceItemId) {
		return new IntegrityVerificationException(
				"Export refused for evidence item " + evidenceItemId
						+ ": the stored object does not match the digest recorded at preservation. Nothing was"
						+ " released; the finding is recorded in the item's chain of custody and the item is"
						+ " marked COMPROMISED");
	}
}
