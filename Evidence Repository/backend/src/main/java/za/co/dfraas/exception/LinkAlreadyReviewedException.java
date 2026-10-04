package za.co.dfraas.exception;

import java.util.UUID;

import za.co.dfraas.entity.LinkDisposition;

/**
 * A review was attempted on a link that has already been ruled on. Translated to 409 by
 * {@code ApiExceptionHandler}.
 *
 * <p>A conflict rather than a validation error: the request was well formed and would have
 * succeeded a moment earlier, and the usual cause is a second investigator reviewing the
 * same bundle. The message names the ruling that stands so they can see why.
 */
public class LinkAlreadyReviewedException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	public LinkAlreadyReviewedException(UUID linkId, LinkDisposition current) {
		super("EvidenceLink " + linkId + " has already been reviewed and is " + current);
	}
}
