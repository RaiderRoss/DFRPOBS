package za.co.dfraas.resource;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import za.co.dfraas.exception.DuplicateResourceException;
import za.co.dfraas.exception.EvidenceStorageException;
import za.co.dfraas.exception.IntegrityVerificationException;
import za.co.dfraas.exception.ResourceNotFoundException;

/**
 * Translates domain exceptions into RFC 7807 {@code application/problem+json} responses.
 *
 * <p>Applies to every {@code *Resource}, so subsequent entities inherit consistent error
 * shapes without repeating themselves. Structured errors are worth the small effort in this
 * system specifically: a client that can distinguish "no such evidence" from "integrity
 * check failed" from "step-up authentication required" by machine-readable status is the
 * difference between a usable audit trail and a log full of 500s.
 *
 * <p>Messages carry identifiers the caller already supplied and nothing else — no stack
 * traces, no hashes, no storage references.
 */
@RestControllerAdvice
public class ApiExceptionHandler extends ResponseEntityExceptionHandler {

	@ExceptionHandler(ResourceNotFoundException.class)
	public ProblemDetail handleNotFound(ResourceNotFoundException ex) {
		ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, ex.getMessage());
		problem.setTitle("Resource not found");
		return problem;
	}

	@ExceptionHandler(DuplicateResourceException.class)
	public ProblemDetail handleDuplicate(DuplicateResourceException ex) {
		ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, ex.getMessage());
		problem.setTitle("Resource already exists");
		return problem;
	}

	/**
	 * Integrity failures are 422, not 400.
	 *
	 * <p>A 400 tells a caller their request was malformed and they should fix it. This is the
	 * opposite: the request was perfectly well formed, and the <em>content</em> did not survive
	 * intact between the source hashing it and this system receiving or storing it. That is a
	 * finding about the evidence rather than about the message carrying it, and a client that
	 * cannot tell the two apart by status code has an audit trail made of prose.
	 *
	 * <p>The message names the artifact and no digests — see
	 * {@link IntegrityVerificationException}. The values are logged where they belong, on the
	 * server, by the service that compared them.
	 */
	@ExceptionHandler(IntegrityVerificationException.class)
	public ProblemDetail handleIntegrityFailure(IntegrityVerificationException ex) {
		ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.UNPROCESSABLE_ENTITY, ex.getMessage());
		problem.setTitle("Evidence integrity check failed");
		return problem;
	}

	/**
	 * Storage failures are 503 with a fixed message.
	 *
	 * <p>503 because the honest instruction to the caller is "this was not preserved, send it
	 * again", and a retry is safe by construction: the storage key is derived from the
	 * artifact's identity and ingestion dedupes on it, so a second attempt either completes the
	 * interrupted preservation or is rejected as a duplicate.
	 *
	 * <p>The exception's own message carries the object key, which is exactly what this class
	 * promises not to put in a response body, so the detail here is fixed text and the cause is
	 * logged instead.
	 */
	@ExceptionHandler(EvidenceStorageException.class)
	public ProblemDetail handleStorageFailure(EvidenceStorageException ex) {
		logger.error("Evidence store unavailable", ex);
		ProblemDetail problem = ProblemDetail.forStatusAndDetail(
				HttpStatus.SERVICE_UNAVAILABLE,
				"The evidence store is unavailable, so nothing was preserved. Send the artifact again.");
		problem.setTitle("Evidence store unavailable");
		return problem;
	}

	/**
	 * Overrides the Boot default so a bean-validation failure names the offending fields
	 * rather than returning a bare 400.
	 */
	@Override
	protected ResponseEntity<Object> handleMethodArgumentNotValid(
			MethodArgumentNotValidException ex,
			HttpHeaders headers,
			HttpStatusCode status,
			WebRequest request) {

		Map<String, String> fieldErrors = new LinkedHashMap<>();
		ex.getBindingResult().getFieldErrors().forEach(error ->
				fieldErrors.putIfAbsent(error.getField(), error.getDefaultMessage()));

		ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, "Request validation failed");
		problem.setTitle("Invalid request");
		problem.setProperty("fieldErrors", fieldErrors);
		return ResponseEntity.badRequest().body(problem);
	}
}
