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
