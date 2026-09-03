package za.co.dfraas.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.Mockito.never;

import java.time.OffsetDateTime;
import java.util.UUID;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import za.co.dfraas.dto.TriggerEventDto;
import za.co.dfraas.dto.TriggerEventIngestRequest;
import za.co.dfraas.dto.TriggerEventIngestResult;

/**
 * Message-handling behaviour of {@link EvidenceEventConsumer}: what it forwards, what it
 * skips, and what it refuses to swallow.
 *
 * <p>A plain unit test — no Spring context and no broker. The interesting logic is the
 * decision about each message, and a real Kafka would only slow that down. Idempotency
 * itself is covered against Postgres in {@code TriggerEventServiceTest}.
 */
@ExtendWith(MockitoExtension.class)
class EvidenceEventConsumerTest {

	private static final String VALID_MESSAGE = """
			{"eventId":"EVT-1","sourceSystem":"splunk","triggerType":"BRUTE_FORCE_LOGIN",\
			"firedAt":"2026-01-01T09:00:00Z"}""";

	@Mock
	private TriggerEventService triggerEventService;

	@Captor
	private ArgumentCaptor<TriggerEventIngestRequest> requestCaptor;

	private EvidenceEventConsumer consumer;

	@BeforeEach
	void setUp() {
		ObjectMapper objectMapper = JsonMapper.builder().build();
		ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
		Validator validator = factory.getValidator();
		consumer = new EvidenceEventConsumer(triggerEventService, objectMapper, validator);
	}

	@Test
	@DisplayName("A well-formed message is forwarded with the raw payload attached")
	void wellFormedMessageIsForwarded() {
		given(triggerEventService.recordIfAbsent(any())).willReturn(result(true));

		consumer.onEvidenceEvent(VALID_MESSAGE, "key", 0, 42L);

		then(triggerEventService).should().recordIfAbsent(requestCaptor.capture());
		TriggerEventIngestRequest request = requestCaptor.getValue();

		// eventId on the wire becomes externalEventId here — the source's identifier, which
		// is what dedupe keys on.
		assertThat(request.externalEventId()).isEqualTo("EVT-1");
		assertThat(request.sourceSystem()).isEqualTo("splunk");
		assertThat(request.triggerType()).isEqualTo("BRUTE_FORCE_LOGIN");

		// The raw message, not a re-serialisation of the parsed record. The digest has to
		// describe the bytes that actually arrived.
		assertThat(request.payload()).isEqualTo(VALID_MESSAGE);
	}

	@Test
	@DisplayName("A duplicate delivery stops the pipeline instead of raising")
	void duplicateDeliveryIsNotAnError() {
		given(triggerEventService.recordIfAbsent(any())).willReturn(result(false));

		// At-least-once delivery makes redelivery routine. Throwing here would leave the
		// offset uncommitted and redeliver the same message indefinitely.
		assertThatCode(() -> consumer.onEvidenceEvent(VALID_MESSAGE, "key", 0, 42L))
				.doesNotThrowAnyException();
	}

	@Test
	@DisplayName("Unparseable JSON is skipped rather than retried forever")
	void poisonMessageIsSkipped() {
		// A malformed payload fails identically on every redelivery, so retrying it blocks
		// every later message on the partition behind it.
		assertThatCode(() -> consumer.onEvidenceEvent("not json at all", "key", 0, 43L))
				.doesNotThrowAnyException();

		then(triggerEventService).should(never()).recordIfAbsent(any());
	}

	@Test
	@DisplayName("A message missing a required field is skipped before it reaches the service")
	void invalidMessageIsSkipped() {
		// Parses cleanly but has no sourceSystem, so it could never satisfy the dedupe key.
		String missingSource = """
				{"eventId":"EVT-2","triggerType":"BRUTE_FORCE_LOGIN","firedAt":"2026-01-01T09:00:00Z"}""";

		assertThatCode(() -> consumer.onEvidenceEvent(missingSource, "key", 0, 44L))
				.doesNotThrowAnyException();

		then(triggerEventService).should(never()).recordIfAbsent(any());
	}

	@Test
	@DisplayName("A failure inside the service is allowed to propagate and be retried")
	void serviceFailurePropagates() {
		// The opposite of a poison message: a transient fault should leave the offset
		// uncommitted so Kafka redelivers it.
		given(triggerEventService.recordIfAbsent(any()))
				.willThrow(new IllegalStateException("database unavailable"));

		assertThatCode(() -> consumer.onEvidenceEvent(VALID_MESSAGE, "key", 0, 45L))
				.isInstanceOf(IllegalStateException.class);
	}

	private static TriggerEventIngestResult result(boolean created) {
		TriggerEventDto dto = new TriggerEventDto(
				UUID.fromString("33333333-3333-3333-3333-333333333333"),
				"EVT-1",
				"splunk",
				"BRUTE_FORCE_LOGIN",
				OffsetDateTime.parse("2026-01-01T09:00:00Z"),
				OffsetDateTime.parse("2026-01-01T09:00:05Z"),
				"c82fb88239e96ae95bfdc7fc1b17a9ef3015a8ac3135bc8955850e0da4398ae8");
		return new TriggerEventIngestResult(dto, created);
	}
}
