package za.co.dfraas.service;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.Mockito.never;

import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import za.co.dfraas.dto.EvidenceIngestRequest;
import za.co.dfraas.dto.EvidenceItemDto;
import za.co.dfraas.entity.EvidenceItem;
import za.co.dfraas.entity.EvidenceSource;
import za.co.dfraas.entity.EvidenceStatus;
import za.co.dfraas.entity.WorkGroup;
import za.co.dfraas.exception.DuplicateResourceException;
import za.co.dfraas.exception.IntegrityVerificationException;
import za.co.dfraas.exception.ResourceNotFoundException;
import za.co.dfraas.mapper.EvidenceItemMapper;
import za.co.dfraas.repository.EvidenceItemIndicatorRepository;
import za.co.dfraas.repository.EvidenceItemRepository;
import za.co.dfraas.repository.EvidenceSourceRepository;

/**
 * The preservation pipeline's own contract: what gets verified, in what order, and what is
 * left behind when a step fails.
 *
 * <p>{@link HashingService} and {@link EvidenceItemMapper} are the real implementations
 * rather than mocks. Both are pure, and the digest comparison is the behaviour under test —
 * stubbing the hasher would leave these tests asserting against their own fixture instead of
 * against SHA-256.
 */
@ExtendWith(MockitoExtension.class)
class EvidenceItemServiceTest {

	private static final UUID ITEM_ID = UUID.fromString("33333333-3333-3333-3333-333333333333");
	private static final UUID SOURCE_ID = UUID.fromString("22222222-2222-2222-2222-222222222222");
	private static final UUID WORK_GROUP_ID = UUID.fromString("11111111-1111-1111-1111-111111111111");

	private static final String SOURCE_KEY = "pde-sim-ufw-01";
	private static final String ARTIFACT_ID = "firewall_20260905143000";
	private static final byte[] CONTENT = "hello".getBytes(UTF_8);

	/** SHA-256 of "hello". A real digest, so a broken hasher cannot pass by agreeing with itself. */
	private static final String CONTENT_SHA256 =
			"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

	/** SHA-256 of "goodbye" — a valid digest of the wrong bytes. */
	private static final String OTHER_SHA256 =
			"82e35a63ceba37e9646434c5dd412ea577147f1e4a41ccde1614253187e3dbf9";

	private static final String STORAGE_REF = SOURCE_KEY + "/" + ARTIFACT_ID;

	private static final String PRINCIPAL = "j.mokoena";

	@Mock
	private EvidenceItemRepository repository;

	@Mock
	private EvidenceSourceRepository sourceRepository;

	@Mock
	private EvidenceStorageService storageService;

	@Mock
	private CustodyChainService custodyChainService;

	@Mock
	private EvidenceItemIndicatorRepository indicatorRepository;

	@Captor
	private ArgumentCaptor<EvidenceItem> itemCaptor;

	private EvidenceItemService service;
	private WorkGroup workGroup;
	private EvidenceSource source;

	@BeforeEach
	void setUp() {
		service = new EvidenceItemService(
				repository,
				sourceRepository,
				new EvidenceItemMapper(),
				new HashingService(),
				storageService,
				custodyChainService,
				new IndicatorExtractor(),
				indicatorRepository);

		workGroup = new WorkGroup();
		workGroup.setId(WORK_GROUP_ID);
		workGroup.setName("PDE Testbed");
		workGroup.setClassificationCode("PDE_TESTBED");

		source = new EvidenceSource();
		source.setId(SOURCE_ID);
		source.setSourceKey(SOURCE_KEY);
		source.setDisplayName("PDE testbed firewall (ufw)");
		source.setWorkGroup(workGroup);
		source.setSourceType("FIREWALL");
	}

	@Test
	@DisplayName("A verified artifact is stored, recorded, and stamps the source's liveness")
	void preservesVerifiedArtifact() {
		givenRegisteredSourceWithNoPriorArtifact();
		given(storageService.read(STORAGE_REF)).willReturn(CONTENT);
		given(repository.saveAndFlush(any(EvidenceItem.class))).willAnswer(invocation -> {
			EvidenceItem item = invocation.getArgument(0);
			item.setId(ITEM_ID);
			return item;
		});

		EvidenceItemDto preserved = service.preserve(request(CONTENT_SHA256), CONTENT, "text/plain", PRINCIPAL);

		then(storageService).should().store(STORAGE_REF, CONTENT, "text/plain");
		then(repository).should().saveAndFlush(itemCaptor.capture());
		then(sourceRepository).should().touchLastEvidenceAt(SOURCE_ID);

		EvidenceItem saved = itemCaptor.getValue();
		assertThat(saved.getCurrentHash()).isEqualTo(CONTENT_SHA256);
		assertThat(saved.getStorageRef()).isEqualTo(STORAGE_REF);
		assertThat(saved.getStatus()).isEqualTo(EvidenceStatus.PRESERVED);
		assertThat(saved.getSourceArtifactId()).isEqualTo(ARTIFACT_ID);
		assertThat(saved.getEventStart()).isEqualTo(OffsetDateTime.parse("2026-09-05T14:30:00Z"));
		assertThat(preserved.currentHash()).isEqualTo(CONTENT_SHA256);
	}

	@Test
	@DisplayName("The addresses an artifact mentions are recorded against the item it became")
	void recordsIndicatorsFromVerifiedBytes() {
		byte[] content = "SRC=10.99.0.20 DST=10.98.0.1\nSRC=10.99.0.20 DST=10.98.0.1\n".getBytes(UTF_8);
		givenRegisteredSourceWithNoPriorArtifact();
		given(storageService.read(STORAGE_REF)).willReturn(content);
		given(repository.saveAndFlush(any(EvidenceItem.class))).willAnswer(invocation -> {
			EvidenceItem item = invocation.getArgument(0);
			item.setId(ITEM_ID);
			return item;
		});

		service.preserve(request(new HashingService().sha256Hex(content)), content, "text/plain", PRINCIPAL);

		then(indicatorRepository).should().saveIpv4(ITEM_ID, Set.of("10.98.0.1", "10.99.0.20"));
	}

	@Test
	@DisplayName("A rejected artifact records no indicators")
	void rejectedArtifactRecordsNoIndicators() {
		assertThatThrownBy(() -> service.preserve(request(OTHER_SHA256), CONTENT, "text/plain", PRINCIPAL))
				.isInstanceOf(IntegrityVerificationException.class);

		then(indicatorRepository).shouldHaveNoInteractions();
	}

	/**
	 * Provenance is not optional, and it is not a second write that might not happen: the
	 * opening entry is appended to the same item that was just inserted, attributed to the
	 * authenticated caller, inside the same transaction.
	 */
	@Test
	@DisplayName("Preservation appends the opening custody entry for the item it just stored")
	void appendsOpeningCustodyEntry() {
		givenRegisteredSourceWithNoPriorArtifact();
		given(storageService.read(STORAGE_REF)).willReturn(CONTENT);
		given(repository.saveAndFlush(any(EvidenceItem.class))).willAnswer(invocation -> invocation.getArgument(0));

		service.preserve(request(CONTENT_SHA256), CONTENT, "text/plain", PRINCIPAL);

		then(repository).should().saveAndFlush(itemCaptor.capture());
		// The same instance, not an equal one: the entry has to carry the createdAt the
		// database stamped on that row, which is why it is written after the flush.
		then(custodyChainService).should().recordCreation(same(itemCaptor.getValue()), eq(PRINCIPAL), anyString());
	}

	/**
	 * A rolled-back preservation must leave no custody entry — a ledger describing a
	 * preservation that never happened is worse than a missing one, because it reads as
	 * authoritative. Here the entry is simply never written; the {@code REQUIRED} propagation
	 * on the append is what covers the case where it has been.
	 */
	@Test
	@DisplayName("A failed preservation writes no custody entry")
	void writesNoCustodyEntryWhenPreservationFails() {
		givenRegisteredSourceWithNoPriorArtifact();
		given(storageService.read(STORAGE_REF)).willReturn("tampered".getBytes(UTF_8));

		assertThatThrownBy(() -> service.preserve(request(CONTENT_SHA256), CONTENT, "text/plain", PRINCIPAL))
				.isInstanceOf(IntegrityVerificationException.class);

		then(custodyChainService).shouldHaveNoInteractions();
	}

	/**
	 * The classification is copied off the source at this moment rather than resolved through
	 * it later, so reclassifying the source cannot rewrite what past artifacts were preserved
	 * under.
	 */
	@Test
	@DisplayName("The work group is snapshotted from the source onto the item")
	void snapshotsClassificationFromSource() {
		givenRegisteredSourceWithNoPriorArtifact();
		given(storageService.read(STORAGE_REF)).willReturn(CONTENT);
		given(repository.saveAndFlush(any(EvidenceItem.class))).willAnswer(invocation -> invocation.getArgument(0));

		service.preserve(request(CONTENT_SHA256), CONTENT, "text/plain", PRINCIPAL);

		then(repository).should().saveAndFlush(itemCaptor.capture());
		assertThat(itemCaptor.getValue().getWorkGroup()).isSameAs(workGroup);
	}

	/**
	 * The check that closes the gap between a source hashing a file at capture and this
	 * repository holding it. Nothing may be written on the way to discovering the mismatch —
	 * not the object, and not the row.
	 */
	@Test
	@DisplayName("Bytes that do not match the asserted digest are rejected before anything is stored")
	void rejectsDigestMismatchBeforeStoringAnything() {
		assertThatThrownBy(() -> service.preserve(request(OTHER_SHA256), CONTENT, "text/plain", PRINCIPAL))
				.isInstanceOf(IntegrityVerificationException.class)
				.hasMessageContaining(ARTIFACT_ID)
				.hasMessageNotContaining(CONTENT_SHA256)
				.hasMessageNotContaining(OTHER_SHA256);

		then(storageService).shouldHaveNoInteractions();
		then(sourceRepository).shouldHaveNoInteractions();
		then(repository).should(never()).saveAndFlush(any(EvidenceItem.class));
	}

	/**
	 * Verify-on-read, pulled forward to the write: the digest recorded against an item has
	 * been checked against what storage is actually holding, not merely against what arrived
	 * at the HTTP layer. A write that did not land intact produces no row — an orphaned
	 * object is litter, a row pointing at corrupt bytes is a lie.
	 */
	@Test
	@DisplayName("An object that reads back different is not recorded")
	void rejectsWhenStoredObjectReadsBackDifferent() {
		givenRegisteredSourceWithNoPriorArtifact();
		given(storageService.read(STORAGE_REF)).willReturn("tampered".getBytes(UTF_8));

		assertThatThrownBy(() -> service.preserve(request(CONTENT_SHA256), CONTENT, "text/plain", PRINCIPAL))
				.isInstanceOf(IntegrityVerificationException.class)
				.hasMessageContaining(ARTIFACT_ID);

		then(repository).should(never()).saveAndFlush(any(EvidenceItem.class));
		then(sourceRepository).should(never()).touchLastEvidenceAt(any(UUID.class));
	}

	@Test
	@DisplayName("A re-sent artifact is rejected as a duplicate without being stored again")
	void rejectsDuplicateArtifact() {
		given(sourceRepository.findBySourceKey(SOURCE_KEY)).willReturn(Optional.of(source));
		given(repository.existsByEvidenceSourceIdAndSourceArtifactId(SOURCE_ID, ARTIFACT_ID)).willReturn(true);

		assertThatThrownBy(() -> service.preserve(request(CONTENT_SHA256), CONTENT, "text/plain", PRINCIPAL))
				.isInstanceOf(DuplicateResourceException.class)
				.hasMessageContaining(ARTIFACT_ID);

		then(storageService).shouldHaveNoInteractions();
		then(repository).should(never()).saveAndFlush(any(EvidenceItem.class));
	}

	/**
	 * An unregistered producer cannot preserve anything, which is what makes registration the
	 * point at which classification is decided rather than a formality.
	 */
	@Test
	@DisplayName("An unregistered source key preserves nothing")
	void rejectsUnknownSourceKey() {
		given(sourceRepository.findBySourceKey(SOURCE_KEY)).willReturn(Optional.empty());

		assertThatThrownBy(() -> service.preserve(request(CONTENT_SHA256), CONTENT, "text/plain", PRINCIPAL))
				.isInstanceOf(ResourceNotFoundException.class)
				.hasMessageContaining(SOURCE_KEY);

		then(storageService).shouldHaveNoInteractions();
		then(repository).should(never()).saveAndFlush(any(EvidenceItem.class));
	}

	private void givenRegisteredSourceWithNoPriorArtifact() {
		given(sourceRepository.findBySourceKey(SOURCE_KEY)).willReturn(Optional.of(source));
		given(repository.existsByEvidenceSourceIdAndSourceArtifactId(SOURCE_ID, ARTIFACT_ID)).willReturn(false);
	}

	private static EvidenceIngestRequest request(String sourceSha256) {
		return new EvidenceIngestRequest(
				SOURCE_KEY,
				ARTIFACT_ID,
				OffsetDateTime.parse("2026-09-05T14:30:00Z"),
				OffsetDateTime.parse("2026-09-05T14:30:30Z"),
				sourceSha256);
	}
}
