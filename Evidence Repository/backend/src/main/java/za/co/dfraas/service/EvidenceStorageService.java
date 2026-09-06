package za.co.dfraas.service;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

import org.springframework.stereotype.Service;

import io.minio.GetObjectArgs;
import io.minio.MinioClient;
import io.minio.PutObjectArgs;
import za.co.dfraas.config.StorageProperties;
import za.co.dfraas.exception.EvidenceStorageException;

/**
 * Reads and writes evidence blobs in the MinIO bucket.
 *
 * <p>The one place in the application that touches object storage, so that the bucket name,
 * the client's exception zoo and the decision to hold an artifact in memory are all stated
 * once. Callers deal in an object key and bytes.
 *
 * <p><strong>Bytes rather than a stream, deliberately.</strong> Ingestion has to hash an
 * artifact, store it, and read it back to confirm the write landed — three passes over the
 * same content, which a single stream cannot serve. Holding an artifact in memory is
 * therefore a design decision rather than laziness, and it is sound at the sizes this
 * handles (log bundles and captures, bounded by the multipart limit in
 * application.properties). An artifact large enough to make that untrue — a disk image, a
 * memory dump from a real host — needs a different ingestion path anyway, one that streams
 * to storage while hashing in flight and never holds the whole thing at once.
 *
 * <p>Nothing here deletes. Evidence is soft-delete only, and even an object orphaned by a
 * failed ingest is not this service's to remove: it is bytes whose provenance is unclear,
 * which is the one category most deserving of a human decision.
 */
@Service
public class EvidenceStorageService {

	/** Lets the client choose its own part size, which it can because the size is known. */
	private static final long AUTO_PART_SIZE = -1L;

	private final MinioClient minioClient;
	private final StorageProperties properties;

	public EvidenceStorageService(MinioClient minioClient, StorageProperties properties) {
		this.minioClient = minioClient;
		this.properties = properties;
	}

	/**
	 * Writes an object, overwriting any object already at that key.
	 *
	 * <p>Overwriting is safe here and nowhere else: ingestion derives the key
	 * deterministically from the artifact's identity, so the only thing that can already be
	 * at it is the same artifact from an interrupted attempt — identical bytes, written
	 * again. What stops a *different* artifact from taking an occupied key is
	 * {@code uq_evidence_item_storage_ref}, one row per object, enforced in the database.
	 */
	public void store(String objectKey, byte[] content, String contentType) {
		try (InputStream stream = new ByteArrayInputStream(content)) {
			minioClient.putObject(PutObjectArgs.builder()
					.bucket(properties.bucket())
					.object(objectKey)
					.stream(stream, content.length, AUTO_PART_SIZE)
					.contentType(contentType)
					.build());
		} catch (Exception ex) {
			// The client throws nine unrelated checked types for what is, to every caller
			// here, one condition: the bytes are not safely stored. Catching the supertype is
			// the honest translation; enumerating them would only be longer.
			throw new EvidenceStorageException("Could not store evidence object " + objectKey, ex);
		}
	}

	/**
	 * Reads an object back in full.
	 *
	 * <p>Used immediately after {@link #store} to verify the write, and by any later
	 * integrity re-check: the SecureRS rule is to re-verify on read, and that is only
	 * possible if reading returns the bytes rather than a promise of them.
	 */
	public byte[] read(String objectKey) {
		try (InputStream stream = minioClient.getObject(GetObjectArgs.builder()
				.bucket(properties.bucket())
				.object(objectKey)
				.build())) {
			return stream.readAllBytes();
		} catch (Exception ex) {
			throw new EvidenceStorageException("Could not read evidence object " + objectKey, ex);
		}
	}
}
