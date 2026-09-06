package za.co.dfraas.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

import org.springframework.stereotype.Service;

/**
 * Digest computation for the preservation pipeline.
 *
 * <p>Exists as its own bean rather than a static helper because every hash in this system
 * is an evidentiary claim, and there needs to be exactly one place that decides how they
 * are produced. When the algorithm is upgraded — SecureRS treats SHA-256 as the floor, not
 * the ceiling — this is the only file that changes, and stored digests will need an
 * algorithm discriminator alongside them at that point.
 */
@Service
public class HashingService {

	private static final String ALGORITHM = "SHA-256";

	/**
	 * Lowercase hex SHA-256 of the given bytes.
	 *
	 * <p>Prefer this overload wherever the raw bytes are available. Hashing bytes is the
	 * only honest option for evidence: a digest is a claim about exactly what arrived, and
	 * anything that decodes and re-encodes on the way in can change those bytes.
	 */
	public String sha256Hex(byte[] content) {
		try {
			MessageDigest digest = MessageDigest.getInstance(ALGORITHM);
			return HexFormat.of().formatHex(digest.digest(content));
		} catch (NoSuchAlgorithmException ex) {
			// SHA-256 is mandated by the JDK spec, so this cannot happen on a valid runtime.
			throw new IllegalStateException(ALGORITHM + " is unavailable on this JVM", ex);
		}
	}

	/**
	 * Convenience overload for text payloads, hashing the UTF-8 encoding.
	 *
	 * <p>Only sound while the Kafka listener consumes {@code String}. Once the payload
	 * arrives as {@code byte[]} — which it will when the Avro/Protobuf schema decision is
	 * made — switch the caller to {@link #sha256Hex(byte[])}. Hashing a String that was
	 * itself decoded from bytes digests the decoder's output rather than what was sent.
	 */
	public String sha256Hex(String content) {
		return sha256Hex(content.getBytes(StandardCharsets.UTF_8));
	}
}
