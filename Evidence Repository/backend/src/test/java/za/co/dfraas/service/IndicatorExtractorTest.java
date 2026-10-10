package za.co.dfraas.service;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * What counts as an address in an artifact. The lines are the formats the evaluation
 * actually preserves, so a regression here is a regression in what correlation can match.
 */
class IndicatorExtractorTest {

	private final IndicatorExtractor extractor = new IndicatorExtractor();

	@Test
	@DisplayName("Addresses in a ufw line are found, once each, sorted")
	void ufwLine() {
		String line = "[UFW BLOCK] IN=tun7 SRC=10.99.0.20 DST=10.98.0.1 LEN=60 SPT=38061 DPT=139\n"
				+ "[UFW ALLOW] IN=tun7 SRC=10.99.0.20 DST=10.98.0.1 LEN=60 SPT=38062 DPT=80\n";

		assertThat(extractor.ipv4(line.getBytes(UTF_8))).containsExactly("10.98.0.1", "10.99.0.20");
	}

	@Test
	@DisplayName("An address ending a Slips sentence keeps its last octet and loses the full stop")
	void slipsSentence() {
		String line = "Src IP 10.99.0.20                . Detected Unencrypted HTTP traffic"
				+ " from 10.99.0.14 to 10.98.0.1. Threat level: info.";

		assertThat(extractor.ipv4(line.getBytes(UTF_8))).containsExactly("10.98.0.1", "10.99.0.14", "10.99.0.20");
	}

	@Test
	@DisplayName("Version strings, out-of-range octets and timestamps are not addresses")
	void rejectsLookalikes() {
		String text = "ufw 0.36.2 kernel 7.0.0-1011 build 1.2.3.4.5 bad 300.1.1.1 at 2026-09-30T23:08:18.037881";

		assertThat(extractor.ipv4(text.getBytes(UTF_8))).isEmpty();
	}

	@Test
	@DisplayName("Leading zeros are dropped, so one address has one spelling")
	void canonicalises() {
		assertThat(extractor.ipv4("010.099.000.020 and 10.99.0.20".getBytes(UTF_8))).containsExactly("10.99.0.20");
	}

	@Test
	@DisplayName("Bytes that are not valid UTF-8 do not stop extraction")
	void toleratesBinary() {
		byte[] content = {(byte) 0xff, (byte) 0xfe, '1', '0', '.', '0', '.', '0', '.', '1', (byte) 0xc3};

		assertThat(extractor.ipv4(content)).containsExactly("10.0.0.1");
	}
}
