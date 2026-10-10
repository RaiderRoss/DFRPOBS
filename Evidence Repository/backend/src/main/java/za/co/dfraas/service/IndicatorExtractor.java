package za.co.dfraas.service;

import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.stereotype.Component;

/**
 * Pulls the IPv4 addresses an artifact mentions out of its bytes.
 *
 * <p>What correlation matches an alert's subject against. Deliberately format-blind: a ufw
 * log, a Slips alerts.log and a JSON export all spell an address the same way, and a parser
 * per format would make a source the repository has not seen before uncorrelatable by
 * anything but time. The price is that an address inside a binary capture is not found;
 * such an artifact still correlates on time and on the alert instant.
 *
 * <p>Pure and deterministic: the same bytes always yield the same set, which is what lets
 * anyone holding a preserved artifact reproduce exactly why it was matched.
 */
@Component
public class IndicatorExtractor {

	/**
	 * Four dotted octets not embedded in a longer dotted number. The lookarounds reject a
	 * version string like {@code 1.2.3.4.5} as a whole rather than matching part of it, but
	 * still accept an address ending a sentence ({@code "to 10.98.0.1. Threat"}).
	 */
	private static final Pattern IPV4 = Pattern.compile(
			"(?<![\\d.])(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})(?!\\.?\\d)");

	/**
	 * Upper bound on distinct addresses kept per artifact. A busy edge log can name every
	 * address on the internet; past this many, matching on address says little about
	 * relevance and the rows only cost space.
	 */
	static final int MAX_INDICATORS = 10_000;

	/** Distinct IPv4 addresses in {@code content}, in sorted order. */
	public Set<String> ipv4(byte[] content) {
		// ISO-8859-1 maps every byte to one char, so ASCII digits and dots survive whatever
		// the real encoding is, and invalid UTF-8 cannot throw.
		Matcher matcher = IPV4.matcher(new String(content, StandardCharsets.ISO_8859_1));
		Set<String> found = new TreeSet<>();
		while (matcher.find() && found.size() < MAX_INDICATORS) {
			if (validOctets(matcher)) {
				found.add(canonical(matcher));
			}
		}
		return found;
	}

	private static boolean validOctets(Matcher matcher) {
		for (int group = 1; group <= 4; group++) {
			if (Integer.parseInt(matcher.group(group)) > 255) {
				return false;
			}
		}
		return true;
	}

	/** Without leading zeros, so {@code 010.000.000.001} and {@code 10.0.0.1} are one address. */
	private static String canonical(Matcher matcher) {
		return Integer.parseInt(matcher.group(1)) + "." + Integer.parseInt(matcher.group(2)) + "."
				+ Integer.parseInt(matcher.group(3)) + "." + Integer.parseInt(matcher.group(4));
	}
}
