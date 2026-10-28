package za.co.dfraas.dto;

import java.util.List;
import java.util.UUID;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * Body for confirming or dismissing several {@link za.co.dfraas.entity.EvidenceLink}s with
 * one reason.
 *
 * <p>Exists because a time-window bundle holds tens of links, most of which an investigator
 * sets aside for the same reason ("a different host", "before the attack started"), and
 * making them type it once per link is how reasons turn into "n/a". The same rules as
 * {@link LinkReviewRequest} otherwise: the ruling is in the path, the reviewer is whoever is
 * authenticated, and the reason is required.
 *
 * <p>Capped at one bundle page. A larger selection is not something one reason can honestly
 * cover.
 */
@Schema(name = "LinkBulkReviewRequest",
		description = """
				The links to rule on and the one reason that applies to all of them. Applied all \
				or none: if any link is missing or already reviewed, nothing is recorded.
				""")
public record LinkBulkReviewRequest(

		@Schema(description = "Ids of PROPOSED links. Duplicates are reviewed once.", maxLength = 200)
		@NotEmpty @Size(max = 200) List<@NotNull UUID> linkIds,

		@Schema(description = "The reviewer's reason, recorded on every link in the selection",
				example = "Coverage ends before the first alert; no traffic from 10.99.0.20.",
				maxLength = 4000)
		@NotBlank @Size(max = 4000) String reason) {
}
