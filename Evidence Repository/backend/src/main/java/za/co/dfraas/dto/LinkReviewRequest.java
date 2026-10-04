package za.co.dfraas.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * Body for confirming or dismissing an {@link za.co.dfraas.entity.EvidenceLink}.
 *
 * <p>Carries the reason and nothing else. The ruling is in the path, because confirm and
 * dismiss are different acts rather than two values of one field. The reviewer is whoever
 * is authenticated, never a name in the body: a review is an attributed judgement, and
 * letting the caller type in whose judgement it was would make the attribution worthless.
 *
 * <p>Required for both rulings, not just dismissal. "Confirmed" without a reason is as
 * hard to defend as "dismissed" without one; the overlap that proposed the link is the
 * system's reasoning, and this is where the investigator's own goes.
 */
@Schema(name = "LinkReviewRequest",
		description = """
				Why the reviewer is confirming or dismissing the link. Required and never blank. \
				The reviewer is taken from the authenticated user, not from the body.
				""")
public record LinkReviewRequest(

		@Schema(description = "The reviewer's reason, as it should read in the investigative record",
				example = "Firewall log shows the same source probing ports 13337 and 17171 inside the alert window.",
				maxLength = 4000)
		@NotBlank @Size(max = 4000) String reason) {
}
