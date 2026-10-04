package za.co.dfraas.repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import za.co.dfraas.entity.CustodyEvent;

/**
 * Data access for {@link CustodyEvent}.
 *
 * <p>Two reads, and between them they are the whole ledger: the chain in order, for
 * verification and for showing an artifact's history, and its last entry, for appending the
 * next one. Both are served by {@code uq_custody_event_item_sequence}, whose leading column
 * is {@code evidence_item_id} — which is why {@code 0006} adds no separate index.
 *
 * <p><strong>{@code delete}, {@code deleteAll} and {@code save} on an existing row are all
 * inherited and none of them should ever be called.</strong> That warning appears on the
 * other repositories here too, and on this one it is the difference between a custody record
 * and a suggestion. Two things make it more than a comment, unlike elsewhere: every column on
 * the entity is {@code updatable = false}, so an accidental save writes nothing, and the
 * chain itself makes a deletion or an edit that bypassed both of those visible to
 * {@code CustodyChainService.verify}. The proper lockdown — a revoked grant, or a rule that
 * rejects UPDATE and DELETE in the database — is README open question 8 and belongs to all
 * five tables at once.
 */
@Repository
public interface CustodyEventRepository extends JpaRepository<CustodyEvent, UUID> {

	/**
	 * One artifact's chain, in ledger order — what {@code CustodyChainService.verify} walks,
	 * and what an investigator reading an exhibit's history sees.
	 *
	 * <p>Unpaged, and a {@code List} rather than a {@code Page}, which is the opposite of the
	 * rule {@link EvidenceItemRepository} and {@link EvidenceLinkRepository} follow. The
	 * bound is real here: a chain grows with how often one artifact is handled, not with
	 * anything the estate produces, so it is measured in entries rather than in thousands.
	 * More to the point, verification is not a listing — it has to see the whole chain from
	 * the origin to know that what it read is contiguous, and a paged verification would
	 * simply be a verification with the gaps between pages taken on trust.
	 *
	 * <p>Ordered by {@code sequence}, never by {@code recordedAt}. Two entries written in one
	 * transaction can share a {@code now()}, and a tie would leave the ledger's order
	 * undefined at exactly the moment it is being asked to prove an order.
	 */
	List<CustodyEvent> findByEvidenceItemIdOrderBySequenceAsc(UUID evidenceItemId);

	/**
	 * The head of a chain — the entry a new one links to.
	 *
	 * <p>Empty only for an artifact with no chain at all, which is not a legitimate state
	 * (every item gets an opening entry in the transaction that creates it) but is the state
	 * of any item preserved before changeset {@code 0006}, and of any item whose chain has
	 * been deleted wholesale. {@code CustodyChainService.append} reads it as "start at
	 * sequence 0 from the genesis hash"; {@code verify} reports it as missing its origin
	 * rather than as an intact empty chain.
	 *
	 * <p>Called under a row lock on the parent {@code evidence_item}
	 * ({@link EvidenceItemRepository#findByIdForUpdate}) — on its own this read is a
	 * check-then-act and two concurrent appends would both see the same head.
	 */
	Optional<CustodyEvent> findTopByEvidenceItemIdOrderBySequenceDesc(UUID evidenceItemId);
}
