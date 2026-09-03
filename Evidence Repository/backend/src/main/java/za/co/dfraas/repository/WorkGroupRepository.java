package za.co.dfraas.repository;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import za.co.dfraas.entity.WorkGroup;

/**
 * Persistence for {@link WorkGroup}.
 *
 * <p>Lookup by {@code classificationCode} is here because it is how ingestion will resolve
 * a work group: a SIEM alert carries a classification string, not a UUID.
 */
@Repository
public interface WorkGroupRepository extends JpaRepository<WorkGroup, UUID> {

	Optional<WorkGroup> findByClassificationCode(String classificationCode);

	boolean existsByClassificationCode(String classificationCode);
}
