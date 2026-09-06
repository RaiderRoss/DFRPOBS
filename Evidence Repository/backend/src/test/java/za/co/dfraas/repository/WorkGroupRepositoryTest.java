package za.co.dfraas.repository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Optional;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;

import za.co.dfraas.TestcontainersConfiguration;
import za.co.dfraas.entity.WorkGroup;

/**
 * The contract between {@link WorkGroup} and Liquibase changeset
 * {@code 0001-create-work-group-table}.
 *
 * <p>This is the load-bearing test of the slice. Because
 * {@code spring.jpa.hibernate.ddl-auto=validate} is active, the context simply fails to
 * start if the entity and the changeset disagree on a column name, type or nullability —
 * so {@code contextLoads} is effectively asserted by every method here. The explicit
 * assertions cover the three things validation alone would not catch.
 *
 * <p>{@code replace = NONE} is required: {@code @DataJpaTest} otherwise swaps in an
 * embedded database, which would skip Postgres entirely and defeat the point.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import(TestcontainersConfiguration.class)
class WorkGroupRepositoryTest {

	@Autowired
	private WorkGroupRepository repository;

	@Test
	@DisplayName("Liquibase seed data from changeset 0001-2 is present")
	void seedDataIsApplied() {
		assertThat(repository.findAll())
				.extracting(WorkGroup::getClassificationCode)
				.contains("ONLINE_BANKING", "INTERNAL_SYSTEMS");
	}

	@Test
	@DisplayName("Hibernate assigns the id, and the column default populates createdAt")
	void generatedFieldsArePopulatedOnInsert() {
		WorkGroup saved = repository.saveAndFlush(newWorkGroup("Card Processing", "CARD_PROCESSING"));

		// Assigned in Java by GenerationType.UUID, so it is available without a re-read.
		assertThat(saved.getId()).isNotNull();

		// Assigned by the now() column default and read back via @Generated(INSERT). This is
		// the assertion that fails if that annotation is ever dropped from the entity.
		assertThat(saved.getCreatedAt()).isNotNull();
	}

	@Test
	@DisplayName("classification_code is unique at the database level, not just in the service")
	void duplicateClassificationCodeIsRejectedByTheDatabase() {
		repository.saveAndFlush(newWorkGroup("Treasury", "TREASURY"));

		assertThatThrownBy(() -> repository.saveAndFlush(newWorkGroup("Treasury Duplicate", "TREASURY")))
				.isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	@DisplayName("findByClassificationCode resolves the lookup ingestion will use")
	void findsBySeededClassificationCode() {
		Optional<WorkGroup> found = repository.findByClassificationCode("ONLINE_BANKING");

		assertThat(found).isPresent();
		assertThat(found.get().getName()).isEqualTo("Online Banking");
		assertThat(repository.findByClassificationCode("NO_SUCH_CODE")).isEmpty();
	}

	private static WorkGroup newWorkGroup(String name, String classificationCode) {
		WorkGroup workGroup = new WorkGroup();
		workGroup.setName(name);
		workGroup.setClassificationCode(classificationCode);
		return workGroup;
	}
}
