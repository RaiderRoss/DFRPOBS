/**
 * JPA entities mirroring the Liquibase schema under
 * {@code src/main/resources/liquibase/changes/}.
 *
 * <p>Liquibase owns the schema; {@code spring.jpa.hibernate.ddl-auto=validate} means these
 * classes must match the changesets or the application refuses to start.
 */
package za.co.dfraas.entity;
