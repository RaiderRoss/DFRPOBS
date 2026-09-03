/**
 * API layer. {@code *Resource} classes expose HTTP endpoints, validate request DTOs and
 * delegate straight to a {@code *Service}.
 *
 * <p>Resources never touch repositories or entities directly — they speak DTOs only.
 */
package za.co.dfraas.resource;
