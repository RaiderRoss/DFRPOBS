/**
 * Domain exceptions shared between the service and API layers.
 *
 * <p>A deliberate eighth package alongside the seven in the README. Services must be able
 * to signal "not found" or "already exists" without importing anything HTTP — otherwise
 * the business layer starts deciding status codes — and the API layer needs a common type
 * to translate. These live in the middle so neither layer depends on the other's internals.
 */
package za.co.dfraas.exception;
