/**
 * Business logic layer. {@code *Service} classes own transactions, enforce the forensic
 * rules (hash-before-processing, verify-on-read, soft-delete-only) and are the only place
 * that maps between entities and DTOs via a {@code *Mapper}.
 */
package za.co.dfraas.service;
