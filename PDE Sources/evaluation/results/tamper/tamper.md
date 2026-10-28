# Tamper test results (tamper)

Window `20260930230812_port-scan`, artifact `firewall_20260930230812.log`. Run 2026-10-04T18:35:16.342255+00:00.

| Test | Attack | Expected | Outcome | Pass |
|---|---|---|---|---|
| T1 | Artifact altered in transit: one byte flipped, original digest claimed | HTTP 422; nothing stored | REJECTED | yes |
| T2 | Evidence altered in storage: object overwritten in MinIO, bypassing the API | HASH_MISMATCH recorded; item COMPROMISED; recorded digest kept; stays COMPROMISED after the object is restored | DETECTED | yes |
| T3 | Custody entry edited in the database: performed_by of entry 1 rewritten | PREVENTED, or DETECTED at sequence 1 | DETECTED | yes |
| T4a | Custody entries reordered: entries 1 and 2 swapped | PREVENTED, or DETECTED at sequence 1 | DETECTED | yes |
| T4b | Custody entry deleted from the middle of the chain (entry 1 of 0-2) | PREVENTED, or DETECTED at sequence 1 (the hole) | DETECTED | yes |
| T5 | Custody chain truncated: newest entry deleted | UNDETECTED by chain verification (known limitation); would be caught by a head hash witnessed outside the database | UNDETECTED | yes |
| T6 | Duplicate submission: an already preserved artifact sent again | HTTP 409; no second item; custody chain unchanged | REJECTED | yes |

**T5:** chain length 3 -> 2, still verifies as intact. Head hash before `83366fc91359deb1...`, after `10146b2e0d031eae...`; a head witnessed outside the database would detect the truncation.

**Note:** the repository's database role is a superuser. Revoking UPDATE/DELETE grants does not bind a superuser, and a superuser can disable triggers, so append-only enforcement needs a separate, non-superuser application role.
