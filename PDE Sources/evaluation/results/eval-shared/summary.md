# Correlation results: eval-shared (classification: shared)

## Preservation

| Submitted | Preserved | Already preserved | Rejected | Repository digest = capture digest |
|---|---|---|---|---|
| 96 | 96 | 0 | 0 | 96 of 96 |

## Incidents

76 alerts grouped into 6 incidents (6 expected); 6 of 6 triggered on the attacker.

| Window | Profile | Alerts | Links | Own window (of 4) | Other windows | Missing own sources | Audit trail proposed |
|---|---|---|---|---|---|---|---|
| 20260930231520 | guaranteed-alert | 18 | 24 | 4 | 20 (-7 to +11 min) | none | yes |
| 20260930232604 | db-probe | 7 | 24 | 4 | 20 (-18 to -4 min) | none | yes |
| 20261001104201 | guaranteed-alert | 15 | 32 | 4 | 28 (-16 to +15 min) | none | yes |
| 20261001105708 | db-probe | 9 | 36 | 4 | 32 (-27 to +12 min) | none | yes |
| 20261001111257 | guaranteed-alert | 19 | 32 | 4 | 28 (-23 to +8 min) | none | yes |
| 20261001112124 | db-probe | 8 | 36 | 4 | 32 (-28 to +13 min) | none | yes |

## Summary

| Measure | Value |
|---|---|
| Mean recall (own-window artifacts proposed) | 100% |
| Mean precision (proposed artifacts from own window) | 13% |
| Incidents whose bank audit trail was proposed | 6 of 6 |
| Per-source recall | firewall 6/6, ids 6/6, banking-events 6/6, banking-audit 6/6 |
| Links to review, grouped by incident | 184 |
| Links to review, one bundle per alert | 2300 |
