# Correlation results: eval-design (classification: design)

## Preservation

| Submitted | Preserved | Already preserved | Rejected | Repository digest = capture digest |
|---|---|---|---|---|
| 96 | 96 | 0 | 0 | 96 of 96 |

## Incidents

76 alerts grouped into 6 incidents (6 expected); 6 of 6 triggered on the attacker.

| Window | Profile | Alerts | Links | Own window (of 4) | Other windows | Missing own sources | Audit trail proposed |
|---|---|---|---|---|---|---|---|
| 20260930231520 | guaranteed-alert | 18 | 12 | 2 | 10 (-7 to +11 min) | banking-events, banking-audit | **no** |
| 20260930232604 | db-probe | 7 | 12 | 2 | 10 (-18 to -4 min) | banking-events, banking-audit | **no** |
| 20261001104201 | guaranteed-alert | 15 | 16 | 2 | 14 (-16 to +15 min) | banking-events, banking-audit | **no** |
| 20261001105708 | db-probe | 9 | 18 | 2 | 16 (-27 to +12 min) | banking-events, banking-audit | **no** |
| 20261001111257 | guaranteed-alert | 19 | 16 | 2 | 14 (-23 to +8 min) | banking-events, banking-audit | **no** |
| 20261001112124 | db-probe | 8 | 18 | 2 | 16 (-28 to +13 min) | banking-events, banking-audit | **no** |

## Summary

| Measure | Value |
|---|---|
| Mean recall (own-window artifacts proposed) | 50% |
| Mean precision (proposed artifacts from own window) | 13% |
| Incidents whose bank audit trail was proposed | 0 of 6 |
| Per-source recall | firewall 6/6, ids 6/6, banking-events 0/6, banking-audit 0/6 |
| Links to review, grouped by incident | 92 |
| Links to review, one bundle per alert | 1150 |
