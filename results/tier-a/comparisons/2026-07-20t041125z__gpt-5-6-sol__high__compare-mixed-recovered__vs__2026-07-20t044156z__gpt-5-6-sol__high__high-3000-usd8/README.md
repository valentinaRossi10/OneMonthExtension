# Tier A comparison: 2026-07-20t041125z__gpt-5-6-sol__high__compare-mixed-recovered vs 2026-07-20t044156z__gpt-5-6-sol__high__high-3000-usd8

Generated at: `2026-07-20T05:02:07.133252+00:00`.

## Runs

| Role | Date | Model | Reasoning |
|---|---|---|---|
| Baseline | 2026-07-20 | `gpt-5.6-sol` | `high` |
| Candidate | 2026-07-20 | `gpt-5.6-sol` | `high` |

## Configuration changes

| Setting | Baseline | Candidate |
|---|---|---|
| policy_version | tier-a-policy-v4 | tier-a-policy-v5 |
| max_output_tokens | 1900 | 3000 |
| hard_budget_ceiling_usd | 5.0 | 8.0 |

## Metric changes

| Metric | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| `decision_coverage` | 0.13333333333333333 | 0.4 | 0.2666666666666667 |
| `end_to_end_recall` | 0.2 | 0.2 | 0.0 |
| `observable_positive_recall` | 0.25 | 0.25 | 0.0 |
| `precision` | 0.25 | 0.125 | -0.125 |
| `end_to_end_specificity` | 0.07272727272727272 | 0.2727272727272727 | 0.19999999999999998 |
| `false_positive_rate` | 0.05454545454545454 | 0.12727272727272726 | 0.07272727272727272 |
| `balanced_accuracy` | 0.13636363636363635 | 0.23636363636363636 | 0.1 |
| `strict_accuracy` | 0.08333333333333333 | 0.26666666666666666 | 0.18333333333333335 |
| `f1` | 0.22222222222222224 | 0.15384615384615385 | -0.06837606837606838 |
| `count.abstention` | 1 | 3 | 2 |
| `count.false_negative` | 0 | 1 | 1 |
| `count.false_positive` | 3 | 7 | 4 |
| `count.invalid_output` | 1 | 2 | 1 |
| `count.missing_output` | 50 | 31 | -19 |
| `count.true_negative` | 4 | 15 | 11 |
| `count.true_positive` | 1 | 1 | 0 |
| `cost.recorded_cumulative_usd` | 0.428205 | 1.40728 | 0.9790750000000001 |

## Task-level changes

- Categories changed for 20 of 60 tasks.
- Verdicts changed for 18 of 60 tasks.
- See `task-changes.csv` for the complete task-level comparison.
- See `per-class-metrics.csv` for class-specific metric deltas.
