# Tier A comparison: 2026-07-18__gpt-5-6-sol__mixed-recovered vs 2026-07-20t044156z__gpt-5-6-sol__high__high-3000-usd8

Generated at: `2026-07-20T05:02:06.121219+00:00`.

## Runs

| Role | Date | Model | Reasoning |
|---|---|---|---|
| Baseline | 2026-07-18 | `gpt-5.6-sol` | `mixed: provider-default and low` |
| Candidate | 2026-07-20 | `gpt-5.6-sol` | `high` |

## Configuration changes

| Setting | Baseline | Candidate |
|---|---|---|
| reasoning_effort | mixed: provider-default and low | high |
| policy_version | tier-a-policy-v4 | tier-a-policy-v5 |
| max_output_tokens | mixed: 1200 and 1900 | 3000 |
| hard_budget_ceiling_usd | 5.0 | 8.0 |

## Metric changes

| Metric | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| `decision_coverage` | 0.8333333333333334 | 0.4 | -0.43333333333333335 |
| `end_to_end_recall` | 0.6 | 0.2 | -0.39999999999999997 |
| `observable_positive_recall` | 0.75 | 0.25 | -0.5 |
| `precision` | 0.21428571428571427 | 0.125 | -0.08928571428571427 |
| `end_to_end_specificity` | 0.6363636363636364 | 0.2727272727272727 | -0.36363636363636365 |
| `false_positive_rate` | 0.2 | 0.12727272727272726 | -0.07272727272727275 |
| `balanced_accuracy` | 0.6181818181818182 | 0.23636363636363636 | -0.38181818181818183 |
| `strict_accuracy` | 0.6333333333333333 | 0.26666666666666666 | -0.36666666666666664 |
| `f1` | 0.3157894736842105 | 0.15384615384615385 | -0.16194331983805665 |
| `count.abstention` | 10 | 3 | -7 |
| `count.false_negative` | 1 | 1 | 0 |
| `count.false_positive` | 11 | 7 | -4 |
| `count.invalid_output` | 0 | 2 | 2 |
| `count.missing_output` | 0 | 31 | 31 |
| `count.true_negative` | 35 | 15 | -20 |
| `count.true_positive` | 3 | 1 | -2 |
| `cost.recorded_cumulative_usd` | 1.88903 | 1.40728 | -0.4817499999999999 |

## Task-level changes

- Categories changed for 37 of 60 tasks.
- Verdicts changed for 37 of 60 tasks.
- See `task-changes.csv` for the complete task-level comparison.
- See `per-class-metrics.csv` for class-specific metric deltas.
