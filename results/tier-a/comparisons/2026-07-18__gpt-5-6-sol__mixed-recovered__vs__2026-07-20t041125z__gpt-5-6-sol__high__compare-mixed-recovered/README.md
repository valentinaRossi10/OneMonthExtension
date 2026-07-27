# Tier A comparison: 2026-07-18__gpt-5-6-sol__mixed-recovered vs 2026-07-20t041125z__gpt-5-6-sol__high__compare-mixed-recovered

Generated at: `2026-07-20T04:35:31.059976+00:00`.

## Runs

| Role | Date | Model | Reasoning |
|---|---|---|---|
| Baseline | 2026-07-18 | `gpt-5.6-sol` | `mixed: provider-default and low` |
| Candidate | 2026-07-20 | `gpt-5.6-sol` | `high` |

## Configuration changes

| Setting | Baseline | Candidate |
|---|---|---|
| reasoning_effort | mixed: provider-default and low | high |
| max_output_tokens | mixed: 1200 and 1900 | 1900 |

## Metric changes

| Metric | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| `decision_coverage` | 0.8333333333333334 | 0.13333333333333333 | -0.7000000000000001 |
| `end_to_end_recall` | 0.6 | 0.2 | -0.39999999999999997 |
| `observable_positive_recall` | 0.75 | 0.25 | -0.5 |
| `precision` | 0.21428571428571427 | 0.25 | 0.035714285714285726 |
| `end_to_end_specificity` | 0.6363636363636364 | 0.07272727272727272 | -0.5636363636363636 |
| `false_positive_rate` | 0.2 | 0.05454545454545454 | -0.14545454545454548 |
| `balanced_accuracy` | 0.6181818181818182 | 0.13636363636363635 | -0.4818181818181818 |
| `strict_accuracy` | 0.6333333333333333 | 0.08333333333333333 | -0.5499999999999999 |
| `f1` | 0.3157894736842105 | 0.22222222222222224 | -0.09356725146198827 |
| `count.abstention` | 10 | 1 | -9 |
| `count.false_negative` | 1 | 0 | -1 |
| `count.false_positive` | 11 | 3 | -8 |
| `count.invalid_output` | 0 | 1 | 1 |
| `count.missing_output` | 0 | 50 | 50 |
| `count.true_negative` | 35 | 4 | -31 |
| `count.true_positive` | 3 | 1 | -2 |
| `cost.recorded_cumulative_usd` | 1.88903 | 0.428205 | -1.460825 |

## Task-level changes

- Categories changed for 53 of 60 tasks.
- Verdicts changed for 53 of 60 tasks.
- See `task-changes.csv` for the complete task-level comparison.
- See `per-class-metrics.csv` for class-specific metric deltas.
