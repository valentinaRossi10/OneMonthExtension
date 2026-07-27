# Tier A comparison: 2026-07-18__gpt-5-6-sol__mixed-recovered vs 2026-07-20t111012z__gpt-5-6-sol__high__high-4500-usd10-streaming

Generated at: `2026-07-20T11:48:42.714322+00:00`.

## Runs

| Role | Date | Model | Reasoning |
|---|---|---|---|
| Baseline | 2026-07-18 | `gpt-5.6-sol` | `mixed: provider-default and low` |
| Candidate | 2026-07-20 | `gpt-5.6-sol` | `high` |

## Configuration changes

| Setting | Baseline | Candidate |
|---|---|---|
| reasoning_effort | mixed: provider-default and low | high |
| policy_version | tier-a-policy-v4 | tier-a-policy-v8 |
| max_output_tokens | mixed: 1200 and 1900 | 4500 |
| hard_budget_ceiling_usd | 5.0 | 10.0 |

## Visual outcome summary

| Reasoning run | TP | FP | TN | FN | Abstention | API error | Total |
|---|---:|---:|---:|---:|---:|---:|---:|
| Low/mixed recovered baseline | 3 | 11 | 35 | 1 | 10 | 0 | 60 |
| High v8 streaming | 2 | 11 | 31 | 1 | 8 | 7 | 60 |

The baseline is preserved as a mixed/recovered run: it contains low-reasoning
tasks together with recovered historical provider-default attempts and used
different output-token limits. The table is a descriptive comparison, not a
controlled estimate of the causal effect of reasoning effort.

### Indexed expected-positive CVEs

| CVE | Vulnerability class | Low/mixed recovered | High |
|---|---|---|---|
| CVE-2026-29004 | Heap buffer overflow | **TP** | **TP** |
| CVE-2017-15873 | Integer overflow | **TP** | **API error** |
| CVE-2021-42373 | NULL-pointer dereference | **TP** | **TP** |
| CVE-2021-42374 | Out-of-bounds read | **Abstention** | **API error** |
| CVE-2021-42386 | Use-after-free | **FN** | **FN** |

All five rows above are expected-positive vulnerable samples. They can
therefore produce a TP, FN, abstention, or operational failure, but not a TN
or FP. The false positives in the outcome summary come from the 55
expected-negative CVE/class combinations in each complete Tier A matrix.

## Metric changes

| Metric | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| `decision_coverage` | 0.8333333333333334 | 0.75 | -0.08333333333333337 |
| `end_to_end_recall` | 0.6 | 0.4 | -0.19999999999999996 |
| `observable_positive_recall` | 0.75 | 0.5 | -0.25 |
| `precision` | 0.21428571428571427 | 0.15384615384615385 | -0.06043956043956042 |
| `end_to_end_specificity` | 0.6363636363636364 | 0.5636363636363636 | -0.07272727272727275 |
| `false_positive_rate` | 0.2 | 0.2 | 0.0 |
| `balanced_accuracy` | 0.6181818181818182 | 0.4818181818181818 | -0.13636363636363635 |
| `strict_accuracy` | 0.6333333333333333 | 0.55 | -0.08333333333333326 |
| `f1` | 0.3157894736842105 | 0.2222222222222222 | -0.0935672514619883 |
| `count.abstention` | 10 | 8 | -2 |
| `count.api_error` | 0 | 7 | 7 |
| `count.false_negative` | 1 | 1 | 0 |
| `count.false_positive` | 11 | 11 | 0 |
| `count.true_negative` | 35 | 31 | -4 |
| `count.true_positive` | 3 | 2 | -1 |
| `cost.recorded_cumulative_usd` | 1.88903 | 3.37444 | 1.48541 |

## Task-level changes

- Categories changed for 14 of 60 tasks.
- Verdicts changed for 14 of 60 tasks.
- See `task-changes.csv` for the complete task-level comparison.
- See `per-class-metrics.csv` for class-specific metric deltas.
- See `INTERPRETATION.md` for the evidence and working hypothesis behind the
  indexed out-of-bounds-read transition from baseline abstention to v8 API
  error. The transition is operational, not a new semantic verdict.
