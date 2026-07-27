# Tier A run: 2026-07-20t044156z__gpt-5-6-sol__high__high-3000-usd8

This directory is one self-contained Tier A experiment. API attempts are
append-only within this run; a changed model or reasoning setting must use a
new run directory.
Interpret this run under the canonical protocol in
[`EXPERIMENT.md`](../../../../EXPERIMENT.md).

## Run configuration

| Field | Value |
|---|---|
| Run date (UTC) | 2026-07-20 |
| Created at (UTC) | 2026-07-20T04:41:56.119436+00:00 |
| Last executed at (UTC) | not available |
| Scored at (UTC) | 2026-07-20T05:01:54.352987+00:00 |
| Model | `gpt-5.6-sol` |
| Reasoning effort | `high` |
| Status | `scored` |
| Policy | `tier-a-policy-v5` |
| Prompt | `tier-a-prompt-v1` |
| Schema | `tier-a-result-v1` |
| Maximum output tokens | 3000 |
| Hard spending ceiling | $8.000000 |
| Approved run budget | $8.000000 |

## Experiment purpose

- Uniform high-reasoning Tier A replacement run after the 1,900-token v4 run stopped on repeated incomplete output; use tier-a-policy-v5 with a 3,000-token output cap and hard USD 8 cumulative ceiling.

## Difference from the previous experiment

Previous run: `2026-07-20t041125z__gpt-5-6-sol__high__compare-mixed-recovered`

| Setting | Previous | This run |
|---|---|---|
| policy_version | tier-a-policy-v4 | tier-a-policy-v5 |
| max_output_tokens | 1900 | 3000 |
| hard_budget_ceiling_usd | 5.000000 | 8.000000 |

## Scored outcome

| Metric | Value |
|---|---|
| `tasks` | 60 |
| `decision_coverage` | 0.400000 |
| `end_to_end_recall` | 0.200000 |
| `observable_positive_recall` | 0.250000 |
| `precision` | 0.125000 |
| `end_to_end_specificity` | 0.272727 |
| `false_positive_rate` | 0.127273 |
| `balanced_accuracy` | 0.236364 |
| `strict_accuracy` | 0.266667 |
| `f1` | 0.153846 |

Outcome counts: `abstention`=3, `false_negative`=1, `false_positive`=7, `invalid_output`=2, `missing_output`=31, `true_negative`=15, `true_positive`=1.

## Pipeline interpretation

Tier A scoring is strict: `indeterminate` remains an abstention with no
correctness credit. The later cascade forwards both `vulnerable` and
`indeterminate` to Tier B; forwarding does not relabel the Tier A result.

## Artifacts

- `run-metadata.json`: machine-readable experiment metadata.
- `manifest.jsonl` and `manifest-summary.json`: frozen task/configuration plan.
- `inputs/`: normalized isolated function inputs for this run.
- `results.jsonl`: append-only API attempts for this run.
- `scoring/`: task-level scores, summary metrics, and paired transitions.
