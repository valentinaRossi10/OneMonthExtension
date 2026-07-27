# Tier A run: 2026-07-20t041125z__gpt-5-6-sol__high__compare-mixed-recovered

This directory is one self-contained Tier A experiment. API attempts are
append-only within this run; a changed model or reasoning setting must use a
new run directory.
Interpret this run under the canonical protocol in
[`EXPERIMENT.md`](../../../../EXPERIMENT.md).

## Run configuration

| Field | Value |
|---|---|
| Run date (UTC) | 2026-07-20 |
| Created at (UTC) | 2026-07-20T04:11:25.925812+00:00 |
| Last executed at (UTC) | not available |
| Scored at (UTC) | 2026-07-20T04:35:23.939429+00:00 |
| Model | `gpt-5.6-sol` |
| Reasoning effort | `high` |
| Status | `scored` |
| Policy | `tier-a-policy-v4` |
| Prompt | `tier-a-prompt-v1` |
| Schema | `tier-a-result-v1` |
| Maximum output tokens | 1900 |
| Hard spending ceiling | $5.000000 |
| Approved run budget | $5.000000 |

## Experiment purpose

- Uniform high-reasoning Tier A run for comparison with 2026-07-18__gpt-5-6-sol__mixed-recovered; freeze the existing 1,900-token output cap and all policy, prompt, schema, input, and pricing settings.

## Difference from the previous experiment

Previous run: `2026-07-18__gpt-5-6-sol__mixed-recovered`

| Setting | Previous | This run |
|---|---|---|
| reasoning_effort | mixed: provider-default and low | high |
| max_output_tokens | mixed: 1200 and 1900 | 1900 |

## Scored outcome

| Metric | Value |
|---|---|
| `tasks` | 60 |
| `decision_coverage` | 0.133333 |
| `end_to_end_recall` | 0.200000 |
| `observable_positive_recall` | 0.250000 |
| `precision` | 0.250000 |
| `end_to_end_specificity` | 0.072727 |
| `false_positive_rate` | 0.054545 |
| `balanced_accuracy` | 0.136364 |
| `strict_accuracy` | 0.083333 |
| `f1` | 0.222222 |

Outcome counts: `abstention`=1, `false_positive`=3, `invalid_output`=1, `missing_output`=50, `true_negative`=4, `true_positive`=1.

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
