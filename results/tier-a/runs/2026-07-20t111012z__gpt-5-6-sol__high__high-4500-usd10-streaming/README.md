# Tier A run: 2026-07-20t111012z__gpt-5-6-sol__high__high-4500-usd10-streaming

This directory is one self-contained Tier A experiment. API attempts are
append-only within this run; a changed model or reasoning setting must use a
new run directory.
Interpret this run under the canonical protocol in
[`EXPERIMENT.md`](../../../../EXPERIMENT.md).

## Run configuration

| Field | Value |
|---|---|
| Run date (UTC) | 2026-07-20 |
| Created at (UTC) | 2026-07-20T11:10:12.180055+00:00 |
| Last executed at (UTC) | 2026-07-20T11:47:47.072155+00:00 |
| Scored at (UTC) | 2026-07-20T11:48:23.935950+00:00 |
| Model | `gpt-5.6-sol` |
| Reasoning effort | `high` |
| Status | `scored` |
| Policy | `tier-a-policy-v8` |
| Prompt | `tier-a-prompt-v1` |
| Schema | `tier-a-result-v1` |
| Transport | `synchronous_streaming` |
| SDK retries | 0 |
| Maximum output tokens | 4500 |
| Hard spending ceiling | $10.000000 |
| Approved run budget | $10.000000 |

## Experiment purpose

- Uniform high-reasoning Tier A replacement after policy-v7 background mode exceeded the frozen 4,500-token accounting bound; use policy-v8 synchronous SSE streaming, zero SDK retries, explicit usage-cap breach stopping, and an isolated USD 10 ceiling.

## Difference from the previous experiment

Previous run: `2026-07-20t061556z__gpt-5-6-sol__high__high-4500-usd10-background`

| Setting | Previous | This run |
|---|---|---|
| policy_version | tier-a-policy-v7 | tier-a-policy-v8 |
| transport_mode | not available | synchronous_streaming |
| sdk_max_retries | not available | 0 |

## Scored outcome

| Metric | Value |
|---|---|
| `tasks` | 60 |
| `decision_coverage` | 0.750000 |
| `end_to_end_recall` | 0.400000 |
| `observable_positive_recall` | 0.500000 |
| `precision` | 0.153846 |
| `end_to_end_specificity` | 0.563636 |
| `false_positive_rate` | 0.200000 |
| `balanced_accuracy` | 0.481818 |
| `strict_accuracy` | 0.550000 |
| `f1` | 0.222222 |

Outcome counts: `abstention`=8, `api_error`=7, `false_negative`=1, `false_positive`=11, `true_negative`=31, `true_positive`=2.

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
