# Tier A run: 2026-07-20t061556z__gpt-5-6-sol__high__high-4500-usd10-background

This directory is one self-contained Tier A experiment. API attempts are
append-only within this run; a changed model or reasoning setting must use a
new run directory.
Interpret this run under the canonical protocol in
[`EXPERIMENT.md`](../../../../EXPERIMENT.md).

## Run configuration

| Field | Value |
|---|---|
| Run date (UTC) | 2026-07-20 |
| Created at (UTC) | 2026-07-20T06:15:56.509898+00:00 |
| Last executed at (UTC) | not available |
| Scored at (UTC) | not available |
| Model | `gpt-5.6-sol` |
| Reasoning effort | `high` |
| Status | `dry-run` |
| Policy | `tier-a-policy-v7` |
| Prompt | `tier-a-prompt-v1` |
| Schema | `tier-a-result-v1` |
| Maximum output tokens | 4500 |
| Hard spending ceiling | $10.000000 |
| Approved run budget | $10.000000 |

## Experiment purpose

- Uniform high-reasoning Tier A replacement after policy-v6 exposed unaudited SDK retries and long-request connection failures; use policy-v7, a 4,500-token cap, hard USD 10 ceiling, background Responses polling, and zero SDK-level retries.

## Difference from the previous experiment

Previous run: `2026-07-20t050813z__gpt-5-6-sol__high__high-4500-usd10`

| Setting | Previous | This run |
|---|---|---|
| policy_version | tier-a-policy-v6 | tier-a-policy-v7 |

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
