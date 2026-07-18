# Tier A run: 2026-07-18__gpt-5-6-sol__mixed-recovered

This directory is the recovered baseline from the original Tier A execution.
Its API attempts remain unchanged and append-only.
Interpret it under the canonical protocol in
[`EXPERIMENT.md`](../../../../EXPERIMENT.md).

## Run configuration

| Field | Value |
|---|---|
| Run date (UTC) | 2026-07-18 |
| Model | `gpt-5.6-sol` |
| Reasoning effort | `mixed: 3 provider-default, 57 low` |
| Maximum output tokens | `mixed: 50 tasks at 1200, 10 tasks at 1900` |
| Hard spending ceiling | $5.00 |
| Conservative cumulative ledger | $1.889030 |
| Status | `scored` |

## Experiment purpose

- Establish the first complete 60-task Tier A cross-product baseline.
- Recover from structured-schema and output-cap integration failures without
  repeating successful paid calls.

## Difference from the previous experiment

There is no previous recorded run; this is the comparison baseline. Because
the recovery reused successful calls, this run is not a clean single-setting
reasoning experiment. Future low/medium/high runs must each use a separate run
directory and a uniform frozen setting.

## Scored outcome

TP=3, FN=1, TN=35, FP=11, and abstentions=10. Decision coverage was
83.33%, end-to-end recall 60%, observable-positive recall 75%, specificity
63.64%, and strict accuracy 63.33%.

## Tier B handoff interpretation

Strict scoring and downstream selection are separate. The OOB indexed positive
remains an abstention, but the cascade rule forwards both `vulnerable` and
`indeterminate`. For this run that queue contains 24/60 task-class
combinations, 4/5 indexed positives, and all 4/4 function-locally observable
positives. The UAF indexed positive was `not_vulnerable` and remains the known
function-local observability limitation; oracle Tier B evaluation must include
it independently of Tier A selection.

### Reasoning

- CVE-2021-42386 UAF: FN but due to an observability issue
- CVE-2026-29004 Buffer Overflow: TP
- CVE-2017-15873 Integer Overflow: TP
- CVE-2021-42373 Null Pointer Dereference: TP
- CVE-2021-42374 Out Of Bounds Read: ABSTENTION

## Artifacts

- `run-metadata.json`: machine-readable experiment metadata.
- `manifest.jsonl` and `manifest-summary.json`: frozen task plan.
- `inputs/`: normalized isolated function inputs.
- `results.jsonl`: 64 append-only API attempt records.
- `scoring/`: 60 task scores, aggregate metrics, and paired transitions.
