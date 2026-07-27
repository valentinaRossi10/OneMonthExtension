# Interpretation of the indexed out-of-bounds-read transition

## Observed result

The indexed task `CVE-2021-42374__vulnerable__out-of-bounds-read` changed
category from `abstention` in the recovered baseline to `api_error` in v8.
This is not a model-verdict transition: v8 returned no verdict.

| Run | Reasoning | Output cap | Recorded outcome | Output usage |
|---|---|---:|---|---:|
| `2026-07-18__gpt-5-6-sol__mixed-recovered` | low | 1,900 | completed `indeterminate` | 1,832 |
| `2026-07-20t050813z__gpt-5-6-sol__high__high-4500-usd10` | high | 4,500 | two recorded connection errors | unavailable |
| `2026-07-20t111012z__gpt-5-6-sol__high__high-4500-usd10-streaming` | high | 4,500 | no `response.completed` event | unavailable |

The baseline explanation found the suspicious local pattern: an index is
adjusted after becoming negative and is then used by a read without another
check. It abstained because the allocation is performed by an opaque callee,
so the readable extent cannot be established from the isolated function, and
the relevant decoder state is not fully resolved.

## Working hypothesis

The task appears to sit close to the boundary between positive local evidence
and required missing context. High reasoning may therefore spend a large
amount of computation trying to prove both the readable object extent and path
feasibility while remaining consistent with the strict Tier A rubric and JSON
schema. It may then exhaust the response budget or fail during structured
response finalization before emitting JSON. The low-reasoning baseline already
used 1,832 of 1,900 output tokens, while multiple high-reasoning attempts did
not complete, which is consistent with this explanation.

This remains a hypothesis. The v8 failure record has no response text, token
usage, completion reason, or provider response ID, so transport instability or
another provider-side failure cannot be excluded.

## Interpretation rule

Treat the change as an operational reliability regression, not as evidence
that high reasoning changed the semantic classification. The baseline remains
an abstention; v8 remains an API error with no correctness credit. No
`vulnerable` or `not_vulnerable` verdict should be imputed to v8.

To test the hypothesis, first capture incomplete-stream events, completion
details, and usage in the runner. Any controlled retry of this exact task must
retain the frozen prompt/code, receive a new cost projection and explicit
approval, and remain inside the existing v8 ceiling.
