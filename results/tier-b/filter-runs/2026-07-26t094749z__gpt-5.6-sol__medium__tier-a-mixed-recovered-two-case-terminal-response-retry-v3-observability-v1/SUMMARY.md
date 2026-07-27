# Two-case terminal-response retry result

Run ID:
`2026-07-26t094749z__gpt-5.6-sol__medium__tier-a-mixed-recovered-two-case-terminal-response-retry-v3-observability-v1`

Manifest SHA-256:
`feef815a46b475fd3a2753629f8d497c84bb53d10a2a03a27349e283d1741503`

This retry-only protocol-v3 cohort contains exactly the two reviewed
evaluator-positive cases from the original six-case scope whose historical
attempts ended with the generic missing-`response.completed` SDK error. No
other case was included.

| CVE | Case | Class | Calls | Actual spend | Terminal provider state | Pipeline result |
|---|---|---|---:|---:|---|---|
| CVE-2017-15873 vulnerable | `tier-b-case-599ba94926f0028709065453` | integer-overflow | 13 | $0.713990 | `response.incomplete`; `max_output_tokens`; 4,500 output tokens | `unresolved`; `retain_and_escalate`; `resource_exhausted` |
| CVE-2021-42374 vulnerable | `tier-b-case-b99dc78d5275592661bdc5b9` | out-of-bounds-read | 12 | $0.827345 | `response.incomplete`; `max_output_tokens`; 4,500 output tokens | `unresolved`; `retain_and_escalate`; `resource_exhausted` |

Aggregate actual spend was $1.541335 against the $20.108110 adaptive
projection and $20.140000 hard ceiling. The ledger contains 25
`response.created` records and 25 matching model-call outcome records: 23
`completed` and 2 `incomplete_max_output_tokens`. No retrieval was necessary,
because neither terminal event was lost or interrupted.

Neither vulnerability received confirmation credit. Both remain available
for downstream dynamic analysis, and neither was suppressed. The run
establishes that the historical generic terminal-response error masked a
specific output-budget failure for these cases; it does not establish a
reasoning or suppression-gate failure and does not justify an unchanged retry.
