# BusyBox Tier B v3 four-pair follow-on summary

Status: completed historical cohort  
Execution date: 2026-07-23 UTC  
Model: `gpt-5.6-sol`  
Reasoning effort: `high`  
Protocol/policy/prompt: `experiment-protocol-v3` /
`tier-b-policy-v3` / `tier-b-prompt-v3`

## Scope and reporting boundary

This file summarizes the first completed multi-pair BusyBox Tier B
oracle-candidate follow-on. The cohort consists of four independently approved
two-case runs: CVE-2017-15873, CVE-2021-42373, CVE-2021-42374, and
CVE-2021-42386.

This was **not** the complete five-pair oracle matrix. The separately prepared
CVE-2026-29004 matrix run was not executed, and its standalone pilot is not
combined with this cohort. The results below must not be reported as
five-pair-matrix performance or mixed with later protocol-v4 remediation
results.

Historical manifests and ledgers remain immutable. This summary records their
frozen scores and separately records the later evaluator-only diagnostic
interpretation.

## Frozen runs and accounting

| Pair | Manifest SHA-256 | Projected maximum | Accounted spend | Provider calls |
|---|---|---:|---:|---:|
| [CVE-2017-15873](../runs/2026-07-23t021238z__gpt-5-6-sol__high__busybox-cve-2017-15873-oracle-matrix-v1/results.jsonl) | `e0326a3aa046f5a7dae06d41a4c8f6309bcb2c23d2901f92aee2244cdcfa1380` | $9.021100 | $0.953760 | 22 |
| [CVE-2021-42373](../runs/2026-07-23t021238z__gpt-5-6-sol__high__busybox-cve-2021-42373-oracle-matrix-v1/results.jsonl) | `9071d7311f83939fa36e66d41231d07eac16782f7a601d1e46c6c2166a8708d0` | $9.021540 | $1.064675 | 21 |
| [CVE-2021-42374](../runs/2026-07-23t021238z__gpt-5-6-sol__high__busybox-cve-2021-42374-oracle-matrix-v1/results.jsonl) | `78c99ea506bcf131ca9030b13cbf4d02aa0a0c8e8f51e80830b503b639ae4ba2` | $9.021210 | $1.752940 | 22 |
| [CVE-2021-42386](../runs/2026-07-23t021238z__gpt-5-6-sol__high__busybox-cve-2021-42386-oracle-matrix-v1/results.jsonl) | `8a023dda6c4f7b58fd7ab901ee7ced3830fe04b09f965137125368ecab00b2b9` | $9.020935 | $0.941690 | 18 |
| **Aggregate** | — | **$36.084785** | **$4.713065** | **83** |

Each run had an independent $10 ceiling; the cohort ceiling was $40.

## Case outcomes

| Pair | Vulnerable case | Patched case | Frozen scoring outcome |
|---|---|---|---|
| CVE-2017-15873, integer overflow | `indeterminate` | `indeterminate` | Two abstentions |
| CVE-2021-42373, NULL pointer dereference | `indeterminate` | `indeterminate` | Two abstentions |
| CVE-2021-42374, out-of-bounds read | `api_error` | `confirmed` | One failure; one false positive under the frozen oracle |
| CVE-2021-42386, use-after-free | `rejected` | `rejected` | One false negative; one true negative |

No pair produced the intended vulnerable-`confirmed` to patched-`rejected`
transition.

## Aggregate frozen metrics

- Total cases: 8.
- Valid structured responses: 7/8 (87.5%).
- Decisive `confirmed` or `rejected` responses: 3/8 (37.5% decision
  coverage).
- Abstentions: 4/8 (50%).
- Explicit execution failures: 1/8 (12.5%).
- Correct cases under the frozen oracle: 1/8 (12.5% strict accuracy).
- Vulnerable-case sensitivity: 0/4 (0%); no expected-positive case was
  confirmed.
- Patched-case specificity: 1/4 (25%).
- Precision among `confirmed` responses: 0/1 (0%).
- Frozen outcome counts: 4 abstentions, 1 API failure, 1 false positive,
  1 false negative, and 1 true negative.

`indeterminate` receives no correctness credit. The API error is no verdict and
is not converted to `rejected`.

## Post-run diagnostic interpretation

### CVE-2017-15873

Both cases reached the final model-call limit with valid `indeterminate`
outputs. The traces found the candidate and its direct caller, but the original
entry crossed a decompiler label/indirect-call hop that the v1 direct-call
index did not resolve. Numeric range and signedness facts also remained
unresolved.

The vulnerable artifact remains eligible for a versioned retry with a verified
closer entry. The patched artifact is no longer considered a clean negative for
the broad integer-overflow class because evaluator review found that the
packaged historical fix does not establish the complete bound needed by that
oracle. It is excluded from protocol-v4 remediation scoring.

Classification: reachability-representation gap, numeric/type evidence gap,
and patched-control oracle limitation.

### CVE-2021-42373

Both cases returned `indeterminate`. Because the candidate was also the fixed
entry, reachability itself was not missing. The model focused on generic
option-parser configuration instead of resolving the candidate-local argument
access and patched guard. Evaluator review retained both controls as a valid
pair.

Classification: candidate-first reasoning error and insufficient focus on the
local dominating guard, rather than an oracle mismatch.

### CVE-2021-42374

The vulnerable trace remained on track but model call 11 ended with:

`RuntimeError: Didn't receive a response.completed event.`

It therefore produced no verdict. It is eligible only for an explicitly
approved append-only retry under the original manifest and remaining $10
run ceiling.

The patched case returned `confirmed`, which remains a false positive under
the immutable historical oracle. However, the response alleged an alternate
allocation-size versus dictionary-size out-of-bounds condition. Evaluator
review has not yet proved or disproved that alternate condition, so the
patched control is audit-pending and excluded from new protocol-v4 manifests.

Classification: transport failure on the vulnerable case; possible
secondary-weakness/oracle mismatch on the patched case.

### CVE-2021-42386

The vulnerable case was reachable but returned `rejected`. Its reasoning
treated absence of a physical allocator `free()` as blocking, while the
historical condition depends on logical pool-slot release/reuse,
reinitialization, and a surviving stale alias. The v1 package did not expose
that lifetime relation clearly enough.

The patched candidate was absent and correctly returned `rejected`; this is the
cohort's sole true negative and does not need another paid run.

Classification: logical-lifetime/alias representation gap plus a
use-after-free reasoning error.

## Methodological changes motivated by this cohort

The separately prepared protocol-v4 remediation evaluation:

1. uses neutral package-v2 semantic facts for indirect calls, address/data
   references, declarations, strings, and memory operations;
2. directs the model to inspect the fixed candidate early;
3. states class-neutral necessary conditions, including logical release/reuse
   as a possible lifetime end;
4. uses verified closer entries for the eligible CVE-2017-15873 and
   CVE-2021-42386 vulnerable cases; and
5. excludes audit-pending or redundant patched controls.

Those changes require new immutable manifests and a separate summary file
after execution. They do not revise any outcome or label recorded here.

## Evidence and related documentation

- Normative protocol: [`EXPERIMENT.md`](../../../EXPERIMENT.md)
- Evaluator-only diagnostic checklist:
  [`diagnostics.md`](../../../confirm-vulnerability-reachability/references/diagnostics.md)
- Evaluator-only control audit:
  [`oracle-audits.md`](../../../confirm-vulnerability-reachability/references/oracle-audits.md)
- Per-case prompts, manifests, metadata, and complete append-only ledgers are
  preserved in the four run directories linked in the accounting table.
