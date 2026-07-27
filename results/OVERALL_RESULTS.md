# Overall pipeline results

Last updated: 2026-07-23

This is the human-readable progress dashboard for the experiment. The
normative methodology remains in [`EXPERIMENT.md`](../EXPERIMENT.md), and the
immutable run directories and versioned cohort summaries remain the source of
truth. Results from different Tier B protocol versions are shown separately;
they are not pooled into a synthetic five-pair matrix score.

## Progress at a glance

| Pipeline component | Status | Current result |
|---|---|---|
| Tier A recovered baseline | Completed | 60/60 tasks scored; mixed provider-default/low historical configuration |
| Tier A high-reasoning run | Completed | 60/60 tasks scored; 7 operational API errors |
| Tier B CVE-2026-29004 standalone pilot | Completed | Vulnerable case TP; patched case TN |
| Tier B v3 four-pair follow-on | Completed | 8/8 cases scored, but only 1 correct case and no correct pair transition |
| Tier B v4 remediation subset | Completed | 3 abstentions and 1 API failure; no decisive correct verdict |
| Tier B v5 targeted follow-up | Completed | NULL-dereference vulnerable TP, its patched control FP, UAF vulnerable FN, integer-overflow retry API failure |
| Complete five-pair Tier B oracle matrix | **Not completed** | Historical pilot and versioned follow-ups cannot be pooled as one matrix |
| Tier A → Tier B cascade | **Not executed** | No end-to-end pipeline accuracy or recall can be claimed yet |
| Dynamic-analysis validation | **Not executed** | Outside the current static benchmark |

## Tier A outcome counts

| Reasoning run | TP | FP | TN | FN | Abstention | API error | Total |
|---|---:|---:|---:|---:|---:|---:|---:|
| Low/mixed recovered baseline | 3 | 11 | 35 | 1 | 10 | 0 | 60 |
| High v8 streaming | 2 | 11 | 31 | 1 | 8 | 7 | 60 |

The recovered baseline is not a clean low-only experiment. It combines
low-reasoning tasks with recovered historical provider-default attempts and
uses different output-token limits. The comparison is descriptive and does
not isolate reasoning effort as the cause of the observed differences.

The low/mixed run has 63.3% strict accuracy and 60% recall over the five
expected positives. The high run has 55.0% strict accuracy and 40% recall.
API errors and abstentions receive no correctness credit.

## Tier A indexed expected-positive CVEs

| CVE | Vulnerability class | Low/mixed recovered | High |
|---|---|---|---|
| CVE-2026-29004 | Heap buffer overflow | **TP** | **TP** |
| CVE-2017-15873 | Integer overflow | **TP** | **API error** |
| CVE-2021-42373 | NULL-pointer dereference | **TP** | **TP** |
| CVE-2021-42374 | Out-of-bounds read | **Abstention** | **API error** |
| CVE-2021-42386 | Use-after-free | **FN** | **FN** |

These five rows are expected-positive vulnerable samples, so their applicable
scored outcomes are TP or FN; they may also abstain or fail operationally.
The Tier A false positives come from the other 55 expected-negative
CVE/class combinations in each full cross-product.

### Why the Tier A positive cases were not all TPs

| Outcome | Affected case | Evidence-based reason |
|---|---|---|
| **Abstention** | CVE-2021-42374 OOB, low/mixed | The function contains a suspicious adjusted index that is read without another bounds check. However, the allocation occurs in an opaque callee, so Tier A cannot establish the readable object extent from the isolated function. Decoder-state constraints also leave the failing path unresolved. The model therefore returned `indeterminate`, which is scored as an abstention. |
| **FN** | CVE-2021-42386 UAF, low/mixed and high | The isolated `nvalloc` function does not contain the complete logical release, surviving stale alias, pool-slot reuse, and later use sequence. Because no physical release operation is visible locally, both runs concluded that a use-after-free was not demonstrated. This is a known function-local observability limitation rather than evidence that the historical UAF is absent. |
| **API error** | CVE-2017-15873 integer overflow, high | The synchronous response stream ended without a `response.completed` event. No structured verdict was produced, so the task is an operational failure—not a model decision that the function is safe or vulnerable. The preserved record does not establish a more specific provider-side cause. |
| **API error** | CVE-2021-42374 OOB, high | The response stream likewise ended without a `response.completed` event and returned no verdict. It must remain an API error. It does not replace or semantically contradict the low/mixed run's OOB abstention. |

## Tier B results by preserved cohort

| Cohort | Scope | TP | FP | TN | FN | Abstention | API error | Recorded spend |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Defensive-v3 standalone pilot | 2 cases | 1 | 0 | 1 | 0 | 0 | 0 | $1.274780 |
| Protocol-v3 four-pair follow-on | 8 cases | 0 | 1 | 1 | 1 | 4 | 1 | $4.713065 |
| Protocol-v4 remediation subset | 4 cases | 0 | 0 | 0 | 0 | 3 | 1 | $3.070945 |
| Protocol-v5 targeted actions, including unchanged v4 retry | 4 actions | 1 | 1 | 0 | 1 | 0 | 1 | $3.222740 additional |

The rows use different scopes, packages, prompts, limits, and protocol
versions. The protocol-v5 row also includes one append-only retry in its
original v4 ledger. These figures are therefore cohort summaries, not values
that may be added together and presented as a single oracle-matrix result.

## Current Tier B evidence by CVE

This table shows the most recent or otherwise controlling evidence for each
case. It is a status view across preserved experiments, not a cross-version
aggregate metric.

| CVE | Vulnerable case | Patched case | Current interpretation |
|---|---|---|---|
| CVE-2026-29004 | **TP** in standalone defensive-v3 pilot | **TN** in the same pilot | Successful two-case pilot; not part of a completed five-pair matrix |
| CVE-2017-15873 | **API error** on the unchanged v4 retry | Excluded from remediation; historical v3 result was an abstention | Vulnerable result remains unresolved because the transport twice failed to complete; patched oracle is not a clean broad-class negative |
| CVE-2021-42373 | **TP** under prompt v5 | **FP** under prompt v5 | Targeted prompt recovered sensitivity but did not preserve specificity |
| CVE-2021-42374 | **API error** under v3 | **FP** under v3; control remains audit-pending | Vulnerable result and patched-control validity remain unresolved |
| CVE-2021-42386 | **FN** under package v3/policy v6 | **TN** in the historical v3 follow-on | Patched rejection works, but the vulnerable logical-lifetime path is still missed |

## What the results currently support

- Tier A can find the function-local heap-overflow and NULL-dereference
  positives in both preserved runs.
- Tier A consistently misses the designated function-local UAF case.
- The completed Tier B pilot shows that the harness can correctly confirm one
  vulnerable heap-overflow case and reject its patched control.
- The wider Tier B experiments are not yet reliable across classes. The
  strongest targeted improvement is the CVE-2021-42373 vulnerable TP, but its
  patched control became an FP.
- CVE-2017-15873 remains blocked by a repeated stream-completion failure,
  CVE-2021-42374 remains unresolved and audit-pending, and CVE-2021-42386
  remains a vulnerable-case FN despite richer package facts and a larger tool
  budget.
- No end-to-end Tier A → Tier B performance result exists because the cascade
  has not been executed.

## Detailed reports

- [Tier A low/mixed versus high comparison](tier-a/comparisons/2026-07-18__gpt-5-6-sol__mixed-recovered__vs__2026-07-20t111012z__gpt-5-6-sol__high__high-4500-usd10-streaming/README.md)
- [Tier B v3 four-pair follow-on](tier-b/matrix-summaries/2026-07-23__busybox-four-pair-follow-on__tier-b-v3.md)
- [Tier B v4 remediation subset](tier-b/matrix-summaries/2026-07-23__busybox-remediation-subset__tier-b-v4.md)
- [Tier B v5 targeted follow-up](tier-b/matrix-summaries/2026-07-23__busybox-targeted-follow-up__tier-b-v5.md)
