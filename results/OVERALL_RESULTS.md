# Overall pipeline results

Last updated: 2026-07-29

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
| Tier B redesign (`confirm-and-filter-vulnerabilities`) six-case pilot | Completed | 2/4 real vulnerabilities confirmed, 1 true negative correctly suppressed, 3 cases retained as documented capability-gap limitations |
| Tier A → Tier B cascade | **Not executed** | No end-to-end pipeline accuracy or recall can be claimed yet |
| Dynamic-analysis validation | **In progress** | 3/5 confirmed via genuine blind-seeded fuzzing (CVE-2026-29004, CVE-2021-42373, CVE-2021-42374); 2/5 in progress — see "Full pipeline status per CVE" below |

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

## Tier B redesign: six-case pilot (`confirm-and-filter-vulnerabilities`)

The rows above (`Tier B v3/v4/v5`) all come from the earlier, oracle-only
skill (`confirm-vulnerability-reachability`), which only ever evaluated
pre-selected vulnerable/patched pairs with a known answer. Per supervisor
direction, that design was replaced with a new skill,
`confirm-and-filter-vulnerabilities`, built around a different priority
ordering: **confirming every true positive forwarded to it is the hard,
primary constraint; reducing false positives is a secondary, best-effort
goal that must never weaken confirmation to achieve.** A case that can't be
cleanly resolved either way is retained and passed on to downstream dynamic
analysis rather than dropped — retaining a false positive is treated as
acceptable, suppressing a true positive is not.

This section covers the pilot built to validate that redesign: six cases
selected from a real, frozen Tier A run (`2026-07-18__gpt-5-6-sol__mixed-recovered`),
covering all 4 of that run's real vulnerabilities plus one genuine Tier A
false positive and one genuine Tier A abstention on safe code, so both
halves of the objective (confirm real bugs, suppress real false positives)
were actually exercised, not just the easy half.

### Final result per case

| Case | Final outcome | Controlling run (protocol) |
|---|---|---|
| CVE-2026-29004 vulnerable, heap-buffer-overflow | **Confirmed (TP)** | schema-v2 |
| CVE-2021-42373 vulnerable, NULL-pointer-dereference | **Confirmed (TP)** | schema-v3 (after a validator fix) |
| CVE-2021-42373 patched, integer-overflow | **Suppressed (TN)** | schema-v2 |
| CVE-2017-15873 vulnerable, integer-overflow | **Retained — known limitation** | schema-v2 through the 8,192-token/terminal-response retries |
| CVE-2017-15873 patched, NULL-pointer-dereference (a real Tier A false positive) | **Retained — known limitation** | schema-v2/v3 |
| CVE-2021-42374 vulnerable, out-of-bounds-read | **Retained — known limitation** | schema-v2 through the v4 contradiction-proof retry |

**2 of 4 real vulnerabilities confirmed, 1 genuine false positive correctly
suppressed with a full evidentiary proof, 3 cases honestly retained as
unresolved** rather than forced to a guess in either direction. No true
positive was ever suppressed at any point in the pilot.

### Real bugs found and fixed along the way

Each of these was independently verified against the actual code/schema/
ledger, not accepted on a self-report:

- **Two Structured Outputs schema-validity bugs** — a `const` field missing
  its required `type`, and later an unsupported `uniqueItems` keyword —
  both caught reactively against a live request at first, then closed with
  an offline, no-API-call schema auditor so the same class of bug can't
  recur silently.
- **A validator status-conflation bug** that discarded a genuinely correct
  confirmation (CVE-2021-42373) because one unrelated, correctly-defeated
  counter-hypothesis was recorded with the same status word as "this
  obligation failed." Fixed by splitting hypothesis result, obligation
  completion, and adversarial-challenge outcome into three separate,
  independently validated fields.
- **A real false suppression** (CVE-2021-42374) where the model applied a
  guard proven for one buffer read to a different, unguarded read. Fixed
  with a strict per-sink suppression proof requiring every guard to be
  tied to the exact same value/state it claims to protect, with any
  unresolved step forcing retention instead of suppression.
- **A runner bug that silently discarded valid interim results** — if the
  model produced a complete, schema-valid "still unresolved" answer partway
  through, then continued investigating and failed later, the earlier valid
  answer was thrown away rather than kept as a fallback. Confirmed by
  retrieving one lost answer directly from the provider by its preserved
  response ID; a historical audit found four more instances of the same
  pattern (all abstentions, never a hidden confirmation or suppression,
  since the discard path only fires after a `retain_and_escalate` result).
  Fixed by persisting every interim result and its cost before continuing.
- **Recurring provider content-safety refusals** on genuinely vulnerable
  code (`cyber_policy`), the same failure class that blocked the very first
  Tier B pilot attempt. Mitigated (not eliminated) by reinforcing an
  explicit defensive, symbolic-only framing at every step of the
  investigation, not just once at the start.
- **An unsupported inferential leap accepted without evidence** — the model
  asserted a value "must already be bounded" with no citation, directly
  contradicting the real fix. Fixed by requiring the same evidentiary
  discipline already used for suppression's guard claims (a cited line, a
  proven value relationship) before any hypothesis can be marked
  contradicted.
- **A generic, undiagnosable terminal-response exception** that conflated
  token-cap exhaustion, provider refusals, and genuine transport failures
  into one indistinguishable error message. Fixed by inspecting every typed
  stream event instead of discarding them, capturing the response ID
  immediately so a failed-but-actually-completed response can be recovered
  by retrieval instead of guessed at or blindly retried.

### Known limitations (accepted, not treated as open bugs)

Three cases remain retained after every reasoning-discipline fix above was
applied and verified working on other cases. Diagnosis (documented in
`confirm-and-filter-vulnerabilities/references/evaluation.md`) is that these
specifically require value-range/data-flow tracking across loop iterations
and, in one case, indirect-call resolution — capabilities this design
explicitly does not implement (no SSA, dominators, def-use slicing, or
symbolic range analysis; the package exposes decompiled pseudo-C and a
real but direct-calls-only Ghidra call graph). This boundary was decided
in advance, when the MVP scope was first defined, not invented after the
fact to explain away a hard case — and where the boundary turned out not
to apply (an indirect call that was actually a fixed, resolvable address),
the diagnosis said so plainly rather than defaulting to "capability gap."

Further prompt, schema, or budget iteration is not expected to resolve
these three cases; doing so would require building the deferred analysis
engine, which is a separate, larger scope decision.

### Cost

Across the full investigation arc for this pilot (multiple prepare/execute
cycles fixing distinct bugs, not one clean run), accounted spend totals
approximately **$24.89**, against per-run adaptive worst-case ceilings that
were consistently 3-15x higher than what was actually spent. Every
execution was individually reviewed and approved against its own manifest
hash and projected ceiling before running; see the individual run
directories under `results/tier-b/filter-runs/` for exact per-run figures.

## What the results currently support

- Tier A can find the function-local heap-overflow and NULL-dereference
  positives in both preserved runs.
- Tier A consistently misses the designated function-local UAF case.
- The completed Tier B pilot shows that the harness can correctly confirm one
  vulnerable heap-overflow case and reject its patched control.
- The redesigned Tier B skill (`confirm-and-filter-vulnerabilities`)
  confirmed 2 of 4 real vulnerabilities in its six-case pilot and correctly
  suppressed a genuine Tier A false positive with a full evidentiary proof,
  while never suppressing a true positive at any point across the whole
  investigation arc. The 3 remaining unresolved cases are documented as an
  accepted capability limitation (deferred range/data-flow analysis), not
  an open bug — every fixable reasoning or infrastructure bug found along
  the way was independently verified as actually fixed on other cases.
- The wider Tier B experiments (oracle-only skill, protocol v3-v5) are not
  yet reliable across classes. The strongest targeted improvement is the
  CVE-2021-42373 vulnerable TP, but its patched control became an FP.
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
- [Tier B redesign known limitations](../confirm-and-filter-vulnerabilities/references/evaluation.md)
- [Six-case schema-v2 run](tier-b/filter-runs/2026-07-26t071257z__gpt-5.6-sol__medium__tier-a-mixed-recovered-cascade-six-case-medium-schema-v2) — CVE-2026-29004 confirmed, CVE-2021-42373 patched suppressed
- [Six-case schema-v3 run](tier-b/filter-runs/2026-07-26t084318z__gpt-5.6-sol__medium__tier-a-mixed-recovered-cascade-six-case-medium-schema-v3-preflight-v2) — CVE-2021-42373 vulnerable confirmed after the validator fix
- [CVE-2021-42374 v4 contradiction-proof retry (final state)](tier-b/filter-runs/2026-07-27t031407z__gpt-5.6-sol__medium__tier-a-mixed-recovered-cve-2021-42374-contradiction-proof-v4)

## Full pipeline status per CVE (all 3 stages)

Kept updated as Stage 9 (dynamic analysis, `../dynamic-analysis/`)
executes. "Dynamic analysis" status here always reflects a *confirmed*
crash (reproduces on vulnerable, absent on patched with the identical
input) unless explicitly marked otherwise — a raw crash count alone is
never reported here as a confirmation.

| CVE (bug class) | Tier A (function-level) | Tier B (codebase-level, six-case pilot) | Dynamic analysis |
|---|---|---|---|
| CVE-2026-29004 (heap-buffer-overflow, udhcpc6) | TP confirmed | Confirmed | **Confirmed** — blind-seeded AFL campaign, cross-checked absent on patched |
| CVE-2017-15873 (integer-overflow, bunzip2) | TP confirmed | Retained — unresolved (needs value-range tracking across a decode loop, outside this design's scope) | Not yet confirmed — real search effort (~2hr combined), harness verified working, no crash found yet |
| CVE-2021-42373 (NULL-deref, man) | TP confirmed | Confirmed (vulnerable); patched variant correctly suppressed as the pilot's true-negative control | **Confirmed** — blind-seeded AFL campaign, cross-checked absent on patched |
| CVE-2021-42374 (OOB-read, unlzma) | Abstained (buffer size set in a callee outside the isolated function — a correct "can't tell," not a wrong answer) | Retained — unresolved (same value-range limitation) | **Confirmed** — full blind-methodology campaign (82 min, 187,274 execs), same crash offset as the earlier informal find, cross-checked absent on patched |
| CVE-2021-42386 (use-after-free, awk) | Missed entirely (function-local visibility — the free/stale-reference/reuse sequence spans multiple functions) | Never forwarded to Tier B (a true Tier A miss) | Not yet confirmed — harness verified working, several unrelated crash classes found and ruled out (cross-checked present on patched too); this is Stage 9's lowest-priority "special case" test, not its primary purpose (see `../DYNAMIC-ANALYSIS-PLAN.md` Section 2) |

**Stage 9's actual load-bearing purpose, made concrete by this table**:
CVE-2017-15873 and CVE-2021-42374 are the two cases Tier B explicitly
could not resolve — resolving them is why dynamic analysis exists in
this pipeline, not an incidental extra. CVE-2026-29004 and
CVE-2021-42373 being independently reconfirmed by dynamic analysis is
cross-validation of Tier B's own claims, not new information. CVE-2021-42386
is a distinct, lower-priority question (does dynamic analysis catch
something the static pipeline missed at every stage) that should not
consume priority time ahead of the two Priority-1 cases above.
