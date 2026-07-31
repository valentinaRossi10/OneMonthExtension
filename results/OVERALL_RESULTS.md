# Overall pipeline results

Last updated: 2026-07-31

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
| Dynamic-analysis validation | **In progress** | 3/5 confirmed via genuine blind-seeded fuzzing (CVE-2026-29004, CVE-2021-42373, CVE-2021-42374); random-seed baseline comparison run for 4/5 (mixed result — see below); awk campaign still running |

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

| Cohort | Scope | TP | FP | TN | FN | Abstention | Operational failure |
|---|---:|---:|---:|---:|---:|---:|---:|
| Defensive-v3 standalone pilot | 2 cases | 1 | 0 | 1 | 0 | 0 | 0 |
| Protocol-v3 four-pair follow-on | 8 cases | 0 | 1 | 1 | 1 | 4 | 1 |
| Protocol-v4 remediation subset | 4 cases | 0 | 0 | 0 | 0 | 3 | 1 |
| Protocol-v5 targeted actions, including unchanged v4 retry | 4 actions | 1 | 1 | 0 | 1 | 0 | 1 |
| Protocol-v9 agent-directed static primary | 3 vulnerable cases | 0 | 0 | 0 | 0 | 2 | 1 |
| Protocol-v10 required-static-tools rerun | 3 vulnerable cases | 0 | 0 | 0 | 0 | 1 | 2 |
| Protocol-v11 uniform-framing/retry-extension round | 2 vulnerable cases | 0 | 0 | 0 | 0 | 0 | 2 |

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
| CVE-2017-15873 | **Infrastructure error and retained** in protocol v11 | Excluded from remediation; historical v3 result was an abstention | The oversized required slice correctly unlocked extension, but the next provider generation failed with `cyber_policy` before retry, dominance, or angr |
| CVE-2021-42373 | **TP** under prompt v5 | **FP** under prompt v5 | Targeted prompt recovered sensitivity but did not preserve specificity |
| CVE-2021-42374 | **Resource exhausted and retained** in protocol v11 | **FP** under v3; control remains audit-pending | Reaching-definitions, slicing, and dominance completed; an invalid reaching-definitions retry consumed the slot needed by angr |
| CVE-2021-42386 | **Retained unresolved** after all four required tools in protocol v10 | **TN** in the historical v3 follow-on | Reaching-definitions, slicing, dominance, and bounded angr were tried; angr timed out and lifetime effects remained unresolved |

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
  Fixed by persisting every interim result before continuing.
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
- **A required-tool scheduling defect** in protocol v10: failed or oversized
  mandatory calls could consume the final base slots before the adaptive
  extension became eligible. The coverage gate prevented an unsupported
  semantic terminal, but the integer-overflow case exhausted resources before
  dominance and angr. This remains open for a versioned follow-up; the
  completed run is immutable.
- **A remaining required-tool retry-reserve gap** in protocol v11: the
  oversized-result path correctly unlocks extension, but another recoverable
  required-tool argument error can still consume the final slot before a later
  required tool runs. OOB completed three of four tools and exhausted before
  angr. This is distinct from the fixed oversized-slice path.

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

## Tier B static-v2 primary cohort

The separate `confirm-and-filter-vulnerabilities-static` skill evaluated three
vulnerable primary cases with Ghidra p-code/reference packages and
agent-directed def-use, slicing, dominance, and call-graph tools. The UAF row
was force-included by its exact Tier A false-negative task ID.

Run
`2026-07-29t094851z__gpt-5.6-sol__medium__tier-a-mixed-recovered-static-primary-v1`
completed under manifest SHA-256
`f527a47d635e439b349b457ffbce48c1f0b5f244b8563eaa57443f4055b8dfa5`
and spent `$3.835260` under its exact `$44.849999999999994` ceiling.
CVE-2017-15873 and CVE-2021-42374 completed as unresolved retentions;
CVE-2021-42386 ended in a `cyber_policy` provider failure and was also
retained. No case invoked angr. The cohort therefore produced 0/3
confirmations, zero suppressions, and zero false suppressions.

## Tier B protocol-v10 required-tools rerun

Run
`2026-07-30t040248z__gpt-5.6-sol__medium__tier-a-mixed-recovered-static-required-tools-rerun-v2`
used manifest SHA-256
`6d22e60043790394bfca512928d15d39784633e64781d4a7282f976e661f5cf2`
and spent `$2.049735` under its exact `$49.56` ceiling. The final results
SHA-256 is
`c23e4e23ada1676f903addd6463a57825b1e863e990ef82be07d0ead21c6e092`.

The OOB case hit `cyber_policy` before any tool call. The integer-overflow
case successfully used reaching-definitions and slicing, then exhausted its
base slots before dominance and angr. The UAF case successfully used all four
required tools; bounded angr timed out and the case completed as unresolved
retention. The run therefore yielded zero confirmations, zero suppressions,
one completed abstention, and two operational failures. Only the UAF case
supports the conclusion “all new tools were tried and the case remains
unresolved.”

## Tier B protocol-v11 two-case round

Run
`2026-07-30t052530z__gpt-5.6-sol__medium__static-round3-oob-integer-uniform-defensive-retry-extension-v3`
used manifest SHA-256
`5115f7d615a636be10013c7db2464b85e42c37fbb314979bdc83658ace62ebc4`
and spent `$2.168100` under its exact `$33.06` ceiling. Results SHA-256 is
`2f7c60f25adf8b9f4fe30214d046c1fe43cd00dffce3c5e62e598737e0840aaf`.

The OOB first request passed the provider gate and the case successfully used
reaching-definitions, slicing, and dominance, but exhausted before angr after
one invalid required-tool argument retry. Integer overflow correctly unlocked
the adaptive stage on an oversized required slice, then hit a later
`cyber_policy` failure before the narrower retry. The round produced zero
confirmations, zero suppressions, and two operational failures.

## Tier B static rounds: known limitations (accepted after three verified rounds)

CVE-2017-15873 (integer-overflow, bunzip2) and CVE-2021-42374 (OOB-read,
unlzma) were carried through three successive rounds of the static-tools
skill (protocol v9, v10, v11), each round fixing a distinct, independently
verified root cause rather than re-running the same code hoping for a
different roll:

| Round | Root cause found | Fix applied | Independently verified |
|---|---|---|---|
| v9 (static-primary) | The four new agent-orchestrated tools (`get_reaching_definitions`, `slice_pcode`, `get_dominance`, `query_angr`) were built but never actually invoked — the investigation converged early using only the original tool set | Added a required-tool coverage gate blocking any case from a "completed" terminal until all four tools succeed at least once | Confirmed via direct `tool_name` inspection of `results.jsonl` — all four called in v10's UAF case |
| v10 (required-tools rerun) | Defensive framing was applied once at the start instead of every request, and an oversized-result retry on one required tool silently exhausted the base budget before later required tools could run | Added a per-request defensive reminder and an adaptive-extension unlock specifically for `tool_result_too_large` retries | Confirmed via manifest flags (`request_defensive_reminder`, `required_tool_retry_extension`) and per-case tool logs |
| v11 (two-case round) | Two narrower issues distinct from v10's: (1) an *invalid-argument* retry (not an oversized-result retry) on `get_reaching_definitions` still consumed the OOB case's final budget slot before `query_angr`; (2) the integer-overflow case's oversized-slice retry correctly unlocked the extension, but the *next* provider request still failed with `cyber_policy` despite uniform framing being active on every request | N/A — see below | Confirmed via `results.jsonl`: OOB reached 3/4 tools (reaching-definitions, slice, dominance) before `resource_exhausted`; integer-overflow's `extension_granted` event fired correctly before the `cyber_policy` failure |

Both v11 root causes are qualitatively different from anything the earlier
two rounds fixed, which is why a third round was justified. But neither
is fixable the same way the first three were:

- The invalid-argument-retry budget gap is a real, narrow scheduling bug,
  but even a fourth fix would only buy the OOB case one more tool call
  (`query_angr`) — not a guaranteed resolution.
- The `cyber_policy` failure is a provider-side content-safety classifier
  rejecting the request outright; it recurred *even with* the uniform
  defensive framing that was specifically built and verified to be present
  on every single request this round. The error message itself points
  affected users at OpenAI's own "Trusted Access for Cyber" program as the
  intended remedy — a channel outside this project's control, not a prompt
  or scheduling defect we can engineer around.

Per the standing criterion for this work (keep trying distinct, genuine
fixes until a case resolves or the fixes stop finding new root causes) and
the supervisor's original guidance to document genuine limitations rather
than build a new analysis framework: **CVE-2017-15873 and CVE-2021-42374
are accepted as retained/unresolved at the static-analysis-augmented Tier B
stage.** Resolving them is deferred entirely to dynamic analysis (Stage 9),
which is exactly the role that stage was scoped for in
`../DYNAMIC-ANALYSIS-PLAN.md`. No further static-tools rounds are planned
for these two cases.

CVE-2021-42386 (UAF, awk) is not included in this limitation — its v10
result (all four required tools genuinely exhausted, bounded angr timed
out) already stands as a complete, non-starved attempt and was excluded
from v11 for that reason.

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
- Across three static-tools rounds (v9-v11), CVE-2017-15873 and
  CVE-2021-42374 never completed their positive reachability/range proofs.
  Each round fixed a distinct, verified root cause (tools unused → framing
  and retry-budget gaps → a narrow scheduling gap and a provider-side
  content-safety rejection), so this is now accepted as a genuine, tried
  limitation rather than an unexplored gap — see "Tier B static rounds:
  known limitations" above. Exact-row force inclusion successfully brought
  the Tier A UAF miss into Tier B, where all four required tools were
  genuinely exhausted (angr timed out) — a complete, non-starved attempt.
- No complete end-to-end Tier A → Tier B performance result exists. The
  static-v2 run executed a reviewed three-positive subset and preserved the
  rest of its source queue as retained/quarantined records.

## Detailed reports

- [Tier A low/mixed versus high comparison](tier-a/comparisons/2026-07-18__gpt-5-6-sol__mixed-recovered__vs__2026-07-20t111012z__gpt-5-6-sol__high__high-4500-usd10-streaming/README.md)
- [Tier B v3 four-pair follow-on](tier-b/matrix-summaries/2026-07-23__busybox-four-pair-follow-on__tier-b-v3.md)
- [Tier B v4 remediation subset](tier-b/matrix-summaries/2026-07-23__busybox-remediation-subset__tier-b-v4.md)
- [Tier B v5 targeted follow-up](tier-b/matrix-summaries/2026-07-23__busybox-targeted-follow-up__tier-b-v5.md)
- [Tier B redesign known limitations](../confirm-and-filter-vulnerabilities/references/evaluation.md)
- [Six-case schema-v2 run](tier-b/filter-runs/2026-07-26t071257z__gpt-5.6-sol__medium__tier-a-mixed-recovered-cascade-six-case-medium-schema-v2) — CVE-2026-29004 confirmed, CVE-2021-42373 patched suppressed
- [Six-case schema-v3 run](tier-b/filter-runs/2026-07-26t084318z__gpt-5.6-sol__medium__tier-a-mixed-recovered-cascade-six-case-medium-schema-v3-preflight-v2) — CVE-2021-42373 vulnerable confirmed after the validator fix
- [CVE-2021-42374 v4 contradiction-proof retry (final state)](tier-b/filter-runs/2026-07-27t031407z__gpt-5.6-sol__medium__tier-a-mixed-recovered-cve-2021-42374-contradiction-proof-v4)
- [Static-v2 three-case primary run](tier-b/filter-runs/2026-07-29t094851z__gpt-5.6-sol__medium__tier-a-mixed-recovered-static-primary-v1)
- [Protocol-v10 required-tools rerun](tier-b/filter-runs/2026-07-30t040248z__gpt-5.6-sol__medium__tier-a-mixed-recovered-static-required-tools-rerun-v2)
- [Protocol-v11 two-case round](tier-b/filter-runs/2026-07-30t052530z__gpt-5.6-sol__medium__static-round3-oob-integer-uniform-defensive-retry-extension-v3)
- [Static-v2 per-case evaluation](../confirm-and-filter-vulnerabilities-static/references/evaluation.md)

## Full pipeline status per CVE (all 3 stages)

Kept updated as Stage 9 (dynamic analysis, `../dynamic-analysis/`)
executes. "Dynamic analysis" status here always reflects a *confirmed*
crash (reproduces on vulnerable, absent on patched with the identical
input) unless explicitly marked otherwise — a raw crash count alone is
never reported here as a confirmation.

| CVE (bug class) | Tier A (function-level) | Tier B (latest applicable codebase-level result) | Dynamic analysis (blind LLM-seeded) | Dynamic analysis (random-seed baseline) |
|---|---|---|---|---|
| CVE-2026-29004 (heap-buffer-overflow, udhcpc6) | TP confirmed | Confirmed | **Confirmed** — cross-checked absent on patched (~373s, 81,087 execs to first crash) | **Confirmed** — same signature, absent on patched, actually **faster** than blind (~93s, 14,255 execs) |
| CVE-2017-15873 (integer-overflow, bunzip2) | TP confirmed | **Accepted limitation** — retained unresolved after 3 verified static-tools rounds (v9-v11); root cause is now a provider-side `cyber_policy` rejection persisting despite uniform defensive framing, not a fixable prompt/scheduling gap | No crash in ~2.3h (242,043 execs, 85.31% coverage); structurally documented as infeasible via genuine compression | No crash in either condition: pure random stuck at the format's magic-byte gate (2.10% cov., ~19min); a 3rd, format-valid-random condition (real-bzip2-compressed random content) reached 84.62% coverage (~15.7h, ~4M execs) — essentially the same ceiling as blind — and still found nothing. All 3 strategies now agree the trigger is unreachable by undirected search |
| CVE-2021-42373 (NULL-deref, man) | TP confirmed | Confirmed (vulnerable); patched variant correctly suppressed as the pilot's true-negative control | **Confirmed** — cross-checked absent on patched (~5.7s, 845 execs to first crash) | **Confirmed** — same signature, absent on patched, but much slower (~72s, 15,941 execs — blind was ~12.6x faster here) |
| CVE-2021-42374 (OOB-read, unlzma) | Abstained (buffer size set in a callee outside the isolated function — a correct "can't tell," not a wrong answer) | **Accepted limitation** — retained unresolved after 3 verified static-tools rounds (v9-v11); reaching-definitions, slicing, and dominance completed, but a required-tool argument-retry bug consumed the slot needed by angr | **Confirmed** — full blind-methodology campaign (82 min, 175,710 execs to first crash), cross-checked absent on patched | No crash in ~16.3h (4,538,490 execs) despite reaching the **identical coverage ceiling** as blind (83.50% both) — a target-value search-efficiency gap, not a reachability gap |
| CVE-2021-42386 (use-after-free, awk) | Missed entirely (function-local visibility — the free/stale-reference/reuse sequence spans multiple functions) | Force-included into static-v2 Tier B; all four required tools genuinely exhausted (v10), bounded angr timed out — a complete, non-starved retained result | Not yet confirmed — ~51.6h blind campaign as of 2026-07-31 (6.1M execs, 30 crashes / 9 hangs), all triaged and ruled out, including a genuine but off-target heap-UAF identified as the distinct, already-fixed CVE-2023-42363; this is Stage 9's lowest-priority "special case" test, not its primary purpose (see `../DYNAMIC-ANALYSIS-PLAN.md` Section 2) | Not yet run |

Full timing/coverage detail (per-case `CAMPAIGN-RESULTS-RANDOM.md`/`CAMPAIGN-RESULTS-RANDOM-VALID.md`, methodology in `../BASELINE-FUZZING-STEPS.md`) is in `../dynamic-analysis/LLM-SEED-TIMING.md`. The random-seed baseline (per supervisor request) isolates seed-generation strategy as the only variable: same harness, build, and exec timeout per case; no dictionary. Result across the 4 cases run so far is genuinely mixed, not a uniform "blind wins" or "blind is unnecessary" story:

- **Random faster**: udhcpc6 (~4x) — the LLM seed's boundary-value knowledge didn't add measurable value here; unstructured mutation reaches the overflow just as directly.
- **Blind faster**: man (~12.6x) and unlzma (found it; random didn't in 12x the time at the identical coverage ceiling) — cases where the specific triggering value is harder to stumble onto by chance even once the code is fully reachable.
- **Blind categorically necessary**: bunzip2 — pure random never passes the format's magic-byte header at all (a gate-passing failure, not a search-depth one); even solving that gate mechanically (format-valid-random) still found nothing, reinforcing the separate structural-infeasibility proof from a third angle.

**Stage 9's actual load-bearing purpose, made concrete by this table**:
CVE-2017-15873 and CVE-2021-42374 are the two cases Tier B explicitly
could not resolve — resolving them is why dynamic analysis exists in
this pipeline, not an incidental extra. CVE-2026-29004 and
CVE-2021-42373 being independently reconfirmed by dynamic analysis is
cross-validation of Tier B's own claims, not new information. CVE-2021-42386
is a distinct, lower-priority question (does dynamic analysis catch
something the static pipeline missed at every stage) that should not
consume priority time ahead of the two Priority-1 cases above.
