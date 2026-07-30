# Experimental protocol

Protocol version: `experiment-protocol-v9-agent-directed-static-analysis`.

This document is the canonical definition of the experiment. `PIPELINE.md`
explains the design rationale, and `LOG.md` records implementation status
(Part 1) and preserves chronology (Part 2). If an implementation or result is interpreted
differently from this protocol, the discrepancy must be documented and the
protocol or implementation versioned before another run.

## Research questions

The static-analysis evaluation has three distinct questions. They must not be
collapsed into one score.

1. **Tier A — strict function-local classification:** Can the model identify a
   class-consistent vulnerability pattern from one isolated decompiled
   function while remaining quiet on other classes and patched code?
2. **Tier B — oracle-candidate confirmation:** When given a known candidate,
   one specific entry point, and whole-codebase context, can the model confirm
   or reject the vulnerability independently of Tier A selection?
3. **Tier A → Tier B cascade:** When Tier B receives only cases forwarded by
   Tier A, what recall, false-positive filtering, and analysis workload does
   the combined static pipeline achieve?

Dynamic analysis is a later fourth stage. It validates Tier B confirmations;
it is not part of the current static benchmark.

## Tier A: strict isolated-function experiment

### Unit of analysis and input visibility

One Tier A task contains exactly one function and one target vulnerability
class. The primary representation is stripped-binary Ghidra pseudo-C;
function-only LLVM IR is the fallback when pseudo-C cannot represent the
indexed function.

The model may see the normalized function, representation name, target class,
class rubric, and output schema. It must not see:

- CVE ID, project/sample identity, vulnerable/patched label, or expected label;
- the historical indexed class or CVE description;
- source path, paired variant, callers, callees, or other codebase context; or
- reachability, attacker-control, or exploitability ground truth.

Reliable standard-library names may be interpreted locally. Opaque callees,
caller preconditions, and cross-function behavior must not be invented.

### Task matrix and labels

The current benchmark has 5 samples × 2 variants × 6 target classes = 60
tasks. The six classes are heap buffer overflow, use-after-free, integer
overflow, NULL pointer dereference, out-of-bounds read, and command injection.

`samples/index.csv` defines one verified historical class per sample. A task is
an expected positive only when it uses the vulnerable variant and tests the
sample's indexed class. The other 55 tasks are benchmark-negatives. A
mismatched-class positive is therefore a false positive *relative to the
benchmark label*; it is not proof that the function has no secondary weakness.

### Verdict meaning and strict scoring

- `vulnerable`: the isolated function supplies a concrete, feasible,
  class-consistent local pattern.
- `not_vulnerable`: the requested local pattern is not supported by the
  displayed function.
- `indeterminate`: the displayed function cannot establish or exclude the
  requested pattern without missing context.

`indeterminate` is scored as an abstention with no correctness credit. It is
not silently converted to either a positive or a negative. Refusals, invalid
outputs, API errors, missing results, and guarded/unavailable inputs remain
separate failure categories.

Tier A intentionally remains strict because false-positive control is part of
the research question. Tier B does not justify retroactively counting an
abstention as a Tier A true positive.

### Known interpretation cases

- **CVE-2021-42374 out-of-bounds read:** the vulnerable function exposes a
  suspicious index adjustment and subsequent read, but the completed run did
  not locally establish the opaque allocation's readable extent. Its
  `indeterminate` verdict remains a Tier A abstention and is forwarded for
  contextual confirmation. In policy-v8, the same frozen task did not return
  a completed response and is therefore scored as `api_error`, not as a new
  verdict. This operational transition from abstention to API error supplies
  no evidence that high reasoning resolved the underlying ambiguity or would
  have classified the function differently.
- **CVE-2021-42386 use-after-free:** the isolated `nvalloc` body contains
  neither the complete free/stale-alias/use sequence nor enough local evidence
  to flag it. This is a designated function-local observability limitation,
  reported separately rather than hidden inside aggregate recall.

### Tier A metrics

Report TP, FN, TN, FP, abstentions, explicit failure statuses, decision
coverage, recall, observable-positive recall, precision, specificity,
false-positive rate, F1, balanced accuracy, strict accuracy, per-class
metrics, per-representation metrics, and vulnerable/patched transitions.

Because the full cross-product contains 55 benchmark-negatives and only 5
positives, raw accuracy alone is not an adequate headline result.

## Handoff policy: scoring is separate from escalation

The operational handoff rule is deliberately broader than the Tier A positive
verdict:

- forward `vulnerable` tasks to Tier B;
- forward `indeterminate` tasks to Tier B for missing-context resolution; and
- do not forward `not_vulnerable` tasks in the basic cascade simulation.

Forwarding an abstention does not change its Tier A score. This separation
keeps the classifier strict while preventing a suspicious but context-limited
case such as the OOB read from being silently dropped.

For the completed recovered run, this rule forwards 24 of 60 task-class
combinations (40% workload), including 4 of 5 historical positives and all 4
function-locally observable positives. These are descriptive results of that
specific mixed-configuration run, not fixed expectations for future models.
Candidate counts should also be reported after deduplicating repeated
function/variant pairs, because Tier B may analyze one function for multiple
forwarded classes in a single contextual session.

The UAF case remains absent from the basic Tier A-selected queue because its
Tier A verdict was negative. This is precisely why Tier B must first be
evaluated independently with oracle candidates before the cascade is assessed.

## Tier B: oracle-candidate confirmation experiment

### Purpose

Tier B measures contextual confirmation, not unknown-vulnerability discovery
and not Tier A's candidate-selection ability. Its first evaluation therefore
uses ground-truth candidates independently of Tier A output.

### Unit of analysis and model-visible input

Each Tier B case fixes:

- one candidate function and requested vulnerability class;
- one specific entry point;
- whole-codebase context sufficient to inspect relevant callers, callees,
  guards, object contracts, and data/control flow; and
- one variant, vulnerable or patched.

The model is told where to start because this is a confirmation task. It must
not receive the expected label, CVE description, paired variant/diff, manual
ground-truth path, or exploitability conclusion. Manual analysis is used only
to construct and score the case.

### Completed single-pair pilot

The completed Tier B development pilot is one standalone BusyBox evaluation
for CVE-2026-29004 only. It contains exactly two cases: the fixed
candidate and entry point in the vulnerable package, plus the corresponding
patched control. The exact commits have already been built into complete,
neutral-ID Tier B packages. No other BusyBox candidate pair is in scope for
this pilot, and this pilot is not partial progress toward reporting the full
oracle matrix.

Run
`2026-07-21t094500z__gpt-5-6-sol__high__busybox-cve-2026-29004-oracle-neutral`
is retained as a failed pilot diagnostic, not as a successful or representative
Tier B result. Earlier attempts exposed a harness defect that replayed the
SDK-only `parsed_arguments` field and received HTTP 400 responses. After that
defect was bypassed, both cases followed relevant call paths but exhausted the
seven-tool/eight-model-call per-case budget and ended as `tool_limit`. The
ledger closed under its USD ceiling, but 0 of 2 cases produced a scorable JSON
verdict; the run therefore confirmed or rejected nothing. It is evidence that
the request replay required repair and the per-case call budgets required
raising.

Run
`2026-07-21t162742z__gpt-5-6-sol__high__busybox-cve-2026-29004-pilot-v2`
verified the repaired request replay and raised limits of at most 10 tool calls
and 11 model calls per case, with the last model call reserved for a
tool-disabled schema-only conclusion. The patched case produced a valid
`rejected` verdict. The vulnerable case followed a relevant seven-tool path but
the provider stopped model call 8 with a cybersecurity content-policy error.
That run therefore produced 1 of 2 scorable verdicts and is not a complete
two-case pilot result.

Run
`2026-07-22t012045z__gpt-5-6-sol__high__busybox-cve-2026-29004-pilot-defensive-v3`
used `tier-b-prompt-v3`, which states the authorized defensive, static-only
purpose explicitly and excludes exploit construction, payloads, weaponization,
execution instructions, and real-world action. It preserved the fixed
candidate, class, entry point, evidence rules, verdict meanings, output schema,
and evaluator-information boundary. Both cases produced scorable verdicts: the
vulnerable case was `confirmed` and the patched control was `rejected`, with no
abstention or execution failure. The run spent an accounted USD 1.27478 under
its independently approved USD 10 ceiling. This completed pilot demonstrates
that the Tier B harness and defensive prompt can complete this one pair; it is
not a result from, or partial substitute for, the full oracle matrix.

### Separately prepared oracle-candidate follow-on

Five BusyBox candidate pairs were prepared independently of Tier A with both
vulnerable and patched controls. Preparation made no provider calls. Paid
execution was subsequently approved and completed for only the four pairs
other than CVE-2026-29004: 4 candidate pairs, 8 cases, each under its own
immutable run ID, manifest SHA-256, and USD 10 ceiling. The separately
prepared CVE-2026-29004 matrix run remains unexecuted; its completed standalone
pilot remains a separate result and is not folded into this follow-on.

Because `tier-b-policy-v3` caps each run at USD 10 and a complete two-case pair
can project close to that ceiling, each pair was prepared as an immutable
two-case run. The approved four runs retain identical model, reasoning, prompt,
schema, policy, pricing, and limits and are reported together as one four-pair
oracle-candidate follow-on. They must not be mixed with the earlier standalone
pilot or described as a completed five-pair matrix.

Running only the five vulnerable cases would measure sensitivity but not
whether Tier B rejects false confirmations. Patched controls are required for
specificity. A specific entry point and reproducible whole-codebase package
are supplied for every case. The complete packages and evaluator-only case
records were revalidated while preparing each immutable manifest. Execution,
scoring, and reporting of the approved four-pair follow-on remain separate from
the CVE-2026-29004 pilot.

The four completed runs spent an accounted USD 4.713065 in aggregate. The
integer-overflow pair produced two `indeterminate` verdicts, and the NULL
pointer dereference pair also produced two `indeterminate` verdicts. For the
out-of-bounds-read pair, the vulnerable case ended in `api_error` because the
stream did not deliver a `response.completed` event, while the patched case
returned `confirmed` and scored as a false positive. For the use-after-free
pair, the vulnerable case returned `rejected` and scored as a false negative,
while the patched case returned `rejected` and scored as a true negative.
Across the eight cases this is four abstentions, one explicit failure, one
false positive, one false negative, and one true negative, with no correct
paired transition. These are follow-on results, not full five-pair matrix
metrics. The versioned cohort report, including per-case diagnostic triage, is
preserved in
[`results/tier-b/matrix-summaries/2026-07-23__busybox-four-pair-follow-on__tier-b-v3.md`](results/tier-b/matrix-summaries/2026-07-23__busybox-four-pair-follow-on__tier-b-v3.md).

### Completed protocol-v4 evaluator-remediation runs

Protocol v4 preserves every historical v3 run and introduces a separately
controlled remediation evaluation. It uses `tier-b-prompt-v4`,
`tier-b-policy-v4`, and neutral `tier-b-package-v2` indexes. Package v2 adds
mechanically extracted indirect-call, address/data-reference, declaration,
string, and memory-operation facts. These facts contain no CVE identity,
variant role, expected verdict, pair diff, manual path, or exploitability
conclusion. Prompt v4 directs candidate-first analysis and defines
class-neutral necessary conditions, including logical release/reuse as a
possible object-lifetime end.

The remediation scope is limited to:

- CVE-2017-15873 vulnerable only, using verified closer entry
  `FUN_00113194`; its patched artifact is excluded because it is not a clean
  negative for the broad integer-overflow class.
- CVE-2021-42373 vulnerable and patched, retaining entry/candidate
  `FUN_00105d3e`; this is the only complete remediation pair.
- CVE-2021-42386 vulnerable only, using verified closer entry
  `FUN_001150ce`; its already-correct patched rejection is not rerun.

CVE-2021-42374 is not repackaged under v4. Its vulnerable transport-error case
remains eligible only for an explicitly approved append-only retry under the
original v3 manifest and remaining ceiling. Its patched control remains
audit-pending and is excluded. Consequently, the three remediation runs must
be reported as one vulnerable-only integer-overflow case, one complete NULL
pointer pair, and one vulnerable-only use-after-free case—not as a complete
four-pair or five-pair matrix.

The four remediation cases completed with three `indeterminate` abstentions
and one stream `api_error`; no case produced a correct decisive verdict.
Aggregate accounted spend was $3.070945 under the approved $30 aggregate
ceiling. The preserved report is
[`results/tier-b/matrix-summaries/2026-07-23__busybox-remediation-subset__tier-b-v4.md`](results/tier-b/matrix-summaries/2026-07-23__busybox-remediation-subset__tier-b-v4.md).

### Protocol-v5 targeted corrections

Protocol v5 versions two different corrections without treating them as one
undifferentiated rerun. `tier-b-prompt-v5` keeps the 10-tool/11-model-call
limits and package v2 for the CVE-2021-42373 pair, but requires sequence-based
NULL analysis to test the shortest feasible non-null prefix and the exact
pointer/index advance. `tier-b-policy-v6` uses package v3 and
12-tool/13-model-call limits for the vulnerable-only CVE-2021-42386 case.
Package v3 adds mechanically derived `call_result_alias_reuse` facts that
report a call result's assignment and later syntactic reuse without claiming
object identity, deallocation, stale lifetime, or vulnerability.

The CVE-2017-15873 infrastructure failure is not changed or repackaged. It
remains eligible only for an explicitly approved append-only retry of the
exact v4 case under its original manifest and cumulative $10 ceiling.

The approved targeted follow-up completed as follows. The unchanged
CVE-2017-15873 retry reproduced the missing-`response.completed` API error.
For CVE-2021-42373, prompt v5 produced a true positive on the vulnerable case
and a false positive on the patched case. The package-v3 CVE-2021-42386
vulnerable case returned `rejected` and remained a false negative. Additional
spend for these actions was $3.222740; current cumulative spend across their
three ledgers is $4.385025. The separate report is
[`results/tier-b/matrix-summaries/2026-07-23__busybox-targeted-follow-up__tier-b-v5.md`](results/tier-b/matrix-summaries/2026-07-23__busybox-targeted-follow-up__tier-b-v5.md).

### Protocol-v6 recall-first filtering MVP

Protocol v6 is a redesign, not an incremental rerun of v4 or v5. Historical
fixed-candidate runs remain immutable. The new operational unit is the actual
Tier A queue, and the safety priority is to avoid silently discarding a
forwarded true positive.

Queue ingestion uses the exact logical key
`(artifact-scoped function UID, normalized target class)`. It never
deduplicates by function UID alone or by address. Exact duplicates from
multiple Tier A prompts, attempts, or runs may be coalesced only after their
artifact identity agrees; the case preserves the union of source evidence and
reasoning and records how many raw rows were coalesced. Missing, ambiguous, or
conflicting bindings are quarantined and retained for escalation rather than
dropped.

The MVP analysis package replaces regex-only call-edge discovery with
mechanical facts from Ghidra's Program Model: analyzed function identities and
content hashes, direct call references, and explicit unresolved indirect-call
sites. It does not claim SSA, dominators, def-use slicing, symbolic range
proofs, indirect-dispatch resolution, or cross-binary function matching.
Those are deferred capabilities with their own future correctness burden.

The three operational dispositions are:

- `retain_confirmed` when the class and contextual path obligations are
  evidenced;
- `suppress_proven_false_positive` only when the complete rejection gate is
  satisfied and no material identity or unresolved-indirect-call uncertainty
  remains; and
- `retain_and_escalate` for every unresolved, refused, failed, ambiguous, or
  resource-exhausted case.

The MVP has no configured second model/provider, deterministic vulnerability
analyzer, or staffed human-review service. When additional escalation
facilities are unavailable, `retain_and_escalate` is the terminal state for
this pass.

Each case starts with at most 12 tool calls and 13 model calls. An adaptive
extension of at most four tool calls and four model calls may be granted only
after mechanically recorded investigation progress, for absolute limits of
16 and 17. Before any paid execution, real packages and prompts must be frozen
and the exact worst-case projection recomputed. The planning envelope at the
frozen reference rates is approximately USD 9.86 per case, USD 49.30 for the
five-positive acceptance set, or USD 98.60 for ten cases; these are design
ceilings, not approval or actual spend.

The only current positive acceptance set is the five reviewed BusyBox CVEs.
A target of 5/5 confirmations with zero true-positive suppressions applies
only to this known set. Meeting it would not establish universal recall,
generalization to unseen CVEs, or held-out performance. No held-out cohort is
available; constructing one is a separate ground-truth project.

The Netgear CVE-2016-6277 case is an additional real-firmware Tier B case with
candidate `netgear_commonCgi`, entry point `parse_http_request`, and expected
path through `handle_get`. Its selected snippets establish ground truth, but
the complete codebase package and Tier B automation are not yet present.

### Protocol-v9 agent-directed static primary cohort

Protocol v9 adds a separate top-level skill,
`confirm-and-filter-vulnerabilities-static`, without changing the original
recall-first skill or its historical runs. Static package v2 preserves the
reviewed Ghidra function layout and adds raw p-code operations, basic blocks,
instruction references, and explicit indirect-call candidates. Read-only
agent tools expose reaching definitions, bounded slices, dominance, call
paths, site-local indirect-call resolution, and optional bounded angr
queries. Function-wide references are candidates only; they cannot resolve a
specific indirect site without site-local evidence.

The first static-primary evaluation froze three vulnerable cases from
`2026-07-18__gpt-5-6-sol__mixed-recovered`: CVE-2017-15873 integer overflow,
CVE-2021-42374 out-of-bounds read, and CVE-2021-42386 use after free. The UAF
row was the one evaluator-reviewed Tier A false negative and was force
included by exact task ID. The override changed eligibility only; it did not
change the Tier A verdict, label, identity, or Tier B proof standard.

Approved run
`2026-07-29t094851z__gpt-5.6-sol__medium__tier-a-mixed-recovered-static-primary-v1`
used manifest SHA-256
`f527a47d635e439b349b457ffbce48c1f0b5f244b8563eaa57443f4055b8dfa5`
and exact aggregate ceiling `44.849999999999994`. It completed with accounted
spend `$3.835260`. The integer-overflow and OOB cases completed as
`unresolved / retain_and_escalate`; the UAF case ended as
`infrastructure_error / retain_and_escalate` after a `cyber_policy` provider
failure and bounded retrieval. No case used angr, no candidate was confirmed,
and no candidate was suppressed.

The three executed evaluator positives therefore have 0/3 confirmation
recall and zero false suppressions. The scoring snapshot additionally
preserves 18 ingestion quarantines outside the deliberately packaged
three-case scope, producing five total unconfirmed positives and 16 surviving
negatives across 21 retained records. Do not report these results as a
complete five-positive acceptance run or full end-to-end cascade.

### Protocol-v10 required-static-tools rerun

The protocol-v9 ledger showed a tool-selection failure:
`get_reaching_definitions` ran once in one case, while `slice_pcode`,
`get_dominance`, and `query_angr` were never invoked. The tools were exposed
and described, but their use was optional and the runner did not block an
early terminal retention when coverage was incomplete.

Protocol v10 keeps the same three reviewed case identities and freezes
`get_reaching_definitions`, `slice_pcode`, `get_dominance`, and `query_angr`
as required for every case. Failed calls and an unavailable angr backend do
not count. An early proposed result is preserved only as nonterminal audit
evidence, and the runner forces missing required tools before the frozen slots
expire. The UAF case receives repeated defensive, symbolic-only framing with
abstract ownership, alias, release, reuse, and dereference terminology.

Prepared run
`2026-07-30t040248z__gpt-5.6-sol__medium__tier-a-mixed-recovered-static-required-tools-rerun-v2`
has manifest SHA-256
`6d22e60043790394bfca512928d15d39784633e64781d4a7282f976e661f5cf2`,
adaptive projection `$49.534110`, and exact aggregate hard ceiling `$49.56`.
Preparation and dry-run validation made zero provider calls. The approved
execution completed with accounted spend `$2.049735` and final results
SHA-256
`c23e4e23ada1676f903addd6463a57825b1e863e990ef82be07d0ead21c6e092`.

Direct `tool_name` audit found that the OOB case failed with `cyber_policy`
before any tool call; the integer-overflow case completed
`get_reaching_definitions` and `slice_pcode` but exhausted its base tool slots
before `get_dominance` and `query_angr`; and the UAF case successfully invoked
all four required tools before completing as unresolved
`retain_and_escalate`. Its bounded angr query timed out, leaving the
failure-handler and incoming-list lifetime states unresolved.

The gate correctly blocked coverage-incomplete semantic retention, but the
run exposed a scheduling defect. Oversized mandatory slice results consumed
retries while the extension remained unavailable until after the base stage,
so the integer case could not use progress-qualified extension slots to finish
coverage. Only the UAF result is a genuine all-four-tools
tried-but-unresolved finding. The other two cases remain operationally
incomplete, and this run does not satisfy the intended three-case tool-coverage
goal.

### Protocol-v11 uniform-framing and retry-extension round

Round 3 contains only the prior CVE-2021-42374 OOB infrastructure failure and
CVE-2017-15873 integer-overflow resource exhaustion. The UAF case is excluded
because protocol v10 already exercised all four required tools and produced a
genuine tools-tried unresolved result.

Audit confirmed that protocol v10 supplied identical defensive text and the
same reinforced runner reminder policy to all three cases. The remaining
framing gap was that the first tool-enabled request relied on its prompt; a
fresh reminder was appended only after tool output. Protocol v11 ensures every
provider request in the two-case scope ends with the same reinforced
symbolic-only reminder, including the first.

The scheduling correction immediately grants the already-projected adaptive
stage when a required tool returns `tool_result_too_large`. The oversized call
remains counted and immutable, but a narrower retry no longer has to wait
until the base stage has exhausted the slots needed by dominance and angr.
Optional oversized calls and other error kinds do not trigger the exception.
Absolute model-call, tool-call, and monetary limits are unchanged.

Prepared run
`2026-07-30t052530z__gpt-5.6-sol__medium__static-round3-oob-integer-uniform-defensive-retry-extension-v3`
has manifest SHA-256
`5115f7d615a636be10013c7db2464b85e42c37fbb314979bdc83658ace62ebc4`,
adaptive projection `$33.045570`, and exact aggregate hard ceiling `$33.06`.
Preparation and dry-run validation made zero provider calls. The approved
execution completed with accounted spend `$2.168100` and results SHA-256
`2f7c60f25adf8b9f4fe30214d046c1fe43cd00dffce3c5e62e598737e0840aaf`.

The two intended mechanisms activated correctly. OOB passed the initial
provider-policy boundary and completed reaching-definitions, slicing, and
dominance. Integer overflow recorded an immediate adaptive extension when its
required slice was oversized. Neither case completed all-four-tool coverage:
OOB spent one required-call retry on an invalid p-code input index and
exhausted its slots before angr; integer overflow hit a later `cyber_policy`
provider failure before its narrower slice retry.

These are new residual limitations, not recurrences of the two exact
round-three mechanisms. Non-oversized required-tool argument failures still
lack retry reserve, while uniform repeated defensive framing remains a
risk-reduction measure rather than a guarantee against provider refusal. Both
cases remain operationally incomplete.

Across protocol v9-v11, each round fixed a distinct, independently verified
root cause (unused tools; once-only framing and an oversized-retry budget
gap; a narrower argument-retry budget gap and a persistent provider-side
`cyber_policy` rejection under uniform framing). CVE-2017-15873 and
CVE-2021-42374 are accordingly accepted as static-analysis-stage
limitations — not an unexplored gap — with resolution deferred to the
dynamic-analysis stage (`DYNAMIC-ANALYSIS-PLAN.md`); no further static-tools
round is planned for either case. See `results/OVERALL_RESULTS.md`, "Tier B
static rounds: known limitations."

### Tier B metrics

Use the structured three-way result—confirmed, rejected, or indeterminate.
For the two-case CVE-2026-29004 pilot, report both case outcomes and failures
directly; do not present two cases as matrix-level sensitivity, specificity, or
precision. For the separately approved four-pair follow-on, report
vulnerable-case sensitivity, patched-case specificity, precision, abstentions,
failures, per-class outcomes, and paired vulnerable-to-patched transitions
over its eight cases only. Preserve the evidence path and unresolved
assumptions for manual audit. Do not combine the pilot and follow-on into a
nominal five-pair matrix score.

## End-to-end cascade experiment

After Tier B works on the oracle matrix, run a separate cascade evaluation:

1. Produce the Tier A queue using `vulnerable ∪ indeterminate`.
2. Deduplicate compatible function/variant candidates while retaining every
   requested class and Tier A reason.
3. Run Tier B only on that queue with the same confirmation protocol used in
   the oracle experiment.
4. Report selection recall before Tier B, Tier B rejection/confirmation rates,
   surviving false positives, end-to-end recall, end-to-end specificity, and
   Tier B workload before and after deduplication.

Oracle Tier B results and cascade results must be reported separately. The
former measures Tier B capability without selection bias; the latter measures
the practical combined pipeline and exposes Tier A misses.

## Experimental controls and run comparisons

Every paid Tier A or Tier B experiment uses a new immutable run directory with
a README and `run-metadata.json`. Model, reasoning effort, output cap,
prompt/schema/policy/experiment versions, pricing, and task/input hashes are
frozen per run. Tier B approval additionally names the manifest SHA-256.
Preparation refuses an existing run ID.

Change one experimental factor at a time when making causal comparisons. In
particular, low/medium/high reasoning experiments must use the same model,
prompt, schema, policy, inputs, output cap, and pricing. The recovered July 18
run mixes reasoning and output caps because successful paid calls were reused;
it is a historical baseline, not a clean reasoning-effort control.

Before paid execution, prepare the complete manifest without API calls,
validate guards and pricing, show the worst-case cost, obtain explicit
approval, and enforce a hard per-run ceiling no greater than the active
versioned policy limit before each request (USD 10 in `tier-a-policy-v8` and
USD 10 in the active Tier B policies; historical Tier B runs retain their
frozen policy). Tier B approval must name both the run ID and
manifest SHA-256. Retries remain in the same run ledger and ceiling. A new
experiment requires its own reviewed projection and approval.

## Reporting boundaries

The current repository supports Tier B automation, preserves the two failed
CVE-2026-29004 diagnostic runs, and contains the completed defensive-v3
single-pair pilot described above. Five separate pair runs were prepared, but
provider execution was completed only for the four pairs other than
CVE-2026-29004. The repository therefore contains a completed four-pair
follow-on but not a completed five-pair oracle matrix or end-to-end cascade
result. Protocol v4 additionally supports the separately controlled
evaluator-remediation subset described above. The dynamic-analysis stage
(Stage 9, `DYNAMIC-ANALYSIS-PLAN.md`) is a separate, non-LLM-static-analysis
protocol with its own evidentiary bar (crash reproduces on vulnerable, absent
on patched, identical input) — it is in progress, not absent: 3/5 CVEs
confirmed via genuine blind-seeded AFL++ campaigns as of 2026-07-30, with
CVE-2017-15873 and CVE-2021-42374 as its explicit Priority-1 targets since
Tier B could not resolve them (see `results/OVERALL_RESULTS.md`, "Full
pipeline status per CVE"). Accordingly:

- do not describe Tier A positives as confirmed exploitable vulnerabilities;
- do not describe oracle candidates as discoveries by the model;
- do not describe the zero-verdict diagnostic as confirming either case, and
  do not translate the newer run's vulnerable-case API failure into a verdict
  or present its single patched verdict as representative Tier B performance;
- do not present the completed defensive-v3 single-pair pilot as full-matrix
  performance or reuse it as one of the five separately controlled matrix
  pairs;
- do not present the approved four-pair follow-on, alone or combined with the
  historical pilot, as a completed five-pair matrix;
- do not present the protocol-v4 remediation subset or protocol-v5 targeted
  corrections as a complete oracle
  matrix or combine its results with immutable v3 metrics;
- do not claim full-matrix Tier B or end-to-end cascade performance before
  those separately approved experiments exist; and
- keep historical results immutable when methodology changes—version the
  protocol/prompt and create a new run instead.
