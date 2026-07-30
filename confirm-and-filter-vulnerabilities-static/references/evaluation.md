# Recall-first Tier B evaluation

## Objective priority

Confirmation of true positives is the primary objective and hard constraint.
Tier B must not suppress a true positive in order to improve precision or
reduce downstream workload. Confirmation investigation receives the full
configured base and adaptive resource allowance; suppression logic must not
reduce that allowance, lower the confirmation evidentiary bar, override a
completed positive proof, or force an unresolved case into a negative result.

False-positive suppression is a secondary, best-effort objective. It is
deliberately subject to a stricter and asymmetric proof gate. A case that
cannot satisfy the complete suppression gate is retained as
`retain_and_escalate` and continues downstream to later dynamic analysis,
including fuzzing. Retaining such a case is preferable to falsely suppressing
a real vulnerability.

## Oracle acceptance

Evaluate a new coherent cohort; do not combine historical Tier B protocol
versions. Use the five existing BusyBox vulnerable cases as the positive
acceptance set. Include only independently audited, eligible patched controls.

Report:

- vulnerable confirmation count and recall;
- true-positive suppressions, with an observed objective of zero;
- unresolved or retained vulnerable cases;
- eligible-control specificity and best-effort false-positive suppression;
- surviving negative candidates forwarded to dynamic analysis;
- precision before and after filtering;
- refusal, infrastructure, invalid-output, and resource-exhaustion counts;
- cost per confirmed positive and per suppressed negative.

An unresolved or failed vulnerable case is retained operationally but receives
no confirmation credit. A retained negative case is not a false suppression;
it remains available for downstream dynamic analysis.

The cohort objective is 5/5 confirmation and an observed false-suppression
count of zero. `target_false_suppression_count: 0` is the safety objective that
the asymmetric suppression gate is designed to approach. It is not a
mathematical guarantee supplied by the current architecture, and an LLM-only
proof gate cannot establish such a guarantee.

These objectives apply only to the five reviewed BusyBox positives and the
eligible reviewed controls included in the cohort. Passing them does not
establish universal recall, universal absence of false suppression,
generalization to unseen CVEs, or held-out performance. No held-out cohort
currently exists.

## Real Tier A cascade

Freeze and name the Tier A run(s), queue policy, and input hashes. Report:

- raw and exact-case-coalesced queue sizes;
- Tier A selection recall before Tier B;
- forwarded evaluator-positive and evaluator-negative cases;
- Tier B confirmation recall among forwarded positives;
- best-effort false-positive suppression and surviving false positives;
- true positives suppressed;
- `retain_and_escalate` count and reasons;
- candidates forwarded to downstream dynamic analysis;
- precision before and after filtering;
- workload before and after exact-case coalescing;
- end-to-end recall, explicitly including Tier A misses.

Tier B cannot recover a positive that Tier A did not forward. Keep Tier A
selection failures separate from Tier B confirmation failures. Tier B is not
the final false-positive-clearing stage; retained candidates continue to
dynamic analysis.

### Accepted cohort limitation: CVE-2017-15873

The reviewed six-case cohort contains two CVE-2017-15873 cases: the vulnerable
integer-overflow case and the patched NULL-pointer-dereference control. Both
are accepted known limitations of this MVP, not open prompt-engineering or
budget-tuning tasks.

The completed diagnosis found that the vulnerable case requires path-sensitive
value/range tracking across decoder state and resolution of the entry root's
indirect dispatch. The patched control likewise requires indirect-dispatch and
argument-provenance analysis before its candidate can be safely confirmed or
suppressed. The current package exposes lexical pseudo-C, analyzed direct
calls, and explicit unresolved indirect sites, but implements no SSA, def-use
slicing, symbolic ranges, or indirect-dispatch resolver.

For this design, both cases therefore remain `retain_and_escalate`. Resolving
them requires the separately deferred analysis engine. Another prompt revision,
larger model/tool budget, or unchanged retry is not an accepted remediation for
either case.

### Accepted cohort limitation: CVE-2021-42374 vulnerable OOB read

The reviewed CVE-2021-42374 vulnerable out-of-bounds-read case
`tier-b-case-b99dc78d5275592661bdc5b9` is also an accepted limitation of the
current MVP. The protocol-v4 run completed cleanly and correctly avoided both
the earlier false suppression and the unsupported assertion that the history
distance “must already be bounded,” but it could not complete a positive
path/range proof and therefore remained `retain_and_escalate`.

This case does not require the deferred indirect-dispatch resolver for its
entry edge. The package callsite record at `1125ae` is conservatively encoded
as unresolved `CALL R14`, but the same frozen package exposes all three facts
needed to recover the fixed target: entry-function line 65 calls
`LAB_001132be`, the entry identity lists data reference `001132be`, and the
candidate identity address is `1132be`. Leaving that edge unresolved was a
reasoning miss, not a genuine dispatch gap.

The decisive limitation is path-sensitive value/range analysis inside the
decoder. Establishing the vulnerable line-92 read requires tracking the
decoded history distance through its assignments and reuse across decoder
states and loop iterations, while relating it to the current output cursor,
dictionary size, allocated extent, and buffer reset/flush transitions.
Establishing the line-244 nonnegative-branch bound likewise requires a proven
loop invariant connecting the cursor and allocation extent. The current
package supplies lexical pseudo-C and call records, but no SSA, def-use,
path-sensitive range, or loop-invariant facts capable of establishing those
relations.

The two history-buffer read sites themselves are enumerable from the existing
package: the run's exact lexical search returned candidate lines 92 and 244.
Thus basic sink enumeration is not independently blocked. Determining complete
class relevance and proving the safety or feasibility of those sinks still
depends on the same missing range/data-flow capability.

For this design, this case remains `retain_and_escalate`. Further prompt,
schema, output-budget, or unchanged-retry changes are not expected to resolve
the decisive range proof. Resolution requires the deferred SSA/def-use/range
analysis engine. No further execution of this case is part of the current MVP.

## Label cautions

A Tier A mismatched-class “false positive” may be a secondary weakness.
Disputed negatives require evaluator audit. Do not alter immutable historical
labels after seeing results; create a versioned oracle correction.

## Agent-directed static primary cohort: completed

The static-v2 three-case primary cohort is frozen in run
`2026-07-29t094851z__gpt-5.6-sol__medium__tier-a-mixed-recovered-static-primary-v1`.
Its manifest SHA-256 is
`f527a47d635e439b349b457ffbce48c1f0b5f244b8563eaa57443f4055b8dfa5`.
Preparation and dry-run validation made zero provider calls. The approved
execution completed on 2026-07-30 with accounted spend of `$3.835260` under
the exact frozen aggregate ceiling `44.849999999999994`.

The reviewed cases are the vulnerable CVE-2017-15873 integer-overflow,
CVE-2021-42374 out-of-bounds-read, and CVE-2021-42386 use-after-free rows. The
last is the single evaluator-reviewed Tier A false negative force-included by
exact task ID; no other `not_vulnerable` row was forwarded by the override.

### Per-case outcomes

- CVE-2017-15873 integer overflow:
  `unresolved / retain_and_escalate / completed`. The investigation identified
  unchecked 32-bit shift, doubling, and addition operations, including the
  capacity-check sum, but did not prove root reachability through the remaining
  indirect site or a format-feasible out-of-range operand state.
- CVE-2021-42374 out-of-bounds read:
  `unresolved / retain_and_escalate / completed`. It identified the line-92
  and line-244 indexed reads and the missing post-adjustment check at line 92,
  but did not complete root reachability, allocation-extent, or feasible
  boundary-crossing proofs.
- CVE-2021-42386 use after free:
  `unresolved / retain_and_escalate / infrastructure_error`. Eight completed
  analysis cycles gathered candidate, call-site, and lexical lifetime facts;
  the ninth provider stream failed with `cyber_policy`. Bounded retrieval did
  not recover a completed result, so the runner preserved the failure as an
  unresolved retention and did not retry it.

The two completed cases each used all 17 progress-qualified model calls. No
case invoked angr; the agent selected Ghidra-backed package queries only. The
run produced zero confirmations, zero suppressions, and therefore zero false
suppressions. All three executed positives continue to downstream dynamic
analysis.

The scorer also preserves 18 ingestion quarantines from the broader source
queue: two evaluator positives and 16 negatives lacked artifact-scoped
bindings outside the deliberately packaged three-case scope. Including those
records, five positives were unconfirmed, 16 negatives survived, and all 21
records were retained. The three-case execution recall is 0/3; the broader
scored queue recall is 0/5. These are static-primary cohort results, not a
completed five-positive acceptance evaluation or a full end-to-end cascade.

## Required-tools three-case rerun: completed

Direct inspection of the completed static-primary `results.jsonl` found that
`get_reaching_definitions` ran once in one case, while `slice_pcode`,
`get_dominance`, and `query_angr` never ran. The prior prompt made these tools
conditional on agent judgment, and the runner had no terminal coverage gate.
It could therefore accept an unresolved retention without exercising the
capabilities built for the diagnosed range/data-flow and indirect-call gaps.
The defensive reminder was already repeated after tool results; for the new
policy, its UAF wording is further constrained to abstract lifetime states.

Protocol v10 binds all four tools to every one of the same three cases. A
failed call or unavailable angr backend does not satisfy coverage. An early
semantic terminal is recorded as nonterminal, the runner forces missing tools
before their slots expire, and a coverage-incomplete proposal cannot later be
recovered as the case's completed semantic result.

The fresh immutable run is
`2026-07-30t040248z__gpt-5.6-sol__medium__tier-a-mixed-recovered-static-required-tools-rerun-v2`,
with manifest SHA-256
`6d22e60043790394bfca512928d15d39784633e64781d4a7282f976e661f5cf2`.
Its adaptive projection was `$49.534110` and exact aggregate hard ceiling was
`$49.56`. Preparation and dry-run validation made zero provider calls. The
approved execution completed with accounted spend of `$2.049735`. The final
results SHA-256 is
`c23e4e23ada1676f903addd6463a57825b1e863e990ef82be07d0ead21c6e092`.

Direct `tool_name` inspection produced these outcomes:

- CVE-2021-42374 OOB: the first provider generation failed with
  `cyber_policy` before any tool call. Bounded retrieval failed; the runner
  retained the case as an infrastructure error and did not retry the refusal.
- CVE-2017-15873 integer overflow: reaching-definitions and slicing completed,
  but two oversized slice results consumed required-call retries. The base
  tool allowance then ended before dominance and angr, producing
  `resource_exhausted / retain_and_escalate`.
- CVE-2021-42386 UAF: all four required tools completed. The angr query
  reached its wall-clock timeout, and the failure-handler lifetime effects and
  incoming-list lifetime invariant remained unresolved. The valid terminal was
  `completed / retain_and_escalate`.

The coverage gate prevented a coverage-incomplete semantic terminal, but only
the UAF case achieved all-four-tool coverage. The run exposed a scheduling
defect: failed mandatory calls can consume the last base slots before the
progress-qualified adaptive extension becomes eligible. Thus this run
distinguishes one genuine tried-but-unresolved result from two operationally
incomplete cases; it does not satisfy the intended three-case coverage goal.

## Round-3 two-case fixes: completed

The prior prompts already contained identical defensive symbolic-only text for
all three cases, and the runner selected the same reinforced reminder from the
shared coverage policy. The OOB refusal was therefore not caused by a
UAF-specific branch. The remaining asymmetry was temporal: tool-enabled
requests relied on the prompt for the first request and appended a fresh
reminder only after tool output. Protocol v11 now ensures every provider
request for every scoped case ends with the reinforced reminder, including the
first tool-enabled request.

Protocol v11 also grants the already-frozen adaptive stage immediately when a
required tool returns `tool_result_too_large`. The failed call remains in the
ledger and counts toward the absolute limits, but a narrower retry can use
extension slots before the base stage is exhausted. Optional oversized tools
and other failures do not trigger this exception.

Only the prior OOB infrastructure failure and integer-overflow resource
exhaustion are in scope; the UAF all-four-tools result is not rerun. Prepared
run
`2026-07-30t052530z__gpt-5.6-sol__medium__static-round3-oob-integer-uniform-defensive-retry-extension-v3`
has manifest SHA-256
`5115f7d615a636be10013c7db2464b85e42c37fbb314979bdc83658ace62ebc4`,
adaptive projection `$33.045570`, and exact aggregate hard ceiling `$33.06`.
Preparation and dry-run validation made zero provider calls. The approved
execution completed with accounted spend `$2.168100`; final results SHA-256 is
`2f7c60f25adf8b9f4fe30214d046c1fe43cd00dffce3c5e62e598737e0840aaf`.

Both narrow fixes behaved as designed, but neither case completed all required
coverage:

- OOB: the first request was accepted, so the prior immediate `cyber_policy`
  failure did not recur. Reaching-definitions, slicing, and dominance
  completed. The first forced reaching-definitions call used an out-of-range
  p-code input index; its successful retry consumed the slot later needed by
  angr, producing `resource_exhausted / retain_and_escalate`.
- Integer overflow: an oversized required slice immediately recorded
  `extension_granted` with reason `required_tool_result_too_large`, confirming
  the scheduling fix. The following provider generation nevertheless failed
  with `cyber_policy` before the narrower slice retry, dominance, or angr.

The new outcomes expose two different residual limitations. Required-tool
argument errors other than the specifically versioned oversized-result class
still have no retry reserve, and repeated defensive framing reduces but does
not eliminate nondeterministic provider refusal. Neither terminal is evidence
that all four tools ran and the case remained semantically unresolved.
