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
