# Recall-first Tier B task contract

## Primary task

Process the actual output of one or more frozen Tier A runs. A case asks
whether one supplied artifact-scoped function exhibits one supplied
vulnerability class in program context. Tier A evidence is an untrusted
hypothesis, not ground truth.

## Exact-case identity

The logical key is:

```text
(function_uid, normalized_target_class)
```

`function_uid` is bound to one artifact SHA-256. Implementations must also
verify the expanded tuple:

```text
(artifact_sha256, function_uid, normalized_target_class)
```

Never coalesce by address or by function UID alone. The same function under
different classes produces independent cases. The same address in different
artifacts cannot identify the same function.

Exact duplicates may be coalesced only when the expanded tuple matches. The
resulting case must preserve every source row, run/task identifier, verdict,
status, prompt/policy variant, evidence item, reasoning summary, and hash.
Conflicts remain explicit.

Every eligible input row must map to exactly one output case or one quarantine
record. Identity ambiguity, unsupported class normalization, or inconsistent
artifact binding is quarantined and routed to `retain_and_escalate`; it is
never dropped.

An evaluator-reviewed `--force-include` selector may bypass only the raw
verdict eligibility filter. It must match exactly one source row. Preserve the
original verdict, category, evidence, and row hash; record the selector and
forced status. Apply all normal binding, class normalization, coalescing,
quarantine, package, and proof checks unchanged.

## Model-visible information

The model may receive the neutral artifact/package identifiers, function UID,
target class, Tier A evidence hypotheses, entry roots, and mechanically
derived code/analysis facts.

Do not expose expected labels, CVE identity or narrative, vulnerable/patched
role, pair correspondence, manual path, or exploitability conclusions.

Agent-directed Ghidra and angr queries must be read-only, artifact-bound, and
bounded. Treat unsupported analysis, timeout, state explosion, or incomplete
data flow as unresolved. A query can add positive evidence or narrow a gap; it
cannot turn its own incompleteness into negative evidence.

For a reviewed required-tools rerun, the frozen manifest lists the exact tool
coverage required for each case. A completed semantic terminal is blocked
until every listed tool has returned without a tool-execution error. The
runner records `tool_name`, arguments, result, and remaining coverage on each
call and forces missing tools as the tool-call deadline approaches. Provider,
budget, or resource failures remain operational failures; they are never
converted into proof that the required analysis was completed.

The reviewed round-3 policy injects the same defensive symbolic-only reminder
into every provider request for every scoped case, including the first
tool-enabled request. It also grants the already-frozen adaptive stage
immediately when a required tool returns `tool_result_too_large`, so a
narrower retry cannot starve later required tools. Optional oversized queries
do not trigger this exception.

## Decisions

Separate semantic status from operational routing:

- `confirmed` + `retain_confirmed`
- `safety_proven` + `suppress_proven_false_positive`
- `unresolved` + `retain_and_escalate`

Execution failures always use `unresolved` and `retain_and_escalate`.

## Objective priority

Confirmation is the primary objective and hard constraint. Investigating a
possible positive receives the complete configured base allowance and every
progress-qualified adaptive extension, plus any narrowly versioned
required-tool retry extension. Suppression work must not reserve,
remove, or shorten that allowance, lower the positive-proof bar, override a
completed positive proof, or downgrade a supported class-consistent
hypothesis.

Suppression is secondary, best-effort, and asymmetrically proof-gated. A case
that cannot satisfy the complete suppression gate remains
`retain_and_escalate` and proceeds to downstream dynamic analysis, including
fuzzing. Tier B is not required to clear every false positive.

## Versioned v3 result semantics

V3 separates three meanings that must never share one status vocabulary:

- hypothesis result: `supported`, `contradicted`, or `unresolved`;
- confirmation-obligation completion: `satisfied`, `unsatisfied`, or
  `unresolved`;
- adversarial-challenge outcome: `confirmation_survives`,
  `confirmation_defeated`, `unresolved`, or `not_applicable`.

Confirmation requires a present, task-matching candidate, evidenced
reachability, at least one supported hypothesis for the fixed target class,
every required identity/reachability/operation/constraint/path/class
obligation satisfied, and a challenge outcome of `confirmation_survives` for
the selected supported hypothesis. Contradicting an alternative hypothesis
does not block confirmation.

## Asymmetric v3 suppression gate

Candidate absence requires audited artifact binding. Unreachability requires
coverage of every in-scope root and no relevant unresolved indirect call.
Semantic safety suppression requires all of the following:

1. Every relevant target-class hypothesis is contradicted.
2. Every relevant sink is inventoried and evaluated independently.
3. Every index, pointer, length, value, or lifetime transformation from origin
   to each sink is listed in execution order.
4. A guard after the last transformation protects the exact sink value and
   state. A guard for another sink cannot be reused without explicit
   same-value/state evidence.
5. An earlier guard is accepted only when every later transformation and
   intervening reset, flush, reassignment, release, reuse, and relevant loop
   transition is enumerated and proven to preserve the relied-upon invariant.
6. Every sink concludes safe and every suppression obligation is satisfied.

Any unresolved hypothesis, obligation, sink, transformation, guard/value
relationship, invariant mutation, indirect call, or other material fact forces
`retain_and_escalate`. The gate enforces a complete impossibility-style proof,
not a merely complete-looking narrative.

The structured gate can enforce record completeness and internal consistency,
but an LLM-only architecture cannot mathematically guarantee that every
semantic fact is correct or every relevant sink was discovered. The observed
target of zero false suppressions is an evaluation objective, not a universal
guarantee.

## Versioned v4 contradiction evidence

V4 preserves all v3 confirmation, obligation, adversarial-challenge, and
asymmetric suppression rules. It additionally requires every hypothesis to
carry a `contradiction_proof` object.

For `result: contradicted`, the proof must name an evidentiary basis, state the
claim being established, cite valid lines in packaged functions, and use one
of these relations:

- `exact_same_value_state`;
- `explicitly_proven_equivalent`, with explicit equivalence evidence; or
- `non_value_fact_directly_excludes`, only for a direct control-flow fact.

For `supported` and `unresolved`, the proof must use the exact neutral
`not_applicable` form. A malformed, uncited, out-of-package, or otherwise
unsupported contradiction is deterministically downgraded to an effective
`unresolved` result. If suppression depended on it, the effective disposition
becomes `retain_and_escalate`. A different, class-consistent supported
hypothesis may still confirm the case; the downgrade cannot override that
positive proof. Raw provider output and the deterministic adjustment record
remain in the append-only ledger.

## Acceptance limitation

The current acceptance set contains only five known BusyBox vulnerable cases.
Achieving 5/5 confirmation and zero false suppressions demonstrates success
only on that reviewed set. It does not establish universal recall,
generalization to unseen CVEs, or held-out performance. There is no held-out
cohort in the repository; creating one is a separate ground-truth project.
