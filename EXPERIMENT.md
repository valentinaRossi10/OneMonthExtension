# Experimental protocol

This document is the canonical definition of the experiment. `PIPELINE.md`
explains the design rationale, `PLAN.md` records implementation status, and
`LOG.md` preserves chronology. If an implementation or result is interpreted
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
  contextual confirmation.
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

### Oracle-candidate matrix

Evaluate all five known BusyBox candidates independently of Tier A and include
both vulnerable and patched controls: 5 candidate pairs, up to 10 cases. If a
fix removes the candidate function, as in the UAF sample, candidate absence is
an explicit patched outcome rather than an invented replacement function.

Running only the five vulnerable cases would measure sensitivity but not
whether Tier B rejects false confirmations. Patched controls are required for
specificity. A specific entry point and reproducible whole-codebase package
must be defined for every case before the matrix is runnable.

The Netgear CVE-2016-6277 case is an additional real-firmware Tier B case with
candidate `netgear_commonCgi`, entry point `parse_http_request`, and expected
path through `handle_get`. Its selected snippets establish ground truth, but
the complete codebase package and Tier B automation are not yet present.

### Tier B metrics

Define a structured three-way result—confirmed, rejected, or indeterminate—
before implementation. Report vulnerable-case sensitivity, patched-case
specificity, precision, abstentions, failures, per-class outcomes, and paired
vulnerable-to-patched transitions. Preserve the evidence path and unresolved
assumptions for manual audit.

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

Every paid Tier A experiment uses a new immutable
`results/tier-a/runs/<run-id>/` directory with a README and
`run-metadata.json`. Model, reasoning effort, output cap, prompt/schema/policy
versions, pricing, and task/input hashes are frozen per run. Preparation
refuses an existing run ID.

Change one experimental factor at a time when making causal comparisons. In
particular, low/medium/high reasoning experiments must use the same model,
prompt, schema, policy, inputs, output cap, and pricing. The recovered July 18
run mixes reasoning and output caps because successful paid calls were reused;
it is a historical baseline, not a clean reasoning-effort control.

Before paid execution, prepare the complete manifest without API calls,
validate guards and pricing, show the worst-case cost, obtain explicit
approval, and enforce a hard per-run ceiling no greater than USD 5 before each
request. Retries remain in the same run ledger and ceiling. A new experiment
requires its own reviewed projection and approval.

## Reporting boundaries

The current repository supports and contains one completed Tier A run. It does
not yet contain a runnable Tier B benchmark or dynamic-analysis stage.
Accordingly:

- do not describe Tier A positives as confirmed exploitable vulnerabilities;
- do not describe oracle candidates as discoveries by the model;
- do not claim Tier B or end-to-end cascade performance before those
  experiments exist; and
- keep historical results immutable when methodology changes—version the
  protocol/prompt and create a new run instead.
