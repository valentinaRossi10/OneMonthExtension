# Design record: Tier A function-level vulnerability classification

This brief records the design that produced the implemented
`classify-function-vulnerabilities/` skill. The skill's `SKILL.md`, references,
and scripts are canonical when this record differs from implementation.

## Purpose and boundary

Given one isolated function and one target vulnerability class, classify the
locally visible pattern. Do not infer caller reachability, attacker control,
opaque-callee behavior, paired-variant facts, whole-program exploitability, or
cross-function data flow. Those belong to Tier B or later dynamic analysis.
The complete evaluation and handoff contract is in `EXPERIMENT.md`.

## Inputs

- Ground truth: `samples/index.csv`.
- Primary representation:
  `pseudo-code/<cve_id>-<project>/<variant>.c`.
- Fallback representation:
  `ir/<cve_id>-<project>/<variant>.ll`, from which only the indexed function
  and necessary type declarations are extracted.
- Six target classes and their evidence/exclusion rules:
  `classify-function-vulnerabilities/references/classification-rubrics.json`.
- Common prompt scaffold and strict output schema in the skill's `references/`
  directory. The removed root `prompts/` templates are not used.

## Benchmark design

Run the complete 5 samples x 2 variants x 6 target classes cross-product.
Only a vulnerable variant tested against its indexed historical class is an
expected positive. Every other task is benchmark-negative, while recognizing
that the index does not prove absence of secondary weaknesses.

Do not expose CVE ID, variant, expected label, indexed class, description,
source path, or paired code to the model. Anonymize the displayed target
function name and preserve the remaining code structure.

## Output and scoring

- `results/tier-a/runs/<run-id>/README.md` and `run-metadata.json`: date,
  model, reasoning effort, experiment note, and configuration differences.
- `results/tier-a/runs/<run-id>/manifest.jsonl`: prepared task manifest.
- `results/tier-a/runs/<run-id>/results.jsonl`: append-only API attempt ledger.
- Model response: strict `tier-a-result-v1` JSON with target class, verdict
  (`vulnerable`, `not_vulnerable`, or `indeterminate`), confidence, evidence
  lines, and summary.
- `results/tier-a/runs/<run-id>/scoring/scoring.csv`: one final row per task.
- `results/tier-a/runs/<run-id>/scoring/summary.json`: overall, per-class, and
  per-representation metrics plus named false positives/negatives.
- `results/tier-a/runs/<run-id>/scoring/paired-transitions.csv`: vulnerable/patched
  transition analysis.
- `results/tier-a/comparisons/<baseline>__vs__<candidate>/`: configuration,
  metric, and task-level differences between scored runs.

`indeterminate` is an abstention with no correctness credit. Refusals,
invalid outputs, API errors, missing results, and guarded inputs remain
explicit failure categories and are never converted to true negatives.

Tier A scoring remains strict, while downstream selection forwards both
`vulnerable` and `indeterminate` cases to Tier B. This does not relabel an
abstention as a positive. Tier B must first be evaluated independently on all
known vulnerable/patched oracle candidates before the selected cascade is
measured.

## Safety and reproducibility requirements

- Prefer pseudo-C and never submit a whole LLVM module.
- Reject code over 50,000 characters or an estimated 16,000 input tokens.
- Prepare and review the full manifest before paid calls.
- Create a new immutable run directory for every changed model, reasoning
  effort, or other experimental setting; never overwrite a prior experiment.
- Require explicit execution approval and enforce a hard cumulative $5
  ceiling across retries and resumed invocations.
- Cache successful calls by task, model, policy/prompt/schema versions,
  reasoning effort, output-token cap, and code hash.
- Stop on refusals, invalid output, quota errors, guard failures, or budget
  breaches. A retry requires explicit review and exact-task authorization.
- Do not disguise decompiled code to bypass provider safety behavior.

## Known Tier A limitation

The isolated `nvalloc` function for CVE-2021-42386 does not show the complete
free, retained stale alias, and later dereference. Report that indexed
use-after-free result separately and include observable-positive recall that
excludes this designated function-local limitation.
