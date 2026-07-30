---
name: classify-function-vulnerabilities
description: Build, run, score, preserve, and compare Tier A function-level vulnerability experiments over isolated Ghidra pseudo-C or function-only LLVM IR. Use for the BusyBox CVE cross-product benchmark, guarded classification against the six supported vulnerability classes, reasoning-effort experiments, run-to-run metric comparison, or parseable results without caller/callee or exploitability reasoning.
---

# Classify Function Vulnerabilities

## Scope

Classify one supplied function against one requested vulnerability class. Treat the function as isolated evidence. Do not infer caller reachability, attacker control, opaque callee behavior, whole-program exploitability, or facts from the vulnerable/patched pair. Leave those questions to later tiers.

Use Ghidra pseudo-C first. When it is missing, extract only the indexed function from LLVM IR. Never submit a whole LLVM module.

## Workflow

1. Read the repository's `EXPERIMENT.md`, `PIPELINE.md`, `LOG.md`, and `samples/index.csv` before changing the benchmark.
2. Read [classification-rubrics.json](references/classification-rubrics.json), [benchmark-policy.json](references/benchmark-policy.json), and [evaluation.md](references/evaluation.md).
3. Prepare the complete six-class manifest without making API calls:

   ```bash
   python3 classify-function-vulnerabilities/scripts/prepare_benchmark.py \
     --repo-root . \
     --results-root results/tier-a \
     --run-label <short-experiment-label> \
     --model gpt-5.6-sol \
     --reasoning-effort <low|medium|high> \
     --experiment-note "<hypothesis or change from prior run>" \
     --input-price-per-million <current-price> \
     --output-price-per-million <current-price>
   ```

   The preparer creates a unique `results/tier-a/runs/<run-id>/`, writes its README and machine-readable metadata, and refuses to overwrite an existing run ID.
4. Review the new run's README and manifest summary, especially configuration differences, task count, largest input, guard skips, estimated tokens, and worst-case projected cost.
5. Keep the run ceiling at or below USD 10. Require current pricing and an explicit `--execute` flag. Do not proceed when the projection exceeds the ceiling.
6. Run the benchmark. Let the runner perform a pseudo-C and LLVM compatibility preflight before releasing the remaining tasks. The active policy uses one synchronous SSE stream per paid request and disables SDK-level retries:

   ```bash
   python3 classify-function-vulnerabilities/scripts/run_benchmark.py \
     --run-dir results/tier-a/runs/<run-id> \
     --input-price-per-million <current-price> \
     --output-price-per-million <current-price> \
     --budget-usd 10 \
     --execute
   ```

7. Stop on a hard refusal, invalid structured output, quota error, exceeded guard, or projected/observed budget breach. Do not retry refusals or disguise decompiled code to bypass safety checks. An invalid-output retry requires explicit review of one exact task ID; prior cost remains part of the same cumulative ceiling.
8. Score every manifest task, including missing, refused, abstained, invalid, and skipped tasks:

   ```bash
   python3 classify-function-vulnerabilities/scripts/score_benchmark.py \
     --run-dir results/tier-a/runs/<run-id>
   ```
9. To compare two scored experiments, run `scripts/compare_runs.py` with `--baseline-run` and `--candidate-run`. Review metric deltas and `task-changes.csv`; do not infer that a reasoning change caused a difference when other frozen settings also changed.
10. Keep Tier A scoring separate from downstream selection. Score `indeterminate` as abstention, but forward both `vulnerable` and `indeterminate` to a later Tier B cascade. Do not claim Tier B performance until its independent oracle-candidate experiment exists.

## Non-negotiable controls

- Run every sample x variant x six target classes. Do not narrow to matched bug classes.
- Do not expose the CVE ID, variant, indexed class, description, source filename, or paired function to the model.
- Anonymize only the displayed target-function name. Strip LLVM debug intrinsics and metadata; preserve the remaining code structure.
- Reject inputs above 50,000 characters or an estimated 16,000 input tokens before any API call.
- Freeze model, reasoning effort, output-token cap, transport mode, SDK retry setting, policy/prompt/schema versions, and pricing per run. Include these settings in the cache identity.
- Store each experiment under a new immutable run ID. Never point preparation at an existing run or mix responses from different reasoning settings.
- Cache within a run by task, model, prompt version, reasoning effort, output-token cap, and code hash. Resume without repeating successful calls.
- Record refusals and errors as explicit statuses. Never interpret empty or failed output as `not_vulnerable`.
- Keep all attempts in the append-only `results.jsonl`; reconstruct cumulative spend from every recorded request before resuming or retrying.
- Stop immediately if provider-reported usage exceeds the request's frozen output-token cap.
- Allow `indeterminate`; report it as abstention with no correctness credit.
- Report CVE-2021-42386's use-after-free positive separately as a known function-local observability limitation.
- Treat mismatched-class negatives as benchmark labels, not proof that no secondary weakness exists.
- Do not loosen or relabel historical Tier A verdicts to improve cascade recall. Version methodology changes and create a new run.

## Resources

- [prompt-template.txt](references/prompt-template.txt): common defensive, isolation-preserving prompt scaffold.
- [classification-rubrics.json](references/classification-rubrics.json): six versioned class definitions and exclusions.
- [result-schema.json](references/result-schema.json): provider-facing structured-output schema.
- [benchmark-policy.json](references/benchmark-policy.json): class universe, limits, budget, and known limitations.
- [evaluation.md](references/evaluation.md): labels, categories, metrics, and interpretation rules.
- `scripts/prepare_benchmark.py`: resolve and normalize inputs, extract LLVM functions, and build the costed manifest.
- `scripts/run_benchmark.py`: perform preflight, enforce guards and budget, call OpenAI, and append auditable results.
- `scripts/score_benchmark.py`: score the complete manifest and write CSV/JSON summaries.
- `scripts/compare_runs.py`: compare configuration, metrics, and task-level outcomes across two scored runs.
