---
name: classify-function-vulnerabilities
description: Build, run, and score Tier A function-level vulnerability classification over isolated Ghidra pseudo-C or function-only LLVM IR. Use for the BusyBox CVE cross-product benchmark, for guarded LLM classification of one function against heap buffer overflow, use-after-free, integer overflow, NULL pointer dereference, out-of-bounds read, and command injection, or when preparing parseable results without caller/callee or exploitability reasoning.
---

# Classify Function Vulnerabilities

## Scope

Classify one supplied function against one requested vulnerability class. Treat the function as isolated evidence. Do not infer caller reachability, attacker control, opaque callee behavior, whole-program exploitability, or facts from the vulnerable/patched pair. Leave those questions to later tiers.

Use Ghidra pseudo-C first. When it is missing, extract only the indexed function from LLVM IR. Never submit a whole LLVM module.

## Workflow

1. Read the repository's `PIPELINE.md`, `PLAN.md`, `LOG.md`, and `samples/index.csv` before changing the benchmark.
2. Read [classification-rubrics.json](references/classification-rubrics.json), [benchmark-policy.json](references/benchmark-policy.json), and [evaluation.md](references/evaluation.md).
3. Prepare the complete six-class manifest without making API calls:

   ```bash
   python3 classify-function-vulnerabilities/scripts/prepare_benchmark.py \
     --repo-root . \
     --output-dir results/tier-a \
     --model gpt-5.6-sol \
     --input-price-per-million <current-price> \
     --output-price-per-million <current-price>
   ```

4. Review the manifest summary, especially task count, largest input, guard skips, estimated tokens, and worst-case projected cost.
5. Keep the run ceiling at or below USD 5. Require current pricing and an explicit `--execute` flag. Do not proceed when the projection exceeds the ceiling.
6. Run the benchmark. Let the runner perform a pseudo-C and LLVM compatibility preflight before releasing the remaining tasks:

   ```bash
   python3 classify-function-vulnerabilities/scripts/run_benchmark.py \
     --manifest results/tier-a/manifest.jsonl \
     --results results/tier-a/results.jsonl \
     --input-price-per-million <current-price> \
     --output-price-per-million <current-price> \
     --budget-usd 5 \
     --execute
   ```

7. Stop on a hard refusal, invalid preflight result, quota error, exceeded guard, or projected/observed budget breach. Do not retry refusals or disguise decompiled code to bypass safety checks.
8. Score every manifest task, including missing, refused, abstained, invalid, and skipped tasks:

   ```bash
   python3 classify-function-vulnerabilities/scripts/score_benchmark.py \
     --manifest results/tier-a/manifest.jsonl \
     --results results/tier-a/results.jsonl \
     --output-dir results/tier-a/scoring
   ```

## Non-negotiable controls

- Run every sample x variant x six target classes. Do not narrow to matched bug classes.
- Do not expose the CVE ID, variant, indexed class, description, source filename, or paired function to the model.
- Anonymize only the displayed target-function name. Strip LLVM debug intrinsics and metadata; preserve the remaining code structure.
- Reject inputs above 50,000 characters or an estimated 16,000 input tokens before any API call.
- Cache by task, model, prompt version, and code hash. Resume without repeating successful calls.
- Record refusals and errors as explicit statuses. Never interpret empty or failed output as `not_vulnerable`.
- Allow `indeterminate`; report it as abstention with no correctness credit.
- Report CVE-2021-42386's use-after-free positive separately as a known function-local observability limitation.
- Treat mismatched-class negatives as benchmark labels, not proof that no secondary weakness exists.

## Resources

- [prompt-template.txt](references/prompt-template.txt): common defensive, isolation-preserving prompt scaffold.
- [classification-rubrics.json](references/classification-rubrics.json): six versioned class definitions and exclusions.
- [result-schema.json](references/result-schema.json): provider-facing structured-output schema.
- [benchmark-policy.json](references/benchmark-policy.json): class universe, limits, budget, and known limitations.
- [evaluation.md](references/evaluation.md): labels, categories, metrics, and interpretation rules.
- `scripts/prepare_benchmark.py`: resolve and normalize inputs, extract LLVM functions, and build the costed manifest.
- `scripts/run_benchmark.py`: perform preflight, enforce guards and budget, call OpenAI, and append auditable results.
- `scripts/score_benchmark.py`: score the complete manifest and write CSV/JSON summaries.

