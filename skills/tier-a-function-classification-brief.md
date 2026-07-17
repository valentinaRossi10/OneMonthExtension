# Skill brief: Tier A — function-level vulnerability classification

Brief for Codex to build this skill's automation from. See
`PLAN.md`/`PIPELINE.md` (Stage 8) for how this fits into the larger
two-tier pipeline, and `LOG.md` for the full history of pitfalls this
brief tries to pre-empt.

## Purpose

Given a single function's source (pseudo-C from a decompiler, or raw
source), classify whether it contains a specific class of vulnerability.
This is the methodology from the original `run_benchmark.py`/`score.py`
(removed 2026-07-17, still in git history / on
`W1/firmware-static-analysis` for reference) — the approach is approved
as-is by the supervisor; only the implementation needs regenerating.

## Inputs

- **Ground truth index**: `samples/index.csv` — one row per CVE sample,
  with `cve_id`, `project`, `bug_class`.
- **Code to classify**, per sample and variant (`vulnerable`/`patched`):
  1. `pseudo-code/<cve_id>-<project>/<variant>.c` (primary — Ghidra
     decompiled pseudo-C), or
  2. `ir/<cve_id>-<project>/<variant>.ll` (fallback — LLVM IR, used only
     when pseudo-code is missing for that variant)
- **Prompt templates**, one per bug class, in `prompts/*.md` — each has
  a `<<<CODE>>>` placeholder for the code to substitute in. These
  templates still exist and are still valid; reuse them rather than
  regenerating new prompt text.
- **Models to call**: `scripts/models.yaml` lists provider + model ID
  per entry (currently `claude-fable-5` and `gpt-5.6-sol` — see
  "Known pitfalls" below on `claude-fable-5` specifically).

## Expected behavior

Run the **full cross-product**: every sample × every variant × every
prompt template (not just each sample's own matching bug class) × every
configured model. Running mismatched prompts too (e.g. the
use-after-free prompt against a NULL-deref sample) is what makes it
possible to tell apart "the specialized prompt correctly found the real
bug" from "an unrelated prompt hallucinated one" — don't narrow this to
matched pairs only.

## Output format

- One raw result file per (sample, variant, model, prompt) combination,
  e.g. `results/runs/<cve_id>__<variant>__<model>__<prompt-slug>.md`,
  containing the model's raw response.
- Responses should follow (and be parsed against) this structured
  format, requested by the prompt templates:
  ```
  Vulnerable: yes/no
  Function/line: <...>
  Bug class: <specific-class> / none
  Confidence: low/medium/high
  Reasoning: <1-3 sentences>
  ```
- A scoring pass over `results/runs/*.md` that:
  - Parses the `Vulnerable: yes/no` line (mark `unparseable` if absent)
  - Determines the expected answer: `yes` only if the variant is
    `vulnerable` AND the prompt's bug class matches the sample's real
    `bug_class`; `no` otherwise
  - Categorizes each result: `true_positive`, `false_negative`,
    `true_negative`, `false_positive`, `unparseable`
  - Writes one row per result to a CSV (e.g. `results/scoring.csv`)
  - Prints a console summary: counts/percentages per category, the
    "specialized-prompt detection rate" (true positives ÷ all
    vulnerable-code-with-matching-prompt cases — the headline number),
    and an itemized listing of **both** false positives (with a reason:
    patched code flagged, or mismatched bug class flagged) and false
    negatives (with which real bug class was missed) — not just
    aggregate counts for either.

## Known pitfalls to design around (from LOG.md)

1. **`claude-fable-5` refuses on decompiled code.** Confirmed
   2026-07-15: it returns an empty `refusal` (no thinking, no text) on
   real Ghidra pseudo-C and LLVM IR input, regardless of whether the
   code is vulnerable or patched, and regardless of variable/function
   naming. `gpt-5.6-sol` handles the identical inputs correctly. Per the
   mentor's reply (2026-07-16), don't spend effort trying to route
   around Claude's refusal — proceed GPT-only for now, but the script
   should detect and clearly log a refusal (e.g. `stop_reason` /
   equivalent field) rather than silently writing an empty file, so a
   future re-attempt with a different model is easy to distinguish from
   "the model just said no."
2. **Unbounded input size caused a real $27.61 runaway spend**
   (2026-07-15). One sample's fallback representation was ~100x larger
   than every other input and got sent whole, repeatedly, before anyone
   noticed. Any new implementation must include an input-size guard
   *before* calling any API — skip (with a clear log message) rather
   than silently pay for oversized input. The prior guard used a 50,000
   character threshold, comfortably above the largest real pseudo-code
   file (~12KB) and well below the problem file (~1MB) — a similar
   order-of-magnitude threshold is reasonable here, but re-derive it
   from whatever inputs Tier A actually uses now rather than assuming
   the old number still applies.
3. **Billing has admission-time, not real-time, enforcement** — a
   single very large accepted request can still fully complete and bill
   even if it exhausts the account balance mid-flight, only blocking
   *subsequent* requests. This is a reason to keep guard #2 strict, not
   a reason to assume quota errors will fail safely on their own.
4. **Missing result files are fine, not an error** — the scoring pass
   should tolerate a sample/variant with no output (e.g. skipped by the
   size guard) rather than crashing; it should just produce fewer scored
   rows.

## Validation

Before trusting this on anything new, re-run against the existing 5
BusyBox CVE samples and sanity-check that results are directionally
consistent with what's already documented in `LOG.md` (e.g.
`gpt-5.6-sol` correctly identifying the `man_main` NULL-deref in
`CVE-2021-42373`).
