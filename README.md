# IoT Firmware Vulnerability Detection via LLM Static Analysis

Research project evaluating LLM-based static analysis as one half of a
hybrid static + dynamic vulnerability-detection pipeline for IoT firmware.

Start with [`EXPERIMENT.md`](EXPERIMENT.md) for the canonical experimental
protocol, [`PIPELINE.md`](PIPELINE.md) for methodology and rationale, and
[`LOG.md`](LOG.md) for current status/next steps (Part 1) and full
chronological history (Part 2).

## Current methodology and status

- **Tier A — function-level classification: complete.** A model receives one
  isolated Ghidra pseudo-C function (or function-only LLVM IR fallback) and
  classifies one requested vulnerability class. The BusyBox benchmark runs the
  full 5 samples x 2 variants x 6 classes cross-product. The recovered baseline
  completed and scored all 60 tasks under a hard cumulative $5 ceiling. Later
  uniform-high experiments are preserved separately as stopped partial runs.
- **Tier B — historical oracle confirmation plus recall-first redesign:
  complete, with 2 cases accepted as documented limitations.** Historical
  protocol-v3/v4/v5 runs are preserved under `results/tier-b/`. The
  `confirm-and-filter-vulnerabilities/` MVP's six-case pilot confirmed 2/4
  real vulnerabilities, correctly suppressed 1 genuine Tier A false
  positive, and retained 3 cases as capability-gap limitations. A second
  skill, `confirm-and-filter-vulnerabilities-static/`, added agent-
  orchestrated def-use/slicing/dominance tools and targeted angr across 3
  verified rounds; CVE-2017-15873 and CVE-2021-42374 are now accepted as
  static-analysis-stage limitations (resolution deferred to Stage 9);
  CVE-2021-42386's static result already stands as a complete attempt (all
  required tools exhausted, angr timed out).
- **Static handoff rule:** Tier A remains strictly scored, but both
  `vulnerable` and `indeterminate` cases advance to Tier B. Forwarding an
  abstention does not retroactively count it as a Tier A positive.
- **Dynamic confirmation (Stage 9): in progress.** Blind LLM-seeded AFL++
  fuzzing per CVE — 3/5 confirmed (CVE-2026-29004, CVE-2021-42373,
  CVE-2021-42374), 2/5 still under active fuzzing (CVE-2017-15873,
  CVE-2021-42386). See `dynamic-analysis/README.md`.

The Netgear CVE-2016-6277 material under `firmware/` currently establishes
ground truth for a future Tier B case. It is not a runnable full-binary
discovery benchmark.

## Repository layout

| Path | Purpose |
|---|---|
| [`EXPERIMENT.md`](EXPERIMENT.md) | Canonical research questions, labels, handoff policy, evaluation matrices, metrics, and reporting boundaries |
| [`classify-function-vulnerabilities/`](classify-function-vulnerabilities/SKILL.md) | Canonical Tier A skill, rubrics, schema, policy, and automation |
| [`confirm-and-filter-vulnerabilities/`](confirm-and-filter-vulnerabilities/SKILL.md) | Recall-first Tier B MVP for real Tier A queue ingestion, Ghidra-backed packages, proof-gated filtering, execution, and scoring |
| [`confirm-and-filter-vulnerabilities-static/`](confirm-and-filter-vulnerabilities-static/SKILL.md) | Tier B static-tools augmentation: def-use/slicing/dominance/angr, force-include |
| [`confirm-vulnerability-reachability/`](confirm-vulnerability-reachability/SKILL.md) | Historical fixed-candidate Tier B oracle protocol and preserved run tooling |
| [`dynamic-analysis/`](dynamic-analysis/README.md) | Stage 9 fuzzing: per-CVE AFL++/ASAN harnesses, blind seeds, campaign results |
| [`samples/`](samples/README.md) | Verified vulnerable/patched BusyBox source ground truth |
| [`binaries/`](binaries/README.md) | Linked and stripped BusyBox binaries used for decompilation |
| [`pseudo-code/`](pseudo-code/README.md) | Primary Ghidra pseudo-C function inputs |
| [`ir/`](ir/README.md) | LLVM IR fallback inputs; the skill extracts only the indexed function |
| [`results/`](results/README.md) | Immutable Tier A experiment runs, ledgers, scoring, and comparisons |
| [`firmware/`](firmware/README.md) | Netgear ground truth and snippets for the planned Tier B case |
| [`scripts/`](scripts/README.md) | Shared extraction tooling, currently the headless Ghidra exporter |
| [`skills/`](skills/tier-a-function-classification-brief.md) | Design provenance for the generated Tier A skill |

## Tier A quick start

The skill is exposed to Codex through
`.codex/skills/classify-function-vulnerabilities`. Invoke it with:

```text
Use $classify-function-vulnerabilities to prepare, run, and score Tier A.
First show the dry-run projection, enforce the active versioned per-run ceiling,
wait for approval before paid API calls, and create a new named run rather
than reusing results from an earlier model or reasoning configuration.
```

For direct commands and result schemas, see
[`results/README.md`](results/README.md) and the skill's
[`SKILL.md`](classify-function-vulnerabilities/SKILL.md).

## Recall-first Tier B quick start

The redesign skill is exposed through
`.codex/skills/confirm-and-filter-vulnerabilities`. Invoke it with:

```text
Use $confirm-and-filter-vulnerabilities to ingest the named frozen Tier A
run, build hash-verified Ghidra packages, and prepare—but do not execute—a
recall-first Tier B run. Report quarantine and exact-duplicate coalescing,
the immutable manifest SHA-256, and the exact worst-case cost.
```

Preparation makes no provider calls. Execution requires a separate approval
that names the run ID, manifest SHA-256, and spending ceiling.

## Requirements

- Linux, Python 3, `clang`/LLVM, `git`, and Ghidra
- `OPENAI_API_KEY` only for separately approved paid Tier A or Tier B execution
- Python dependencies from
  `classify-function-vulnerabilities/scripts/requirements.txt`

Do not commit API keys, proprietary firmware images, or extracted proprietary
files; see [`firmware/README.md`](firmware/README.md).
