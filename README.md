# IoT Firmware Vulnerability Detection via LLM Static Analysis

Research project evaluating LLM-based static analysis as one half of a
hybrid static + dynamic vulnerability-detection pipeline for IoT firmware.

Start with [`EXPERIMENT.md`](EXPERIMENT.md) for the canonical experimental
protocol, [`PIPELINE.md`](PIPELINE.md) for methodology and rationale,
[`PLAN.md`](PLAN.md) for current status and next steps, and [`LOG.md`](LOG.md)
for chronological history.

## Current methodology and status

- **Tier A — function-level classification: complete.** A model receives one
  isolated Ghidra pseudo-C function (or function-only LLVM IR fallback) and
  classifies one requested vulnerability class. The BusyBox benchmark runs the
  full 5 samples x 2 variants x 6 classes cross-product. All 60 tasks were run
  and scored under a hard cumulative $5 ceiling.
- **Tier B — codebase-level confirmation: not built yet.** Given a candidate
  plus the whole codebase and one specific entry point, confirm whether it is
  reachable and genuinely vulnerable. First evaluate Tier B independently on
  all known vulnerable/patched candidate pairs; only then evaluate the
  operational Tier A → Tier B cascade. This is not blind discovery.
- **Static handoff rule:** Tier A remains strictly scored, but both
  `vulnerable` and `indeterminate` cases advance to Tier B. Forwarding an
  abstention does not retroactively count it as a Tier A positive.
- **Dynamic confirmation: not started.** Fuzzing follows Tier B to validate
  confirmed findings.

The Netgear CVE-2016-6277 material under `firmware/` currently establishes
ground truth for a future Tier B case. It is not a runnable full-binary
discovery benchmark.

## Repository layout

| Path | Purpose |
|---|---|
| [`EXPERIMENT.md`](EXPERIMENT.md) | Canonical research questions, labels, handoff policy, evaluation matrices, metrics, and reporting boundaries |
| [`classify-function-vulnerabilities/`](classify-function-vulnerabilities/SKILL.md) | Canonical Tier A skill, rubrics, schema, policy, and automation |
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
First show the dry-run projection, enforce a hard cumulative $5 per-run ceiling,
wait for approval before paid API calls, and create a new named run rather
than reusing results from an earlier model or reasoning configuration.
```

For direct commands and result schemas, see
[`results/README.md`](results/README.md) and the skill's
[`SKILL.md`](classify-function-vulnerabilities/SKILL.md).

## Requirements

- Linux, Python 3, `clang`/LLVM, `git`, and Ghidra
- `OPENAI_API_KEY` only for paid Tier A execution
- Python dependencies from
  `classify-function-vulnerabilities/scripts/requirements.txt`

Do not commit API keys, proprietary firmware images, or extracted proprietary
files; see [`firmware/README.md`](firmware/README.md).
