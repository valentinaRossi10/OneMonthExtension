# IoT Firmware Vulnerability Detection via LLM Static Analysis

Research project investigating whether LLMs can identify known
vulnerability classes in IoT firmware code, as the static-analysis half
of a hybrid (static + dynamic) vulnerability-detection approach.

**Start here: [`PIPELINE.md`](PIPELINE.md)** — a narrative walkthrough of
the full pipeline with a brief note on why each major decision was made.

## Status

Both benchmarks are built and verified:
- A 5-sample CVE calibration benchmark (BusyBox, memory-safety bugs),
  self-compiled and Ghidra-decompiled.
- A real-firmware proof-of-concept (Netgear R6400, CVE-2016-6277 command
  injection), with all ~2,000 functions from the real vendor binary
  bulk-decompiled.

Both are blocked on API budget approval before running for real. See
[`PLAN.md`](PLAN.md) for the current stage checklist and
[`LOG.md`](LOG.md) for the full chronological/debugging history.

## Repo layout

| Folder | Purpose |
|---|---|
| [`samples/`](samples/README.md) | CVE source (vulnerable/patched pairs) — the calibration ground truth |
| [`ir/`](ir/README.md) | LLVM IR — fallback representation, not primary |
| [`binaries/`](binaries/README.md) | Compiled, linked, stripped executables for the 5 CVE samples |
| [`pseudo-code/`](pseudo-code/README.md) | Ghidra-decompiled pseudo-C for the 5 CVE samples (primary LLM input) |
| [`firmware/`](firmware/README.md) | Real-firmware phase: ground truth, bulk-export tooling, no-redistribution policy |
| [`prompts/`](prompts/README.md) | Prompt templates, one per vulnerability class |
| [`scripts/`](scripts/README.md) | Benchmark runners + scorers (BusyBox and firmware variants) |
| [`results/`](results/README.md) | Raw LLM output and scoring, once runs happen |

## Requirements

- Linux (native or VM)
- `clang`/`llvm`, `git`, `python3`, `binwalk`, Ghidra (manual install)
- LLM API access (Anthropic/OpenAI) — see `PLAN.md`'s "Getting API
  access" section

See [`PLAN.md`](PLAN.md) for install commands per stage.
