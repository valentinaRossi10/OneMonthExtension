# IoT Firmware Vulnerability Detection via LLM Static Analysis

Research project investigating whether LLMs (via LLVM IR analysis) can identify
known vulnerability classes in IoT firmware, as a first stage of a hybrid
(static + dynamic) analysis approach.

## Status

Early stage — building the CVE benchmark and IR generation pipeline before
firmware has been provided by the mentor. See [PLAN.md](PLAN.md) for the full
step-by-step workflow.

## Repo layout

| Folder | Purpose |
|---|---|
| [`samples/`](samples/README.md) | Source code with known CVEs, used as ground truth |
| [`ir/`](ir/README.md) | LLVM IR (`.ll`/`.bc`) generated from samples and/or firmware |
| [`firmware/`](firmware/README.md) | Raw and extracted firmware images (once received) |
| [`prompts/`](prompts/README.md) | Prompt templates, one per vulnerability class |
| [`results/`](results/README.md) | LLM outputs and scoring against ground truth |
| [`scripts/`](scripts/README.md) | Automation scripts (added once API access is set up) |

## Requirements

- Linux (native or VM)
- `clang`/`llvm`, `git`, `python3`
- `binwalk` (for firmware extraction, once firmware is available)
- LLM API access (Anthropic/OpenAI) — not yet set up, manual chat UI used in the meantime

See [PLAN.md](PLAN.md) for install commands per stage.
