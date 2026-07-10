# Plan: LLM-based Static Analysis of IoT Firmware

## Context

Mentor's proposed approach for the first (static analysis) stage of a hybrid
IoT vulnerability detection project:

1. Download firmware (link to be provided by mentor).
2. Convert firmware to LLVM IR.
3. Use an LLM to identify vulnerabilities in the IR.
4. Validate against code with already-known vulnerabilities (CVEs), to check
   whether the LLM actually finds them.
5. Engineer prompts ("skills") specialized per bug class, starting with
   memory vulnerabilities.

Suggested models: to be confirmed with mentor (exact identifiers unclear as
of writing — "GPT-5.6" / "Claude 5" need verifying against real API model
names before use).

## Key clarification: two possible cases

"Convert firmware to LLVM IR" is not a single well-defined step — it depends
on what form the firmware takes:

- **Case A — source code available**: compile directly to IR with
  `clang -emit-llvm`. Straightforward.
- **Case B — binary-only firmware image** (the more likely case for a vendor
  firmware download): no source exists, so a **binary lifter** (RetDec,
  McSema, Remill) is needed to reconstruct LLVM IR from the disassembled
  binary. This is lossy and architecture-dependent (ARM/MIPS common in IoT),
  and is a nontrivial task on its own.

Since nothing has been received from the mentor yet, this plan covers both
cases, and sequences work so that progress doesn't block on which case
applies.

## Environment

- Linux (native or VM)
- New to LLVM/binary analysis tooling — plan assumes a learning ramp-up
- No LLM API access yet — Stage 4/5 done manually via chat UI until keys are
  available

## Stage 0 — Environment setup

Not dependent on firmware; do this first.

```bash
sudo apt update
sudo apt install build-essential clang llvm git python3 python3-pip binwalk
clang --version
```

## Stage 1 — Build a CVE ground-truth benchmark (start immediately)

Independent of the firmware link — do this now.

- Pick 3-5 CVEs in C code from projects actually used in IoT firmware
  (BusyBox, dnsmasq, uClibc/musl, lighttpd, older OpenSSL).
- Use NVD (nvd.nist.gov) to find CVE IDs and affected versions.
- Use the project's git history to find the exact fixing commit and get the
  vulnerable version:
  ```bash
  git clone <upstream-repo>
  git log --oneline -- <affected_file>
  git show <fixing_commit_hash>
  git checkout <commit_before_fix>
  ```
- Cover at least 2 bug classes to start (e.g. buffer overflow,
  use-after-free).
- Log each sample in `samples/index.csv`: cve_id, project, file, function,
  line, bug_class, description.

Output goes in `samples/`.

## Stage 2 — Generate LLVM IR from source

Applies to all `samples/` and to firmware if Case A applies.

```bash
clang -S -emit-llvm -g -O0 <file.c> -o <file.ll>
```
- `-g`: keep debug info (line numbers), to map IR back to source.
- `-O0`: avoid optimizing away the vulnerable pattern.

For multi-file builds, capture the full build with `Bear` or `WLLVM` instead
of invoking clang directly on one file.

Output goes in `ir/`.

## Stage 3 — Firmware, once received

Determine which case applies (source vs binary-only) and proceed
accordingly:

**Case A (source):** reuse Stage 2.

**Case B (binary):**
1. Extract: `binwalk -e firmware.bin`
2. Identify architecture: `file <extracted_binary>`
3. Lift to LLVM IR with RetDec first (lowest setup cost); fall back to
   McSema/Remill only if RetDec proves insufficient.

Recommendation: prioritize Stages 1-2 and get a working source-based
benchmark before investing time in binary lifting, since lifting is the
hardest and least certain part of the pipeline.

Output goes in `firmware/` (raw/extracted, not committed to git) and `ir/`.

## Stage 4 — Prompt design per vulnerability class

Build one prompt template per bug class (start with memory safety: buffer
overflow, use-after-free, double-free; expand to integer overflow, format
string, etc. later).

Each template should:
- Name the specific IR-level pattern to look for (e.g. unchecked
  `getelementptr` offsets, `memcpy`/`strcpy` calls without bounds checks).
- Take `.ll` IR as input; test IR-only vs IR+source as a variable.
- Request structured output (vulnerable yes/no, function/line, bug class,
  confidence, short reasoning) for easy scoring.

Output goes in `prompts/`.

## Stage 5 — Run the benchmark

No API access yet, so run manually:
1. Paste each `ir/*.ll` sample into the chat UI (claude.ai / chatgpt.com)
   with each relevant prompt template.
2. Save raw output in `results/runs/`.
3. Score against `samples/index.csv` (hit / miss / false positive) in
   `results/scoring.csv`.

## Stage 6 — Analyze and write up

Compare across models, prompt templates, and bug classes: which
combinations detect known CVEs correctly, which produce false positives,
whether IR-only is sufficient or source context is needed. This comparison
is the actual deliverable for this stage and motivates the next phase of
the hybrid approach.

## Optional — automation (once API access exists)

Script Stages 4-5 with the Anthropic/OpenAI SDKs (`scripts/run_benchmark.py`,
`scripts/score.py`) to loop over samples x templates x models automatically.

## Immediate next actions (this week, unblocked by firmware)

1. Stage 0: environment setup.
2. Stage 1: pick 3-5 CVEs, pull vulnerable source, log in `samples/index.csv`.
3. Stage 2: generate `.ll` files for each sample.
4. Confirm with mentor: exact model names/versions, and whether Case A or
   Case B applies to the firmware he'll send.
