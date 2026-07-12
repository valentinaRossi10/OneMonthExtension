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

## Update (2026-07-11): mentor reply changed the code-representation plan

The mentor sent 4 reference papers (FirmAgent, HermeScan, MANGODFA, PANGOLIN)
and pointed to Ghidra/angr. Reading those papers surfaced a real design
question: they split into two paradigms — deterministic static analysis on
raw IR (HermeScan/MANGODFA, via angr/VEX, no LLM) vs. LLM-driven reasoning
on **decompiled pseudo-code** (FirmAgent/PANGOLIN, via IDA Pro). Since this
project's design uses an LLM as the analysis engine, the pseudo-code
paradigm is the closer precedent — confirmed by the mentor's reply:

> "You can start with the decompiled pseudo-code from the binary. Since
> binaries may adopt various strategies to thwart decompilation, the
> decompiled pseudo-code may miss some potentially vulnerable code. If you
> encounter such cases, you could revert to using IR or even disassembly
> code."

**This supersedes the original "convert firmware to LLVM IR" framing below.**
Decompiled pseudo-code (via Ghidra) is now the primary representation shown
to the LLM; LLVM IR (already generated in Stage 2), VEX IR (angr), Ghidra
P-code, or raw disassembly are documented fallbacks for cases where
pseudo-code analysis misses a known-vulnerable pattern.

A related methodology correction: the binaries must be **stripped** before
decompiling (`strip <binary>`), not compiled with debug symbols retained.
Real deployed firmware (what FirmAgent/PANGOLIN analyze, and what this
project ultimately targets) ships stripped, with no variable/function
names — decompiling an unstripped binary would hand the LLM human-chosen
names (`addrs`, `dlist`) as a free hint unrelated to actual vulnerability
reasoning, inflating results in a way that wouldn't transfer to real
firmware. See `LOG.md` (2026-07-11 entries) for the full reasoning and the
email exchange that led to this decision.

## Key clarification: two possible cases (original framing, superseded above)

"Convert firmware to LLVM IR" is not a single well-defined step — it depends
on what form the firmware takes:

- **Case A — source code available**: compile directly to IR with
  `clang -emit-llvm`. Straightforward.
- **Case B — binary-only firmware image** (the more likely case for a vendor
  firmware download): no source exists, so a **binary lifter** (RetDec,
  McSema, Remill) is needed to reconstruct LLVM IR from the disassembled
  binary. This is lossy and architecture-dependent (ARM/MIPS common in IoT),
  and is a nontrivial task on its own.

This framing is kept for history; per the mentor's reply above, decompiled
pseudo-code (Ghidra) is now the primary route for binary-only samples,
rather than binary-lifting straight to LLVM IR.

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

## Stage 3 — Compile samples to stripped binaries, decompile to pseudo-code

Applies to the 5 existing vulnerable/patched CVE samples now (not waiting on
firmware — see Update above). For real firmware, once received, the same
pipeline applies: extract with `binwalk -e firmware.bin`, identify
architecture (`file <extracted_binary>`), then decompile directly (no
compile step needed, it's already a binary).

For the CVE samples:
1. Compile each vulnerable/patched version normally to a binary (same
   commits/build-flag approach as Stage 2, but without `-emit-llvm`).
2. **Strip debug symbols**: `strip <binary>` — mandatory, not optional (see
   Update above for why: matches real firmware, avoids handing the LLM
   human-chosen variable names as a free hint).
3. Install Ghidra, decompile each stripped binary to pseudo-C (headless
   analyzer + a decompiler script — see `LOG.md` for the specific API
   calls).
4. Inspect the pseudo-C output manually before building any cleanup
   tooling — with only 5 small, known functions, check by eye whether the
   output is already LLM-readable (likely yes, per PANGOLIN/FirmAgent's
   documented cleanup needs being driven by *large-scale, complex*
   binaries, not small isolated functions). Only build a
   regex/normalization cleanup pass (PANGOLIN-style) or an LLM refinement
   step (FirmAgent-style) if specific problems actually show up.
5. Fallback path (per mentor's guidance): if a sample's decompiled
   pseudo-code looks like it's missing or garbling the known-vulnerable
   logic (anti-decompilation effects), fall back to that sample's LLVM IR
   (already have it) or generate VEX IR (angr) / raw disassembly instead,
   and note this per-sample in `info.md`.

Output goes in `pseudo-code/<sample-name>/{vulnerable,patched}.c` (new
folder, mirroring the `ir/` structure), keeping `ir/` as the fallback
reference.

## Stage 4 — Prompt design per vulnerability class

Build one prompt template per bug class (start with memory safety: buffer
overflow, use-after-free, double-free; expand to integer overflow, format
string, etc. later).

Each template should:
- Take **decompiled pseudo-C as the primary input** (per mentor's
  decision), with LLVM IR/VEX IR/disassembly available as a fallback input
  for samples where pseudo-code is insufficient.
- Name the specific pattern to look for per bug class in pseudo-C terms
  (e.g. size/allocation arithmetic without a bounds check, a pointer used
  after a `free`-equivalent call, a signed/unsigned mismatch feeding an
  allocation size) — analogous to, but adapted from, the earlier
  IR-level patterns (unchecked `getelementptr` offsets,
  `memcpy`/`strcpy` calls without bounds checks).
- Request structured output (vulnerable yes/no, function/line, bug class,
  confidence, short reasoning) for easy scoring.

Output goes in `prompts/`.

## Stage 5 — Run the benchmark

No API access yet, so run manually:
1. Paste each `pseudo-code/*.c` sample into the chat UI (claude.ai /
   chatgpt.com) with each relevant prompt template. For any sample using
   the IR fallback, paste the corresponding `ir/*.ll` file instead and
   note this in the results.
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

## Immediate next actions

1. ~~Stage 0: environment setup.~~ Done.
2. ~~Stage 1: pick 3-5 CVEs, pull vulnerable source, log in
   `samples/index.csv`.~~ Done — 5 samples, 5 memory-safety CWE classes.
3. ~~Stage 2: generate `.ll` files for each sample.~~ Done — all 5 samples
   have verified vulnerable/patched LLVM IR pairs in `ir/`.
4. Stage 3 (current): compile the 5 samples to binaries, strip them,
   install Ghidra, decompile to pseudo-C, check if cleanup is actually
   needed.
5. Still to confirm with mentor: exact model names/versions for the
   benchmark (raised in earlier email, not yet answered — his reply so far
   only addressed the code-representation question).
