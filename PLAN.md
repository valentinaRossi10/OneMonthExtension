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

## Update (2026-07-12): mentor reply changed the code-representation plan

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
firmware. See `LOG.md` (2026-07-11 and 2026-07-12 entries) for the full
reasoning and the email exchange that led to this decision.

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
- No LLM API access yet — Stage 4/5 are scripted and ready to go (see
  `scripts/`), just waiting on keys (see "Getting API access" under
  Stage 5)

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

## Stage 3 — Compile samples to stripped binaries, decompile to pseudo-code (compile+strip done)

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

## Stage 4 — Prompt design per vulnerability class (done — see `prompts/`)

Built one prompt template per bug class, covering all 5 memory-safety
classes currently in `samples/index.csv`: `memory-buffer-overflow.md`,
`memory-use-after-free.md`, `memory-integer-overflow.md`,
`memory-null-pointer-dereference.md`, `memory-out-of-bounds-read.md`.

Each template:
- Takes **decompiled pseudo-C as the primary input** (per mentor's
  decision), with a fallback note prepended when a sample instead uses
  LLVM IR (pseudo-code not yet generated, or per-sample fallback per
  Stage 3 step 5).
- Names the specific pattern to look for per bug class in pseudo-C terms
  (e.g. size/allocation arithmetic without a bounds check, a pointer used
  after a `free`-equivalent call, a signed/unsigned mismatch feeding an
  allocation size), and explicitly states what *not* to flag so scoring
  stays clean across templates.
- Requests structured output (vulnerable yes/no, function/line, bug class,
  confidence, short reasoning) — see `prompts/README.md` for the exact
  format `scripts/score.py` parses.

`scripts/bug_classes.py` maps each sample's `bug_class` column to its
matching template — used by both scripts to know which prompt "should"
detect which sample's real bug.

## Stage 5 — Run the benchmark (scripted — see `scripts/`)

`scripts/run_benchmark.py` and `scripts/score.py` were built ahead of
receiving API keys, so the pipeline is ready to run as soon as they're
set up. The benchmark runs the **full cross-product** — every prompt
template against every sample, not just each sample's own matching
prompt — specifically so mismatched-prompt false positives are visible,
not just missed detections:

1. `run_benchmark.py` loops over every sample × variant
   (vulnerable/patched) × **every prompt template** × model configured in
   `scripts/models.yaml`, builds each prompt (pseudo-code if available,
   else IR fallback), calls the model, and saves raw output to
   `results/runs/<cve_id>__<variant>__<model>__<prompt-slug>.md`.
2. `score.py` parses every run and compares it against what's expected
   *given which prompt was used*: only a matching prompt on vulnerable
   code should say yes; everything else (patched code, or a
   non-matching prompt on vulnerable code) should say no. Labels each
   row `true_positive` / `false_negative` / `true_negative` /
   `false_positive`, writes `results/scoring.csv`, and prints a
   breakdown plus every false positive found (distinguishing "patched
   code flagged" from "wrong bug class hallucinated").

See `scripts/README.md` for setup instructions and `results/README.md`
for output format. Manual chat-UI runs are still fine for one-off spot
checks but are no longer the default path.

### Getting API access

- **Anthropic**: sign in at https://console.anthropic.com/, add billing,
  generate a key under Settings → API Keys, export as
  `ANTHROPIC_API_KEY`.
- **OpenAI**: sign in at https://platform.openai.com/, add billing,
  generate a key at https://platform.openai.com/api-keys, export as
  `OPENAI_API_KEY`.
- `scripts/models.yaml` already has the Anthropic models filled in
  (`claude-sonnet-5`, `claude-opus-4-8`). The OpenAI entry is a
  placeholder (`REPLACE_ME_CONFIRM_WITH_MENTOR`) — still need to confirm
  the exact model ID with the mentor (raised in an earlier email, not yet
  answered); `run_benchmark.py` skips placeholder entries with a warning
  rather than failing.
- Once keys are exported: `pip install -r scripts/requirements.txt`, then
  run `python3 scripts/run_benchmark.py` followed by
  `python3 scripts/score.py`.

## Stage 6 — Analyze and write up

Compare across models, prompt templates, and bug classes: which
combinations detect known CVEs correctly, which produce false positives,
whether IR-only is sufficient or source context is needed. This comparison
is the actual deliverable for this stage and motivates the next phase of
the hybrid approach.

## Stage 7 — Real firmware proof-of-concept (branch `W1/firmware-static-analysis`)

Everything through Stage 6 is a **calibration benchmark**: 5 hand-picked
known CVEs in one open-source project (BusyBox), compiled ourselves. This
validated the *methodology* (decompile → prompt → score), but never
tested it against a real, unmodified vendor binary, a different CPU
architecture, cross-binary vulnerabilities, or a non-memory-safety bug
class. Stage 7 is a single, small proof-of-concept addressing exactly
that gap — not an attempt to replicate the reference papers' scale (see
below).

**Target**: CVE-2016-6277 — an unauthenticated command injection via
`/cgi-bin/;<command>` on the Netgear R6400/R7000 router. Vulnerable
firmware: R6400 v1.0.1.12. Fixed firmware: R6400 v1.0.1.20 (per Netgear's
own advisory). If both versions are obtainable, this gives a real
vulnerable/patched *firmware* pair, extending the existing
vulnerable-vs-patched comparison methodology to vendor binaries instead
of self-compiled ones. Firmware source: the Karonte dataset (49 real
firmware images, Netgear/D-Link/TP-Link/Tenda — the same dataset
MANGODFA evaluates against), or Netgear's own firmware archive directly
if the exact versions are available there.

**Why this differs structurally from Stages 1-5** (see `firmware/README.md`
once created): no source code exists, so there's no `samples/`/`ir/`
equivalent — the pipeline starts directly from a compiled vendor binary.
The vulnerability is also cross-binary (one binary sets a value via NVRAM,
a different binary reads and unsafely uses it), unlike every BusyBox
sample, which was a single self-contained function. Command injection
also needs a new prompt template (`prompts/command-injection.md`) — none
of the 5 existing memory-safety templates apply.

**No-redistribution policy**: vendor firmware is proprietary, unlike
BusyBox (GPL, self-compiled). The repo will document exact download
URLs + checksums for reproducibility, but will not commit the firmware
images or the full `binwalk` extraction — only the small decompiled
pseudo-C snippet actually analyzed (the same scope PANGOLIN/MANGODFA
themselves publish in their papers, not the underlying binaries).

**Steps**:
1. Confirm both firmware versions (1.0.1.12 vulnerable, 1.0.1.20 fixed)
   are actually obtainable (Karonte dataset or Netgear's archive).
2. `binwalk -e` both images, locate the vulnerable binary(ies) — not yet
   known for certain; the CERT advisory names the endpoint
   (`/cgi-bin/`) but not the internal binary name.
3. Ghidra-decompile the vulnerable version, using the same
   string-search/structural-matching techniques already practiced on the
   BusyBox samples (real firmware is typically also stripped).
4. Decompile the patched version, diff to confirm the located code
   actually changed (same verification approach used for all 5 BusyBox
   samples).
5. Write `firmware/CVE-2016-6277-netgear-r6400/info.md`,
   `pseudo-code/{vulnerable,patched}/`, and `index.csv`.
6. Add `prompts/command-injection.md` and the matching entry in
   `scripts/bug_classes.py`.
7. Run through the existing `run_benchmark.py`/`score.py` pipeline
   unchanged (it's already generic over `samples/index.csv`-shaped
   input; may need a small extension to also read `firmware/index.csv`).

### Explicitly out of scope for now: large-scale evaluation

All 4 reference papers' actual headline contributions are large-scale
**zero-day discovery** runs, not known-CVE validation:

| Paper | Firmware images | Result |
|---|---|---|
| FirmAgent | 14 | 182 vulnerabilities, 140 previously unknown, 17 CVEs assigned |
| HermeScan | 30 (0-day set) + 98 (N-day set) | 163 vulnerabilities in the 0-day set |
| MANGODFA | 49 + 7 + 1,698 (large-scale) | 83,644 raw alerts → 70 PoC-verified vulnerabilities |
| PANGOLIN | 12 real devices, 8 vendors | 68 previously unknown, 31 CVEs assigned |

This is two-plus orders of magnitude beyond what's realistic for a
one-month solo extension (their scale reflects teams of 5-9 researchers
over months, plus real vendor-disclosure processes). Genuinely scaling
up — acquiring many real firmware images (e.g. the full 49-image Karonte
dataset) and either validating against many known CVEs or running actual
unlabeled exploratory scanning across every extracted binary — is a
legitimate, meaningful next step **after** the single-CVE proof-of-concept
above works, but is a real scope/time decision (weeks of compute and
manual triage) that should be discussed explicitly with the mentor rather
than assumed as an automatic continuation.

## Immediate next actions

1. ~~Stage 0: environment setup.~~ Done.
2. ~~Stage 1: pick 3-5 CVEs, pull vulnerable source, log in
   `samples/index.csv`.~~ Done — 5 samples, 5 memory-safety CWE classes.
3. ~~Stage 2: generate `.ll` files for each sample.~~ Done — all 5 samples
   have verified vulnerable/patched LLVM IR pairs in `ir/`.
4. ~~Stage 3: compile the 5 samples to binaries, strip them, decompile to
   pseudo-C.~~ Done — all 5 samples have verified vulnerable/patched
   linked+stripped executables in `binaries/` and decompiled pseudo-C in
   `pseudo-code/` (4 full pairs + `CVE-2021-42386`'s intentional
   vulnerable-only case). See `LOG.md` for the relocation-bug,
   `FEATURE_IPV6` dependency bug, and `FEATURE_UDHCPC6_RFC3646` dependency
   bug caught and fixed along the way — no cleanup pass needed, per the
   2026-07-12 assessment (small, self-contained functions decompiled
   cleanly).
5. ~~Stage 4: build prompt templates per bug class.~~ Done — see
   `prompts/`.
6. ~~Stage 5: script the benchmark runner + scorer.~~ Done — see
   `scripts/`. Not yet actually run (no API keys configured yet); will now
   use `pseudo-code/` as primary input for 5/5 samples (falling back to
   `ir/` only for `CVE-2021-42386`'s patched variant, by design).
7. Still to confirm with mentor: exact OpenAI model ID for the benchmark
   (raised in earlier email, not yet answered — his reply so far only
   addressed the code-representation question).
8. **Ready to run once API keys exist** — the full pipeline (samples → IR
   → binaries → pseudo-code → prompts → scripts) is complete end to end.
9. Stage 7 (started, branch `W1/firmware-static-analysis`): confirm the
   Netgear R6400 firmware (v1.0.1.12 vulnerable, v1.0.1.20 fixed) is
   actually obtainable, then extract/decompile/compare per the steps
   above.
