# Pipeline overview

Start here for a quick understanding of the project. This is a narrative
walkthrough of the pipeline as it exists today, with a brief note on
*why* each major decision was made. For full chronological detail
(debugging steps, exact commands, every dead end), see `LOG.md`. For the
current stage checklist and next actions, see `PLAN.md`.

## Goal

Use LLMs to detect known memory-safety and command-injection
vulnerabilities in IoT firmware code, as the static-analysis half of a
larger hybrid (static + dynamic) vulnerability-detection project. This
phase validates the static-analysis methodology before it feeds into a
later dynamic-analysis (fuzzing) phase.

## Stage 1 — CVE benchmark: 5 known BusyBox vulnerabilities

Picked 5 real, historical CVEs in BusyBox (a project genuinely used in
IoT firmware), one per memory-safety bug class (heap buffer overflow,
use-after-free, integer overflow, NULL pointer dereference,
out-of-bounds read), each as a vulnerable/patched source pair verified
directly against the real fixing commit.

**Why memory safety first, and why BusyBox**: a common, well-documented
open-source target with a clear git history made it possible to build a
verifiable ground-truth benchmark quickly, without waiting on firmware
access. Memory-safety CWEs were the most direct fit for the mentor's
original framing of the project.

## Stage 2 — LLVM IR (superseded as primary input, kept as fallback)

Initially compiled each sample to LLVM IR (`clang -emit-llvm`), following
the mentor's first description of the pipeline.

**Why revisited**: the mentor sent 4 reference papers (FirmAgent,
HermeScan, MANGODFA, PANGOLIN). Reading them revealed two different
paradigms — deterministic static analysis on raw IR (HermeScan/MANGODFA,
no LLM) vs. LLM-driven reasoning on decompiled pseudo-C (FirmAgent/
PANGOLIN). Since this project uses an LLM as the analysis engine, the
pseudo-C paradigm is the closer precedent — confirmed by the mentor's
reply: pseudo-code is the primary representation, with IR/disassembly as
an explicit fallback for cases where decompilation fails or looks
incomplete. LLVM IR is kept and used automatically as that fallback
(`run_benchmark.py` checks for pseudo-C first, falls back to `.ll`).

## Stage 3 — Compile, strip, and decompile the 5 samples

Compiled each sample to a real linked ELF executable, stripped it, then
decompiled it with Ghidra to pseudo-C.

**Why stripped, not compiled with debug symbols**: real deployed firmware
ships stripped, with no variable/function names. Decompiling an
unstripped binary would hand the LLM human-chosen names as a free hint
unrelated to actual vulnerability reasoning, inflating results in a way
that wouldn't transfer to real firmware — this was caught before
implementing, not after.

**Two real bugs found and fixed in this stage** (full detail in `LOG.md`):
stripping an *unlinked* object file destroys its relocation table (since
relocations only resolve at link time), producing garbage decompiler
output — fixed by linking the full executable first, then stripping. And
`-ffunction-sections` (part of BusyBox's normal build flags) left
per-function ELF section names surviving `strip --strip-all`, silently
leaking which function was the target — fixed with
`objcopy --rename-section`.

Ghidra decompilation itself was done manually via the GUI, one function
at a time, using string-literal searches and structural matching to
locate each target function in a stripped binary with no symbol names.

## Stage 4-5 — Prompt design and automated benchmark

One prompt template per bug class, each describing the pattern in
pseudo-C terms and requesting a structured, parseable verdict
(`Vulnerable: yes/no`, function/line, bug class, confidence, reasoning).

**Why the benchmark runs every prompt against every sample (a full
cross-product), not just each sample's matching prompt**: running only
matched pairs only measures "can it find the bug when told exactly what
class to look for" — it never tests whether a prompt stays quiet on code
that doesn't have that bug, so mismatched-prompt false positives were
never exercised. The cross-product design lets the scorer distinguish
"the specialized prompt correctly found the real bug" from "an unrelated
prompt hallucinated one" (`true_positive`/`false_negative`/
`true_negative`/`false_positive` categories in `results/scoring.csv`).

Not yet run end-to-end — blocked on API budget approval (see below).

## Stage 6 — Real firmware proof-of-concept

Stage 1-5 validated the *methodology* on binaries fully under our
control (self-compiled, x86-64, single self-contained functions). None of
that tests a real, unmodified vendor binary, a different CPU architecture,
a different bug class, or genuine discovery (finding a bug without being
told where to look).

**Target**: CVE-2016-6277, an unauthenticated command injection on the
Netgear R6400/R7000 router (`/cgi-bin/;<command>`), in `usr/sbin/httpd`.
Chosen over a similar example from one of the reference papers because it
has a real, formally assigned CVE ID and documented vulnerable (v1.0.1.12)
and fixed (v1.0.1.20) firmware versions — obtained directly from Netgear,
after checking that the originally-planned dataset (Karonte, used by
MANGODFA) actually referenced a different, already-patched model/version
and would not have contained this bug.

**Root cause, confirmed by decompiling and diffing both firmware
versions**: `netgear_commonCgi` copies the URL substring after `cgi-bin/`
into a 64-byte buffer via `strcpy` with no sanitization, then splices it
into a shell command string executed via `system()`. The real fix (in
v1.0.1.20) doesn't remove this pattern — it adds a blocklist (rejecting
`;`, `` ` ``, `$`, `..`) and an allowlist (of permitted CGI names) in
front of it, which closes the documented exploit but leaves the
underlying unsafe pattern in place, and doesn't block every shell
metacharacter (e.g. `|`, `&`, `>`, `<`).

**Key methodology decision — ground truth vs. what the LLM sees.** The
first draft of this phase had us manually locate the one known-vulnerable
function and hand *only that function* to the LLM — which would have
just repeated Stage 3's methodology on an uglier binary, testing nothing
new (no real discovery, no way to test cross-binary reasoning). Corrected
this: manual Ghidra work is for establishing ground truth only; the LLM
is shown *every* function in the binary (1004 vulnerable + 1007 patched,
bulk-decompiled via a custom headless Ghidra script), scored on whether
it correctly picks out the one real vulnerable function among hundreds
and stays quiet on everything else.

**A related scoping question, deliberately left unresolved for now**:
even "every function in one binary" is still a hint (which binary to even
look at, out of ~127 in a typical firmware image). Deciding *which*
binary is worth deep analysis is itself a hard, named problem in the
literature (MANGODFA calls it "border binary" selection, and cites real
missed vulnerabilities caused by earlier tools' selection heuristics).
Solving that is out of scope for this proof-of-concept — noted explicitly
as a harder future step, not silently absorbed into this phase's claims.

**Also deliberately out of scope**: replicating the reference papers'
actual scale. Their headline results are large-scale zero-day discovery
across 14-1,698 real firmware images (teams of researchers, months of
work); this project's one-CVE, one-binary proof-of-concept is a
calibration step for that, not an attempt to match it.

Scoped to run only the command-injection prompt (not the full 5-prompt
cross-product) against every function — running the full cross-product at
this scale (~2,011 functions) would be ~5x the API cost for little added
value here.

## Stage 8 — Codebase-level vulnerability confirmation (planned, not started)

An earlier draft of this stage (explored 2026-07-15/16, since discarded)
proposed letting the model search an entire binary from scratch,
choosing its own path via tools like string search and call-graph
lookup, to *discover* an unknown vulnerability among hundreds of
functions with no prior hint. The supervisor's guidance on 2026-07-17
refined this into something more precisely scoped, and split it from
what Stage 1-5's function-level tier already does correctly.

**Two tiers, not one**:
- **Tier A** is exactly Stage 1-5's approach: given one function in
  isolation, classify whether it looks vulnerable. The methodology is
  approved as-is — but not the existing hand-written scripts themselves,
  which are expected to be superseded by Codex-generated automation for
  this tier too (see working method below), same as Tier B.
- **Tier B** is new: given the *whole codebase* plus a candidate
  function that's already been flagged (by Tier A, or known from ground
  truth), determine whether it's *actually* vulnerable by tracing
  reachability from **one specific entry point**. This is a
  confirmation task, not a discovery task — it assumes the "where to
  look" question is already answered, and asks instead "is this
  reachable and real, or a false positive that only looks dangerous in
  isolation."

**Why this framing is better than the earlier discarded draft**: Stage
6/7's `netgear_commonCgi` case is exactly this shape — the unsafe
`strcpy`/`system()` pattern only matters because it's reachable from the
`/cgi-bin/` HTTP entry point through `parse_http_request` →
`handle_get`. A function-level classifier can flag the *pattern*
without ever confirming the *reachability* that makes it a real,
exploitable bug versus dead code or an unreachable branch. Tier B
targets exactly that gap, using the whole codebase as context rather
than one isolated function.

**Working method**: build Stage 8 using Codex in VS Code, which has
full-repo context, rather than hand-writing prompts and scripts as in
earlier stages. The task is to summarize the skill needed for each tier
(one for Tier A's function-level task, one for Tier B's codebase-level
task), then let the agent generate the actual Python automation —
scripts and result files — from those skill definitions.

**Stage 9** (dynamic analysis, fuzzing) follows to confirm Stage 8's
findings, closing the loop on the project's original hybrid
static + dynamic framing.

Exploration branch: `W2/skills-creation`.

## Current status

Both benchmarks (BusyBox calibration, real-firmware discovery) are fully
built and verified, blocked only on API budget approval. Estimated cost:
~$1.90 for the BusyBox benchmark, ~$50-70 for the firmware benchmark
across both configured models (measured from actual file sizes, not
guessed) — see the email thread with the mentor for the full breakdown
and the staged spending plan (cheap dry run → one model → second model)
proposed to keep the larger run from being a blind, single-shot spend.

## Repo structure

```
samples/       CVE source (vulnerable/patched pairs), the ground truth
ir/            LLVM IR — fallback representation, not primary anymore
binaries/      Compiled, linked, stripped executables for the 5 samples
pseudo-code/   Ghidra-decompiled pseudo-C for the 5 samples (primary input)
prompts/       One prompt template per bug class
scripts/       Benchmark runners + scorers (BusyBox and firmware variants)
firmware/      Real-firmware phase: ground truth, ground_truth.csv, ExportAllFunctions.java
results/       Raw model output + scoring, once runs happen
```
