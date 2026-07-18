# Pipeline overview

Start here for a quick understanding of the project. This is a narrative
walkthrough of the pipeline as it exists today, with a brief note on
*why* each major decision was made. For full chronological detail
(debugging steps, exact commands, every dead end), see `LOG.md`. For the
current stage checklist and next actions, see `PLAN.md`.
For the normative task matrices, labels, handoff policy, metrics, and reporting
boundaries, see `EXPERIMENT.md`.

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
incomplete. LLVM IR is kept as that fallback. The Tier A preparer chooses
pseudo-C first and extracts only the target function from LLVM IR when a
pseudo-C variant is unavailable.

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

## Stage 4-5 — Tier A prompt design and automated benchmark

Tier A uses a common isolated-function classification scaffold plus a
class-specific rubric for each of the six supported vulnerability
classes. The prompt explicitly forbids caller/callee assumptions and
exploitability claims, and requests one strict JSON object containing the
verdict (`vulnerable`, `not_vulnerable`, or `indeterminate`), confidence,
evidence, and short reasoning. The canonical prompt construction and
rubrics live in `classify-function-vulnerabilities/`; the earlier root
prompt templates have been retired.

**Why the benchmark runs every class against every sample (a full
cross-product), not just each sample's matching class**: running only
matched pairs only measures "can it find the bug when told exactly what
class to look for" — it never tests whether the classifier stays quiet on
code that doesn't have that bug, so mismatched-class false positives are
never exercised. The cross-product design lets the scorer distinguish
"the class-specific check correctly found the real bug" from "an
unrelated class check hallucinated one." The task-level records and
aggregate metrics are stored inside each experiment under
`results/tier-a/runs/<run-id>/scoring/`.

The runner is intentionally fail-closed: it prepares and validates the
complete 60-task manifest before API use, rejects oversized or malformed
inputs, treats refusals/invalid JSON as explicit non-scorable outcomes,
and enforces the hard cumulative USD ceiling before every request. A
retry is allowed only for the exact reviewed task and remains inside the
same cumulative ledger and ceiling. Every experiment has an immutable run
directory, frozen model/reasoning configuration, and a README describing
how it differs from the preceding experiment; scored runs can be compared
at both metric and task level without further API calls.

The Codex-generated Tier A benchmark was run end-to-end on 2026-07-18:
60/60 tasks returned valid structured results and were scored. See
`results/tier-a/` and the corresponding `LOG.md` entry for metrics, cost,
and the configuration-recovery caveat.

## Stage 6-7 — Real firmware ground truth for Tier B

Stage 1-5 validated isolated-function classification on binaries fully
under our control (self-compiled, x86-64, single functions). The Netgear
case adds a real, unmodified vendor binary, a different CPU architecture,
and command injection. It currently provides researched ground truth for
Tier B; it is not a completed or runnable whole-binary discovery
benchmark in this repository.

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

**Key methodology decision — ground truth vs. what the LLM will see.** An
earlier design proposed showing the LLM every function and asking it to
discover the vulnerable function. That is no longer the intended next
tier. Tier B starts with the already-flagged candidate
`netgear_commonCgi`, one specific entry point (`parse_http_request`), and
the whole available codebase; it asks whether the candidate is reachable
and genuinely vulnerable from that entry point. Manual Ghidra work is
used only to establish the candidate, entry point, and expected path
through `handle_get`, not as model evidence.

Selecting the binary or discovering an unknown candidate across a
firmware image remains out of scope. It is a separate hard problem
(described as "border binary" selection in MANGODFA) and is not measured
by either the completed Tier A benchmark or the planned Tier B
confirmation task.

**Also deliberately out of scope**: replicating the reference papers'
actual scale. Their headline results are large-scale zero-day discovery
across 14-1,698 real firmware images (teams of researchers, months of
work); this project's one-CVE, one-binary proof-of-concept is a
calibration step for that, not an attempt to match it.

The repository currently retains selected vulnerable/patched pseudo-code,
ground-truth metadata, and the reusable headless Ghidra export script. It
does not retain a complete 2,011-function corpus or a Tier B prompt,
runner, manifest, or results. Those must be designed and costed before a
Tier B execution can be claimed.

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
  isolation, classify whether it looks vulnerable. Its Codex-generated
  skill, guarded runner, and completed result set are now the canonical
  implementation.
- **Tier B** is new: given the *whole codebase* plus a candidate
  function that's already been flagged (by Tier A, or known from ground
  truth), determine whether it's *actually* vulnerable by tracing
  reachability from **one specific entry point**. This is a
  confirmation task, not a discovery task — it assumes the "where to
  look" question is already answered, and asks instead "is this
  reachable and real, or a false positive that only looks dangerous in
  isolation."

**Three evaluations, kept separate**: Tier A is scored strictly, so
`indeterminate` remains an abstention rather than being relabeled positive.
Tier B is first evaluated with oracle candidates on all five known BusyBox
vulnerable/patched pairs, independent of Tier A, so Tier B capability is not
confounded by candidate selection. A later cascade experiment forwards both
Tier A `vulnerable` and `indeterminate` cases to Tier B and measures selection
recall, surviving false positives, and workload. This lets a suspicious but
context-limited result such as the OOB-read abstention reach Tier B without
weakening Tier A's already-challenging false-positive threshold.

**Why this framing is better than the earlier discarded draft**: Stage
6/7's `netgear_commonCgi` case is exactly this shape — the unsafe
`strcpy`/`system()` pattern only matters because it's reachable from the
`/cgi-bin/` HTTP entry point through `parse_http_request` →
`handle_get`. A function-level classifier can flag the *pattern*
without ever confirming the *reachability* that makes it a real,
exploitable bug versus dead code or an unreachable branch. Tier B
targets exactly that gap, using the whole codebase as context rather
than one isolated function.

**Working method**: Tier A has been implemented and run from its reviewed
skill definition. For Tier B, first review a separate skill definition
that fixes the candidate, entry point, allowed context, output schema,
evaluation rules, and spending safeguards; only then generate automation
and prepare a dry-run manifest for approval.

The complete normative protocol, including model-visible information and
what may be claimed from each evaluation, is in `EXPERIMENT.md`.

**Stage 9** (dynamic analysis, fuzzing) follows to confirm Stage 8's
findings, closing the loop on the project's original hybrid
static + dynamic framing.

Exploration branch: `W2/skills-creation`.

## Current status

The BusyBox Tier A calibration is complete: all 60 cross-product tasks
were executed and scored under the $5 ceiling, with a $1.889030
conservative local cost ledger. Netgear CVE-2016-6277 has documented
ground truth and selected decompiled functions, but Tier B automation and
a complete codebase input package have not yet been built. Dynamic
confirmation is also not started.

## Repo structure

```
samples/       CVE source (vulnerable/patched pairs), the ground truth
ir/            LLVM IR — fallback representation, not primary anymore
binaries/      Compiled, linked, stripped executables for the 5 samples
pseudo-code/   Ghidra-decompiled pseudo-C for the 5 samples (primary input)
classify-function-vulnerabilities/  Canonical Tier A skill and automation
.codex/skills/ Skill discovery link for new Codex sessions
scripts/       Reusable Ghidra extraction support
firmware/      Tier B case-study ground truth and selected pseudo-code
results/tier-a/ Immutable Tier A runs plus derived run comparisons
skills/        Methodology/design provenance notes
EXPERIMENT.md  Canonical experiment protocol and reporting rules
```
