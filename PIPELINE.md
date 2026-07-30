# Pipeline overview

Start here for a quick understanding of the project. This is a narrative
walkthrough of the pipeline as it exists today, with a brief note on
*why* each major decision was made. For the current stage checklist and
next actions, and full chronological detail (debugging steps, exact
commands, every dead end), see `LOG.md` (Part 1: stage checklist; Part
2: chronological log — merged from the former separate `PLAN.md`).
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

The active policy-v8 transport uses synchronous server-sent-event streaming
with SDK retries disabled. Transport mode and retry policy are frozen in the
manifest/cache identity. This replaces policy-v7 background polling after a
background response reported and billed 27,565 output tokens despite a
4,500-token request cap; the runner now also stops on any such usage breach.

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

## Stage 8 — Codebase-level vulnerability confirmation

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

**Working method**: The historical fixed-candidate oracle protocol and runs
remain under `confirm-vulnerability-reachability/` and `results/tier-b/`.
The protocol-v6 redesign is a separate recall-first filter implemented in
`confirm-and-filter-vulnerabilities/`. It consumes frozen Tier A rows,
coalesces only exact `(artifact-scoped function UID, target class)` duplicate
cases while preserving all provenance, and routes every ambiguous row to
`retain_and_escalate`.

The MVP package is intentionally narrower than a general static-analysis
engine. A Ghidra Program Model export supplies content-bound function
identities, analyzed direct calls, and explicit unresolved indirect-call
sites. Suppression requires a complete rejection proof and is blocked by
material identity or unresolved-dispatch uncertainty. SSA, dominators,
def-use slices, indirect-target resolution, a second provider, deterministic
analyzer fallback, and staffed human review are deferred.

The complete normative protocol, including model-visible information and
what may be claimed from each evaluation, is in `EXPERIMENT.md`.

The protocol-v6 MVP's six-case pilot (`confirm-and-filter-vulnerabilities/`)
confirmed 2/4 real vulnerabilities, correctly suppressed one genuine Tier A
false positive, and honestly retained the 3 remaining cases as capability-gap
limitations (no SSA, dominators, def-use slicing, or symbolic range
analysis by design). Per supervisor direction — tolerate function-level
false negatives if the codebase level catches them; augment with fuller
Ghidra output and agent-orchestrated def-use/slicing/dominance/call-graph
tools plus targeted angr rather than build a new static-analysis framework
— a second skill, `confirm-and-filter-vulnerabilities-static/`, was built
as a separate fork adding exactly those tools, plus a `--force-include`
mechanism that pulled the one Tier A false negative (CVE-2021-42386, UAF)
into Tier B for the first time. Three verified rounds each fixed a distinct,
independently confirmed root cause (tools built but never invoked; framing
applied once instead of per-request and a retry-budget gap; a narrower
scheduling gap and a persistent provider-side content-safety rejection).
CVE-2017-15873 and CVE-2021-42374 are accepted as static-analysis-stage
limitations, with resolution deferred to Stage 9; CVE-2021-42386's static
result already stands as a complete, non-starved attempt (all required
tools exhausted, angr timed out). Full detail in `results/OVERALL_RESULTS.md`.

## Stage 9 — Dynamic analysis (fuzzing)

Closes the loop on the project's original hybrid static + dynamic framing,
and does the concrete work Stage 8 explicitly could not: resolve
CVE-2017-15873 and CVE-2021-42374, its Priority-1 targets. Full design in
`DYNAMIC-ANALYSIS-PLAN.md`.

**Methodology**: a blind two-phase LLM seed-generation process per CVE —
Phase 1, an isolated subagent with no vulnerability framing at all extracts
field structure and boundary values purely as a descriptive/structural task
from the relevant spec or code; Phase 2, seeds built mechanically from that
extraction with no further vulnerability-aware judgment. This replaced an
earlier hand-crafted-seed approach after it was explicitly critiqued as
unrepresentative fuzzing evidence (the seed was built with knowledge of the
bug, not found by the fuzzer). One standalone AFL++/ASAN harness per CVE
recompiles only the target source file against the rest of the pre-built,
uninstrumented BusyBox object graph. A crash is only ever reported confirmed
if it reproduces on the vulnerable binary and is absent on a freshly-built
patched binary given the identical input — a raw crash count alone is never
reported as a confirmation.

**Result as of 2026-07-30**: 3/5 confirmed (CVE-2026-29004 udhcpc6,
CVE-2021-42373 man, CVE-2021-42374 unlzma — the latter also a Priority-1
resolution Tier B couldn't reach). CVE-2017-15873 (bunzip2) not found in
~2.3h of fuzzing, separately shown structurally infeasible via any real
compressed input regardless of fuzz time. CVE-2021-42386 (awk) not found in
~31.7h — this is Stage 9's lowest-priority "special case" (does dynamic
analysis catch something static analysis missed at every stage), not its
primary purpose; every crash class found was triaged and ruled out,
including one genuine but off-target heap-use-after-free identified as the
distinct, already-fixed CVE-2023-42363. Exact timings in
`dynamic-analysis/LLM-SEED-TIMING.md`.

**Next**: a random-seed baseline comparison (per supervisor request,
isolating seed-generation strategy as the only variable — steps in
`BASELINE-FUZZING-STEPS.md`), then, time permitting, a static-analysis-
guided seed-generation variant.

Implementation branches: `W3/codebase-level-redesign` (Stage 8),
`W3/dynamic-analysis-fuzzing` (current, Stage 9).

## Current status

The BusyBox Tier A calibration and historical Tier B protocol-v3/v4/v5 runs
are complete and preserved. The protocol-v6 recall-first Tier B MVP and its
static-tools augmentation are both implemented, executed, and documented as
above. Netgear CVE-2016-6277 still lacks a complete package. Dynamic
analysis (Stage 9) is in progress: 3/5 CVEs confirmed, 2 accepted static-
stage limitations under active fuzzing.

## Repo structure

```
samples/       CVE source (vulnerable/patched pairs), the ground truth
ir/            LLVM IR — fallback representation, not primary anymore
binaries/      Compiled, linked, stripped executables for the 5 samples
pseudo-code/   Ghidra-decompiled pseudo-C for the 5 samples (primary input)
classify-function-vulnerabilities/       Canonical Tier A skill and automation
confirm-vulnerability-reachability/      Historical oracle-only Tier B (protocol v3-v6), superseded
confirm-and-filter-vulnerabilities/      Recall-first Tier B skill (protocol v6 redesign)
confirm-and-filter-vulnerabilities-static/  Tier B static-tools augmentation (protocol v9-v11)
dynamic-analysis/  Stage 9 fuzzing: per-CVE harnesses, blind seeds, campaign results
.codex/skills/ Skill discovery link for new Codex sessions
scripts/       Reusable Ghidra extraction support
firmware/      Tier B case-study ground truth and selected pseudo-code
results/       Immutable Tier A/B runs, filter-runs, and the OVERALL_RESULTS.md dashboard
presentations/ Progress-update slide decks
skills/        Methodology/design provenance notes
EXPERIMENT.md  Canonical experiment protocol and reporting rules
LOG.md         Stage checklist (Part 1) and full chronological log (Part 2)
DYNAMIC-ANALYSIS-PLAN.md  Stage 9 design and per-CVE harness plan
BASELINE-FUZZING-STEPS.md  Random-seed baseline how-to
```
