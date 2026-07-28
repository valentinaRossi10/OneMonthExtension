# Stage 9 — dynamic analysis (fuzzing) plan

Status: **planning only, nothing implemented.** This document records the
design and the decisions taken or still open before any harness, build, or
fuzzing campaign is built. It follows the same discipline used for Tier A
and Tier B: decisions are made explicit and reviewed before anything runs,
nothing is assumed working until independently verified.

## Purpose and scope

Stage 9 takes cases the static pipeline (function-level analysis / Tier A,
codebase-level analysis / Tier B) could not fully resolve, and tests them by
actually running the code, instead of reasoning about it. It exists
specifically to do two things static analysis in this project cannot:

- **Confirm true positives Tier B couldn't reach a verdict on.** Some cases
  are blocked because Tier B would need to reason abstractly about value
  ranges across a loop or resolve an indirect call — capabilities this
  project's static design does not implement. Dynamic execution does not
  need to reason about this abstractly; it runs the code with concrete
  bytes and observes whether it actually crashes, which sidesteps the exact
  gap that blocks Tier B rather than needing to close it.
- **Provide bounded evidence toward removing genuine false positives Tier B
  could not disprove with a full static proof.** This is fundamentally
  asymmetric: a crash is strong, reproducible evidence; the absence of one
  is only ever evidence bounded by how much was actually searched, never
  proof of safety. Section 7 defines exactly what evidentiary bar must be
  met before a case can be marked cleared.

**Scope decision (resolved): BusyBox only.** The Netgear `httpd` case
(proprietary ARM binary, no source, genuinely stateful multi-request
daemon, needing AFLNet + QEMU mode with no well-established solved
integration path) is **out of scope for the remaining one-week extension
timeline** — not merely deferred. It is not being planned or pursued
further here.

## 1. Fuzzer choice

**AFL++**, source-instrumented (`afl-cc`/`afl-clang-fast`), for all 5
BusyBox CVEs. Source is already available at the exact resolved commits
from the Tier B binary corpus work. Original AFL is not used — it is
unmaintained; AFL++ is its actively developed successor and the standard
default for this class of target.

AFLNet was considered given the IoT-firmware angle, and re-examined
specifically for the CVE-2026-29004 case (a network client, not
server). Rejected for all 5 cases: AFLNet's actual value is stateful,
multi-message protocol-session exploration, and none of the 5 CVEs need
that — each is reachable from a single process invocation with one
fuzzed input (a byte buffer or argv), verified per-case below by
reading the real candidate/entry-point linkage before committing to
this. Bringing in AFLNet's server/response-code-state machinery would
add real integration cost for zero corresponding benefit here.

### 1a. Per-case harness feasibility (verified against real source)

| CVE | Candidate linkage | Workaround needed | Status |
|---|---|---|---|
| CVE-2026-29004 (udhcpc6) | `fill_envp`/`option_to_env` are `static` | Small patch — harness appended to the same translation unit, so `static` never actually needs to change | **Built, crash-repro verified** — `dynamic-analysis/cve-2026-29004/` |
| CVE-2017-15873 (bunzip2) | `start_bunzip`/`read_bunzip`/`unpack_bz2_stream` already exported (`FAST_FUNC`), fd-based | None needed, confirmed | **Built, no source patch** — `dynamic-analysis/cve-2017-15873/`; crash not yet reproduced (needs a guided/longer campaign — the bug is inside Huffman-coded run lengths, not hand-craftable like CVE-2026-29004's fixed-offset field) |
| CVE-2021-42374 (unlzma) | `unpack_lzma_stream` already exported (`FAST_FUNC`), fd-based | None needed, confirmed | **Built, crash found and confirmed** — `dynamic-analysis/cve-2021-42374/`; AFL++ found the OOB read autonomously in the same 4-minute calibration window, cross-checked absent on the patched source |
| CVE-2021-42373 (man) | `man_main` itself is the entry point, already externally visible | None for linkage; used AFL's argv-fuzzing mode (`argv-fuzz-inl.h`) instead of byte-buffer; filesystem/env-var dependency confirmed to degrade gracefully by reading `config_open2`/`config_read`'s NULL-handling | **Built, crash found and confirmed** — `dynamic-analysis/cve-2021-42373/`; reproduced on first hand-crafted argv, cross-checked absent on patched source |
| CVE-2021-42386 (awk) | `nvalloc` is `static`, but `awk_main` (self-contained, externally visible) is the natural entry point | None expected at the entry level; needs both argv and file-content fuzzing (script + input text) | Not started |

The CVE-2026-29004 harness confirms the general recipe: append a small
`main()` to the end of the same source file as the candidate function
(sidesteps `static` linkage without changing any existing signature),
compile that one file with `afl-clang-fast -O0 -fsanitize=address`, and
link against the rest of the already-built (non-instrumented) object
graph — ASAN's `malloc`/`free` interposition is global, so this still
catches heap-safety bugs even though most of the linked objects aren't
themselves instrumented. Full build/verification details in
`dynamic-analysis/cve-2026-29004/PROVENANCE.md`.

## 2. Fuzzer inputs

### Which cases (by Tier B disposition, not the original TP/FP label)

| Priority | Source | Purpose |
|---|---|---|
| 1 — primary | Tier B `retain_and_escalate` cases (unresolved real vulnerabilities and unresolved possible false positives) | This is what Stage 9 exists to help resolve |
| 2 — validation | Tier B `retain_confirmed` and `suppress_proven_false_positive` cases | Spot-check the pipeline's own claims: a confirmed TP that also crashes dynamically is strong end-to-end validation; a "proven safe" case that *does* crash would be an important finding about a flaw in Tier B's suppression logic |
| 3 — special case | CVE-2021-42386 (use-after-free) | Never forwarded by Tier A at all (a false negative that never reached Tier B). Run from ground truth directly, bypassing Tier A/B forwarding, as a distinct test of whether dynamic analysis catches what the static AI pipeline missed completely |

*(Open for narrowing if time is tight — priority 1 is the load-bearing
tier; 2 and 3 are valuable but not required for Stage 9 to deliver its core
purpose.)*

### Which binary

Both vulnerable and patched variants, paired, with the identical harness,
seed corpus, and budget — this lets the expected asymmetry (vulnerable
crashes, patched doesn't) be checked directly, and any anomaly in either
direction becomes its own reportable finding, mirroring the paired
vulnerable/patched transition tracking already used in Tier A/B.

### Guided or blind fuzzing

**Decision: directed, not blind coverage-maximizing fuzzing.** Every case
here is an already-localized claim — Tier B already names the entry point,
candidate function, and (where resolved) the reachability path. Blind
coverage-maximizing fuzzing would spend most of its budget exploring
irrelevant code. Bias exploration toward the known target site (AFLGo-style
distance-based scheduling, or an equivalent AFL++ extension), rather than
using AFL++'s default undirected strategy.

## 3. Initial seed creation

**Steering input from the 2026-07-27 supervisor meeting note: an LLM should
generate the seeds.** The design below is derived from a directly relevant
reference paper the supervisor shared —
*LLMIF: Augmented Large Language Model for Fuzzing IoT Devices*
(Wang, Yu, Luo — IEEE S&P 2024) — which builds an LLM-augmented fuzzer for
the Zigbee IoT protocol and hits the same core problem this project has:
how does an LLM produce a *correct, well-formed* seed for a real protocol
without hallucinating the format.

### The paper's key validated finding — already consistent with a decision made here

LLMIF directly tested whether general-purpose LLMs (GPT, Llama 2, PaLM,
Claude) can construct correct protocol message formats from their own
knowledge alone, with no specification given: **15.6% recall** across 96
message types — badly insufficient. Their fix: ground the LLM in the
actual specification document text before asking it to do anything
format-related ("background-augmented prompting" — retrieve the relevant
spec section, concatenate it with the task instruction, rather than
relying on the model's memorized knowledge).

This directly confirms a choice already made in this plan: for the two
compression-format cases (bzip2, LZMA), skip asking any LLM to construct
the binary format from description or memory — just run the real
`bzip2`/`lzma` tool. LLMIF's own data is a strong independent argument for
exactly that decision. For the DHCPv6 case, it means the LLM must be given
the actual relevant text of RFC 8415, not asked to produce a DHCPv6 packet
from parametric knowledge.

### The design change this resolves — the vulnerability-class-hint question

LLMIF's LLM extracts, purely from the specification's own stated
constraints, two categories of field values, and **never mentions
vulnerabilities, security, or bug classes anywhere in the process**:

- **Functioning values** — values that trigger specific documented
  behavior.
- **Dangerous values** — values *outside the range the specification
  itself declares valid* (their example: a field documented as valid only
  in `0x0001–0xfff7`; anything outside that range is a "dangerous value"
  candidate, purely because the spec itself says so).

Their actual prompt templates ask only for format extraction, dependency
reasoning, or spec-conformance checking — never anything resembling "find
an exploitable weakness." The word "vulnerability" does not appear in any
prompt they show.

**This is adopted as the design here, replacing the earlier binary
"tell it the class or don't" framing**: the LLM is never asked to reason
about vulnerabilities at all. It is asked to extract, for each field the
candidate code reads, the *valid range or constraint* — from the actual
specification text where one exists (DHCPv6/RFC 8415), or from explicit
bounds-checks visible in the candidate's own decompiled code where no
external spec exists (the compression/CLI/script cases, where the code's
own comparisons reveal what range it assumes). "Dangerous" seed candidates
are then simply values that exceed or violate that extracted bound — a
byproduct of a purely descriptive task, not a security-framed one. This
should still be confirmed with the supervisor as the actual resolution
(rather than assumed), since it's a specific interpretation of a general
note, but it substantially narrows the open question rather than leaving
it a coin flip.

**Still open**: how close to the *exact* known trigger condition seeds
should land. The bounds-extraction approach above naturally produces
boundary-adjacent candidates without ever citing the literal known-correct
trigger value, which is the same "informed search, not handed-over
answer" principle already used for directed fuzzing — but worth confirming
explicitly rather than assuming it fully resolves this too.

### Design: what the LLM does, in two separated phases

Mirrors LLMIF's structure: extract knowledge **once** per case/variant,
then use that extracted knowledge to drive seed generation and mutation
across many fuzzing rounds — not re-invoking the LLM inside the fuzzing
loop itself.

**Phase 1 — extraction (once per case, per variant):**

Input: the target's input format description (RFC text where one exists;
otherwise the candidate function's own decompiled/source code) plus the
candidate function's real code.

Output: (a) the field structure of the input the candidate function reads,
(b) for each field, its valid range or constraint as stated by the spec or
implied by the code's own checks, (c) "dangerous" candidate values derived
from violating that constraint.

**Phase 2 — seed generation (from the Phase 1 output, no further LLM
reasoning needed):**

Construct a small diverse set (roughly 5–10) of format-valid candidate
inputs from the extracted field structure, populated with a mix of typical
values and the extracted "dangerous" (boundary/out-of-range) values per
field — directly reusable as AFL++ dictionary tokens too (`-x`), not just
initial seeds, extending the directed-fuzzing approach from Section 2 with
informed mutation hints rather than only an informed starting point.

**Validation before use** (non-negotiable — discovered directly while
setting up AFL++ itself: it refuses to start without a seed that doesn't
already crash):

1. Run every generated seed against the real target once, standalone,
   before handing it to AFL++. Confirm it doesn't itself crash, and that
   it's structurally well-formed rather than hallucinated-looking.
2. If a generated seed *does* crash on its own, that is a distinct finding
   in itself — the LLM's static reasoning found the issue directly,
   without the fuzzer's search. Report it as that, separately from a
   fuzzer-discovered crash; do not quietly use it as a seed.
3. Deduplicate/minimize the resulting seed set (`afl-cmin`/`afl-tmin`)
   before starting each campaign.
4. Log the exact model, prompt, and raw output used for both phases,
   versioned per case/variant — auditable, not a black-box step.

LLMIF's remaining phases (type-aware/header-aware mutation operators, and
LLM-based "response reasoning" to judge whether a device's reply indicates
a meaningful state transition) are not carried over here: the mutation
operators are effectively subsumed by AFL++'s own havoc engine plus the
dictionary from Phase 2, and "response reasoning" is specific to a
stateful device that returns structured responses (Zigbee, or the
out-of-scope Netgear case) — the BusyBox targets just crash or don't, with
no separate response semantics to reason about.

### Per-case input format — where it actually comes from

Only one of the five cases is genuinely defined by an RFC; worth being
precise about this rather than assuming "read the spec" applies uniformly:

| CVE | Input shape | Format source | Practical approach |
|---|---|---|---|
| CVE-2026-29004 (udhcpc6, heap overflow) | DHCPv6 option TLV bytes | **RFC 8415** (the actual DHCPv6 spec) | The one case where reading the spec and constructing bytes from it is the right approach — either by the LLM or a captured real exchange |
| CVE-2017-15873 (bunzip2, integer overflow) | compressed bzip2 stream | No RFC — a de facto format spec, not a formal standard | **Skip spec reconstruction entirely** — compress a small real file with the actual `bzip2` tool. Produces a genuinely valid stream instantly, more reliable than reconstructing the binary layout from a description |
| CVE-2021-42374 (unlzma, OOB read) | compressed LZMA stream | No RFC — vendor documentation (7-Zip/LZMA SDK) | Same as above — compress with the real `lzma`/`xz` tool |
| CVE-2021-42373 (man, NULL deref) | **CLI arguments**, not a byte buffer | No RFC — just BusyBox's own `man` applet usage convention | Trivial, not a binary format — "give it 0–2 simple strings." Requires AFL's argv-fuzzing mode (`@@`-file-to-argv or a custom persistent-mode argv constructor) — structurally different harness from the others |
| CVE-2021-42386 (awk, use-after-free) | two-part input (script + data) | No RFC — **POSIX** (IEEE Std 1003.1) defines the awk language | An LLM can write a small valid awk script directly from general knowledge; no spec lookup needed. Harness must split fuzzed bytes into both parts |

## 4. Budget / resource projection

**Decision (resolved): local machine only**, no cloud compute rental for
now. This is the first stage where the constrained resource shifts from
dollars (every prior stage) to CPU-time on the same single local machine
this project has run on throughout — worth naming that shift explicitly
rather than assuming the previous budgeting approach carries over
unchanged. Revisit cloud rental only if local capacity proves genuinely
insufficient once real numbers exist.

Proposed calibration approach, since no real per-case cost data exists yet:

1. Run a small pilot budget (roughly 1–2 CPU-hours) on the **already-known**
   TPs first (priority 2 above). Since ground truth is known, this
   validates whether the harness and seed setup actually work at all — if
   a *known*-vulnerable case doesn't crash within a modest budget, that's a
   signal the harness is wrong, not that the bug is hard to find.
2. Use that calibration to set a realistic per-case ceiling for the
   genuinely unresolved cases (priority 1), rather than guessing a number
   up front the way earlier stages' first cost projections often turned
   out to be far from actual spend.
3. Track wall-clock time against the remaining project timeline explicitly,
   since CPU-hours here are really standing in for calendar time
   available before the deadline, not a metered cost per action.

## 5. Coverage and stopping criteria

To make a negative result (no crash) mean anything, more is needed than
"ran for N hours":

- **Coverage must be verified at the exact flagged line/basic block**, not
  just function-level coverage — a function can be entered constantly while
  the one dangerous branch inside it is never taken.
- **The suspect value itself must show real exploration**, not just code
  coverage — evidence the specific variable Tier B flagged as potentially
  unbounded actually varied across a meaningful range at that point,
  including boundary values (via AFL++'s CmpLog or custom value tracing at
  that site).
- **Stop based on coverage saturation, not an arbitrary timeout** — run
  until new-edge discovery plateaus, so a negative result reflects a
  genuinely exhausted search rather than an early, meaningless stop.

## 6. Crash triage and reproducibility

- AFL++ will likely find multiple crashing inputs that are really the same
  underlying bug. Deduplicate by ASAN report signature / stack trace before
  reporting results — "1 distinct bug confirmed via N crashing inputs,"
  never overstated as N separate findings.
- Minimize every crash (`afl-tmin`) and preserve it as a hash-verified
  reproduction artifact, the same discipline already used for every
  manifest and result file in this project.
- A crash of a *different* type than the one Tier A/B flagged (e.g. a
  segfault where an integer-overflow-driven OOB write was expected) does
  not confirm the specific claim being tested — record it as its own
  separate finding, not proof of the original claim.

## 7. What counts as removing a false positive

Mirrors Tier B's own asymmetric evidentiary bar, realized through dynamic
evidence instead of a static per-sink proof. A case only becomes eligible
for a "cleared" disposition if **all** of the following hold:

1. The exact flagged line/block was reached and repeatedly exercised.
2. The suspect value showed genuine range exploration at that point, not
   just repeated identical inputs.
3. The search ran to coverage saturation, not an arbitrary short timeout.
4. No sanitizer (ASAN/UBSAN) ever flagged an issue there despite that
   exploration.

Even then, the disposition should read as `dynamically_cleared: no crash
after saturated targeted exploration`, explicitly distinct from Tier B's
`suppress_proven_false_positive` — a fuzzer's negative result is a
different, weaker kind of claim than a per-sink evidentiary proof, and the
reporting should say so rather than imply the same certainty. Anything
short of all four bars stays `retain_and_escalate` — inconclusive fuzzing
must never quietly become "cleared."

## 8. Sanitizer selection per bug class

| CVE | Bug class | Sanitizer needed |
|---|---|---|
| CVE-2026-29004 | heap-buffer-overflow | ASAN |
| CVE-2017-15873 | integer-overflow | ASAN **+ UBSAN** — the raw signed-overflow itself is only flagged by UBSAN; ASAN alone only catches the resulting out-of-bounds write, one step downstream |
| CVE-2021-42374 | out-of-bounds-read | ASAN |
| CVE-2021-42373 | NULL-pointer-dereference | None required — a plain SIGSEGV, AFL catches it natively |
| CVE-2021-42386 | use-after-free | ASAN, with quarantine size tuned — too small and a reused freed chunk gets recycled before ASAN can catch the stale access |

## 9. Other open items worth deciding before implementation

- **Environment setup — resolved and verified, not just a risk anymore.**
  AFL++ is already installed on this host (system package, `afl++ 4.09c`)
  and was directly verified end-to-end: a deliberately planted, realistic
  (runtime-dependent, conditionally-triggered) bug was found autonomously
  by `afl-fuzz` from a non-crashing seed plus a dictionary hint, with no
  ground-truth trigger ever supplied. Four environment-specific settings
  are required and now confirmed necessary:
  1. Must run outside this session's default sandboxed execution — the
     sandbox silently prevented ASAN from ever reporting a real,
     deliberately planted crash.
  2. `ASAN_OPTIONS=symbolize=0:abort_on_error=1` — avoids a symbolizer
     hang and makes ASAN actually abort (not just `exit()`) so AFL's fork
     server recognizes it as a crash.
  3. `AFL_SKIP_CPUFREQ=1` — bypasses an irrelevant CPU-governor check.
  4. **Compile targets at `-O0`, not `-O1` or higher.** Empirically
     confirmed on this LLVM toolchain (reproduced identically with plain
     system `clang`, so this is not AFL-specific): `-O1` and `-O3` can
     both eliminate or mask a real, runtime-dependent heap overflow that
     `-O0` catches correctly and reliably. This also happens to be
     standard fuzzing/ASAN practice already, not merely a local
     workaround.
- **Relationship to the open mentor decision on the two remaining static
  limitations.** If Stage 9 successfully crashes CVE-2017-15873 or
  CVE-2021-42374, that resolves them directly — dynamic execution sidesteps
  the exact static-reasoning gap that stopped Tier B, without needing to
  build the deferred SSA/range-analysis engine. This is relevant context
  once the mentor responds: accepting the current limitation and proceeding
  to dynamic analysis might not just be the practical choice, it might
  close both open cases on its own.
- **`EXPERIMENT.md` needs its own Stage 9 section** once this stage is
  implemented, with the same normative, bounded-claims treatment given to
  Tier A and Tier B: what a dynamic result can and cannot establish, stated
  explicitly rather than assumed.

## Summary of decisions

| Decision | Status |
|---|---|
| Fuzzer | **Resolved: AFL++** for all 5 BusyBox CVEs |
| Scope: Netgear | **Resolved: out of scope, abandoned for this timeline** |
| Case priority: which dispositions to fuzz first | Proposed (3-tier), open to narrowing |
| Directed vs. blind fuzzing | **Resolved: directed** |
| Seed generation method | **Resolved: LLM-generated, two-phase extraction-then-generation**, derived from LLMIF (Section 3) |
| Seed content: vulnerability-class hint given to the LLM | **Substantially resolved by design: LLM never reasons about vulnerabilities at all, only extracts declared/implied value bounds** — confirm this interpretation with supervisor |
| Seed content: generic/structural vs. trigger-adjacent | **Open — pending mentor input** |
| Compute: local machine vs. cloud rental | **Resolved: local machine only** |
| AFL++ toolchain setup | **Resolved and verified working** (Section 9) |
| AFLNet vs. AFL++ | **Resolved: AFL++ for all 5 cases** — none need multi-message state (Section 1) |
| Per-case harness feasibility | **Verified for all 5** via real source (Section 1a); 1 of 5 built and crash-repro verified, 4 not started |
| FP-removal evidentiary bar | Defined (Section 7) |
