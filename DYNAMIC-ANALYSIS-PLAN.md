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

**Scope decision (resolved): BusyBox only, for now.** The Netgear
`httpd` case is a genuinely stateful, multi-request network daemon, with no
source available (proprietary ARM binary). Fuzzing it properly needs a
protocol-state-aware fuzzer (AFLNet) combined with binary-only
instrumentation (QEMU mode) — a combination without a well-established,
solved integration path. Rather than absorb that risk into the same
timeline as the tractable BusyBox cases, Netgear/`httpd` is deferred as an
explicit stretch goal, revisited only once the BusyBox pipeline works
end-to-end. This mirrors the same "MVP now, harder capability deferred"
discipline already used for Tier B's own scoping.

## 1. Fuzzer choice

| Target class | Fuzzer | Why |
|---|---|---|
| BusyBox applets (all 5 CVEs — single-shot: process one packet/stream/argv/script and exit) | **AFL++**, source-instrumented (`afl-cc`/`afl-clang-fast`) | Actively maintained standard choice; source is already available at the exact resolved commits from the Tier B binary corpus work |
| Netgear `httpd` (deferred) | AFLNet + QEMU mode (unconfirmed integration) | A real stateful network daemon needs protocol-state-aware fuzzing, not single-input AFL++; explicitly out of scope until BusyBox is proven out |

Original AFL is not used — it is unmaintained; AFL++ is its actively
developed successor and the standard default for this class of target.

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

**Open decision, explicitly unresolved — pending mentor input**: should
seeds stay generic (protocol/format-valid but not derived from the specific
known trigger condition), relying on the directed search to reach the
target efficiently while leaving the actual triggering values to be
discovered by mutation — or should seeds be constructed closer to the known
trigger, prioritizing speed and certainty of finding the crash over
independence of the confirmation? The former produces a stronger, more
independent confirmation if a crash is found; the latter is faster and
lower-risk if time is very limited. Revisit once there's more clarity on
how much of the timeline is available for this stage.

Per-case seed construction, regardless of which side of the above decision
is taken:

| CVE | Input shape | Seed source |
|---|---|---|
| CVE-2026-29004 (udhcpc6, heap overflow) | DHCPv6 option TLV bytes | Hand-constructed from the RFC, or a captured real exchange |
| CVE-2017-15873 (bunzip2, integer overflow) | compressed bzip2 stream | Compress a small real file with the actual `bzip2` tool |
| CVE-2021-42374 (unlzma, OOB read) | compressed LZMA stream | Compress a small real file with the actual `lzma` tool |
| CVE-2021-42373 (man, NULL deref) | **CLI arguments**, not a byte buffer | Requires AFL's argv-fuzzing mode (`@@`-file-to-argv or a custom persistent-mode argv constructor) — structurally different harness from the others |
| CVE-2021-42386 (awk, use-after-free) | two-part input (script + data) | Harness must split fuzzed bytes into both parts; seed with one small, valid, real awk program plus matching input text |

Minimize and deduplicate the initial seed set (`afl-cmin`/`afl-tmin`)
before starting each campaign.

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

- **Environment fragility risk.** `afl-clang-fast`'s instrumentation is
  sensitive to specific LLVM/clang versions. This project already hit one
  real host-environment problem building BusyBox (legacy applets against
  modern kernel/glibc headers). Worth keeping Docker in mind as a fallback
  if the AFL++ build itself turns out fragile on this host, rather than
  assuming it will just work.
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
| Fuzzer: AFL++ for BusyBox, AFLNet+QEMU for Netgear | Resolved — AFL++ for BusyBox now |
| Scope: BusyBox only vs. BusyBox + Netgear together | **Resolved: BusyBox only for now** |
| Case priority: which dispositions to fuzz first | Proposed (3-tier), open to narrowing |
| Directed vs. blind fuzzing | **Resolved: directed** |
| Seed strategy: generic vs. trigger-adjacent | **Open — pending mentor input** |
| Compute: local machine vs. cloud rental | **Resolved: local machine only** |
| FP-removal evidentiary bar | Defined (Section 7) |
