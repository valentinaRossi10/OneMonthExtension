# Log & Plan

Combined stage checklist/how-to reference and chronological action log
(merged 2026-07-30 — previously separate `PLAN.md` and `LOG.md`, kept
apart originally but grown redundant to cross-reference). For *why*
each decision was made, see `PIPELINE.md`. For normative labels,
information boundaries, handoff rules, evaluation matrices, and
metrics, see `EXPERIMENT.md`. For Stage 9 fuzzing specifics, see
`DYNAMIC-ANALYSIS-PLAN.md`.

This file has two parts: **Part 1 — current stage checklist and
how-to** (what stage things are at, right now), and **Part 2 —
chronological log** (dated entries, the full history of how it got
there, including debugging detail). Part 1 is kept current as stages
progress; Part 2 is append-only.

---

# Part 1 — Stage checklist and how-to

## Stage 0 — Environment setup — done

```bash
sudo apt update
sudo apt install build-essential clang llvm git python3 python3-pip binwalk
```
Ghidra installed separately (manual download, not via apt).

## Stage 1 — CVE ground-truth benchmark — done

5 BusyBox CVEs, one per memory-safety bug class, each verified directly
against the real fixing commit. `samples/index.csv` is the ground-truth
index; `samples/<cve>/info.md` documents each one.

## Stage 2 — LLVM IR — done, now the fallback representation

```bash
clang -S -emit-llvm -g -O0 <file.c> -o <file.ll>
```
`ir/<sample>/{vulnerable,patched}.ll`. The Tier A preparer uses it only
when pseudo-code is missing and extracts the target function rather than
sending the whole LLVM module.

## Stage 3 — Compile, strip, decompile the 5 samples — done

`binaries/<sample>/{vulnerable,patched}` (linked, stripped executables) →
`pseudo-code/<sample>/{vulnerable,patched}.c` (Ghidra decompiled). 4 full
vulnerable/patched pairs + `CVE-2021-42386`'s intentional pseudo-C
vulnerable-only case (the fix removes the source-level function; Tier A
uses the small function-only LLVM fallback for the patched variant).

## Stage 4 — Tier A prompt and rubric design — done

The canonical implementation is `classify-function-vulnerabilities/`.
It combines a common isolated-function prompt scaffold with one reviewed
rubric per vulnerability class and requests strict JSON with a
three-valued verdict, confidence, evidence, and reasoning. The legacy
root prompt templates and model registry were removed so they cannot be
mistaken for the active methodology.

## Stage 5 — Tier A automated benchmark — done

The skill prepares the full 5 samples × 2 variants × 6 classes = 60-task
manifest, validates input size and provenance, projects cost without API
calls, and executes only after approval under a hard cumulative ceiling.
The completed run used a $5 ceiling and a conservative local ledger of
$1.889030. Each experiment is stored under
`results/tier-a/runs/<run-id>/`:

- `README.md` and `run-metadata.json`: date, model, reasoning, notes, and
  configuration differences from the previous experiment
- `manifest.jsonl`: immutable task definitions and prompt hashes
- `manifest-summary.json`: input, token, guard, and projected-cost totals
- `results.jsonl`: append-only attempts, responses, and cumulative cost inputs
- `scoring/scoring.csv`: one final scored row per manifest task
- `scoring/summary.json` and `scoring/paired-transitions.csv`: aggregate and
  paired evaluation

Preparation refuses an existing run ID. Model, reasoning effort, output cap,
transport mode, SDK retry setting, policy/prompt/schema versions, and pricing
are frozen per run. Pairwise comparisons are written under
`results/tier-a/comparisons/` with metric deltas and task-level verdict/category
changes.

Five 2026-07-20 uniform-high follow-up experiments are preserved separately.
Policies v4/v5 stopped at 9/27 valid tasks because output
caps were exhausted. Policy v6 reached 46 valid tasks but had unaudited SDK
retries and connection errors. Policy v7 background polling reached 26 valid
tasks, then stopped when one response reported 27,565 output tokens despite a
4,500-token cap. Policy v8 replaces background polling with synchronous SSE
streaming and zero SDK retries. Its immutable 60-task run is preserved at
`results/tier-a/runs/2026-07-20t111012z__gpt-5-6-sol__high__high-4500-usd10-streaming/`;
all tasks received one attempt, producing 53 valid responses and 7 explicit
stream-completion errors. Its conservative ledger is $3.374440 under the
isolated $10 ceiling. The run is scored and compared with the recovered
baseline, but the failures and simultaneous configuration changes mean it
does not support a clean reasoning-effort claim.

## Stage 6 — Tier A analysis and write-up — done

All 60 tasks produced valid structured outputs and were scored. The
summary reports detection, specificity, abstention/indeterminate counts,
variant-pair behavior, and per-class metrics. See `results/README.md` and
the 2026-07-18 entries in `LOG.md` for exact interpretation and caveats.

## Stage 7 — Real firmware Tier B ground truth — prepared; package incomplete

CVE-2016-6277 (Netgear R6400/R7000 command injection) is documented in
`firmware/CVE-2016-6277-netgear-r6400/info.md`. The repository retains
selected vulnerable/patched pseudo-code and ground-truth metadata for:

- candidate function: `netgear_commonCgi`
- specific entry point: `parse_http_request`
- expected path: `parse_http_request` → `handle_get` → `netgear_commonCgi`

This material is a future Tier B case, not a runnable blind-discovery
benchmark. The generic protocol-v6 Tier B skill, runner, and scorer now exist,
but this Netgear sample still needs a complete analyzed codebase package and
case-specific costed manifest. Binary selection and unknown-candidate
discovery remain out of scope.

## Stage 8 — Recall-first codebase filtering — done (LLM cascade); static-tools augmentation done, 2 cases accepted as limitations

Approved by supervisor 2026-07-17. Two-tier pipeline; the function-level
tier is confirmed correct as already built:

- **Tier A (function-level, methodology already built = Stage 1-5) —
  complete**: given one function in isolation,
  classify whether it looks vulnerable. The *approach* is confirmed
  correct as-is — the old hand-written scripts were removed and
  regenerated by Codex as a proper skill,
  `classify-function-vulnerabilities/` (repo root; see `SKILL.md`
  there). Built from a written skill brief + a prompt asking Codex to
  summarize its own design before generating any code (see `LOG.md`,
  2026-07-17). Independently verified (not just taken from Codex's
  self-report): 60 tasks (5 samples × 2 variants × 6 classes), hard $5
  spend ceiling enforced both pre-flight and per-request, refusal/
  invalid-output detection that aborts immediately instead of writing
  silent empty results, and — the actual fix for the 2026-07-15
  runaway-spend root cause — LLVM IR inputs now extracted down to just
  the target function instead of whole modules (`CVE-2021-42386`'s
  patched `.ll`: 1,081,065 → 611 bytes). The real run completed on
  2026-07-18 with 60/60 valid results; final scoring and the audited cost
  ledger are in
  `results/tier-a/runs/2026-07-18__gpt-5-6-sol__mixed-recovered/` (see
  `LOG.md` for metrics and recovery details).
- **Tier B (codebase-level, new)**: given the *whole* codebase plus one
  already-flagged candidate function, determine whether that function
  is *actually* vulnerable by tracing reachability from **one specific
  entry point** through the codebase — confirming the flagged function
  is genuinely reachable/exploitable from that entry point, not just
  pattern-matched in isolation. Tier B assumes the candidate function is
  already known (from Tier A, or from ground truth like Stage 6/7's
  `netgear_commonCgi`) and narrows to *confirming* it, not discovering
  an unknown vulnerability from scratch across an entire binary.

Evaluation order is fixed by `EXPERIMENT.md`:

1. Keep Tier A's strict three-way scoring; an `indeterminate` result remains
   an abstention.
2. Evaluate Tier B independently using all five known BusyBox candidates and
   their patched controls (up to 10 cases), with one entry point and a
   reproducible whole-codebase package per case.
3. Evaluate the operational cascade separately by forwarding Tier A
   `vulnerable ∪ indeterminate`, deduplicating compatible candidates, and
   measuring end-to-end recall, specificity, false-positive survival, and
   Tier B workload.

The protocol-v6 MVP is implemented in
`confirm-and-filter-vulnerabilities/`. It includes:

- exact-case Tier A ingestion keyed by artifact-scoped function UID and class,
  with evidence-union coalescing and complete raw-row audit maps;
- quarantine instead of silent loss for ambiguous or conflicting identity;
- Ghidra Program Model export of analyzed function identities, direct calls,
  and explicit unresolved indirect-call sites;
- hash-verified packages and model tools;
- proof-gated `retain_confirmed`, `suppress_proven_false_positive`, and
  `retain_and_escalate` routing;
- immutable no-API preparation, explicit manifest-bound approval, adaptive
  but bounded investigation limits, append-only execution, and scoring.

The redesigned skill's six-case pilot confirmed 2/4 real vulnerabilities,
correctly suppressed 1 genuine Tier A false positive, and honestly
retained 3 cases as capability-gap limitations (deferred range/data-flow
analysis; see `results/OVERALL_RESULTS.md`, "Known limitations").

Per supervisor direction (tolerate function-level FNs if the codebase
level catches them; use fuller Ghidra output plus agent-orchestrated
def-use/slicing/dominance/call-graph tools and targeted angr rather than
building a new static-analysis framework), a second skill,
`confirm-and-filter-vulnerabilities-static/`, was built as a separate
fork (original left untouched) adding those four tools plus an
exact-row `--force-include` mechanism that pulled the one Tier A
false negative (CVE-2021-42386 UAF) into Tier B for the first time.
Three verified rounds (protocol v9-v11) each fixed a distinct root
cause (tools never invoked → framing/retry-budget gaps → a narrow
scheduling bug and a persistent provider-side `cyber_policy`
rejection). CVE-2017-15873 and CVE-2021-42374 are now accepted as
static-analysis-stage limitations (see `results/OVERALL_RESULTS.md`,
"Tier B static rounds: known limitations") — resolution deferred to
Stage 9. CVE-2021-42386's static result already stands as a complete,
non-starved attempt (all 4 tools exhausted, angr timed out).

## Stage 9 — Dynamic analysis confirmation — in progress

Fuzzing pass to confirm/find what Tier B's static stages could not —
closes the loop on the project's original hybrid static + dynamic
framing. Full design in `DYNAMIC-ANALYSIS-PLAN.md`; harnesses and
campaign results per CVE live under `dynamic-analysis/<cve>/`.

Methodology: a blind two-phase LLM seed-generation process (Phase 1 —
an isolated subagent with no vulnerability framing extracts field
structure/boundary values from spec or code; Phase 2 — seeds built
mechanically from that extraction) feeds AFL++ ASAN-instrumented
harnesses, one per CVE, built by recompiling only the target source
file with the rest of the pre-built BusyBox object graph. Every crash
is only reported confirmed if it reproduces on the vulnerable binary
and is absent on a freshly-built patched binary with the identical
input — never a raw crash count alone.

Status (see `dynamic-analysis/LLM-SEED-TIMING.md` for exact timings,
`results/OVERALL_RESULTS.md`'s "Full pipeline status per CVE" table for
the live per-case summary):

- **3/5 confirmed**: CVE-2026-29004 (udhcpc6, ~19 min), CVE-2021-42373
  (man, ~96s), CVE-2021-42374 (unlzma, ~82 min) — the latter two are
  also this stage's Priority-1 cases, since Tier B could not resolve
  them either.
- **CVE-2017-15873 (bunzip2)**: not found in ~2.3h; separately
  documented as structurally infeasible via any real (non-malformed-
  bitstream) compressed input, not a search-effort shortfall.
- **CVE-2021-42386 (awk)**: not found in ~31.7h; this is Stage 9's
  lowest-priority "special case" (does dynamic analysis catch something
  static analysis missed at every stage), not its primary purpose — see
  `DYNAMIC-ANALYSIS-PLAN.md` Section 2. Every crash class found was
  triaged and ruled out, including one genuine but off-target heap-UAF
  identified as the distinct, already-fixed CVE-2023-42363.

Next: a random-seed baseline comparison (per supervisor request,
isolating seed-generation strategy as the only variable — see
`BASELINE-FUZZING-STEPS.md`), then, time permitting, a static-analysis-
guided seed-generation variant.

## Working method for Stage 8: Codex-based skill automation

Per supervisor guidance: build Stage 8 using Codex in VS Code (full
repo context available to the agent), rather than hand-writing
prompts/scripts the way Stage 1-5 was built. Same approach reused for
the Stage 8 static-tools augmentation (`confirm-and-filter-
vulnerabilities-static/`): a reviewed prompt specifying the new skill
be built as a separate fork (never modifying the original in place),
with each round's self-reported results independently re-verified
against actual code, tests, and manifest hashes before approving the
next paid run.

1. Treat the completed `classify-function-vulnerabilities/` skill and
   `results/tier-a/` outputs as the Tier A baseline.
2. Summarize and review a separate Tier B skill before implementation,
   fixing the candidate, entry point, permitted whole-codebase context,
   output schema, evaluation rules, and spending safeguards.
3. Generate Tier B automation from that reviewed definition, then create
   a no-API dry-run manifest and cost projection for explicit approval.

Branches used across this stage: `W3/codebase-level-redesign` (initial
Tier B redesign), `W3/dynamic-analysis-fuzzing` (current, Stage 9).

## Future possibilities

**Containerize the environment (Docker).** Not needed for the current
one-machine workflow, but worth doing if this pipeline needs to be
reproduced elsewhere (another machine, the mentor's own setup, or a
future continuation of this project) — several real problems this
project hit were specifically *environment* problems, not logic bugs:
- The BusyBox build needed a minimal Kconfig specifically to dodge
  legacy-applet failures against this host's modern kernel headers/glibc
  (`networking/tc.c`, `rdate`'s `stime()`) — a pinned older base image
  would avoid needing that workaround at all.
- The scratchpad holding intermediate build state got wiped between
  sessions multiple times, forcing repeated re-cloning/re-building — a
  container with a mounted volume would make that state durable and
  explicit instead of implicit and fragile.
- Several scripts and this doc currently reference this machine's
  absolute paths (`/home/valentinarossi/...` for the Ghidra install and
  project) — a container would make setup reproducible on any machine
  without hand-editing paths.
- The headless Ghidra pipeline (`analyzeHeadless` + `ExportAllFunctions.java`)
  is a natural fit for a container — no GUI needed, and the exact Ghidra
  version matters (the Jython→PyGhidra change between versions was a real
  issue hit this project; pinning a specific Ghidra version in an image
  avoids that class of surprise entirely).

Not pursuing now since it would take real time away from the actual
research question for a one-machine, one-person project on a one-month
timeline — but a reasonable next step if this needs to be shared,
reproduced, or handed off.

## Immediate next actions

1. Run the random-seed baseline fuzzing campaigns for all 5 cases (see
   `BASELINE-FUZZING-STEPS.md`), matching each case's LLM-seeded run
   time, then document and compare against
   `dynamic-analysis/LLM-SEED-TIMING.md`.
2. Time permitting, a static-analysis-guided seed-generation variant
   (using the Stage 8 static-tools skill's Ghidra/angr output to target
   seed construction) for the two still-unconfirmed cases.
3. Fold the baseline comparison into `results/OVERALL_RESULTS.md`'s
   per-CVE pipeline table once complete.

---

# Part 2 — Chronological log

Does not reference git commit hashes.

---


## 2026-07-11 — Samples 1-5: BusyBox CVE benchmark built

- **CVE-2026-29004** (heap buffer overflow, `option_to_env`,
  `networking/udhcp/d6_dhcpc.c`): `xmalloc(4 + addrs*40 - 1)` undersizes
  the DNS-server buffer relative to the writes that follow. Fix: `+ 1`.
- **CVE-2021-42386** (use-after-free, `nvalloc`/`nvfree`,
  `editors/awk.c`): custom pool allocator lets a freed variable's slot be
  reused while a stale reference is still held. Fix: removes the pool
  allocator entirely, replaced with plain `xzalloc`/`free` per variable —
  structurally different from every other sample (no single vulnerable
  function survives in the patched version).
- **CVE-2017-15873** (integer overflow, `get_next_block`,
  `archival/libarchive/decompress_bunzip2.c`): signed `int` overflow of
  `runCnt`/`dbufCount` bypasses a bounds check. Fix: both changed to
  `unsigned`.
- **CVE-2021-42373** (NULL pointer dereference, `man_main`,
  `miscutils/man.c`): missing check for a following page argument (e.g.
  `man 1`). Fix: one-line `&& argv[1]` check.
- **CVE-2021-42374** (out-of-bounds read, `unpack_lzma_stream`,
  `archival/libarchive/decompress_unlzma.c`): a negative-position check
  isn't re-validated after a later adjustment. Fix: re-checks after the
  adjustment, bails to the error path if still negative.
- Dropped 2 candidates: CVE-2023-42366 (no fixing commit exists upstream,
  can't form a vulnerable/patched pair), CVE-2026-32094 (wrong language —
  JS library, not BusyBox).
- All 5 verified via direct `diff` against the real fixing commit before
  writing `info.md`/`samples/index.csv`.
- Generated LLVM IR for all 5 (`clang -emit-llvm -g -O0`), verified each
  target function appears as a `define`. Two build issues fixed along the
  way: stale `.config`/`autoconf.h` across commit checkouts (regenerate
  every checkout), and BusyBox's own `-Os` silently overriding our `-O0`
  and inlining away `get_next_block` (strip all `-O*` flags from the
  captured build command before adding `-O0`).

## 2026-07-11 — Mentor's 4 reference papers; branch `W1/format-exploration`

- Mentor sent FirmAgent (NDSS'26), HermeScan (NDSS'24), MANGODFA
  (USENIX Sec'24), PANGOLIN (USENIX Sec'26), suggested Ghidra/angr.
- Read all 4: two paradigms found (raw-IR deterministic analysis vs.
  LLM-on-pseudo-C) — see `PIPELINE.md` for the full reasoning. Emailed
  the mentor asking which to pursue.

## 2026-07-12 — Mentor's decision + methodology corrections

- Mentor's reply: decompiled pseudo-code primary, IR/disassembly
  fallback. Full quote and reasoning in `PIPELINE.md`.
- Caught before implementing: compiling with debug symbols retained
  would hand the LLM real variable names as a free hint, unrealistic vs.
  real (stripped) firmware. Decision: strip all binaries before
  decompiling.
- Clarified that stripping (losing names) and decompiler "cleanup" (data
  references rendering as bare addresses, dispatch tables rendering as
  confusing loops) are separate problems — the 5 samples are small enough
  that cleanup tooling likely isn't needed; confirmed true once real
  output was checked (see 2026-07-13).

## 2026-07-13 — Stage 3: compile, strip, decompile all 5 samples

- Compiled all 5 vulnerable/patched pairs to real ELF objects, verified
  target functions present (and `nvalloc` correctly absent from the
  CVE-2021-42386 patched build).
- Found `-ffunction-sections` leaves per-function section names
  (`.text.option_to_env`) surviving `strip --strip-all` — a symbol table
  gets removed but section names don't. Fixed with
  `objcopy --rename-section`, verified clean via `nm`/`strings`.
- **Relocation bug**: stripping *unlinked* `.o` files destroys their
  relocation table (only resolved at link time), producing garbage
  Ghidra output — diagnosed via `readelf -r` showing zero relocations.
  Fix: build the full linked BusyBox executable first, then strip that.
  Branched to `W1/linked-binaries` for the rebuild.
- Rebuild hit two unrelated legacy-build issues (`networking/tc.c` vs.
  modern kernel headers, `rdate`/`date` vs. removed `stime()`) — switched
  from `make defconfig` (slow, builds everything) to a **minimal config**
  (`make allnoconfig` + only the ~6 applets actually needed), which
  avoided both issues and produced much smaller/faster binaries.
- Added an automated check after every build: `nm` on BusyBox's own
  unstripped intermediate to confirm the target function actually
  compiled in. Caught a real bug: `CONFIG_UDHCPC6` silently depends on
  `CONFIG_FEATURE_IPV6`, which `allnoconfig` disables — two binaries
  built cleanly but were completely missing `option_to_env`. Fixed by
  also enabling `CONFIG_FEATURE_IPV6`.
- Confirmed BusyBox's own build already links+strips (no separate strip
  needed) and that linked executables don't have the earlier
  section-name leak at all (linker coalesces per-function sections).
  Replaced the broken `.o` files in `binaries/` with the 10 verified
  linked+stripped executables.
- Built Stage 4-5 ahead of API keys: 5 prompt templates, `run_benchmark.py`,
  `score.py`, `models.yaml` (initial placeholder model IDs).
- Manually Ghidra-decompiled 4 of 5 samples via GUI, using string-literal
  search + XREF-following to locate each target function in a
  stripped/nameless binary (technique details: search for a string used
  only inside the target function, e.g. `"bad lzma header"`; for
  functions with no strings of their own, like `nvalloc`, locate a
  neighboring function that does have one, then match by structural
  shape). Confirmed each known fix visible in the decompiled diff.

## 2026-07-13/14 — Sample 5 (CVE-2026-29004) — two build config bugs found

- `option_to_env` was hard to locate (binary contains every applet from
  the shared minimal config, not just udhcpc6, so generic search
  heuristics kept matching unrelated code). Found via string search on a
  sibling function's unique string; the compiler had inlined that sibling
  directly into `option_to_env` under `-Os`.
- Vulnerable and patched decompiled **identically** — real bug: the fix
  lives inside `case D6_OPT_DNS_SERVERS`, gated by
  `#if ENABLE_FEATURE_UDHCPC6_RFC3646`, which the minimal config never
  enabled. Fixed by adding that flag and rebuilding just these 2
  binaries; added a stronger verification (`nm` for `sprint_nip6`, a
  function only reachable from inside that specific branch) to catch this
  class of bug in the future — a function can exist while a *branch
  inside it* is still missing.
- All 5 samples' pseudo-code complete after the rebuild (4 full pairs +
  CVE-2021-42386's intentional vulnerable-only case).

## 2026-07-14 — Cross-product benchmark redesign; API-access email; Stage 7 planning begins

- Redesigned `run_benchmark.py`/`score.py` to run every prompt against
  every sample (not just matched pairs), so mismatched-prompt false
  positives are visible, not just missed detections. New `category`
  column (`true_positive`/`false_negative`/`true_negative`/
  `false_positive`); verified with a hand-built dry run before trusting
  it. Factored the bug-class↔prompt mapping into shared
  `scripts/bug_classes.py`.
- Emailed the mentor requesting API access; he'd mentioned "Fable"
  (Anthropic) and "the latest model" (OpenAI) — updated
  `scripts/models.yaml` to `claude-fable-5` and looked up OpenAI's
  actual current flagship (`gpt-5.6-sol`) rather than guess.
- Branched `W1/firmware-static-analysis`. Picked CVE-2016-6277 (Netgear
  R6400/R7000 command injection) as the Stage 7 target — full reasoning
  (why this CVE, why not the papers' scale, the ground-truth-vs-LLM-task
  split, the binary-selection scoping question) is in `PIPELINE.md`.
- Checked the Karonte dataset before downloading (~1hr) — its
  `config/NETGEAR/r_6400.json` referenced a different model/version
  already newer than our target fixed version, so it would not have
  contained this CVE. Got both exact firmware versions directly from
  Netgear instead (official download servers, sha256-checksummed).
- Found and reconciled a leftover placeholder `firmware/README.md` from
  before the CVE-benchmark pivot (described an abandoned RetDec
  approach) — rewrote it to match the actual pipeline + no-redistribution
  policy (raw firmware/extracted filesystems never committed, only
  checksums + the decompiled pseudo-C snippets actually analyzed).

## 2026-07-14 — Ground truth found on both sides: `netgear_commonCgi`

- Located the vulnerable function by tracing the real call chain from a
  `"cgi-bin"` string search: `parse_http_request` (routes cgi-bin
  requests around auth checks) → `handle_get` → `netgear_commonCgi`
  (`FUN_00033e0c`). Confirmed the exact mechanism: for a URL with no `?`
  query string, everything after `cgi-bin/` is `strcpy`'d unsanitized
  into a 64-byte stack buffer, then spliced via `sprintf` into a shell
  command string and run with `system()` — matches the real exploit
  (`/cgi-bin/;<command>`) exactly, since `;` becomes a shell command
  separator.
- Located the same function in the patched binary (v1.0.1.20) via string
  search on a unique debug-log string. Root cause **not removed** — the
  fix adds a blocklist (rejects `;`, `` ` ``, `$`, `..`) and an allowlist
  (permitted CGI names) in front of the same unsafe pattern. Worth
  noting: the blocklist doesn't cover every shell metacharacter (`|`,
  `&`, `>`, `<`).
- Documented both sides in `firmware/CVE-2016-6277-netgear-r6400/info.md`
  and saved the decompiled functions, with an explicit note that this is
  ground truth for scoring only, not what the LLM gets shown (see
  `PIPELINE.md`).

## 2026-07-15 — Bulk-exported all `httpd` functions; built the firmware benchmark scripts

- Wrote a headless Ghidra script to decompile every function above a
  minimum size (filters obvious thunks/tiny stubs) — hit and fixed a
  chain of real issues:
  1. `-process httpd` needs `-recursive` (program is nested in a project
     folder, not the root).
  2. Ghidra 12.1.2 dropped Jython `.py` script support (PyGhidra only,
     needs a separate Python runtime) — rewrote in Java
     (`scripts/ghidra/ExportAllFunctions.java`), which needs no extra
     runtime.
  3. Both binaries are named `httpd` — local Ghidra projects can't scope
     `-process` to one folder (only by filename; confirmed by reading the
     actual headless docs). Fixed by having the script write output into
     a subfolder named after each program's real project path.
  4. First real run showed correct logic but opaque `DAT_xxxxx`
     placeholders instead of resolved string literals. Wrong first
     diagnosis (`-noanalysis` reusing incomplete analysis — re-running
     with full analysis from scratch did *not* fix it). Real cause: the
     script never set the decompiler's simplification style; the GUI
     always uses the full "decompile" style, a bare scripted
     `DecompInterface` can default to a less thorough one. Fixed with
     explicit `DecompileOptions` + `setSimplificationStyle("decompile")`.
     Re-verified against the hand-saved ground truth: identical content
     (whitespace-only diff) — and as a bonus, two functions that had
     previously timed out during decompilation (including the giant
     `parse_http_request`) now succeeded too.
- **Final export: 1004 vulnerable + 1007 patched functions**, kept
  outside the git repo (same place as the raw firmware — regeneratable,
  ~2000 auto-generated files not worth committing).
- Confirmed the existing `run_benchmark.py`/`score.py` can't handle this
  (different iteration shape — many function-files per binary, not one
  file per sample/variant) and built dedicated versions:
  `scripts/run_benchmark_firmware.py` (reuses `call_model`/`build_prompt`
  from the original, resumable, command-injection prompt only — running
  the full 5-prompt cross-product at this scale would be ~5x the cost for
  little added value) and `scripts/score_firmware.py` (reads a new
  `ground_truth.csv`, since the same logical function has a *different*
  address in each binary due to different compiler layout). Added
  `prompts/command-injection.md`. Verified `score_firmware.py`'s
  categorization with a hand-built dry run before trusting it.

## 2026-07-15 — API budget: mentor's reply, cost estimates, staged spending plan

- Mentor (via Elaine, handling reimbursement) approved self-funded setup
  but asked to check for a fixed-monthly plan first, and to cap
  pay-as-you-go spending at $200 with approval + a cost quotation before
  purchasing.
- Confirmed via both providers' own documentation that no fixed-monthly
  plan includes programmatic API access (Claude Pro/Max and ChatGPT
  Plus/Pro are billed entirely separately from the API) — pay-as-you-go
  is the only real option.
- Measured (not guessed) real cost from actual file sizes: BusyBox
  benchmark ~$1.90 (both models), firmware benchmark ~$50.73 measured /
  ~$65-70 quoted with a safety margin (both models). Well under the $200
  cap even combined.
- Proposed a staged spending plan to avoid the firmware benchmark being a
  blind single large spend: cheap dry run on a handful of functions
  first → one full model → decide on the second model based on results,
  rather than running both models blind on the first attempt.
- Restructured top-level docs for reviewer-readiness (mentor/Elaine asked
  to see the repo before the full run): added `PIPELINE.md` (the primary
  "why" narrative, stage by stage) and trimmed `PLAN.md` (now a lean
  current-state/how-to reference) and this file (removed narrative
  padding now covered by `PIPELINE.md`, kept the factual timeline).
- **Status**: both benchmarks fully built, blocked only on the spending
  approval + reply confirming the exact OpenAI model ID.

## 2026-07-15 — `claude-fable-5` refuses on decompiler-style code (finding, not a script bug)

- A small trial run (before committing to the full staged spend) on
  `run_benchmark.py` came back with all 60 output files empty. First
  diagnosis attempt: `max_tokens=1024` too low, extended thinking eating
  the whole budget before any `text` block. Fixed regardless
  (`call_anthropic()` now requests `max_tokens=4096` — shared by
  `run_benchmark_firmware.py` too, since it imports `call_model` from the
  same module) but a follow-up check on an actual real prompt showed this
  wasn't the real cause: `resp.stop_reason` came back `refusal`, not
  `max_tokens`, with `resp.content` completely empty (no `thinking`
  block, no `text` block).
- Ablated to find the actual trigger, using the same
  `memory-null-pointer-dereference.md` prompt template throughout, varying
  only the code:
  - Plain, human-written C with an equivalent real NULL-deref bug →
    answered normally (`end_turn`, real `text` block).
  - Real Ghidra-decompiled pseudo-C for `CVE-2021-42373-busybox`
    (`vulnerable.c`) → `refusal`. Same for `patched.c` (rules out
    "vulnerable code specifically") and for a second, unrelated CVE
    sample (rules out "this one function specifically").
  - LLVM IR fallback for the same sample → also `refusal` (rules out
    "Ghidra's pseudo-C style specifically" — the IR fallback path is
    affected too).
  - A trivial 6-line synthetic snippet, correct/benign logic, only
    renamed to Ghidra's `FUN_00118a10`/`FUN_00118a55` convention →
    `refusal`. Suggested (wrongly, see below) that naming alone was the
    trigger.
  - Systematically renamed every Ghidra tell in the *real* sample
    (`FUN_`/`DAT_`/`PTR_s_`/`LAB_` symbols, `undefined4`/`undefined8`/
    `undefined` types, and — the one initially missed — Ghidra's
    autogenerated local-variable convention, `pcVar7`/`iVar4`/`uVar13`/
    `ppuVar8`/`plVar12` → `var_N`) → **still `refusal`**, on two separate
    real samples. So the trivial-snippet result above was misleading:
    naming isn't the (whole) trigger for real firmware-derived code.
    Something in the decompiled code's actual structure/behavior (heavy
    pointer casts, raw hex address literals, goto-based control flow,
    stack-canary/env-manipulation patterns) is what's actually keying the
    refusal, and cosmetic renaming doesn't remove those.
  - Adding explicit research-context framing to the prompt ("this is an
    academic benchmark on already-published, historical, patched CVEs,
    no exploit development requested") made no difference. Stopped
    ablating at this point rather than continuing to probe for a
    prompt-engineering bypass around a safety refusal — treated the
    refusal as a real constraint to document, not a puzzle to route
    around.
- **Implication**: this isn't a fixable script bug. It's a real
  compatibility problem between `claude-fable-5` and this project's core
  input format (decompiled pseudo-C / LLVM IR), independent of API
  budget or prompt wording. Both the BusyBox calibration benchmark and
  the firmware proof-of-concept feed exactly this kind of input, so this
  could block most/all of the planned `claude-fable-5` runs, not just the
  60-file trial.
- Worth keeping as a documented finding either way — LLM safety
  classifiers refusing legitimate reverse-engineering-adjacent security
  analysis based on decompiled-code surface features, independent of
  actual content, is directly relevant to this project's premise
  (LLM-based static analysis of firmware).
- **Status**: `max_tokens` fix committed to `run_benchmark.py` (real
  latent bug, kept regardless). Refusal issue unresolved — next step is
  checking whether `gpt-5.6-sol` shows the same behavior before deciding
  whether to swap/add a model. Blocked on `OPENAI_API_KEY` setup
  (in progress).
- **Follow-up, same day**: tested `gpt-5.6-sol` (OpenAI) against the
  exact four inputs that triggered `refusal` on `claude-fable-5` — the
  real vulnerable pseudo-C, the patched pseudo-C, a second unrelated CVE
  sample's pseudo-C, and the LLVM IR fallback. All four completed
  normally (`finish_reason: stop`), with well-formed structured answers
  matching the prompt's requested format (correctly flagged the real
  NULL-deref in `man_main`, for example). So the refusal is specific to
  `claude-fable-5`, not an inherent property of decompiled/reverse-
  engineered code as an input class — `gpt-5.6-sol` has no trouble with
  it.
- **Decision**: proceed with `gpt-5.6-sol` as the primary/only model for
  now rather than continuing to chase a `claude-fable-5` workaround.
  `models.yaml` already lists both; `claude-fable-5` can stay configured
  but its runs are expected to mostly come back as refusals until/unless
  that's independently resolved (e.g. a different Anthropic model, or
  guidance from the mentor). Worth flagging to the mentor before the full
  spend, since it changes the actual model comparison from "Claude vs
  GPT" to effectively "GPT only" unless addressed.

## 2026-07-15 — Runaway token spend: unguarded LLVM IR fallback for CVE-2021-42386

- Ran the full 5-sample cross-product for real (branch `W1/execution`,
  both models) to check for any additional bugs before the real staged
  spend. All 120 expected output files were produced (exit code 0), but
  actual spend was far higher than the ~$1.90 estimate: OpenAI's own
  Usage dashboard showed **$27.61 spent, 32 requests, ~3.106M input
  tokens** for this project's work today, and the account's credit
  balance had gone negative (-$16.61), which is what caused 33/60
  `gpt-5.6-sol` calls to fail with `429 insufficient_quota` partway
  through the run (the other 60 `claude-fable-5` calls came back as the
  already-documented empty refusals, unrelated to this).
- First hypothesis (hidden reasoning tokens on the flagship `sol` tier)
  was wrong: total tokens (~3.1M) ≈ input tokens (~3.106M), so output/
  reasoning was negligible. The spend was almost entirely **input**
  tokens.
- Root cause, confirmed by measuring actual file sizes: every real
  pseudo-code file in `pseudo-code/` is small (1KB-12KB). But
  `CVE-2021-42386`'s `patched` variant has no pseudo-C (the fix removes
  the function entirely - the one documented case that falls back to
  `ir/CVE-2021-42386-busybox/patched.ll`), and that IR fallback file
  turned out to be **1,081,065 characters** - roughly 100x any real
  pseudo-code file, and LLVM IR tokenizes worse than English/C due to
  its punctuation-heavy syntax (`%`, `i32`, `getelementptr`, ...), so the
  true token count is likely on the high end of a 270K-540K estimate.
  Sent whole, unfiltered, once per prompt template (6x) per model = 12
  calls at that size. Verified the 6 successful `gpt-5.6-sol` calls using
  this file actually went through at full size (small, real answers in
  the output files) - these 6-12 calls plausibly account for nearly all
  of the 3.1M tokens billed, dwarfing the other ~114 calls combined.
- The original "~$1.90, measured from actual file sizes" estimate didn't
  catch this outlier - it measured typical files, not this one edge
  case.
- **Fix**: added `MAX_CODE_CHARS = 50_000` guard in `run_benchmark.py`
  (comfortably above the largest real pseudo-code file, well below the
  1MB+ IR outlier). Any code input over that size is now skipped with a
  `SKIP` message to stderr instead of silently being sent to the API.
  Verified against all 10 real (sample, variant) inputs: only
  `CVE-2021-42386`'s `patched`/IR combination trips the guard: every
  other input passes through unaffected.
- **Implication for `CVE-2021-42386`**: with the guard in place, this
  sample's `patched` variant now produces no result files at all (rather
  than 12 extremely expensive ones) - `score.py` already handles missing
  files gracefully (just fewer rows), so this doesn't break scoring, but
  it does mean this one sample effectively drops out of the "patched
  code stays quiet" true-negative measurement. Worth deciding later
  (Stage 6) whether that's acceptable or whether this sample needs a
  smaller, targeted IR extract instead of skipping outright.
- **Status**: guard committed. Re-running the benchmark for real (clean
  budget, both providers billing-healthy) is still pending -
  `claude-fable-5`'s refusal issue is unresolved, so a clean run will
  still show 60/60 refusals on that side until that's separately
  addressed.
- Also added an itemized false-negative listing to `score.py`'s console
  output, mirroring the existing false-positive listing - false
  negatives (missed real bugs) previously only showed up as an aggregate
  percentage, not named individually, despite arguably being the more
  important failure mode for a vulnerability-detection tool.

## 2026-07-16 — Mentor's reply on the `claude-fable-5` refusal; model choice for now

- Emailed Elaine with the fixed-monthly-plan confirmation, the repo link
  (branch `W1/firmware-static-analysis`), and the `claude-fable-5`
  refusal blocker, asking for guidance before making the actual
  purchase.
- Ningyu (mentor) replied: bypassing Claude's safety check isn't the
  goal here - proceed with evaluation via ChatGPT/OpenAI for now. Noted
  GPT's own safety checks are less strict than Claude's but may still
  need some prompt-phrasing care to avoid triggering them.
- **Decision**: proceed GPT-only (`gpt-5.6-sol`) for the time being.
  `claude-fable-5` stays configured in `models.yaml` but isn't the
  active path until/unless the refusal issue is separately resolved.
- Opened `W2/skills-creation` to start exploring next week's "skills"
  direction the mentor had mentioned. First draft (agentic, tool-using
  exploration of an entire firmware binary with no prior hint - see
  discarded draft below) was written before the 2026-07-17 supervisor
  meeting and superseded by that meeting's more precise scoping - see
  next entry. Draft reverted from the branch; not committed.

## 2026-07-17 — Supervisor meeting: two-tier pipeline, entry-point reachability, Codex-based skills

Met with supervisor. Three concrete decisions, replacing the
speculative Stage 8 draft from the day before:

1. **Approach approved as-is**: the function-level classification tier
   (Stage 1-5's existing benchmark - one function in isolation, classify
   whether it looks vulnerable). Methodology confirmed correct, but the
   existing hand-written scripts (`run_benchmark.py`, `score.py`, etc.)
   are expected to be superseded by Codex-generated automation for this
   tier too, per point 4 below - not kept as-is going forward.
2. **Codebase-level tier, scoped more precisely than the discarded
   draft**: rather than having the model search an entire codebase from
   scratch with no hint (the 2026-07-16 draft's approach), the actual
   task is: given the *whole codebase* and a candidate function already
   flagged as (potentially) vulnerable, determine whether it is
   *actually* vulnerable by considering **one specific entry point** -
   i.e. confirm real reachability/exploitability from that entry point
   through the codebase, rather than re-discovering unknown
   vulnerabilities blind. This is a confirmation task on top of the
   function-level tier's output, not a replacement for it.
3. **Dynamic analysis** (fuzzing) to confirm findings from the
   codebase-level tier - closes the loop on the project's original
   hybrid static + dynamic framing, mentioned since the very first
   description of the project.
4. **Skills, clarified**: work in Codex (VS Code), which has full-repo
   context available to the agent. Task is to summarize the skill
   needed for each tier - one for the function-level task, one for the
   codebase-level task - then have the agent itself generate the actual
   Python automation (scripts + result files) from those skill
   definitions, rather than hand-writing scripts as in earlier stages.

Recorded as Stage 8 (codebase-level confirmation) and Stage 9 (dynamic
analysis) in `PLAN.md`/`PIPELINE.md`, replacing the discarded
2026-07-16 draft. Branch: `W2/skills-creation`.

**Status**: not started. Next concrete step is defining the two skill
summaries (function-level, codebase-level) to hand to Codex.

## 2026-07-17 — Tier A skill built via Codex: `classify-function-vulnerabilities`

- Wrote a Tier A skill brief first (purpose, inputs, output format,
  known pitfalls from this log, validation step) before touching Codex,
  so it had a concrete spec rather than needing to infer intent live.
- Iterated on the actual Codex prompt through several rounds before
  using it: first draft referenced the old (now-removed) scripts as
  reference material - dropped that, since the point was testing
  whether Codex could design this on its own. Second round added far
  more explanation of what Tier A actually is (single function,
  isolated, no cross-function context - a narrow classification task,
  not discovery) and what the real inputs look like, since the first
  draft was too terse and leaned on doc pointers alone. Also moved
  prompt-template design fully onto Codex rather than pointing it at an
  existing `prompts/` library, to test that capability specifically.
- Asked Codex to **summarize the skill design first** and wait for
  approval before writing any code - this surfaced a genuine
  methodological finding before any implementation existed:
  `CVE-2021-42386`'s UAF sample is not actually a clean function-local
  positive under Tier A's strict isolation rule, since the isolated
  function contains neither the free nor the stale use. Worth treating
  as a real Tier A limitation going forward, not just a Codex caveat.
- Codex's proposed design was independently reviewed (not rubber-
  stamped) before approval: it upgraded the old plain-text
  `Vulnerable: yes/no` format to a structured JSON schema with a third
  `indeterminate` verdict (avoids forcing false negatives when
  isolation genuinely can't answer the question), proposed extracting
  just the target function from LLVM IR instead of sending whole
  modules (a real fix for the 2026-07-15 runaway-spend root cause, not
  just a size-guard band-aid), and independently converged on
  anonymizing recognizable function names - consistent with this
  project's own Stage 3 decision to strip binaries in the first place.
  Two items were correctly left as open questions rather than silently
  defaulted: the per-run dollar ceiling and the skill's file location -
  set to $5 (comfortably above the ~$1.90 baseline, tight enough to
  still catch a repeat of the earlier incident) and
  `classify-function-vulnerabilities/` at the repo root respectively.
- **Verified independently after Codex reported completion** (its
  self-report was not taken at face value): ran
  `scripts/prepare_benchmark.py --repo-root . --output-dir
  /tmp/tier-a-verify --model gpt-5.6-sol` directly. Confirmed: 60 tasks
  generated (5 samples × 2 variants × 6 classes), 7,996 largest
  estimated tokens, the $5 ceiling enforced in both
  `prepare_benchmark.py` (pre-flight block before any API call) and
  `run_benchmark.py` (per-request check), refusal detection that halts
  the run immediately on the first refusal/invalid-output rather than
  continuing or writing silent empty results, and - the concrete
  numbers - `CVE-2021-42386`'s patched LLVM IR file reduced from
  1,081,065 to exactly 611 bytes by extracting only the target function
  and its direct type dependencies.
- One real usability quirk found during verification (not a defect):
  `--repo-root` defaults to the current working directory rather than
  auto-detecting the repo root, so it only resolves correctly if run
  from the repo root or with `--repo-root` passed explicitly.
- Committed to `W2/skills-creation` (commit `e668974`): 12 files,
  `SKILL.md` + `scripts/` + `references/` + `agents/openai.yaml`.
  `__pycache__` excluded.
- **Status**: skill built and verified via dry run only - no API calls
  made, no money spent yet. Next step is the real dry-run-then-approve
  flow through Codex itself, then scoring the results once run.

## 2026-07-18 — API budget purchase, real Tier A dry run

- Before purchasing, sent Ms. Chow (Elaine) the decision + cost
  estimate + a billing-page screenshot as quotation, per her request to
  be informed before any purchase/subscription. Kept this request
  scoped to the new incremental need (~$10) rather than the earlier
  2026-07-15 runaway-spend debt - that debt was cleared separately, out
  of pocket, as a deliberate choice to keep it distinct from what's
  being asked of the mentor/Elaine to approve.
- Cleared the account's outstanding negative balance (-$17.31 -> $0.00,
  confirmed on the actual Billing -> Overview page rather than trusting
  the purchase-confirmation modal's own math, which showed inconsistent
  numbers - "negative balance settlement: -$0.00" alongside "estimated
  balance after purchase" that didn't obviously account for the debt).
  Then purchased $10 in OpenAI credit for the actual Tier A run, per
  supervisor conversation, without waiting on Elaine's email reply
  first this time.
- Ran the real dry run (not a local `prepare_benchmark.py` check this
  time, but the actual Codex-invoked flow) via the
  `classify-function-vulnerabilities` skill. Reported: 60 tasks (5
  samples x 2 variants x 6 classes), 0 guarded/unavailable, 5 expected
  positives / 55 negatives, largest input 11,885 characters / 7,996
  estimated prompt tokens, worst-case projected cost **$2.1196** against
  the $5 ceiling ($2.8804 margin), $0 actually spent, execution paused
  pending explicit approval.
- **Independently reproduced, not taken at face value**: ran
  `prepare_benchmark.py --repo-root . --output-dir <tmp> --model
  gpt-5.6-sol --input-price-per-million 5.0 --output-price-per-million
  30.0` directly. Got the exact same numbers - 60/60 ready tasks,
  $2.1196 worst-case cost, 11,885/7,996 largest input. One implementation
  detail worth knowing: pricing isn't auto-looked-up - the script needs
  `--input-price-per-million`/`--output-price-per-million` passed
  explicitly, or it silently estimates $0 cost. Codex's flow presumably
  supplies these itself; a bare manual invocation without them would
  give a misleadingly reassuring "free" estimate.
- **Status**: dry run verified and matches independently. Not yet
  approved to execute for real - next step is authorizing the actual
  $5-ceiling run through Codex, then scoring against
  `samples/index.csv`.

## 2026-07-18 — Tier A benchmark executed and scored

- Completed the full 60-task cross-product with `gpt-5.6-sol`: 5 samples
  x 2 variants x 6 target classes. All 60 latest task records have
  `status=ok`; there were no refusals in the final result set.
- The compatibility gate caught two real integration problems before a
  full release: the first structured-output schema lacked explicit string
  types, and the initial 400-token output cap was consumed by reasoning
  before JSON was emitted. The schema was corrected, cumulative spending
  across resumed invocations was added to the runner, and reviewed retries
  were made exact-task-only. Output caps were raised under explicit
  approval (1,200, then 1,900 tokens) while retaining the hard $5 ceiling.
- Cost: **$1.858540** usage-derived estimate at the configured uncached
  prices; **$1.889030** conservative cumulative ledger, including a
  worst-case reserve for the schema-rejected request. This stayed
  $3.110970 below the $5 ceiling.
- Overall scoring: TP=3, FN=1, TN=35, FP=11, abstentions=10; decision
  coverage 83.33%, recall 60%, observable-positive recall 75%, precision
  21.43%, specificity 63.64%, false-positive rate 20%, balanced accuracy
  61.82%, strict accuracy 63.33%, F1 31.58%.
- The designated function-local observability limitation behaved as
  expected: `CVE-2021-42386__vulnerable__use-after-free` was the sole
  false negative because isolated `nvalloc` does not contain the full
  free/stale-alias/use sequence. The out-of-bounds-read positive was an
  abstention. Heap-buffer-overflow and null-pointer-dereference produced
  correct vulnerable-to-patched transitions; the integer-overflow patched
  variant remained positive.
- Recovery caveat: successful cached results were not repeated. Of the 60
  final results, 3 used the provider-default reasoning setting and 57 used
  `low`; 50 used a 1,200-token cap and the final 10 used 1,900. Treat this
  as a run-engineering limitation when comparing fine-grained behavior.
- Artifacts were later migrated without content changes to
  `results/tier-a/runs/2026-07-18__gpt-5-6-sol__mixed-recovered/`; see the
  repository-cleanup and multi-run entries below.

## 2026-07-18 — Repository reconciled with the current two-tier methodology

- Audited the repository after the Tier A run and made the implemented
  workflow canonical across `README.md`, `PIPELINE.md`, `PLAN.md`, and the
  component READMEs. Tier A is now consistently described as completed
  isolated-function classification; Tier B is planned codebase-level
  confirmation from one already-flagged candidate and one specific entry
  point; dynamic confirmation remains future work.
- Reclassified the Netgear CVE-2016-6277 material as Tier B ground truth,
  not a built blind-discovery benchmark. The repository contains selected
  pseudo-code and metadata, but not the complete 2,011-function export,
  Tier B automation, or Tier B results. The expected confirmation case is
  `parse_http_request` -> `handle_get` -> `netgear_commonCgi`.
- Removed the unreferenced root `prompts/` templates, `scripts/models.yaml`,
  and root `scripts/requirements.txt`. They belonged to the superseded
  plain-text, multi-provider workflow and conflicted with the reviewed
  class rubrics, strict JSON schema, and guarded OpenAI runner in
  `classify-function-vulnerabilities/`. They remain recoverable from git
  history.
- Kept `scripts/ghidra/ExportAllFunctions.java` as useful extraction support
  for assembling a future Tier B whole-codebase input. Updated the Tier A
  skill to document exact-task reviewed retries and reconstruction of the
  cumulative spend from the append-only `results.jsonl` ledger.
- No benchmark inputs, API responses, or scored Tier A results were changed
  by this cleanup.

## 2026-07-18 — Tier A multi-run experiment storage added

- Replaced the single mutable `results/tier-a/` output location with unique
  `results/tier-a/runs/<run-id>/` experiment directories. Preparation now
  refuses an existing run ID, so changing model or reasoning settings cannot
  overwrite a previous experiment.
- Added `run-metadata.json` and a generated README to every run. They record
  UTC date, model, reasoning effort, output cap, policy/prompt/schema versions,
  prices, budget, experiment notes, status, metrics, and automatic
  configuration differences from the previous run.
- Froze reasoning effort in each manifest and added reasoning, output cap,
  policy, and schema versions to cache identity. The executor now uses the
  manifest's frozen reasoning setting rather than the live policy setting.
- Added pairwise comparison automation producing configuration changes,
  metric deltas, and task-level category/verdict changes under
  `results/tier-a/comparisons/`, with no API calls.
- Migrated the completed run to
  `results/tier-a/runs/2026-07-18__gpt-5-6-sol__mixed-recovered/`. SHA-256
  checks confirmed its manifest, API ledger, scoring CSV, and summary were
  unchanged. Its README explicitly records the mixed recovery configuration
  (3 provider-default/57 low reasoning; 50 tasks at a 1,200-token cap and 10
  at 1,900), so it is not misrepresented as a uniform-low experiment.

## 2026-07-18 — Static experiment protocol and Tier B handoff clarified

- Added `EXPERIMENT.md` as the canonical protocol so research questions,
  task units, labels, information boundaries, metrics, escalation rules, and
  reporting claims are no longer implicit or distributed across the pipeline,
  plan, skill, and result documentation.
- Kept Tier A as a strict three-way classifier because false positives are
  already a material result. `indeterminate` remains an abstention with no
  correctness credit; the known OOB-read abstention was not retroactively
  relabeled as a true positive.
- Separated strict scoring from downstream selection. The basic cascade sends
  both `vulnerable` and `indeterminate` tasks to Tier B. On the recovered run,
  this forwards 24/60 task-class combinations, including 4/5 indexed positives
  and all 4/4 function-locally observable positives. The cross-function UAF
  remains the designated Tier A observability limitation.
- Defined three non-interchangeable evaluations: standalone Tier A; Tier B
  with oracle candidates independent of Tier A; and the operational Tier A →
  Tier B cascade. Oracle Tier B must include all five known BusyBox candidates
  and patched controls (up to 10 cases) so both sensitivity and specificity
  are measurable. A removed patched function is recorded as absence, not
  replaced with an artificial function.
- Required one fixed entry point and reproducible whole-codebase package per
  Tier B case. Expected labels, CVE descriptions, paired diffs, manual paths,
  and exploitability conclusions remain hidden from the model. Tier B and
  cascade performance must not be claimed until their automation and runs
  actually exist.

## 2026-07-20 — Uniform-high Tier A attempts; policy v5 budget/output revision

- Prepared a uniform `high` reasoning run at the existing 1,900-token cap
  under `tier-a-policy-v4`. Its 60-task worst-case projection was $4.819600
  under the $5 ceiling. Execution stopped after 9 valid tasks when
  `CVE-2026-29004__patched__integer-overflow` twice consumed the full output
  cap without returning JSON. The partial run was scored with 1 invalid and
  50 missing tasks; its conservative cumulative ledger is $0.428205.
- After explicit approval, versioned the active controls as
  `tier-a-policy-v5`: 3,000 maximum output tokens and an $8 hard cumulative
  ceiling. The new immutable 60-task manifest projected $6.799600 worst case
  and passed both representation preflights.
- The 3,000-token run resolved the task that failed under v4, but later
  `CVE-2017-15873__vulnerable__integer-overflow` and
  `CVE-2017-15873__vulnerable__out-of-bounds-read` each consumed all 3,000
  output tokens without JSON. The integer-overflow reviewed retry encountered
  two conservatively reserved connection errors and then repeated the invalid
  output; execution stopped without further retries.
- Policy-v5 final ledger: 32 append-only attempts, 27 tasks with valid latest
  results, 2 terminal invalid tasks, 31 missing tasks, and $1.407280 cumulative
  recorded/committed cost under the $8 ceiling. Strict scoring yielded TP=1,
  FN=1, TN=15, FP=7, abstentions=3, decision coverage 40%, and strict accuracy
  26.67%. These are partial-run bookkeeping metrics, not a complete estimate
  of high-reasoning performance.
- Generated comparisons against both
  `2026-07-18__gpt-5-6-sol__mixed-recovered` and the partial v4 uniform-high
  run. Because the candidate is incomplete and changes policy/output cap as
  well as reasoning relative to the recovered baseline, no causal reasoning-
  effort claim is supported.

## 2026-07-20 — Policy-v8 synchronous-streaming Tier A run prepared

- Preserved the partial policy-v6 and policy-v7 experiments. Policy v6 reached
  46 valid tasks but hidden SDK retries made request exposure unauditable.
  Policy v7 background mode reached 26 valid tasks before response
  `resp_0cc44442c378c20b006a5df762251c819bbc67822df72b270f` reported 5,190
  input and 27,565 output tokens for a request whose frozen output cap was
  4,500. The provider dashboard independently showed the same token counts.
- Versioned the active controls as `tier-a-policy-v8`: synchronous SSE
  streaming, `max_retries=0`, high reasoning effort, a 4,500-token output cap,
  and an isolated hard $10 ceiling. The runner now stops if provider-reported
  usage itself exceeds the frozen output cap, in addition to its existing
  cumulative pre-request budget checks.
- Prepared the new immutable run
  `2026-07-20t111012z__gpt-5-6-sol__high__high-4500-usd10-streaming` without
  making API calls. All 60 tasks are ready and preserve the policy-v7 prompt
  and code hashes. At $5 per million input tokens and $30 per million output
  tokens, its 279,920 projected input tokens cost at most $1.399600 and its
  270,000 reserved output tokens cost at most $8.100000: $9.499600 total,
  leaving $0.500400 below the separate $10 ceiling.
- The no-API runner dry run and a local fake-stream test passed. The fake test
  also confirmed that a 4,501-token provider usage record is classified as a
  budget breach. No `results.jsonl` exists for v8 and its recorded spend is
  $0. Execution remains pending explicit approval of this exact manifest and
  projection.

## 2026-07-20 — Policy-v8 executed, scored, and compared

- After explicit approval, executed all 60 frozen v8 tasks exactly once with
  synchronous SSE streaming and SDK retries disabled. Fifty-three responses
  completed with valid structured output. Seven streams ended without a
  `response.completed` event and were recorded as `api_error`; none was
  retried. The affected tasks were the vulnerable integer-overflow and both
  out-of-bounds-read checks for CVE-2017-15873, plus both integer-overflow and
  both out-of-bounds-read checks for CVE-2021-42374.
- Completed responses used 159,937 input tokens and 46,133 output tokens for
  $2.183675 at the frozen rates. The largest completed output was 3,789 tokens,
  so no completed response breached the 4,500-token cap. Reserving each failed
  stream at its full per-task worst case gives the conservative cumulative
  ledger of $3.374440, $6.625560 below the isolated $10 ceiling.
- Strict 60-task scoring: TP=2, FN=1, TN=31, FP=11, abstentions=8, API errors=7;
  decision coverage 75%, recall 40%, observable-positive recall 50%, precision
  15.38%, specificity 56.36%, balanced accuracy 48.18%, strict accuracy 55%,
  and F1 22.22%. The two true positives were heap-buffer-overflow and
  null-pointer-dereference. The indexed integer-overflow and out-of-bounds-read
  positives were API errors; the designated cross-function UAF remained the
  one false negative.
- Compared with `2026-07-18__gpt-5-6-sol__mixed-recovered`: recall changed
  60% to 40%, observable-positive recall 75% to 50%, specificity 63.64% to
  56.36%, strict accuracy 63.33% to 55%, F1 31.58% to 22.22%, and recorded
  conservative cost $1.889030 to $3.374440. The false-positive count remained
  11. Fourteen task categories/verdicts changed. This is not a clean causal
  reasoning-effort comparison because reasoning, policy, output cap, transport,
  and budget changed, and v8 contains seven API failures.

## 2026-07-20 — Interpreting the indexed out-of-bounds-read API error

- For `CVE-2021-42374__vulnerable__out-of-bounds-read`, the recovered baseline
  returned `indeterminate` at low reasoning after using 1,832 of its 1,900
  output tokens. Its explanation identified the unrechecked adjusted index and
  subsequent read, but could not prove the readable extent of the allocation
  made by an opaque callee or fully resolve the decoder-state constraints.
- The same prompt and code hash did not yield a verdict at high reasoning.
  Policy-v6 recorded two connection errors on this exact task, subject to that
  run's SDK-retry audit caveat. Policy-v8, with synchronous streaming and SDK
  retries disabled, ended without a `response.completed` event and recorded
  one `api_error`. The v8 record contains no text, usage, or provider response
  ID from which a verdict can be reconstructed.
- **Working hypothesis:** this task lies near Tier A's function-local evidence
  boundary. It presents a plausible local read-after-index-adjustment pattern,
  while the rubric correctly requires an inferable object extent and feasible
  path. High reasoning may spend substantially more computation trying to
  reconcile those competing signals and reach the output limit or fail during
  structured-response finalization before emitting JSON. The baseline's
  1,832/1,900 output usage and repeated high-reasoning failures are consistent
  with this hypothesis, but do not prove it; a transport or provider failure
  remains an alternative explanation.
- Consequently, the comparison's `abstention -> api_error` transition is an
  operational reliability regression, not evidence of a semantic change from
  `indeterminate` to either `vulnerable` or `not_vulnerable`. A future test
  should first preserve incomplete-stream event details and usage, then run
  this exact frozen task under controlled reasoning/cap settings with a new
  cost projection and explicit retry approval.

## 2026-07-23 — Protocol-v6 recall-first Tier B MVP implemented

- Reconciled the workspace to the already checked-out
  `W3/codebase-level-redesign` branch at base commit `7e16ff0`; no remote
  branch or fetch was required. Existing historical Tier A/Tier B files and
  runs remain uncommitted and preserved.
- Added `confirm-and-filter-vulnerabilities/` as a separate Tier B redesign,
  leaving `confirm-vulnerability-reachability/` and all historical runs
  unchanged. The redesign treats Tier B as a recall-first filter over real
  Tier A output and never converts failures or uncertainty into suppression.
- Fixed queue identity at `(artifact-scoped function UID, normalized target
  class)`. Exact duplicates retain the union of evidence and full source-row
  provenance; different classes never merge. Every eligible raw row maps to
  one case or an explicit quarantine record.
- Replaced regex call-edge inference in the new package format with a Ghidra
  Program Model exporter for function content hashes, direct call references,
  and explicit unresolved indirect-call sites. A real read-only headless
  validation against the CVE-2017-15873 BusyBox binary exported 647 functions,
  1,978 direct calls, and 15 unresolved indirect calls.
- Added proof-gated dispositions, hash-verified package access, immutable
  no-API preparation, manifest-bound execution approval, append-only ledgers,
  adaptive 12+4 tool and 13+4 model-call limits, and evaluator scoring.
- Kept SSA/dominator/def-use analysis, indirect-target resolution, a second
  provider, deterministic analyzer fallback, and staffed human review out of
  the MVP. `retain_and_escalate` is terminal when those facilities are
  unavailable.
- Documented that the five known BusyBox positives are an acceptance set, not
  a held-out cohort. A 5/5 result would not establish universal recall.
  Planning cost is approximately $9.86 per case, $49.30 for five positives, or
  $98.60 for ten cases; exact cost must be recomputed from frozen real
  packages before any approval. No provider API calls were made.

## 2026-07-24/26 — Tier B redesigned as `confirm-and-filter-vulnerabilities`; six-case pilot

- Replaced the oracle-only `confirm-vulnerability-reachability` skill
  (protocol v3-v6, only ever evaluated pre-selected known-answer pairs)
  with a new design: confirming every forwarded true positive is the
  hard, primary constraint; reducing false positives is secondary and
  must never weaken confirmation. A case that can't be cleanly resolved
  is retained and passed downstream, not dropped.
- Six-case pilot (2 schema-fix runs, schema-v2 then schema-v3) against
  a real frozen Tier A run: **2/4 real vulnerabilities confirmed
  (CVE-2026-29004, CVE-2021-42373), 1 genuine Tier A false positive
  correctly suppressed with a full evidentiary proof, 3 cases honestly
  retained** as capability-gap limitations (deferred range/data-flow
  analysis — no SSA, dominators, def-use slicing, or symbolic range
  analysis in this MVP). No true positive was ever suppressed.
- Real bugs found and independently fixed along the way (not accepted
  on self-report): two Structured Outputs schema-validity bugs; a
  validator status-conflation bug that discarded a genuinely correct
  CVE-2021-42373 confirmation; a real false suppression on
  CVE-2021-42374 (a guard proven for one buffer read wrongly applied to
  a different unguarded read); a runner bug silently discarding valid
  interim "still unresolved" answers instead of persisting them; an
  unsupported inferential leap accepted without evidence; a generic,
  undiagnosable terminal-response exception conflating token-cap
  exhaustion, provider refusals, and genuine transport failures. Full
  detail in `results/OVERALL_RESULTS.md`, "Tier B redesign" section.
- Recurring `cyber_policy` provider content-safety refusals on
  genuinely vulnerable code first hit here — mitigated (not
  eliminated) by reinforcing explicit defensive, symbolic-only framing.
  This exact failure class recurs throughout Stage 8's static-tools
  work below.

## 2026-07-27/28 — Stage 9 (dynamic analysis) begins: 5 AFL++ harnesses, first confirmations

- Built one standalone AFL++/ASAN harness per CVE
  (`dynamic-analysis/<cve>/harness_*.c`), each recompiling only the
  target source file with the rest of the pre-built, non-instrumented
  BusyBox object graph — no source patches to the target files
  themselves. `udhcpc6` and `man` use compiler-flag entry-point renames
  (`-Dmain_fn=main_fn_impl`); `man` additionally needs
  `utils/argv_fuzzing/argv-fuzz-inl.h` for argv fuzzing.
- **CVE-2026-29004 (udhcpc6) confirmed**: initial hand-crafted-seed
  "confirmation" explicitly critiqued (built with knowledge of the bug,
  not real fuzzing evidence) — redone with a genuinely blind two-phase
  LLM seed methodology (Phase 1: an isolated subagent with no
  vulnerability framing extracts field structure/boundary values from
  spec/code; Phase 2: seeds built mechanically from that extraction,
  no further vulnerability-aware judgment). Verified against the actual
  LLMIF paper (Section 4, page 884) rather than assumed. Blind campaign
  found 7/7 crashes, identical signature, absent on patched — ~19 min.
- **CVE-2021-42373 (man) confirmed** the same way: 9 blind argv shapes,
  crash in ~96s/845 execs, absent on patched.
- Real harness/methodology bugs found and fixed: AFL++ dictionaries
  need quoted byte values (`name="\x.."`, not `name=\x..`) — silently
  failed to load otherwise, cost ~53 min on the unlzma campaign before
  caught; the shared `bb_show_usage()` linker stub called `abort()`,
  turning normal "invalid option" behavior into false-positive crashes
  in any harness reaching `getopt32` (man, awk) — fixed to `_exit(2)`
  in all 5 harnesses.

## 2026-07-28/29 — Remaining harnesses; bunzip2 structural infeasibility; supervisor guidance pivot

- **CVE-2021-42374 (unlzma) confirmed** via the full blind methodology
  (82 min, 187,274 execs, cross-checked absent on patched) — supersedes
  an earlier informal (non-blind-methodology) find from the same crash
  offset.
- **CVE-2017-15873 (bunzip2)**: determined via precise `int32`
  accumulation simulation that the specific `runCnt`/`dbufCount`
  overflow trigger needs ~1043 consecutive RUNB symbols — a value
  `dbufSize`'s 900,000-byte hard cap makes structurally unreachable by
  any real, standards-conforming compressor regardless of input size.
  Only a hand-crafted malformed bitstream reaches it. Explicitly
  scoped out of legitimate fuzzing methodology, not pursued as a PoC.
- **CVE-2021-42386 (awk)**: blind taxonomy extraction found 7
  call-nesting shapes; original 5 seeds only covered 2. Round 2 added 3
  more seed scripts covering the untested categories (self-referential
  call in argument position, mutual recursion, sibling-argument calls),
  injected directly into the running campaign's `queue/` (AFL only
  reads `-i` once at startup). `print > "file"` redirection found to
  let any script write arbitrary files relative to the harness's cwd,
  ungated — created 1,187 junk files during triage; fixed practice to
  always run from a disposable scratch directory.
- Supervisor's reply on the six-case pilot's 3 retained cases: tolerate
  function-level FNs as long as the codebase level catches them; do
  **not** build a new static-analysis framework — instead use fuller
  Ghidra output plus agent-orchestrated def-use/slicing/dominance/
  call-graph tools and targeted angr, and document genuine limitations
  rather than invent new algorithms; requested a random-seed baseline
  for dynamic analysis and a cross-stage results table. Own review
  caught the ingestion pipeline's `--forward-verdict` default was
  silently excluding the one known Tier A false negative
  (CVE-2021-42386 UAF) from ever reaching Tier B — fixed via a new
  `--force-include` exact-row selector, not a broadened verdict filter.

## 2026-07-29/30 — Static-tools Tier B skill (3 verified Codex rounds); awk overnight campaign

- New skill `confirm-and-filter-vulnerabilities-static/` built as a
  separate fork (original `confirm-and-filter-vulnerabilities/` left
  completely untouched — verified via `git diff`), adding
  `get_reaching_definitions`, `slice_pcode`, `get_dominance`,
  `query_angr`, fuller Ghidra p-code/CFG exports, and the
  `--force-include` ingestion mechanism. Narrowed to 3 primary cases
  (bunzip2, unlzma, awk vulnerable); patched control deprioritized.
- **Round 1** (protocol-v9, static-primary): 0/3 confirmations. Own
  audit of `results.jsonl`'s `tool_name` field found the 3 new tools
  were built but never actually invoked (only `get_reaching_definitions`
  once) — the investigation converged early on the old tool set alone.
- **Round 2** (protocol-v10, required-tools rerun): added a required-tool
  coverage gate blocking any case from a "completed" terminal until all
  4 tools succeed at least once, plus a per-request (not once-only)
  defensive reminder. UAF case genuinely exhausted all 4 tools (angr
  timed out) — a complete, non-starved result. OOB hit `cyber_policy`
  before any tool call; integer-overflow exhausted its base budget on
  retries before dominance/angr.
- **Round 3** (protocol-v11, two-case round): fixed the retry-budget
  starvation for oversized-result retries specifically, and confirmed
  uniform defensive framing on every request. Verified via raw
  `results.jsonl`: OOB reached 3/4 tools before a *different*,
  narrower bug (an invalid-argument retry, not oversized-result, ate
  the final slot); integer-overflow's oversized-slice retry correctly
  unlocked the extension, then the next request still hit
  `cyber_policy` despite uniform framing. Since this is now a
  provider-side content-safety rejection outside prompt/scheduling
  control, and not a fixable mechanical gap, **CVE-2017-15873 and
  CVE-2021-42374 accepted as static-analysis-stage limitations** — see
  `results/OVERALL_RESULTS.md`, "Tier B static rounds: known
  limitations." No further static-tools rounds planned for these two.
- Overnight awk blind campaign (~31.7h, 1.59M execs, 40 cycles): 19
  crashes triaged. One genuinely new class — `heap-use-after-free` in
  `clrvar` (awk.c:917) — found and traced via `addr2line` through a
  `split_f0`/`Fields[]` realloc chain, then **reproduced identically on
  patched source**, ruling it out as CVE-2021-42386. Identified via
  upstream git history as a distinct, already-fixed bug,
  **CVE-2023-42363** (fix `fb08d43d4`, May 2024 — postdates both our
  checkouts): the fix comment's own description ("second `evaluate()`
  reallocates and moves `Fields[]`... L.v now points to freed mem")
  matches the traced chain almost verbatim, and the crash input
  contains a large field reference (`$222222`) matching upstream's own
  `"$444 $44444"` repro. Not a zero-day; target UAF still unconfirmed.
- Wrote `dynamic-analysis/LLM-SEED-TIMING.md` (exact time/execs-to-crash
  per case, from `fuzzer_stats`/crash-file timestamps, not estimated)
  and `BASELINE-FUZZING-STEPS.md` (steps for the supervisor-requested
  random-seed baseline: same harness/timeout, no dictionary, isolating
  seed-generation strategy as the only variable).
- 5-slide `presentations/W3_progress.pptx` built for a progress
  update, iterated per feedback (terminology, arrow/box relabeling,
  schematic results layout).
- Repo cleanup: removed an empty scratch file; gitignored the large
  (111M) untracked static-analysis run-input packages (regenerable
  from manifest-recorded case IDs, immutable outputs stay committed);
  documented (not archived — the versioned filenames are load-bearing
  for `tier_b_common.py`'s exact-version policy/prompt loader) the
  version sprawl in `confirm-vulnerability-reachability/references/`;
  merged this file (`LOG.md`) and `PLAN.md` into one, since they'd
  grown redundant to cross-reference and `PLAN.md`'s Stage 8/9 sections
  were badly stale.
