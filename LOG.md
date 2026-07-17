# Action Log

Chronological record of work done, for session-to-session continuity.
For *why* decisions were made, see `PIPELINE.md`. For current
stage/status, see `PLAN.md`. Does not reference git commit hashes.

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
