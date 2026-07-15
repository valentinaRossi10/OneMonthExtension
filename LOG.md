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
