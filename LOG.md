# Action Log

Running log of work done on this project, in reverse-chronological order.
One entry per session/action — used to track progress against `PLAN.md`.

## Format

```
## YYYY-MM-DD — short title
- what was done
- decisions made / open questions
- next step
```

---

## 2026-07-11 — First CVE benchmark sample: CVE-2026-29004 (BusyBox)

- Searched NVD for memory-safety CVEs in BusyBox, found CVE-2026-29004
  (udhcpc6 DHCPv6 client heap buffer overflow via DNS servers), with a
  direct link to the fixing patch on GitHub.
- Identified the fix ("udhcpc6: fix buffer overflow") and the version right
  before it (the vulnerable version). Root cause: `option_to_env()` in
  `networking/udhcp/d6_dhcpc.c` allocates the DNS server list buffer with
  `xmalloc(4 + addrs * 40 - 1)` instead of `+ 1`, undersizing it relative to
  the writes that follow (heap buffer overflow, CWE-131 → CWE-787/CWE-122).
- Noted a second, later patch to the same function ("check the size of
  D6_OPT_IAPREFIX option") is a separate, unrelated fix (different DHCPv6
  option) — excluded from this sample.
- Pulled `d6_dhcpc.c` at both the vulnerable and patched versions into
  `samples/CVE-2026-29004-busybox/{vulnerable,patched}/d6_dhcpc.c`.
  Verified with `diff` that only the expected lines differ (the `xmalloc`
  fix plus two unrelated style-only changes on the same lines).
- Added `samples/CVE-2026-29004-busybox/info.md` (CVE id, file, function,
  line, bug class, description, references) and `samples/index.csv` (ground
  truth row for scoring later).
- Working on branch `W1/CVE-benchmark`, not yet committed.

## 2026-07-11 — Second sample: CVE-2021-42386 (BusyBox, use-after-free)

- Investigated the "Unboxing BusyBox: 14 vulnerabilities" disclosure
  (Claroty/JFrog) for a use-after-free candidate. Found CVE-2021-42386 in
  the `awk` applet's custom pool allocator (`nvalloc`/`nvfree`).
- Identified the fix (removal of the pool allocator, replaced with direct
  alloc/free per variable) and the version right before it as the
  vulnerable one. Root cause: reused pool slots could still be referenced
  after being freed, when processing a crafted awk pattern.
- Noted this sample's diff is much larger/structural (full rewrite of the
  allocator) compared to the first sample's single-line fix — flagged in
  `info.md` since it changes what the vulnerable/patched comparison looks
  like for this pair.
- Pulled `editors/awk.c` at both versions into
  `samples/CVE-2021-42386-busybox/{vulnerable,patched}/awk.c`, verified via
  diff. Added `info.md` and `samples/index.csv` row.

## 2026-07-11 — Considered CVE-2023-42366, dropped

- Found a heap-buffer-overflow candidate in `awk.c`'s `next_token` function
  (BusyBox 1.36.1), file/line given directly by NVD.
- Checked for a fixing commit: none found. Diffed the exact vulnerable code
  between the 1.36.1 tag and current upstream master — identical, meaning
  this CVE appears to still be unpatched upstream. Since no patched version
  exists, it can't form a clean vulnerable/patched pair like the other
  samples.
- Decision: dropped rather than using as a vulnerable-only sample, to keep
  all samples in the paired-comparison format and prioritize bug-class
  variety with the remaining slots instead.

## 2026-07-11 — Considered CVE-2026-32094, dropped

- Found while browsing NVD; a shell-escaping vulnerability in "Shescape", a
  JavaScript library (BusyBox sh named only as one of the affected shells,
  not the vulnerable component).
- Dropped: wrong language (JS, not C — doesn't fit the clang/LLVM IR
  pipeline) and wrong bug class (shell injection/escaping, not memory
  safety).

## 2026-07-11 — Samples 3-5: integer overflow, NULL deref, OOB read (BusyBox)

- Queried the NVD API for BusyBox CVEs filtered to memory-safety CWEs
  (CWE-190, 120, 125, 191, 415, 416, 476, 401) to find class-variety
  candidates, avoiding files/classes already covered (`awk.c` UAF,
  `d6_dhcpc.c` heap overflow).
- Selected and pulled three more paired vulnerable/patched samples:
  - **CVE-2017-15873** (integer overflow, CWE-190) —
    `archival/libarchive/decompress_bunzip2.c`, `get_next_block`. Signed
    `int` overflow of `runCnt`/`dbufCount` (attacker-controlled via crafted
    bzip2 input) bypasses a bounds check, causing an out-of-bounds write.
    Fix changes the relevant variables to `unsigned`.
  - **CVE-2021-42373** (NULL pointer dereference, CWE-476) —
    `miscutils/man.c`, `man_main`. Missing check for a following page
    argument when a section name is given (e.g. `man 1`) causes a NULL
    deref. Fix adds an `&& argv[1]` check — a minimal one-line fix.
  - **CVE-2021-42374** (out-of-bounds read, CWE-125) —
    `archival/libarchive/decompress_unlzma.c`, `unpack_lzma_stream`. A
    negative-position check isn't re-validated after a later adjustment,
    allowing a read before the start of the output buffer on crafted LZMA
    input. Fix re-checks the position after the adjustment.
- All three verified via direct `diff` between vulnerable/patched files
  before writing `info.md` and adding rows to `samples/index.csv`.
- **Benchmark set now complete for this round: 5 samples, 5 distinct bug
  classes** (heap buffer overflow, use-after-free, integer overflow, NULL
  pointer dereference, out-of-bounds read). Still on branch
  `W1/CVE-benchmark`, not yet committed.
- Next: Stage 2 — generate LLVM IR (`.ll`) for all 5 samples with
  `clang -emit-llvm -g -O0`, checking which ones compile standalone vs.
  need more of BusyBox's build context pulled in.

## 2026-07-11 — Stage 2: generated LLVM IR for all 5 samples

- Confirmed standalone `clang -emit-llvm` fails on these files (missing
  BusyBox-internal headers and config macros like `ENABLE_FEATURE_*`,
  `IF_*`, which only exist once the source tree is configured).
- Workflow that worked: clone BusyBox, checkout the target commit,
  `make defconfig` to generate `include/autoconf.h`, then `make V=1
  <file>.o` to capture the real compiler invocation (include paths,
  defines) BusyBox's own build uses for that file. Adapted that command by
  swapping `gcc ... -c -o file.o` for `clang -S -emit-llvm -g -O0 ... -o
  file.ll`, dropping GCC-only flags clang doesn't recognize
  (`-malign-data=abi`, `-fno-guess-branch-probability`).
- Hit two issues worth remembering:
  - Switching commits without regenerating `.config`/`autoconf.h` breaks
    the build on older commits (Kconfig mismatch, `make` tries an
    interactive `oldconfig` and aborts non-interactively). Fix: wipe and
    regenerate the config after every checkout, not just once.
  - The adapted command still contained the original build's `-Os`
    (BusyBox default), which — appearing after our `-O0` — won and caused
    optimization/inlining that silently removed a target function
    (`get_next_block` vanished, inlined into its caller). Fix: strip all
    `-O*` flags from the captured command before adding `-O0`, then
    verified every target function was still present as a separate
    `define` in the resulting IR.
- Generated and verified vulnerable + patched `.ll` pairs for all 5
  samples; confirmed each target function (`option_to_env`, `nvalloc`,
  `get_next_block`, `man_main`, `unpack_lzma_stream`) appears as a `define`
  in the expected file(s) — and confirmed `nvalloc` is correctly *absent*
  from the CVE-2021-42386 patched IR, since the fix removed it entirely.
- Copied results into `ir/<sample-name>/{vulnerable,patched}.ll` for all 5
  samples. Still on branch `W1/CVE-benchmark`, not yet committed.
- Next: Stage 3/4 — design prompt templates per bug class (memory safety
  first) and start testing them against these `.ll` files manually via
  chat UI, since API access isn't set up yet.

## 2026-07-11 — Branch `W1/format-exploration`: mentor reply + code-format research

- Received a reply from Prof. Luo (mentor) with 4 reference papers
  (FirmAgent NDSS'26, HermeScan NDSS'24, MANGODFA USENIX Sec'24, PANGOLIN
  USENIX Sec'26) and a suggestion to try Ghidra and angr — tools that
  operate on binaries, not source, and produce different IR formats
  (Ghidra: P-code; angr: VEX IR) than the LLVM IR used so far.
- Read all 4 papers (saved in `papers-11July/`) to understand how prior
  work represents code for analysis. Found two distinct paradigms:
  - **Algorithmic/deterministic static analysis** (HermeScan, MANGODFA):
    no LLM, built on angr/VEX IR, doing classical dataflow/taint tracking
    (Reaching Definition Analysis, Sink-to-Source Analysis, Assumed
    Nonimpact). IR suits this because the "analyzer" is a fixed algorithm
    that needs precise, unambiguous, uniform low-level instructions — not
    readability.
  - **LLM-as-analyzer** (FirmAgent, PANGOLIN): LLM agents do the actual
    vulnerability reasoning, and both feed the LLM **decompiled pseudo-C**
    (via IDA Pro), not raw IR or assembly — PANGOLIN states directly that
    pseudocode is easier for LLMs than assembly-level representations.
    Both also apply a cleanup/normalization pass to raw decompiler output
    before using it (PANGOLIN: rule-based regex substitution for
    data-segment references and loop→switch-case rewriting; FirmAgent: a
    separate LLM refinement call) — plain decompiler output isn't used
    as-is.
  - Since this project's design also uses an LLM as the analysis engine,
    the LLM-as-analyzer paradigm (pseudo-C) is the closer precedent, not
    the algorithmic one (raw IR) — but this is a real design decision, not
    an obvious default, so it was raised with the mentor rather than
    assumed.
  - Also noted: none of the 4 papers deeply cover this project's bug-class
    scope (UAF, integer overflow, NULL deref, OOB read) — they cluster on
    command injection and stack buffer overflow. This project's 5-sample,
    5-class benchmark is already broader on that front, worth keeping
    regardless of which representation is chosen.
- Identified 4 possible code representations for the next stage, all
  reusable against the existing 5 vulnerable/patched sample pairs:
  1. LLVM IR from source (current, done) — `clang -emit-llvm`.
  2. VEX IR from binary, via angr — matches HermeScan/MANGODFA.
  3. Ghidra P-code from binary — direct analogue of VEX IR, uses the
     tool the mentor named.
  4. Decompiled pseudo-code from binary, via Ghidra + a cleanup pass —
     matches FirmAgent/PANGOLIN, closest to what the LLM-based papers
     actually validated.
- Emailed the mentor summarizing this paradigm split and asking which
  representation to pursue next (pseudo-code / VEX IR-P-code / stay with
  LLVM IR), rather than guessing and re-implementing later.
- **This branch exists specifically to isolate this exploration.** If the
  mentor's answer is "stay with LLVM IR," switch back to
  `W1/CVE-benchmark` (or merge only this LOG entry) and continue Stage 3/4
  there without carrying over any binary/Ghidra/angr-specific work. If the
  answer favors pseudo-code, VEX IR, or P-code, continue implementation on
  this branch instead.
- Next: wait for mentor's reply, then either (a) discard/park this branch
  and resume Stage 3/4 on `W1/CVE-benchmark` with LLVM IR, or (b) compile
  the 5 samples to actual binaries and implement the chosen representation
  (angr/VEX, Ghidra/P-code, or Ghidra/pseudo-code + cleanup) here.

## 2026-07-12 — Mentor's decision: decompiled pseudo-code, with IR/disassembly as fallback

- Mentor's reply: start with **decompiled pseudo-code from the binary**
  (matches option 4 / FirmAgent+PANGOLIN's paradigm). Explicit caveat:
  some binaries use anti-decompilation techniques that cause the
  decompiled pseudo-code to miss potentially vulnerable code — if that's
  encountered, fall back to **IR or raw disassembly** for those cases.
- Decision going forward: this branch (`W1/format-exploration`) is now the
  active line of work — no need to switch back to `W1/CVE-benchmark`
  unless a future case specifically forces a fallback to IR.
- Implication for the pipeline: pseudo-code becomes the default
  representation shown to the LLM, but the workflow should stay able to
  regenerate IR (already have LLVM IR from Stage 2; VEX IR via angr and
  Ghidra P-code are documented fallback options) or raw disassembly for
  any sample where pseudo-code analysis fails or looks suspiciously
  incomplete (e.g. missing/garbled logic around a known vulnerable
  function).
- Next: compile the existing 5 vulnerable/patched sample pairs to actual
  binaries (same commits, same build-flag approach as Stage 2 but without
  `-emit-llvm`), install/set up Ghidra, decompile each to pseudo-C, assess
  whether a cleanup pass (data-segment resolution, etc., per
  PANGOLIN/FirmAgent) is actually needed for these specific
  functions before building one, then resume Stage 3/4 (prompt design +
  manual benchmark) using pseudo-code as the primary input.

## 2026-07-12 — Methodology correction: strip binaries before decompiling

- Caught an issue before implementing: the plan to compile the 5 samples
  with debug symbols retained (`-g`) would give the LLM real, human-chosen
  variable/function names (`addrs`, `dlist`, `runCnt`) in the decompiled
  pseudo-code. That's not representative of the actual problem — real
  deployed IoT firmware (what FirmAgent and PANGOLIN both extract via
  `binwalk`, and what this project ultimately targets) ships **stripped**
  binaries with no debug info, which is exactly why those papers'
  decompilers only recover generic names (`local_1c`, `iVar1`, `param_1`)
  and why they needed extra LLM-refinement/regex cleanup steps in the
  first place. Compiling with symbols retained would hand the LLM a hint
  unrelated to actual vulnerability reasoning and inflate detection
  numbers in a way that wouldn't transfer to real firmware.
- Decision: compile the 5 samples normally, then **strip** the resulting
  binaries (`strip <binary>`) before decompiling with Ghidra, matching
  real firmware conditions and FirmAgent/PANGOLIN's actual setup. This
  is now the default/primary pipeline.
- Noted as a possible secondary experiment (not a replacement for the
  above): also decompiling the *unstripped* versions and comparing
  detection accuracy against the stripped versions would isolate how much
  naming/symbol information affects LLM-based detection — a measurement
  neither FirmAgent nor PANGOLIN isolated. Worth doing only after the
  primary (stripped) benchmark is working.
- Next: proceed with compiling all 5 samples to binaries, `strip` each,
  install Ghidra, decompile the stripped binaries to pseudo-C, then check
  whether a cleanup pass is actually needed before building one
  preemptively.

## 2026-07-12 — Clarified: stripping vs. the actual "cleanup" problem

- Went back to check whether the stripping decision (above) reopens the
  need for PANGOLIN/FirmAgent-style cleanup, which was earlier deprioritized
  on the assumption that debug symbols would be retained. Conclusion: these
  are two separate issues, and stripping only affects one of them.
  - **Stripping's effect**: loses readable variable/function names —
    Ghidra will auto-generate placeholders (`local_1c`, `param_1`,
    `iVar1`). This is expected and *not* something cleanup fixes — it's
    an inherent, accepted property of analyzing a stripped binary (exactly
    matching FirmAgent/PANGOLIN's real target binaries, which also never
    had recoverable names). The LLM can still reason about generically
    named variables; this is a readability cost being deliberately
    accepted for realism, not a defect.
  - **The actual cleanup problem** (opaque data-segment references
    rendering as bare addresses instead of resolved string/constant
    content; loop-based indirect-call dispatch tables rendering as
    confusing loops instead of switch/case) is driven by what the code
    *does*, not by whether it's stripped. A stripped binary with simple,
    straightforward logic can still decompile cleanly on both fronts; a
    symbol-rich binary with a dispatch table would have the same problem.
- Since the 5 samples are small, self-contained functions with no
  route-dispatch-style logic, the earlier plan still holds unchanged:
  generate pseudo-C from the stripped binaries, read the actual output,
  and only build cleanup tooling for the two specific problems above if
  they actually appear — expect uglier variable names than hoped, but
  that alone doesn't imply the full regex/data-resolution machinery is
  needed.

## 2026-07-13 — Stage 3: compiled and stripped all 5 samples to binaries

- Compiled all 5 vulnerable/patched commit pairs to real ELF relocatable
  objects (`.o`, via BusyBox's own captured build command — same commits
  and config-regeneration approach as Stage 2's IR build, but without
  `-emit-llvm`, i.e. actual `gcc` compilation). Verified via `nm` that
  each target function (`option_to_env`, `nvalloc`, `get_next_block`,
  `man_main`, `unpack_lzma_stream`) is present in the expected file(s),
  and correctly absent from CVE-2021-42386's patched object (`nvalloc`
  removed by the fix, same as the IR check in Stage 2).
- Stripped all 10 objects: `strip --strip-all`.
- Caught a second, more subtle information leak before finishing: BusyBox
  compiles with `-ffunction-sections`, so each function lives in its own
  ELF section (e.g. `.text.option_to_env`). `strip --strip-all` removes
  the *symbol table* but does **not** remove section names — so even a
  "stripped" object still had the vulnerable function's name sitting
  directly in its section headers, undermining the whole point of
  stripping (avoiding handing the LLM a free hint). Fixed by renaming
  every per-function `.text.<fn>` / `.data.<fn>` / `.rodata.<fn>` section
  to its generic form (`.text`, `.data`, `.rodata`) via
  `objcopy --rename-section`, then re-verified with `nm` (no symbols) and
  `strings` (no target function names anywhere in the file) across all 10
  objects — all clean.
- Copied results into `binaries/<sample-name>/{vulnerable,patched}.o` for
  all 5 samples, with a `binaries/README.md` documenting the build +
  strip + section-anonymization steps and why each was necessary.
- Next: install Ghidra, decompile each stripped `.o` to pseudo-C (headless
  analyzer + decompiler script), then inspect the output by eye before
  deciding whether any cleanup pass is actually needed (per the 2026-07-12
  clarification above).

## 2026-07-13 — Diagnosed and started fixing a relocation bug in Stage 3's binaries

- While trying Ghidra on the stripped `man_main` object, the decompiler
  output was heavily garbled (warnings like "Removing unreachable block",
  "Read-only address is written"). `readelf -r` showed the stripped `.o`
  had **zero relocation entries**. Root cause: the Stage 3 binaries were
  compiled but never *linked* — they're relocatable objects (`.o`, ELF
  type `ET_REL`) whose call targets and data references are only resolved
  at link time via relocations. Stripping an unlinked `.o` destroys the
  symbol table those relocations depend on, but since linking never
  happened, the addresses were never resolved either — Ghidra was handed
  garbage placeholder bytes instead of real instructions.
- Fix: build the **full linked BusyBox executable** per commit (real
  `make`, not a single-file compile), then strip *that* — safe, because by
  link time all relocations are already resolved into real addresses; only
  symbol names disappear, not the instructions.
- Branched to `W1/linked-binaries` to do this rebuild, keeping
  `W1/CVE-benchmark`'s Stage 3 output untouched in case this direction
  needs reverting.
- Hit two more build issues in the full-BusyBox build (unrelated to any of
  the 5 samples): `networking/tc.c` fails against modern kernel headers
  (missing legacy CBQ traffic-control structs) — fixed by disabling
  `CONFIG_TC`; `rdate`/`date` fail with undefined reference to `stime()`
  (removed from glibc) for the bunzip2 commits specifically.
- Rather than keep disabling individual broken legacy applets one at a
  time on top of `make defconfig` (which builds every applet, slow and
  fragile), switched to a **minimal config**: `make allnoconfig` plus
  enabling only the ~5 applets each sample actually needs
  (`CONFIG_BUNZIP2`, `CONFIG_BZCAT`, `CONFIG_UNLZMA`, `CONFIG_AWK`,
  `CONFIG_MAN`, `CONFIG_UDHCPC6`). Confirmed this works: the two bunzip2
  builds redone this way produced valid, much smaller binaries (~128KB vs
  ~1.2MB under defconfig) with `get_next_block` present in both.
- All 10 full linked binaries now build successfully. Still to do:
  `strip --strip-all` each one, re-check/re-apply the
  `-ffunction-sections` section-rename fix from the earlier Stage 3 entry
  (BusyBox still compiles with that flag, so linked binaries likely have
  the same per-function section-name leak), verify clean with `nm`/
  `strings`, then copy into `binaries/` replacing the old broken `.o`
  files and update `binaries/README.md`.

## 2026-07-13 — Finished the linked-binary rebuild; Stage 3 binaries done

- The scratchpad holding the first 10 linked binaries was wiped between
  sessions (this has happened before), so the rebuild had to start over.
  Only one sample (CVE-2026-29004) had its exact commit SHAs recorded in
  `info.md`; re-derived the other 4 samples' exact vulnerable/fixing
  commits by pickaxe-searching BusyBox's full git history for unique code
  fragments from each sample's already-saved source, then confirmed every
  vulnerable/patched pair byte-for-byte matches what's already committed
  in `samples/` before rebuilding — all 4 matched exactly, so the rebuild
  targets the same ground truth as before, just re-derived from history
  instead of a saved note.
- Rebuilt all 10 with the minimal-config approach from the previous
  entry, this time adding an automated check: after each build, `nm` on
  BusyBox's own unstripped intermediate (`busybox_unstripped`) to confirm
  the sample's target function actually made it into the binary (or, for
  CVE-2021-42386's patched build, confirm `nvalloc` is correctly absent,
  same exception as the Stage 2 IR check).
- That check caught a real bug on the first rebuild attempt: two binaries
  (the CVE-2026-29004 pair) built "successfully" with no errors but were
  completely missing `option_to_env` — the whole `udhcpc6` applet hadn't
  been compiled in. Root cause: `CONFIG_UDHCPC6` depends on
  `CONFIG_FEATURE_IPV6`, which `allnoconfig` disables by default; simply
  enabling `CONFIG_UDHCPC6=y` in `.config` without also enabling its
  dependency silently produced a binary without the applet at all, no
  build failure to signal it. This is exactly the kind of silent failure
  the automated `nm` check exists to catch — without it, this could have
  gone unnoticed all the way into a garbled/empty Ghidra decompilation
  and wasted more time misdiagnosed as another Ghidra-side issue. Fixed
  by also enabling `CONFIG_FEATURE_IPV6=y`; reran and all 10 builds now
  pass the per-function verification.
- Confirmed BusyBox's own build system already links `busybox_unstripped`
  down to a stripped `busybox` as its final step (no separate strip
  needed), and that a fully linked executable doesn't have the earlier
  `-ffunction-sections` section-name leak at all — the linker coalesces
  all per-function `.text.<fn>` sections from the individual `.o` files
  into a single `.text` section in the final binary. Ran `strip
  --strip-all` again anyway for clarity/documentation. Verified all 10
  clean via `nm` (no symbols), `readelf -S` (no per-function sections),
  and `strings` (no target function names or source filenames anywhere).
- Replaced the old broken unlinked-and-stripped `.o` files in `binaries/`
  with these 10 verified linked-and-stripped executables
  (`binaries/<sample>/{vulnerable,patched}`, no `.o` extension since
  they're now real executables, not objects). Updated `binaries/README.md`
  to describe the corrected pipeline and both bugs caught along the way.
- **Stage 3 is now complete and correct.** Next: install/use Ghidra to
  decompile these 10 binaries to pseudo-C, producing
  `pseudo-code/<sample>/{vulnerable,patched}.c` for the Stage 4/5
  automation scripts (`scripts/run_benchmark.py` already looks for these
  first, falling back to `ir/` if absent).

## 2026-07-13 — Stage 4-5: built prompt templates and benchmark automation scripts

- Built ahead of having API keys, per explicit decision to start on the
  "full matrix" automated version now (all samples × all bug-class
  prompts × all configured models) rather than waiting for keys or
  building a minimal single-model version first.
- `prompts/`: one template per bug class, covering all 5 memory-safety
  classes in `samples/index.csv` (`memory-buffer-overflow.md`,
  `memory-use-after-free.md`, `memory-integer-overflow.md`,
  `memory-null-pointer-dereference.md`, `memory-out-of-bounds-read.md`).
  Each names the specific pseudo-C-level pattern for its bug class, states
  what *not* to flag (to keep cross-template scoring clean), and requests
  a structured, regex-parseable response format.
- `scripts/run_benchmark.py`: for every sample × variant
  (vulnerable/patched) × model in `scripts/models.yaml`, finds
  `pseudo-code/<sample>/<variant>.c` if it exists (primary representation)
  else falls back to `ir/<sample>/<variant>.ll`, builds the matching
  prompt, calls the Anthropic or OpenAI SDK, and saves raw output to
  `results/runs/<cve_id>__<variant>__<model>.md`.
- `scripts/score.py`: parses every file under `results/runs/`, extracts
  the `Vulnerable: yes/no` line, compares against the expected verdict
  (yes for vulnerable, no for patched), writes `results/scoring.csv`
  (cve_id, bug_class, model, variant, expected, actual, hit,
  false_positive), and prints overall accuracy.
- `scripts/models.yaml`: lists models to benchmark — `claude-sonnet-5` and
  `claude-opus-4-8` on the Anthropic side; the OpenAI side is a
  placeholder (`REPLACE_ME_CONFIRM_WITH_MENTOR`) pending mentor
  confirmation of the exact model ID (question raised in an earlier email,
  still unanswered). `run_benchmark.py` skips placeholder entries with a
  warning instead of failing.
- Updated `scripts/README.md`, `prompts/README.md`, `results/README.md`
  to match what actually got built (they previously described an
  IR-centric, manual-only workflow left over from before the mentor's
  pseudo-code decision), and added API key setup instructions
  (Anthropic console / OpenAI platform key pages, `ANTHROPIC_API_KEY` /
  `OPENAI_API_KEY` env vars) since no keys are configured yet.
- Not yet run end-to-end: no API keys configured yet, and `pseudo-code/`
  doesn't exist yet (blocked on finishing the linked-binaries rebuild
  above), so a real run today would silently use the `ir/` fallback for
  all 5 samples.

## 2026-07-13 — Manual Ghidra decompilation: workflow and first 3 samples

- Started manually decompiling the 10 binaries in `binaries/` with
  Ghidra's GUI (`CodeBrowser`), one function at a time, per the pipeline
  documented in `pseudo-code/README.md` (new file).
- Locating each target function in a stripped binary needed different
  techniques per sample, since there are no symbol names to search for:
  - **String-literal anchor** (fastest, used for `man_main`,
    `unpack_lzma_stream`, `nvfree`): search for a string used nowhere else
    in the source but inside the target function (e.g.
    `"MANDATORY_MANPATH"`, `"bad lzma header"`, `"Internal error"`), then
    follow Ghidra's XREF from the string to its calling function.
  - **Shared-global-reference chaining** (used for `nvalloc`, which has no
    strings of its own): found `nvfree` via its unique string first, then
    located `nvalloc` by checking which nearby function shares the same
    global block-list state and matches the expected shape (single `int`
    parameter, loop over `pos`/`size`/`nv` arithmetic, conditional
    allocation, zeroing loop) — confirmed against the real source's struct
    math (`MINNVBLOCK` = 64 = `0x40` showing up as the exact immediate
    constant in the decompiled comparison).
  - Address-adjacency (assuming the compiler kept source-order layout) was
    tried first for `nvalloc` and **failed** — the function immediately
    before `nvfree` by address turned out to be an unrelated helper, not
    `nvalloc`. Not a reliable heuristic on its own; only used the
    structural/reference-based checks above as ground truth.
  - Several functions weren't recognized as functions by Ghidra's
    auto-analysis at all (shown as `LAB_...`/decompiled ad-hoc as
    `UndefinedFunction_<addr>` instead of `FUN_...`) — fixed per-function
    with `Create Function` at the correct address once located via the
    Listing view.
- Saved and verified 3 of 5 samples so far, confirming the known fix is
  visible in each vulnerable/patched decompiled diff:
  - `CVE-2021-42373` (`man_main`): fix shows up as an added
    `|| (plVar12[1] == 0)` condition — matches the real `&& argv[1]` fix.
  - `CVE-2021-42374` (`unpack_lzma_stream`): fix shows up as a re-check
    `(int)pos < 0` added after the adjustment, jumping to the
    `"corrupted data"` error path if still negative — matches the real
    fix exactly.
  - `CVE-2021-42386` (`nvalloc`): **vulnerable side only, intentionally.**
    The fix removes `nvalloc`/`nvfree` entirely rather than patching them,
    so there is no equivalent "patched `nvalloc`" to decompile. Documented
    in detail in `pseudo-code/README.md`. `scripts/run_benchmark.py`
    already handles this correctly via its existing IR-fallback logic —
    it'll use `ir/CVE-2021-42386-busybox/patched.ll` for that variant
    automatically, no script changes needed.
- Remaining: `get_next_block` (bunzip2, CVE-2017-15873) and
  `option_to_env` (udhcpc6, CVE-2026-29004) — both need the
  size-sort/call-graph approach since neither has a usable string anchor.

## 2026-07-13 — Sample 4 done (get_next_block); found a real bug in sample 5's binaries

- `CVE-2017-15873` (`get_next_block`, bunzip2): located via `Window →
  Functions` sorted by size, confirmed unambiguously by the presence of
  bzip2's actual magic numbers (`0x177245`/`0x385090` = digits of √2,
  `0x314159`/`0x265359` = digits of π, used for end-of-stream/new-block
  markers) and by finding the exact vulnerable bounds check
  (`if (iVar17 < iVar6 + local_774) goto ...`, matching
  `dbufCount + runCnt > dbufSize`) with both operands declared `int`. The
  patched version's fix is clearly visible: the same check becomes an
  explicit `(uint)` comparison, with `dbufCount`/the run-length multiplier
  promoted to `uint` and the cached signed `dbufSize` local removed
  entirely in favor of re-reading `param_1[0x12]` with an explicit
  `(uint)` cast at each use — exactly the "changed the relevant variables
  to unsigned" fix described in `info.md`. Both saved.
- `CVE-2026-29004` (`option_to_env`, udhcpc6): took several wrong turns
  before landing on the right function, because this binary — like all
  10 — contains every applet from the shared minimal build config (man,
  awk, bunzip2, unlzma, udhcpc6 all together, not just the one relevant
  applet per sample), so generic heuristics like "self-recursive
  function" or a string search on a *shared* global matched unrelated
  code from other applets first (awk's AST-size walker, then what turned
  out to be ash/hush shell option-parsing code). Eventually found it by
  searching for `"option data exceeds option length"` (a string that
  belongs to a sibling function, `string_option_to_env`) and discovering
  the compiler had **inlined `string_option_to_env` directly into
  `option_to_env`** under `-Os` (it was only called from one call site),
  so there was really only one function to find, not two — explains the
  earlier confusion. Confirmed via the self-recursive call
  (`option_to_env(param_1+0x10, ...)` matching the `D6_OPT_IA_PD`/`IA_NA`
  recursion) and the IAADDR/IAPREFIX case bodies.
- **Bug found comparing vulnerable vs. patched**: the two decompiled
  `option_to_env` functions came back byte-for-byte identical. Checked
  the real source diff directly — the actual fix
  (`xmalloc(4 + addrs * 40 - 1)` → `xmalloc(4 + addrs * 40 + 1)`, plus two
  `!= 0` loop-condition changes) lives inside `case D6_OPT_DNS_SERVERS`,
  which is wrapped in `#if ENABLE_FEATURE_UDHCPC6_RFC3646`. The minimal
  build config only enabled `CONFIG_UDHCPC6` + its `CONFIG_FEATURE_IPV6`
  dependency, never `CONFIG_FEATURE_UDHCPC6_RFC3646` — so that entire
  branch, including the actual bug, was never compiled into either
  binary. Both binaries contain a real, legitimately-decompiled
  `option_to_env` — it's just missing the one branch that matters for
  this CVE.
- This is a real blind spot in Stage 3's automated build verification:
  the `nm`-based per-sample check (added after the earlier `FEATURE_IPV6`
  incident) only confirms the target *function* is present, not that a
  specific *branch inside it* survived preprocessing. A function can
  exist and still be missing its bug if a narrower feature flag gates
  just that branch. Documented in `pseudo-code/README.md` as a "known
  bug, not yet fixed" so it isn't lost, along with the exact fix needed:
  add `CONFIG_FEATURE_UDHCPC6_RFC3646=y`, rebuild only the 2
  `CVE-2026-29004-busybox` binaries (the other 8 samples are unaffected —
  none of their fixes sit behind an additional feature flag beyond what's
  already enabled), verify the DNS-servers branch actually compiled in
  this time (e.g. check for a reference to `sprint_nip6`, only called
  from within that branch), then redo this sample's Ghidra decompilation.
- **Committed as-is for the day**: 4 of 5 samples' pseudo-code done and
  verified (`CVE-2021-42373`, `CVE-2021-42374`, `CVE-2021-42386`
  vulnerable-only, `CVE-2017-15873`). `CVE-2026-29004` saved but flagged
  unusable until the rebuild above happens — do not run the benchmark
  against it in its current state.

## 2026-07-14 — Fixed CVE-2026-29004: rebuilt with the missing config flag

- Added `CONFIG_FEATURE_UDHCPC6_RFC3646=y` to the minimal build config
  (its only dependency, `CONFIG_UDHCPC6`, was already enabled) and
  rebuilt just the 2 `CVE-2026-29004-busybox` binaries — the other 8 were
  unaffected by this gap and didn't need touching.
- Extended the per-sample verification for this rebuild beyond the
  existing "target function present" `nm` check: also confirmed
  `sprint_nip6` (a function only called from inside the
  `D6_OPT_DNS_SERVERS` branch) is present in `busybox_unstripped` for
  both binaries — proof the specific vulnerable branch actually compiled
  in this time, not just the surrounding function.
- Re-stripped and re-verified clean the same way as the other 9 binaries
  (`nm`: no symbols, `readelf -S`: no per-function sections, `strings`:
  no leaked function/file names). Replaced
  `binaries/CVE-2026-29004-busybox/{vulnerable,patched}` in the repo.
- Re-decompiled `option_to_env` in Ghidra for both binaries. This time
  vulnerable and patched differ exactly where expected: inside the
  `D6_OPT_DNS_SERVERS` case, the allocation size changes from
  `(addrs >> 4... ) * 0x28 + 3` to `* 0x28 + 5` — the decompiled/optimized
  form of `xmalloc(4 + addrs*40 - 1)` → `xmalloc(4 + addrs*40 + 1)`
  (constant-folded: `4 - 1 = 3`, `4 + 1 = 5`). Confirms the fix is
  correctly represented now. Saved both files, overwriting the earlier
  (incomplete) vulnerable-only save.
- **All 5 samples are now complete**: 4 full vulnerable/patched pairs
  (`CVE-2026-29004`, `CVE-2021-42373`, `CVE-2021-42374`,
  `CVE-2017-15873`) plus `CVE-2021-42386`'s intentional vulnerable-only
  case (fix removes the function entirely; `run_benchmark.py` falls back
  to IR for that one variant). Stage 3 (compile/strip/decompile) is done.
- Updated `pseudo-code/README.md` and `binaries/README.md` to mark this
  resolved rather than in-progress.
- Next: no API keys yet, so Stage 5 (actually running
  `scripts/run_benchmark.py`/`scripts/score.py`) is still blocked on
  that. Otherwise the full pipeline (samples → IR → binaries → pseudo-code
  → prompts → scripts) is complete and ready to run end-to-end once keys
  are available.

## 2026-07-14 — Redesigned the benchmark as a full prompt x sample cross-product

- Raised a methodology question before running anything for real: the
  original `run_benchmark.py` only ran each sample against its own
  matching bug-class prompt (e.g. the NULL-deref sample only ever saw the
  NULL-deref prompt). That only measures "can it find the bug when told
  exactly what to look for" — it never tests whether a prompt stays quiet
  on code that doesn't have that bug class, so mismatched-prompt false
  positives (and the model's ability to correctly say "no, that's not
  this bug class") were never exercised. Decided to run every prompt
  template against every sample instead, not just matched pairs.
- Factored the `bug_class -> prompt filename` mapping out of
  `run_benchmark.py` into a new shared `scripts/bug_classes.py`, imported
  by both `run_benchmark.py` and `score.py`, so the two can't drift apart
  on which prompt "should" match which sample.
- `run_benchmark.py`: now loops sample × variant × **every prompt in
  `ALL_PROMPT_FILES`** × model (previously just sample × variant ×
  model). Output filenames gained a 4th component:
  `<cve_id>__<variant>__<model>__<prompt-slug>.md`. With 9 valid
  sample/variant pairs (`CVE-2021-42386` patched has no code file, by
  design), 5 prompts, and N models, that's `9 x 5 x N` calls — 90 for 2
  models.
- `score.py`: rewrote the expected-answer logic for the cross-product —
  a prompt should only say "yes" if the code is the vulnerable variant
  *and* the prompt's bug class actually matches the sample's real bug
  class (checked via `bug_classes.BUG_CLASS_TO_PROMPT`); every other
  combination should say "no." Replaced the old binary
  hit/false_positive columns with a `category` column
  (`true_positive`/`false_negative`/`true_negative`/`false_positive`) so
  a "matching prompt found the real bug" is clearly distinguishable from
  a "mismatched prompt hallucinated a bug that isn't there." Also prints
  a per-category breakdown, a specialized-prompt detection rate, and
  lists every false positive with its reason (patched code flagged vs.
  wrong bug class hallucinated).
- Verified the new scoring logic with a small dry run using hand-written
  fake result files before trusting it: confirmed a matched
  vulnerable-variant "yes" scores `true_positive`, and a mismatched
  prompt saying "yes" on the same vulnerable file correctly scores
  `false_positive` with the right reason. Deleted the test fixtures
  afterward.
- Added `.gitignore` (`__pycache__/`, `*.pyc`, `.venv/`) — hadn't been
  needed until Python scripts started actually being imported/run
  locally.
- Updated `scripts/README.md`, `results/README.md`, and `PLAN.md`'s
  Stage 5 section to describe the cross-product design and the new
  `scoring.csv` columns.
- Still blocked on API keys to actually run this for real.
