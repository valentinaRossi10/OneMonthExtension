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

## 2026-07-11 — Mentor's decision: decompiled pseudo-code, with IR/disassembly as fallback

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
