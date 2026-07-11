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
