# firmware/

Stage 7: ground truth from real, unmodified vendor firmware for the planned
Tier B codebase-level confirmation task. It is kept separate from the
BusyBox Tier A benchmark because no source code exists and the starting
point is a compiled vendor binary extracted from a firmware image.
See `../EXPERIMENT.md` for the oracle-candidate, cascade, information-boundary,
and reporting rules that any Tier B implementation must follow.

```
firmware/
├── raw/                    # (gitignored) original downloaded firmware images
├── extracted/               # (gitignored) binwalk output
└── CVE-2016-6277-netgear-r6400/
    ├── info.md               # ground truth: function, mechanism, versions, references
    ├── index.csv             # same shape as samples/index.csv, scoped to this phase
    └── pseudo-code/
        ├── vulnerable/       # decompiled functions from the vulnerable binary
        └── patched/          # decompiled functions from the patched binary
```

## No-redistribution policy

Unlike BusyBox (GPL, self-compiled), vendor firmware is proprietary. This
repo does **not** commit firmware images or the full `binwalk` extraction
— `raw/` and `extracted/` are gitignored (only `.gitkeep` is tracked, to
keep the folder structure visible). Only the small decompiled pseudo-C
snippets actually analyzed are committed, under each CVE's `pseudo-code/`
— the same scope PANGOLIN/MANGODFA themselves publish in their papers,
not the underlying binaries. Exact download URLs and checksums for
reproducibility are recorded in each CVE's `info.md` instead.

## Pipeline

1. Obtain the firmware image(s) (see each CVE's `info.md` for the
   download source). Do not commit them — save to `raw/` locally, which
   is gitignored.
2. Extract with `binwalk -e <firmware.chk>` — produces a
   `squashfs-root/` filesystem locally in `extracted/` (also gitignored).
3. Identify the relevant binary (architecture via `file <binary>` — real
   firmware is typically ARM or MIPS, not x86-64) and Ghidra-decompile it,
   same manual technique used for the BusyBox samples (string-search
   anchors, `Window → Functions` sorted by size, `Create Function` for
   anything Ghidra didn't auto-recognize).
4. Trace the actual vulnerable code path by hand — this is **ground truth
   only**, not model-visible evidence. Record one candidate function, one
   specific entry point, and the expected reachability path. Tier B will
   receive the already-flagged candidate plus whole-codebase context and
   test confirmation from that entry point; it will not search blindly for
   an unknown candidate.
5. Document the ground truth in `info.md`, save every relevant
   decompiled function to `pseudo-code/{vulnerable,patched}/`.

## Current scope

This directory contains the ground-truth metadata and selected pseudo-code
needed to design the first Tier B case. It does **not** contain the vendor
firmware, a complete exported codebase, Tier B automation, or Tier B results.
The retained `scripts/ghidra/ExportAllFunctions.java` utility can help build
a future reproducible whole-codebase input after the Tier B skill and
evaluation protocol are reviewed.

## Samples

- [`CVE-2016-6277-netgear-r6400`](CVE-2016-6277-netgear-r6400/info.md) —
  unauthenticated command injection via `/cgi-bin/;<command>` on the
  Netgear R6400/R7000, in `usr/sbin/httpd`.
