# firmware/

Stage 7: real, unmodified vendor firmware — a proof-of-concept extending
the CVE-benchmark methodology (`samples/`/`ir/`/`binaries/`/`pseudo-code/`)
to inputs we don't control, per `PLAN.md`'s Stage 7. Kept as a separate
top-level folder rather than nested inside those, since the pipeline
shape genuinely differs here: no source code exists, so there's no
`samples/`/`ir/` equivalent, and the starting point is a compiled vendor
binary extracted from a firmware image.

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
4. Trace the actual vulnerable code path by hand — this is **ground
   truth only**, not what gets shown to an LLM. See `PLAN.md`'s Stage 7
   for why: handing an LLM one pre-isolated function would just repeat
   the BusyBox benchmark, testing no real discovery capability. The
   LLM's actual task (once built) is scored against every function in
   the relevant binary, not the one function we already know is
   vulnerable.
5. Document the ground truth in `info.md`, save every relevant
   decompiled function to `pseudo-code/{vulnerable,patched}/`.

## Samples

- [`CVE-2016-6277-netgear-r6400`](CVE-2016-6277-netgear-r6400/info.md) —
  unauthenticated command injection via `/cgi-bin/;<command>` on the
  Netgear R6400/R7000, in `usr/sbin/httpd`.
