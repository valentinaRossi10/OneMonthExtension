# pseudo-code/

Ghidra-decompiled pseudo-C for each sample's target function, mirroring
`samples/` and `ir/`. This is the **primary** representation shown to the
LLM (per the mentor's decision — see `LOG.md`, 2026-07-12), with `ir/` as
the documented fallback.

```
pseudo-code/
├── CVE-2021-42373-busybox/
│   ├── vulnerable.c
│   └── patched.c
└── ...
```

## How these are produced (manual, per sample)

Ghidra's decompiler is used interactively (GUI, not headless) against the
linked+stripped binaries in `binaries/`:

1. Import a `binaries/<sample>/{vulnerable,patched}` binary into a Ghidra
   project, let auto-analysis run.
2. Locate the target function inside the stripped binary. Since symbol
   names are gone, this is done either by:
   - Searching for a unique string literal referenced only inside the
     target function (`Search → For Strings`, then follow the XREF from
     the string to its caller) — used for `man_main`
     (`"MANDATORY_MANPATH"`), `unpack_lzma_stream` (`"bad lzma header"`),
     and `nvfree` (`"Internal error"`, used to then locate the nearby
     `nvalloc` via its shared reference to the same global block-list
     state), or
   - Sorting `Window → Functions` by size and cross-checking candidate
     functions' structure (parameter count, loop shape, arithmetic)
     against the real source in `samples/`.
   If Ghidra hasn't recognized the address as a function yet (shows as
   `LAB_...`/`UndefinedFunction_...` instead of `FUN_...`), `Create
   Function` at that address first.
3. Copy the function's full decompiled text from the Decompile panel
   as-is — no manual cleanup or renaming of the saved output (only the
   local Ghidra project's function name is renamed, for the researcher's
   own navigation; this does not change the binary or the exported text).
4. Save to `pseudo-code/<sample>/{vulnerable,patched}.c`.

## Known asymmetry: CVE-2021-42386 (awk, use-after-free)

Only `pseudo-code/CVE-2021-42386-busybox/vulnerable.c` exists — there is
**no `patched.c`** for this sample, intentionally.

The CVE-2021-42386 fix does not modify `nvalloc`/`nvfree` — it **removes
them entirely**, replacing every call site with plain `xzalloc()`/`free()`
calls scattered across `editors/awk.c`. This was already confirmed at the
IR stage (Stage 2: `nvalloc` correctly absent from the patched `.ll`) and
re-confirmed during the Stage 3 binary rebuild's automated verification
(`nm` check against `busybox_unstripped` for the patched build). There is
therefore no single "patched `nvalloc`" function to decompile — attaching
one artificially (e.g. picking one of the many scattered `xzalloc` call
sites) would misrepresent the fix and wouldn't be a fair vulnerable/patched
comparison for the benchmark.

This is handled automatically by `scripts/run_benchmark.py`, which already
falls back to `ir/CVE-2021-42386-busybox/patched.ll` when no matching
pseudo-code file exists — a legitimate use of the documented IR-fallback
path (per the mentor's guidance: fall back to IR when pseudo-code can't
represent the target), not a gap to fill in later.
