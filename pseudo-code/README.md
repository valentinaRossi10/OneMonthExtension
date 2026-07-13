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

## Known bug (in progress): CVE-2026-29004 binaries are missing the vulnerable code path

`pseudo-code/CVE-2026-29004-busybox/vulnerable.c` is saved but is **not
usable yet** — do not run the benchmark against it until this is fixed.

The actual vulnerable line (`xmalloc(4 + addrs * 40 - 1)`, inside `case
D6_OPT_DNS_SERVERS`) is wrapped in `#if ENABLE_FEATURE_UDHCPC6_RFC3646` in
the source. The minimal BusyBox build config used for all 10 binaries (see
`binaries/README.md`) only enables `CONFIG_UDHCPC6` and its
`CONFIG_FEATURE_IPV6` dependency — it never enabled
`CONFIG_FEATURE_UDHCPC6_RFC3646`, so that entire `case` block, including
the buggy allocation, was preprocessed out of both the vulnerable and
patched binaries. Confirmed by decompiling both: `option_to_env` in each
is byte-for-byte identical, because the only difference between the real
vulnerable/patched source (the `xmalloc` size and two `!= 0` loop-condition
changes) lives entirely inside the missing branch.

This also exposes a real blind spot in Stage 3's automated build
verification (`LOG.md`, 2026-07-13 entries): the `nm`-based check only
confirmed the *function* `option_to_env` was compiled in, not that the
*specific vulnerable branch inside it* was — a function can exist and
still be missing the bug if a sub-feature flag gating that branch isn't
enabled. Worth keeping in mind for any future sample where the vulnerable
line sits behind its own `#if`/`#ifdef`.

**Fix (not yet done):** add `CONFIG_FEATURE_UDHCPC6_RFC3646=y` to the
minimal config, rebuild just the two `CVE-2026-29004-busybox`
vulnerable/patched binaries (the other 8 are unaffected — none of their
vulnerable lines are behind an extra feature flag beyond what's already
enabled), re-verify via `nm`/`objdump` that the DNS-servers branch is
actually present this time (e.g. check for a reference to `sprint_nip6`,
which is only called from within that branch), re-run the Ghidra
decompilation for this sample only, and overwrite both
`pseudo-code/CVE-2026-29004-busybox/{vulnerable,patched}.c`.
