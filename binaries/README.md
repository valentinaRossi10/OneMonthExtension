# binaries/

Compiled, linked, stripped ELF executables for each sample, one
`vulnerable` / `patched` pair per CVE, mirroring `samples/` and `ir/`.

These are the input to Stage 3's decompilation step (Ghidra) — see
`LOG.md` for the full pipeline and reasoning.

## How these were produced

1. Built the **full linked BusyBox executable** at each sample's
   vulnerable/patched commit — not a single-file compile. This matters:
   an earlier attempt compiled each sample's `.c` file alone into an
   unlinked relocatable object (`.o`) and stripped that directly, which
   destroys the object's relocation table before it was ever resolved
   (relocations only get resolved at link time), leaving Ghidra with
   garbage placeholder bytes instead of real call targets. Building and
   linking the full executable first means all relocations are already
   resolved to real addresses by the time anything gets stripped. See the
   2026-07-13 "relocation bug" entry in `LOG.md` for the full diagnosis.
2. Used a **minimal config** (`make allnoconfig` plus only the ~6 applets
   the 5 samples actually need: `CONFIG_BUNZIP2`, `CONFIG_BZCAT`,
   `CONFIG_UNLZMA`, `CONFIG_AWK`, `CONFIG_MAN`, `CONFIG_UDHCPC6` +
   `CONFIG_FEATURE_IPV6`, which `CONFIG_UDHCPC6` depends on) rather than
   `make defconfig` — much faster, and avoids several legacy-applet build
   failures against modern kernel/glibc headers that are unrelated to any
   of the 5 samples (e.g. `networking/tc.c` needing removed kernel CBQ
   structs, `date`/`rdate` needing the removed `stime()` syscall).
3. Verified via `nm` on the **unstripped** intermediate
   (`busybox_unstripped`, which BusyBox's own build produces before its
   own final strip step) that each sample's target function
   (`option_to_env`, `nvalloc`, `get_next_block`, `man_main`,
   `unpack_lzma_stream`) actually made it into the binary — not
   optimized away or (for the CVE-2021-42386 patched build) confirmed
   correctly **absent**, since that fix removes `nvalloc` entirely. This
   caught a real bug during the rebuild: `CONFIG_UDHCPC6` silently
   depends on `CONFIG_FEATURE_IPV6`, which `allnoconfig` disables by
   default, so the first rebuild attempt produced two binaries missing
   `option_to_env` (and the whole udhcpc6 applet) entirely without any
   build error.
4. BusyBox's own build system already links `busybox_unstripped` down to
   a stripped `busybox` binary as its last step — no separate strip pass
   was actually needed. Ran `strip --strip-all` again anyway as an
   explicit, documented step. Confirmed via `nm` (no symbols) and
   `readelf -S` that, unlike the earlier unlinked-`.o` attempt, a fully
   linked executable's per-function `-ffunction-sections` sections get
   coalesced by the linker into single `.text`/`.data`/`.rodata` sections
   — so the earlier section-name leak (`.text.<fn>` surviving `strip`)
   does not apply here; no `objcopy --rename-section` step is needed for
   linked binaries.
5. Verified with `strings` across all 10 files that no target function
   name, or any other sample-identifying source filename, appears
   anywhere in the binary.

This matters because these binaries stand in for real, deployed firmware
binaries, which ship linked and stripped — the whole point of stripping
here is to avoid handing the LLM information (names) it wouldn't have on
a real target. See `LOG.md` (2026-07-12 methodology correction entry) for
why stripping is necessary, and the 2026-07-13 entries for the
relocation-bug fix and the udhcpc6/`FEATURE_IPV6` bug caught during the
rebuild.

## Update (2026-07-14): fixed a second config gap in the CVE-2026-29004 binaries

Manually decompiling `CVE-2026-29004-busybox` in Ghidra revealed the
vulnerable/patched `option_to_env` decompiled **identically** — the actual
CVE-2026-29004 fix (`xmalloc(4 + addrs * 40 - 1)` →
`xmalloc(4 + addrs * 40 + 1)`, inside `case D6_OPT_DNS_SERVERS`) is gated
by `#if ENABLE_FEATURE_UDHCPC6_RFC3646` in the source, and the minimal
config only enabled `CONFIG_UDHCPC6` + `CONFIG_FEATURE_IPV6` — never
`CONFIG_FEATURE_UDHCPC6_RFC3646` — so that whole branch, including the
bug, was preprocessed out of both binaries. `option_to_env` the function
was present and correctly verified by the existing `nm` check (see point 3
above), but the *specific branch* wasn't — the earlier check had no way to
catch that.

Fixed by adding `CONFIG_FEATURE_UDHCPC6_RFC3646=y` and rebuilding just
these 2 binaries, this time also checking (via `nm` on
`busybox_unstripped`) that `sprint_nip6` is present — it's a function only
called from inside the `D6_OPT_DNS_SERVERS` branch, so its presence proves
that specific branch actually compiled in. Re-stripped and re-verified
clean (no symbols, no per-function sections, no leaked names) the same way
as the other 9 binaries. See `LOG.md`/`pseudo-code/README.md` for the full
diagnosis.
