# binaries/

Compiled, stripped ELF relocatable object files for each sample, one
`vulnerable.o` / `patched.o` pair per CVE, mirroring `samples/` and `ir/`.

These are the input to Stage 3's decompilation step (Ghidra) — see
`PLAN.md` and `LOG.md` for the full pipeline and reasoning.

## How these were produced

1. Compiled normally from the same vulnerable/patched commits used for
   `samples/` and `ir/`, using BusyBox's own build flags (captured via
   `make V=1 <file>.o`), producing a real ELF relocatable object
   (`gcc ... -c -o file.o file.c` — no `-emit-llvm`).
2. Stripped all symbols: `strip --strip-all file.o`.
3. Anonymized per-function section names: BusyBox compiles with
   `-ffunction-sections`, so each function gets its own section
   (e.g. `.text.option_to_env`) — `strip --strip-all` removes the symbol
   table but does **not** remove these section names, which would
   otherwise leak the vulnerable function's name straight through
   stripping. Renamed every `.text.<fn>` / `.data.<fn>` / `.rodata.<fn>`
   section back to its generic form (`.text`, `.data`, `.rodata`) with
   `objcopy --rename-section`.
4. Verified with `nm` (no symbols) and `strings` (no target function names
   anywhere in the file) that no sample leaks which function is the
   vulnerable one before it even reaches Ghidra.

This matters because these object files stand in for real, deployed
firmware binaries, which ship stripped — the whole point of stripping here
is to avoid handing the LLM information (names) it wouldn't have on a real
target. See `LOG.md` (2026-07-12 methodology correction entry) for why this
was necessary.
