# Stage 9 — dynamic analysis (fuzzing)

Implementation artifacts for the plan in `../DYNAMIC-ANALYSIS-PLAN.md`.
One subdirectory per ground-truth case, each containing:

- `harness.patch` — the minimal source change needed to make the
  candidate function fuzzable (only present when one is actually
  needed — several cases reuse an already-exported entry point as-is).
- `build.sh` — reproducible build script; takes a path to the
  corresponding `dataset/` checkout (gitignored, rebuilt from the
  commit hashes in `binaries/tier-b/*/PROVENANCE.md`) and produces the
  harness binary under a local, gitignored `build/`.
- `seeds/` — the initial corpus (at minimum: one known-crashing PoC,
  one non-crashing seed for AFL++'s dry-run check).
- `PROVENANCE.md` — what the harness does, why it's built this way,
  and what's been empirically verified vs. still assumed.

## Status

| Case | Harness | Verified crash repro | Calibration run |
|---|---|---|---|
| CVE-2026-29004 (udhcpc6) | done | **yes — via real blind-seeded exploration** (~19 min, 7/7 crashes cross-checked as fix-specific true positives; supersedes the earlier hand-crafted-seed confirmation). See `CAMPAIGN-RESULTS.md` | yes (60s, no false positives) |
| CVE-2017-15873 (bunzip2) | done | not yet — needs a longer/guided campaign, not a hand-craftable trigger | yes (4 min, 80.42% coverage, 0 crashes, no false positives) |
| CVE-2021-42374 (unlzma) | done | **yes — found autonomously** by AFL++ (SEGV, wild pointer read); cross-checked absent on patched source | yes (4 min, 83.50% coverage, 1 crash) |
| CVE-2021-42373 (man) | done | yes (hand-crafted argv, first try — NULL deref); cross-checked absent on patched source | yes (60s, 14,813 execs, 2 crashes, re-verified after linker-stub fix) |
| CVE-2021-42386 (awk) | done | not yet — 21 crashes found in discovery campaign, all cross-checked and ruled out as unrelated to this CVE (19 stack-overflow + 1 unrelated SEGV, both also present on patched source); target UAF needs a more targeted (nested-call) seed | yes (4 min, 39,536 execs) |

**Found and fixed while building the awk harness**: the shared
`bb_show_usage()` linker stub called `abort()`, turning ordinary
"invalid CLI option" behavior into a false-positive crash in any
harness that reaches `getopt32` (`man`, `awk`). Fixed to `_exit(2)` in
all 5 harnesses; `man`'s calibration numbers above are the corrected
re-run. See `cve-2021-42386/PROVENANCE.md` for the full account.

## Summary — all 5 harnesses built (2026-07-28)

All 5 ground-truth BusyBox cases now have a working AFL++/ASAN harness,
built while awaiting the mentor's reply on the Tier B SSA/range-analysis
decision (`DYNAMIC-ANALYSIS-PLAN.md` still lists this as open). Each
harness was built following the same discipline used throughout the
rest of this project: build it, verify it actually exercises the real
code (not just that it links), and where a crash is found, cross-check
it against the *patched* source with the identical input before calling
it a confirmation — a crash alone is not evidence for a specific CVE
unless it's absent once the fix is applied.

**Harness design patterns that emerged, reusable across cases:**
- Byte-buffer input (udhcpc6, bunzip2, unlzma): feed fuzzer bytes
  directly via stdin/`src_fd` to an already- or newly-exposed decode
  function.
- Argv input (man, awk): use AFL++'s `argv-fuzz-inl.h` shim (man) or a
  fixed single-token argv built directly from the fuzzer's stdin bytes
  (awk, since only one script argument was actually needed).
- `static` linkage is essentially never a real blocker: either append
  the harness's `main()` to the same translation unit (udhcpc6) or
  rename the entry point at compile time via `-Dfoo_main=foo_main_impl`
  (man, awk) — no case needed the candidate function's own signature
  changed.
- Every harness links a small set of "dead code, satisfy the linker
  only" stubs (`applet_name`, `string_array_len`, `bb_show_usage`)
  because `appletlib.o` (BusyBox's real `main()`) is deliberately
  excluded from every build.

**Results, plainly stated:**
- **3 of 5 confirmed as true positives via dynamic analysis**:
  CVE-2026-29004, CVE-2021-42374, CVE-2021-42373 — each has a crash
  that reproduces on the vulnerable source and is absent (clean
  rejection) on the patched source with the identical input.
- **2 of 5 not yet confirmed**: CVE-2017-15873 (bunzip2 — harness
  works, no crash found yet, bug needs a specific Huffman/run-length
  structure not reachable by blind mutation from one valid seed) and
  CVE-2021-42386 (awk — harness works, 21 crashes found but all
  cross-checked and ruled out as unrelated to this specific CVE; the
  real UAF needs a *nested* function-call pattern in argument position,
  confirmed not triggered by plain linear recursion).
- **1 real methodology bug found and fixed along the way**: the
  `bb_show_usage` stub inflating crash counts with normal usage-error
  exits, caught specifically *because* of the patched-source
  cross-check discipline, not by luck.
