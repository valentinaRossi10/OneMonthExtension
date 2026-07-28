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
| CVE-2026-29004 (udhcpc6) | done | yes (hand-crafted seed) | yes (60s, no false positives) |
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
