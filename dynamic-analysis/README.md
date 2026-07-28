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
| CVE-2021-42374 (unlzma) | not started | — | — |
| CVE-2021-42373 (man) | not started | — | — |
| CVE-2021-42386 (awk) | not started | — | — |
