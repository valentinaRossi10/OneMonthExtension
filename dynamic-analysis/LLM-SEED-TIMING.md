# Time-to-crash: LLM blind-seeded campaigns (baseline for random-seed comparison)

This documents, per case, how long the blind Phase 1/2 LLM-seeded AFL++
campaigns took to reach a confirmed crash (or, for the two unresolved
cases, how much search time was spent without one). This is the
comparison point for the random-seed baseline (Stage 9's professor-
requested control): same harness, same timeout/build, only the seed
corpus differs.

All figures are read directly from `out-blind/default/fuzzer_stats` and
crash-file `time:`/`execs:` fields (AFL's `time:` is milliseconds since
campaign start), not estimated.

## Confirmed cases

| CVE (target) | Seed corpus | Dictionary | Time to first crash | Execs to first crash | Total run time | Total execs | Saved crashes | Result |
|---|---|---|---|---|---|---|---|---|
| CVE-2021-42373 (man, NULL-deref) | 9 blind argv shapes | none | **~5.7s** (`time:5662`) | **845** | 96s | 9,844 | 1 | Confirmed — absent on patched |
| CVE-2026-29004 (udhcpc6, heap-overflow) | 2 blind seeds | none | **~372.8s** (`time:372814`) | **81,087** | 1,138s (~19 min) | 235,528 | 7 | Confirmed — absent on patched, all 7 identical signature |
| CVE-2021-42374 (unlzma, OOB-read) | blind seeds + boundary-value dict | yes | **~4,824.5s** (`time:4824520`, ~80.4 min) | **175,710** | 4,927s (~82 min), 8 cycles | 187,274 | 1 | Confirmed — absent on patched |

## Unresolved cases (no crash of the target class within the time spent)

| CVE (target) | Seed corpus | Dictionary | Total run time | Total execs | Cycles | Saved crashes | Result |
|---|---|---|---|---|---|---|---|
| CVE-2017-15873 (bunzip2, integer-overflow) | blind seeds | yes | 8,182s (~2.3h) | 242,043 | 14 | 0 | No crash found; separately documented as structurally infeasible via any real (non-malformed-bitstream) compressed input — `dbufSize`'s 900,000-byte cap makes the real trigger unreachable by genuine compression regardless of fuzz time |
| CVE-2021-42386 (awk, use-after-free) | blind seeds (2 rounds, 8 scripts total) | none | 114,079s (~31.7h) | 1,587,759 | 40 | 19 (all triaged: stack-overflow / `bb_perror_msg` SEGV / one off-target heap-UAF identified as the distinct, already-fixed CVE-2023-42363) | Target pool-allocator UAF never found; every crash class present also reproduces on patched source |

## Reading this for the random-seed comparison

- The 3 confirmed cases give a real spread to compare against: seconds
  (man), minutes (udhcpc6), over an hour (unlzma) — a random baseline
  that matches or beats these times on the same harness would suggest
  the LLM seed-taxonomy step added little; one that takes materially
  longer (or never finds it in an equal time budget) would support the
  seed-generation step's value.
- The 2 unresolved cases are honest negative results at ~2.3h and
  ~31.7h respectively — a random baseline is not expected to do better
  on these (bunzip2's trigger is structurally unreachable by any
  legitimate fuzzed input; awk's real bug has a narrow alloc/free
  interleaving requirement blind mutation hasn't hit in 31.7h either).
  They're included for completeness, not as cases where a fast random
  win is anticipated.
- For a fair comparison, the random baseline must isolate the same
  variable it's testing: same harness binary/build, same exec timeout,
  and — since the dictionary in `cve-2021-42374`/`cve-2017-15873` is
  itself LLM-extracted boundary-value knowledge, not neutral — the
  random baseline should run **without** any dictionary, from
  minimal/non-crafted seed files only. See `../BASELINE-FUZZING-STEPS.md`
  for the exact commands.
