# Time-to-crash: LLM blind-seeded campaigns vs. random-seed baseline

This documents, per case, how long the blind Phase 1/2 LLM-seeded AFL++
campaigns took to reach a confirmed crash (or, for the two unresolved
cases, how much search time was spent without one). This is the
comparison point for the random-seed baseline (Stage 9's professor-
requested control): same harness, same timeout/build, only the seed
corpus differs.

All figures are read directly from `out-blind/default/fuzzer_stats` and
crash-file `time:`/`execs:` fields (AFL's `time:` is milliseconds since
campaign start), not estimated.

## Confirmed cases — LLM blind-seeded

| CVE (target) | Seed corpus | Dictionary | Time to first crash | Execs to first crash | Total run time | Total execs | Saved crashes | Result |
|---|---|---|---|---|---|---|---|---|
| CVE-2021-42373 (man, NULL-deref) | 9 blind argv shapes | none | **~5.7s** (`time:5662`) | **845** | 96s | 9,844 | 1 | Confirmed — absent on patched |
| CVE-2026-29004 (udhcpc6, heap-overflow) | 2 blind seeds | none | **~372.8s** (`time:372814`) | **81,087** | 1,138s (~19 min) | 235,528 | 7 | Confirmed — absent on patched, all 7 identical signature |
| CVE-2021-42374 (unlzma, OOB-read) | blind seeds + boundary-value dict | yes | **~4,824.5s** (`time:4824520`, ~80.4 min) | **175,710** | 4,927s (~82 min), 8 cycles | 187,274 | 1 | Confirmed — absent on patched |

## Confirmed cases — random-seed baseline (control)

Same harness/build/timeout, no dictionary, seed corpus = 3 files of 64
random bytes (`/dev/urandom`). Full detail per case in
`<cve>/CAMPAIGN-RESULTS-RANDOM.md`.

| CVE (target) | Time to first crash | Execs to first crash | Total run time | Total execs | Saved crashes | vs. blind |
|---|---|---|---|---|---|---|
| CVE-2021-42373 (man) | **~71.8s** (`time:71762`) | **15,941** | 407s | 50,355 | 4 | Blind was **~12.6x faster**, ~19x fewer execs |
| CVE-2026-29004 (udhcpc6) | **~93.2s** (`time:93248`) | **14,255** | 375s | 58,372 | 9 | **Random was ~4x faster**, ~5.7x fewer execs — the LLM seed advantage did not generalize to this case |
| CVE-2017-15873 (bunzip2) | No crash | N/A | 1,142s (~19 min), 45 cycles | 296,317 | 0 | **Qualitatively different failure**: stuck at the format's magic-byte header gate the whole run (corpus never grew past 3 seeds, edges_found 3/143 = 2.10% vs. blind's 85.31%) — random mutation never even reached the code the bug lives in, vs. blind's genuine-but-unsuccessful search *inside* the format. See `CAMPAIGN-RESULTS-RANDOM.md`. |

The confirmed baseline runs give a genuinely mixed result: the blind
taxonomy-derived seeds gave a large head start on `man` (a shallow argv-
shape bug the seed corpus's argv variety happened to target directly), but
`udhcpc6`'s overflow is reached just as easily by unstructured random-byte
mutation on the address-count field, so the blind seeds' domain knowledge
added no measurable value there — reported plainly rather than adjusted to
fit a single expected direction.

`bunzip2` shows the opposite extreme instead: for a format gated behind a
fixed multi-byte magic header, random mutation cannot even pass the entry
check, so the comparison isn't "who found the bug faster" but "one
strategy could search the format's interior at all, and the other
couldn't." This is the clearest case for the value of Phase 1 extraction
specifically — not because it points the search *toward* the bug, but
because it supplies the structural constant needed to get *past the door*
before any search is possible.

## A third condition for bunzip2: format-valid, content-random seeds

To separate "can't build a well-formed file" from "can't find the
dangerous shape inside a well-formed file," a third seeding condition was
added: 3 seeds built by compressing random content with the **real
`bzip2` tool** (mechanical, no LLM, no bug-specific knowledge — see
`cve-2017-15873/CAMPAIGN-RESULTS-RANDOM-VALID.md`). At just 22
executions, before any real mutation search:

| Condition | Coverage | Edges found |
|---|---|---|
| Pure random (45 cycles, 296,317 execs) | 2.10% | 3 / 143 |
| **Format-valid random (3 seeds, 22 execs)** | **56.64%** | **81 / 143** |
| Blind LLM-seeded (calibration) | 85.31% | 122 / 143 |

Confirms the diagnosis directly: pure random's near-zero coverage was a
gate-passing failure, not a hard-interior problem. Once a well-formed
input exists, the fuzzer starts most of the way to the blind campaign's
own coverage before mutation has even begun. Full results (execs, time,
any crash) pending — campaign in progress.

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
