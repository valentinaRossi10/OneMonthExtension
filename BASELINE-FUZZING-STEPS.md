# Random-seed baseline: how to run it

Per-supervisor request: compare the LLM blind-seeded campaigns
(`dynamic-analysis/LLM-SEED-TIMING.md`) against a random-seed baseline,
isolating seed-generation strategy as the only variable. Same harness
binary, same build, same exec timeout. No dictionary (the existing
`dict.txt` files are themselves LLM-extracted boundary-value knowledge,
not neutral, so a fair baseline excludes them). Only the seed corpus
changes: minimal, content-free random bytes instead of the blind
Phase-1/2 taxonomy-derived seeds.

## 1. Generate a random seed corpus per case

One directory per case, named `seeds-random/`, sitting next to the
existing `seeds-blind/`. 3 files of random bytes each, sized roughly
like the smallest real seed already in `seeds-blind/` for that case (a
completely empty seed gives AFL no initial coverage to mutate from and
isn't representative of *any* real fuzzing baseline; a handful of
small random-byte files is the standard "no domain knowledge" control).

```bash
DA=/home/valentinarossi/Scrivania/UNI/POLYU/IRSS/repo/OneMonthExtension/dynamic-analysis

for case in cve-2026-29004 cve-2017-15873 cve-2021-42374 cve-2021-42373 cve-2021-42386; do
  mkdir -p "$DA/$case/seeds-random"
  for i in 1 2 3; do
    head -c 64 /dev/urandom > "$DA/$case/seeds-random/random_$i.bin"
  done
done
```

(`awk`'s harness treats the entire input as a script; random bytes are
fine as an AFL seed — a script that fails to parse just returns early,
same as any other rejected input, so it's a legitimate "no knowledge"
starting point, not something that needs to be syntactically valid.)

## 2. Build each harness (same as before — no changes)

```bash
DS=/home/valentinarossi/Scrivania/UNI/POLYU/IRSS/repo/OneMonthExtension/dataset

"$DA/cve-2026-29004/build.sh" "$DS/busybox-CVE-2026-29004-vulnerable"  /home/valentinarossi/afl-harnesses/cve-2026-29004
"$DA/cve-2017-15873/build.sh" "$DS/busybox-CVE-2017-15873-vulnerable"  /home/valentinarossi/afl-harnesses/cve-2017-15873
"$DA/cve-2021-42374/build.sh" "$DS/busybox-CVE-2021-42374-vulnerable" /home/valentinarossi/afl-harnesses/cve-2021-42374
"$DA/cve-2021-42373/build.sh" "$DS/busybox-CVE-2021-42373-vulnerable" /home/valentinarossi/afl-harnesses/cve-2021-42373
"$DA/cve-2021-42386/build.sh" "$DS/busybox-CVE-2021-42386-vulnerable" /home/valentinarossi/afl-harnesses/cve-2021-42386
```

(Skip any that are already built and unchanged — the binaries under
`/home/valentinarossi/afl-harnesses/` from the blind campaigns are
still valid, since the harness source hasn't changed.)

## 3. Run each campaign — no `-x` dictionary flag, output to `out-random/`

```bash
# udhcpc6
ASAN_OPTIONS=symbolize=0:abort_on_error=1:detect_leaks=0 AFL_SKIP_CPUFREQ=1 \
  afl-fuzz -m none -i "$DA/cve-2026-29004/seeds-random" -o "$DA/cve-2026-29004/out-random" \
  -- /home/valentinarossi/afl-harnesses/cve-2026-29004/harness_d6dns

# bunzip2 (no -x dict.txt this time)
ASAN_OPTIONS=symbolize=0:abort_on_error=1:detect_leaks=0 AFL_SKIP_CPUFREQ=1 \
  afl-fuzz -m none -i "$DA/cve-2017-15873/seeds-random" -o "$DA/cve-2017-15873/out-random" \
  -- /home/valentinarossi/afl-harnesses/cve-2017-15873/harness_bunzip2

# unlzma (no -x dict.txt this time)
ASAN_OPTIONS=symbolize=0:abort_on_error=1:detect_leaks=0 AFL_SKIP_CPUFREQ=1 \
  afl-fuzz -m none -i "$DA/cve-2021-42374/seeds-random" -o "$DA/cve-2021-42374/out-random" \
  -- /home/valentinarossi/afl-harnesses/cve-2021-42374/harness_unlzma

# man
ASAN_OPTIONS=symbolize=0:abort_on_error=1:detect_leaks=0 AFL_SKIP_CPUFREQ=1 \
  afl-fuzz -m none -i "$DA/cve-2021-42373/seeds-random" -o "$DA/cve-2021-42373/out-random" \
  -- /home/valentinarossi/afl-harnesses/cve-2021-42373/harness_man

# awk
ASAN_OPTIONS=symbolize=0:abort_on_error=1:detect_leaks=0 AFL_SKIP_CPUFREQ=1 \
  afl-fuzz -m none -i "$DA/cve-2021-42386/seeds-random" -o "$DA/cve-2021-42386/out-random" \
  -- /home/valentinarossi/afl-harnesses/cve-2021-42386/harness_awk
```

Run each in its own terminal (or `tmux`/`screen` pane) exactly as the
blind campaigns were run — don't background/redirect blindly, so the
live TUI stats stay directly inspectable.

## 4. How long to run each

For a fair comparison, match (or exceed) the LLM-seeded campaign's
total run time per case, not a fixed uniform duration for all 5 — the
LLM campaigns themselves varied a lot (96s to ~31.7h), so "same time
budget" only makes sense per-case:

| Case | Match/exceed this run time |
|---|---|
| man | at least 96s, but let it run a few minutes to be meaningful |
| udhcpc6 | at least ~19 min |
| unlzma | at least ~82 min |
| bunzip2 | at least ~2.3h (already a negative result at that point for the LLM run) |
| awk | at least ~31.7h if practical, or a clearly-stated shorter cap if not — note the cap explicitly when reporting |

Stop each with `Ctrl+C` once its target time is reached (or a crash is
found, whichever comes first — same as the blind campaigns).

## 5. Triage exactly like the blind campaigns

Same process as every confirmed case so far — reproduce each saved
crash standalone, extract the ASAN signature, build the patched
comparison binary, replay the identical input, and only call it
confirmed if it reproduces on vulnerable and is absent on patched:

```bash
BIN=/home/valentinarossi/afl-harnesses/<case>/<harness_binary>
for f in "$DA/<case>/out-random/default/crashes/"id:*; do
  echo "=== $(basename "$f") ==="
  ASAN_OPTIONS=symbolize=0:abort_on_error=1:detect_leaks=0 "$BIN" < "$f" 2>&1 | grep -E "ERROR|WRITE of size|READ of size|bytes after"
done
```

## 6. Document the result

Add a `CAMPAIGN-RESULTS-RANDOM.md` per case (same structure as the
existing `CAMPAIGN-RESULTS.md` files), then fold the comparison numbers
into `dynamic-analysis/LLM-SEED-TIMING.md` as a new "Random baseline"
column once all 5 are done, and update `results/OVERALL_RESULTS.md`'s
per-CVE pipeline table.

## 7. If pure random can't pass a format's magic-byte/header gate

Watch for AFL's own `last new find: none yet (odd, check syntax!)`
warning combined with corpus count never growing past the initial seed
count — that's a gate-passing failure, not evidence about the bug
itself (seen on CVE-2017-15873/bunzip2: 2.10% coverage, corpus stuck at
3 seeds across 45 cycles). It conflates two different questions ("can
the fuzzer build a well-formed file of this type" vs. "can it find the
dangerous shape inside one") into one misleading "random found nothing"
result.

Add a third condition to separate them: seeds that are **format-valid
but content-random**, built mechanically with the real tool for that
format (not the LLM extraction, not hand-picked around the known bug):

```bash
DA=/home/valentinarossi/Scrivania/UNI/POLYU/IRSS/repo/OneMonthExtension/dynamic-analysis
mkdir -p "$DA/<case>/seeds-random-valid"
head -c 256   /dev/urandom | bzip2 -c > "$DA/<case>/seeds-random-valid/valid_random_1.bz2"
head -c 2048  /dev/urandom | bzip2 -c > "$DA/<case>/seeds-random-valid/valid_random_2.bz2"
head -c 16384 /dev/urandom | bzip2 -c > "$DA/<case>/seeds-random-valid/valid_random_3.bz2"

ASAN_OPTIONS=symbolize=0:abort_on_error=1:detect_leaks=0 AFL_SKIP_CPUFREQ=1 \
  afl-fuzz -m none -i "$DA/<case>/seeds-random-valid" -o "$DA/<case>/out-random-valid" \
  -- /home/valentinarossi/afl-harnesses/<case>/<harness_binary>
```

Document as `CAMPAIGN-RESULTS-RANDOM-VALID.md`; see
`dynamic-analysis/cve-2017-15873/CAMPAIGN-RESULTS-RANDOM-VALID.md` for
the worked example.
