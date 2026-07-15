# Plan

Stage checklist and how-to reference. For *why* each decision was made,
see `PIPELINE.md`. For full chronological/debugging detail, see `LOG.md`.

## Stage 0 — Environment setup — done

```bash
sudo apt update
sudo apt install build-essential clang llvm git python3 python3-pip binwalk
```
Ghidra installed separately (manual download, not via apt).

## Stage 1 — CVE ground-truth benchmark — done

5 BusyBox CVEs, one per memory-safety bug class, each verified directly
against the real fixing commit. `samples/index.csv` is the ground-truth
index; `samples/<cve>/info.md` documents each one.

## Stage 2 — LLVM IR — done, now the fallback representation

```bash
clang -S -emit-llvm -g -O0 <file.c> -o <file.ll>
```
`ir/<sample>/{vulnerable,patched}.ll`. Used automatically by
`run_benchmark.py` only when pseudo-code is missing.

## Stage 3 — Compile, strip, decompile the 5 samples — done

`binaries/<sample>/{vulnerable,patched}` (linked, stripped executables) →
`pseudo-code/<sample>/{vulnerable,patched}.c` (Ghidra decompiled). 4 full
vulnerable/patched pairs + `CVE-2021-42386`'s intentional vulnerable-only
case (the fix removes the function entirely; `run_benchmark.py` falls
back to IR for that one variant).

## Stage 4 — Prompt templates per bug class — done

`prompts/memory-{buffer-overflow,use-after-free,integer-overflow,
null-pointer-dereference,out-of-bounds-read}.md` + `command-injection.md`
(for Stage 7). Each requests a structured response:
```
Vulnerable: yes/no
Function/line: <...>
Bug class: <specific-class> / none
Confidence: low/medium/high
Reasoning: <1-3 sentences>
```
`scripts/bug_classes.py` maps each sample's `bug_class` to its template.

## Stage 5 — Automated benchmark — built, not yet run

```bash
python3 scripts/run_benchmark.py   # full cross-product: every prompt x every sample x every model
python3 scripts/score.py           # -> results/scoring.csv
```

### Getting API access

- Anthropic: https://console.anthropic.com/ → add billing → Settings →
  API Keys → export as `ANTHROPIC_API_KEY`.
- OpenAI: https://platform.openai.com/ → add billing →
  https://platform.openai.com/api-keys → export as `OPENAI_API_KEY`.
- `scripts/models.yaml`: `claude-fable-5` and `gpt-5.6-sol` (per mentor's
  guidance) — `run_benchmark.py` skips any model ID starting with
  `REPLACE_ME` rather than failing.
- `pip install -r scripts/requirements.txt` before running.

**Status**: blocked on API budget approval (self-funded, capped at $200
per mentor's reply — see email thread). Estimated cost ~$1.90 for this
benchmark (measured from actual file sizes).

## Stage 6 — Analyze and write up — not started

Compare across models/prompts/bug classes once Stage 5 has run.

## Stage 7 — Real firmware proof-of-concept — built, not yet run

CVE-2016-6277 (Netgear R6400/R7000 command injection). Ground truth
fully documented (`firmware/CVE-2016-6277-netgear-r6400/info.md`), all
1004 vulnerable + 1007 patched functions bulk-decompiled, benchmark
scripts ready:

```bash
python3 scripts/run_benchmark_firmware.py CVE-2016-6277-netgear-r6400 \
    <path>/decompiled/netgear_httpd \
    <path>/decompiled/netgear_patched_httpd
python3 scripts/score_firmware.py CVE-2016-6277-netgear-r6400
```

Scoped to the command-injection prompt only (not the full cross-product —
~5x the cost for little added value at this scale). See `PIPELINE.md` for
the reasoning behind the ground-truth/LLM-task split, the binary-selection
scoping question, and why large-scale replication of the reference
papers is explicitly out of scope for now.

**Status**: blocked on the same API budget approval as Stage 5.
Estimated cost ~$50-70 across both models (measured from actual
decompiled file sizes) — staged spending plan (cheap dry run → one
model → second model) proposed to the mentor rather than a single blind
run.

## Future possibilities

**Containerize the environment (Docker).** Not needed for the current
one-machine workflow, but worth doing if this pipeline needs to be
reproduced elsewhere (another machine, the mentor's own setup, or a
future continuation of this project) — several real problems this
project hit were specifically *environment* problems, not logic bugs:
- The BusyBox build needed a minimal Kconfig specifically to dodge
  legacy-applet failures against this host's modern kernel headers/glibc
  (`networking/tc.c`, `rdate`'s `stime()`) — a pinned older base image
  would avoid needing that workaround at all.
- The scratchpad holding intermediate build state got wiped between
  sessions multiple times, forcing repeated re-cloning/re-building — a
  container with a mounted volume would make that state durable and
  explicit instead of implicit and fragile.
- Several scripts and this doc currently reference this machine's
  absolute paths (`/home/valentinarossi/...` for the Ghidra install and
  project) — a container would make setup reproducible on any machine
  without hand-editing paths.
- The headless Ghidra pipeline (`analyzeHeadless` + `ExportAllFunctions.java`)
  is a natural fit for a container — no GUI needed, and the exact Ghidra
  version matters (the Jython→PyGhidra change between versions was a real
  issue hit this project; pinning a specific Ghidra version in an image
  avoids that class of surprise entirely).

Not pursuing now since it would take real time away from the actual
research question for a one-machine, one-person project on a one-month
timeline — but a reasonable next step if this needs to be shared,
reproduced, or handed off.

## Immediate next actions

1. Waiting on mentor/Elaine's approval of the API spending plan
   (~$65-70 estimate, $200 cap) before running Stage 5 or Stage 7 for
   real.
2. Still to confirm with mentor: exact OpenAI model ID
   (`gpt-5.6-sol` assumed correct per his "latest model" guidance, not
   yet explicitly confirmed).
3. Once approved: run Stage 5 (cheap, ~$2, do first), then Stage 7's
   staged plan (small dry run → one model → second model).
4. Stage 6 (analysis/write-up) once both benchmarks have real results.
