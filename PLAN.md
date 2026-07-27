# Plan

Stage checklist and how-to reference. For *why* each decision was made,
see `PIPELINE.md`. For full chronological/debugging detail, see `LOG.md`.
For normative labels, information boundaries, handoff rules, evaluation
matrices, and metrics, see `EXPERIMENT.md`.

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
`ir/<sample>/{vulnerable,patched}.ll`. The Tier A preparer uses it only
when pseudo-code is missing and extracts the target function rather than
sending the whole LLVM module.

## Stage 3 — Compile, strip, decompile the 5 samples — done

`binaries/<sample>/{vulnerable,patched}` (linked, stripped executables) →
`pseudo-code/<sample>/{vulnerable,patched}.c` (Ghidra decompiled). 4 full
vulnerable/patched pairs + `CVE-2021-42386`'s intentional pseudo-C
vulnerable-only case (the fix removes the source-level function; Tier A
uses the small function-only LLVM fallback for the patched variant).

## Stage 4 — Tier A prompt and rubric design — done

The canonical implementation is `classify-function-vulnerabilities/`.
It combines a common isolated-function prompt scaffold with one reviewed
rubric per vulnerability class and requests strict JSON with a
three-valued verdict, confidence, evidence, and reasoning. The legacy
root prompt templates and model registry were removed so they cannot be
mistaken for the active methodology.

## Stage 5 — Tier A automated benchmark — done

The skill prepares the full 5 samples × 2 variants × 6 classes = 60-task
manifest, validates input size and provenance, projects cost without API
calls, and executes only after approval under a hard cumulative ceiling.
The completed run used a $5 ceiling and a conservative local ledger of
$1.889030. Each experiment is stored under
`results/tier-a/runs/<run-id>/`:

- `README.md` and `run-metadata.json`: date, model, reasoning, notes, and
  configuration differences from the previous experiment
- `manifest.jsonl`: immutable task definitions and prompt hashes
- `manifest-summary.json`: input, token, guard, and projected-cost totals
- `results.jsonl`: append-only attempts, responses, and cumulative cost inputs
- `scoring/scoring.csv`: one final scored row per manifest task
- `scoring/summary.json` and `scoring/paired-transitions.csv`: aggregate and
  paired evaluation

Preparation refuses an existing run ID. Model, reasoning effort, output cap,
transport mode, SDK retry setting, policy/prompt/schema versions, and pricing
are frozen per run. Pairwise comparisons are written under
`results/tier-a/comparisons/` with metric deltas and task-level verdict/category
changes.

Five 2026-07-20 uniform-high follow-up experiments are preserved separately.
Policies v4/v5 stopped at 9/27 valid tasks because output
caps were exhausted. Policy v6 reached 46 valid tasks but had unaudited SDK
retries and connection errors. Policy v7 background polling reached 26 valid
tasks, then stopped when one response reported 27,565 output tokens despite a
4,500-token cap. Policy v8 replaces background polling with synchronous SSE
streaming and zero SDK retries. Its immutable 60-task run is preserved at
`results/tier-a/runs/2026-07-20t111012z__gpt-5-6-sol__high__high-4500-usd10-streaming/`;
all tasks received one attempt, producing 53 valid responses and 7 explicit
stream-completion errors. Its conservative ledger is $3.374440 under the
isolated $10 ceiling. The run is scored and compared with the recovered
baseline, but the failures and simultaneous configuration changes mean it
does not support a clean reasoning-effort claim.

## Stage 6 — Tier A analysis and write-up — done

All 60 tasks produced valid structured outputs and were scored. The
summary reports detection, specificity, abstention/indeterminate counts,
variant-pair behavior, and per-class metrics. See `results/README.md` and
the 2026-07-18 entries in `LOG.md` for exact interpretation and caveats.

## Stage 7 — Real firmware Tier B ground truth — prepared; package incomplete

CVE-2016-6277 (Netgear R6400/R7000 command injection) is documented in
`firmware/CVE-2016-6277-netgear-r6400/info.md`. The repository retains
selected vulnerable/patched pseudo-code and ground-truth metadata for:

- candidate function: `netgear_commonCgi`
- specific entry point: `parse_http_request`
- expected path: `parse_http_request` → `handle_get` → `netgear_commonCgi`

This material is a future Tier B case, not a runnable blind-discovery
benchmark. The generic protocol-v6 Tier B skill, runner, and scorer now exist,
but this Netgear sample still needs a complete analyzed codebase package and
case-specific costed manifest. Binary selection and unknown-candidate
discovery remain out of scope.

## Stage 8 — Recall-first codebase filtering — MVP implemented, evaluation pending

Approved by supervisor 2026-07-17. Two-tier pipeline; the function-level
tier is confirmed correct as already built:

- **Tier A (function-level, methodology already built = Stage 1-5) —
  complete**: given one function in isolation,
  classify whether it looks vulnerable. The *approach* is confirmed
  correct as-is — the old hand-written scripts were removed and
  regenerated by Codex as a proper skill,
  `classify-function-vulnerabilities/` (repo root; see `SKILL.md`
  there). Built from a written skill brief + a prompt asking Codex to
  summarize its own design before generating any code (see `LOG.md`,
  2026-07-17). Independently verified (not just taken from Codex's
  self-report): 60 tasks (5 samples × 2 variants × 6 classes), hard $5
  spend ceiling enforced both pre-flight and per-request, refusal/
  invalid-output detection that aborts immediately instead of writing
  silent empty results, and — the actual fix for the 2026-07-15
  runaway-spend root cause — LLVM IR inputs now extracted down to just
  the target function instead of whole modules (`CVE-2021-42386`'s
  patched `.ll`: 1,081,065 → 611 bytes). The real run completed on
  2026-07-18 with 60/60 valid results; final scoring and the audited cost
  ledger are in
  `results/tier-a/runs/2026-07-18__gpt-5-6-sol__mixed-recovered/` (see
  `LOG.md` for metrics and recovery details).
- **Tier B (codebase-level, new)**: given the *whole* codebase plus one
  already-flagged candidate function, determine whether that function
  is *actually* vulnerable by tracing reachability from **one specific
  entry point** through the codebase — confirming the flagged function
  is genuinely reachable/exploitable from that entry point, not just
  pattern-matched in isolation. Tier B assumes the candidate function is
  already known (from Tier A, or from ground truth like Stage 6/7's
  `netgear_commonCgi`) and narrows to *confirming* it, not discovering
  an unknown vulnerability from scratch across an entire binary.

Evaluation order is fixed by `EXPERIMENT.md`:

1. Keep Tier A's strict three-way scoring; an `indeterminate` result remains
   an abstention.
2. Evaluate Tier B independently using all five known BusyBox candidates and
   their patched controls (up to 10 cases), with one entry point and a
   reproducible whole-codebase package per case.
3. Evaluate the operational cascade separately by forwarding Tier A
   `vulnerable ∪ indeterminate`, deduplicating compatible candidates, and
   measuring end-to-end recall, specificity, false-positive survival, and
   Tier B workload.

The protocol-v6 MVP is implemented in
`confirm-and-filter-vulnerabilities/`. It includes:

- exact-case Tier A ingestion keyed by artifact-scoped function UID and class,
  with evidence-union coalescing and complete raw-row audit maps;
- quarantine instead of silent loss for ambiguous or conflicting identity;
- Ghidra Program Model export of analyzed function identities, direct calls,
  and explicit unresolved indirect-call sites;
- hash-verified packages and model tools;
- proof-gated `retain_confirmed`, `suppress_proven_false_positive`, and
  `retain_and_escalate` routing;
- immutable no-API preparation, explicit manifest-bound approval, adaptive
  but bounded investigation limits, append-only execution, and scoring.

The full P-code/SSA engine, indirect-dispatch resolution, second provider,
deterministic analyzer, and staffed human-review queue are deferred. No
protocol-v6 paid execution has occurred.

## Stage 9 — Dynamic analysis confirmation — not started

Fuzzing pass to confirm Stage 8's findings — closes the loop on the
project's original hybrid static + dynamic framing. Not yet scoped in
detail; follows once Stage 8 is working.

## Working method for Stage 8: Codex-based skill automation

Per supervisor guidance: build Stage 8 using Codex in VS Code (full
repo context available to the agent), rather than hand-writing
prompts/scripts the way Stage 1-5 was built.

1. Treat the completed `classify-function-vulnerabilities/` skill and
   `results/tier-a/` outputs as the Tier A baseline.
2. Summarize and review a separate Tier B skill before implementation,
   fixing the candidate, entry point, permitted whole-codebase context,
   output schema, evaluation rules, and spending safeguards.
3. Generate Tier B automation from that reviewed definition, then create
   a no-API dry-run manifest and cost projection for explicit approval.

Branch: `W3/codebase-level-redesign`.

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

1. Bind one named frozen Tier A run to artifact-scoped function UIDs and
   inspect the protocol-v6 ingestion, coalescing, and quarantine audit.
2. Export and build the real Ghidra-backed packages for the resulting cases.
3. Prepare a new immutable protocol-v6 run without API calls and report its
   exact manifest SHA-256 and worst-case cost; the planning envelope is not an
   execution approval.
4. Execute only after a separate manifest-bound approval, then report the
   five-case acceptance cohort separately from the real Tier A cascade.
5. Build a held-out cohort only as a separately scoped ground-truth project.
