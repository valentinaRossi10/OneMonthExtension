# results/

LLM outputs and scoring against the ground truth in `samples/index.csv`.
The current function-level benchmark is Tier A.
Interpret all results under the canonical rules in
[`EXPERIMENT.md`](../EXPERIMENT.md).

For a concise view of progress across Tier A, Tier B, and the remaining
pipeline stages, see [`OVERALL_RESULTS.md`](OVERALL_RESULTS.md).

## Tier A experiment layout

```text
results/
├── tier-a/
│   ├── runs/
│   │   └── <date>__<model>__<reasoning>__<label>/
│   │       ├── README.md             # human-readable experiment record
│   │       ├── run-metadata.json     # machine-readable frozen configuration
│   │       ├── inputs/               # normalized pseudo-C/LLVM inputs
│   │       ├── manifest.jsonl        # 60 sample x variant x class tasks
│   │       ├── manifest-summary.json # guard, token, and projected-cost totals
│   │       ├── results.jsonl         # append-only API attempts
│   │       └── scoring/
│   │           ├── scoring.csv
│   │           ├── summary.json
│   │           └── paired-transitions.csv
│   └── comparisons/
│       └── <baseline>__vs__<candidate>/
│           ├── README.md
│           ├── comparison.json
│           ├── metrics.csv
│           ├── per-class-metrics.csv
│           └── task-changes.csv
```

Each invocation of the preparer creates a new run directory and refuses to
overwrite an existing run ID. Model, reasoning effort, output-token cap,
policy/prompt/schema versions, and pricing are frozen in the manifest and
`run-metadata.json`. The per-run README records the UTC date, model, reasoning
effort, experiment notes, and automatically detected differences from the
previous run.

Every run contains the 5 samples × 2 variants × 6 target classes = 60 tasks.
`results.jsonl` may contain more than 60 records because failures and reviewed
retries are preserved. The scorer selects the latest response per cache key;
`scoring.csv` always contains one final row per manifest task.

## Per-run `scoring/scoring.csv` columns

The generated header is:

```text
task_id,cve_id,project,variant,representation,indexed_bug_class,target_class,expected_positive,limited_observability_reason,input_status,response_status,category,model_verdict,confidence,evidence_lines,summary,model,input_tokens,output_tokens,actual_cost_usd,error
```

| Column | Meaning |
|---|---|
| `task_id` | Unique `<CVE>__<variant>__<target-class>` task identifier. |
| `cve_id`, `project` | Ground-truth sample identity and source project. |
| `variant` | `vulnerable` or `patched`. |
| `representation` | `ghidra_pseudo_c` or the function-only `llvm_ir` fallback. |
| `indexed_bug_class` | Historical vulnerability class from `samples/index.csv`. |
| `target_class` | Class tested by this particular classifier task. |
| `expected_positive` | `True` only for the vulnerable variant tested against its indexed class. |
| `limited_observability_reason` | Explanation for a designated function-local ground-truth limitation, otherwise empty. |
| `input_status` | Input preparation result, normally `ready`; guard/unavailable states are retained when present. |
| `response_status` | Latest API result status, such as `ok`, `refusal`, `invalid_output`, or `api_error`; empty means no result record. |
| `category` | Scored outcome described below. |
| `model_verdict` | `vulnerable`, `not_vulnerable`, or `indeterminate`. |
| `confidence` | Model confidence from 0 to 1. |
| `evidence_lines` | JSON array of line numbers in the normalized, numbered function. |
| `summary` | Short model-provided justification. |
| `model` | API model used for the task. |
| `input_tokens`, `output_tokens` | Provider-reported token usage for the selected result. |
| `actual_cost_usd` | Usage-derived cost estimate at the configured token prices. |
| `error` | API, validation, input, or guard error; empty for a successful response. |

### Categories

For valid decisive responses, `category` is one of `true_positive`,
`false_negative`, `true_negative`, or `false_positive`.
`indeterminate` becomes `abstention` and receives no correctness credit.
Failures remain explicit categories such as `refusal`, `invalid_output`,
`api_error`, `missing_output`, `guard_skip`, or `unavailable`; they are never
silently converted into true negatives.

False positives are relative to the benchmark label. A mismatched-class
positive may indicate a plausible secondary weakness rather than pure model
hallucination, because `samples/index.csv` verifies one historical class per
sample rather than proving the absence of every other weakness.

### Tier B handoff is not Tier A rescoring

Tier A remains strict: `indeterminate` is an abstention with no correctness
credit. For the later cascade, both `vulnerable` and `indeterminate` tasks are
forwarded to Tier B. This preserves false-positive scrutiny while ensuring
context-limited suspicious cases can be checked with callers/callees.

In the recovered run, that policy forwards 24/60 task-class combinations,
including 4/5 indexed positives and all 4 function-locally observable
positives. The OOB positive is forwarded as an abstention; it is not rewritten
as a Tier A true positive. These figures describe this mixed-configuration run
only. See [`EXPERIMENT.md`](../EXPERIMENT.md) for oracle Tier B and cascade
evaluation rules.

### Recall-first Tier B redesign artifacts

The protocol-v6 implementation lives in
[`confirm-and-filter-vulnerabilities/`](../confirm-and-filter-vulnerabilities/SKILL.md).
Its ingestion output records the raw-to-case mapping explicitly:

```text
<queue-output>/
├── queue.jsonl             # one case per exact function UID + class
├── dedup-map.jsonl         # all source rows and evidence merged per case
├── quarantine.jsonl        # ambiguous/conflicting rows retained for escalation
├── raw-row-map.jsonl       # evaluator audit map for every eligible Tier A row
└── ingestion-summary.json  # raw, coalesced, and quarantined counts
```

Historical `results/tier-b/runs/` and matrix summaries remain immutable and
must not be combined with a future protocol-v6 cohort. No paid protocol-v6 run
has been prepared or executed yet.

## Other per-run files

- `manifest.jsonl` records task metadata, expected labels, normalized-code
  hashes, prompt hashes, token estimates, and worst-case task costs.
- `results.jsonl` is the append-only audit ledger containing every API attempt,
  including failures and reviewed retries. It can therefore have multiple
  records for one task.
- `scoring/summary.json` contains overall metrics, per-class metrics,
  per-representation metrics, named false positives/false negatives, and the
  designated limited-observability task. It reports abstentions in aggregate;
  use `scoring.csv` to identify individual abstaining tasks.
- `scoring/paired-transitions.csv` compares each vulnerable/patched pair for
  each target class.

## Tier A workflow

From the repository root:

```bash
python3 classify-function-vulnerabilities/scripts/prepare_benchmark.py \
  --repo-root . \
  --results-root results/tier-a \
  --run-label reasoning-low \
  --model gpt-5.6-sol \
  --reasoning-effort low \
  --experiment-note "Uniform low-reasoning baseline" \
  --input-price-per-million <current-price> \
  --output-price-per-million <current-price>
```

The preparer prints the newly created run directory. Use that exact path for
the dry run, paid execution, and scoring:

```bash
python3 classify-function-vulnerabilities/scripts/run_benchmark.py \
  --run-dir results/tier-a/runs/<run-id> \
  --input-price-per-million <current-price> \
  --output-price-per-million <current-price> \
  --budget-usd 10

# Add --execute only after reviewing the dry-run cost projection.

python3 classify-function-vulnerabilities/scripts/score_benchmark.py \
  --run-dir results/tier-a/runs/<run-id>
```

The runner requires the explicit `--execute` flag before making paid API calls
and enforces the configured cumulative spending ceiling. The active policy
freezes synchronous SSE streaming and zero SDK retries in each manifest and
stops if reported usage exceeds the output-token cap. A changed reasoning or
transport setting must be prepared as a new run; it cannot be applied
retrospectively to an existing manifest.

## Comparing experiments

After both runs are scored:

```bash
python3 classify-function-vulnerabilities/scripts/compare_runs.py \
  --baseline-run results/tier-a/runs/<baseline-run-id> \
  --candidate-run results/tier-a/runs/<candidate-run-id>
```

The comparison records configuration changes, metric deltas, and every task
whose category or verdict changed. It makes no API calls and refuses to replace
an existing comparison unless `--replace` is explicitly supplied.

The original completed benchmark is preserved as
`runs/2026-07-18__gpt-5-6-sol__mixed-recovered/`. Its README identifies the
mixed reasoning/output-cap recovery caveat, so it should not be described as a
clean uniform-low experiment.
