# results/

LLM outputs and scoring against the ground truth in `samples/index.csv`.

```
results/
├── runs/
│   └── <cve_id>__<variant>__<model>__<prompt-slug>.md   # raw LLM response
└── scoring.csv
```

`<variant>` is `vulnerable` or `patched`. `<prompt-slug>` is the prompt
template's filename stem (e.g. `memory-buffer-overflow`) — every prompt is
run against every sample (the full cross-product), not just the prompt
matching each sample's own bug class, so mismatched-prompt false positives
are visible too.

## scoring.csv columns

`cve_id, bug_class, model, variant, prompt, prompt_matches_sample,
expected, actual, category`

`category` is one of `true_positive`, `false_negative`, `true_negative`,
`false_positive` (see `scripts/README.md` for the exact definitions).

## Workflow (automated, via scripts/)

1. Set up API keys (see `scripts/README.md`).
2. `python3 scripts/run_benchmark.py` — runs every sample × variant ×
   prompt × configured model, saves raw output here under `runs/`.
3. `python3 scripts/score.py` — parses `runs/`, compares against
   `samples/index.csv`, writes `scoring.csv`, and prints a breakdown by
   category, the specialized-prompt detection rate, and every false
   positive found (with whether it came from patched code being flagged
   or a mismatched bug class being hallucinated).

This replaces the earlier manual chat-UI workflow (paste `.ll`/`.c` into
claude.ai / chatgpt.com by hand) now that the scripts exist — manual
runs are still fine for one-off spot checks.
