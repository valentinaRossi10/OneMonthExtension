# results/

LLM outputs and scoring against the ground truth in `samples/index.csv`.

```
results/
├── runs/
│   └── <cve_id>__<variant>__<model>.md   # raw LLM response, one per run
└── scoring.csv
```

`<variant>` is `vulnerable` or `patched`.

## scoring.csv columns

`cve_id, bug_class, model, variant, expected, actual, hit, false_positive`

## Workflow (automated, via scripts/)

1. Set up API keys (see `scripts/README.md`).
2. `python3 scripts/run_benchmark.py` — runs every sample × variant ×
   configured model, saves raw output here under `runs/`.
3. `python3 scripts/score.py` — parses `runs/`, compares against
   `samples/index.csv`, writes `scoring.csv` and prints overall accuracy.

This replaces the earlier manual chat-UI workflow (paste `.ll`/`.c` into
claude.ai / chatgpt.com by hand) now that the scripts exist — manual
runs are still fine for one-off spot checks.
