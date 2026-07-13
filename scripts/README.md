# scripts/

Automation for Stages 4-5 (prompt design + running the benchmark). Built
ahead of API access so everything is ready to run as soon as keys exist.

```
scripts/
├── requirements.txt   # pip dependencies
├── models.yaml         # which models to benchmark (edit to add/remove)
├── run_benchmark.py    # calls each model on each sample, saves raw output
└── score.py             # scores results/runs/ against samples/index.csv
```

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r scripts/requirements.txt
```

## API keys

Get keys from each provider's dashboard, then export them as environment
variables (the SDKs read these automatically — nothing to configure in
code):

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-..."
```

- Anthropic: https://console.anthropic.com/ → Settings → API Keys.
- OpenAI: https://platform.openai.com/api-keys.

Only export the key(s) for providers actually listed in `models.yaml` —
`run_benchmark.py` only imports a provider's SDK when it hits a model
configured for that provider.

## `models.yaml`

One entry per model to benchmark:

```yaml
models:
  - provider: anthropic
    model: claude-sonnet-5
```

The `REPLACE_ME_CONFIRM_WITH_MENTOR` placeholder entry is skipped
automatically by `run_benchmark.py` (with a warning) until replaced with a
real model ID.

## `run_benchmark.py`

For every sample in `samples/index.csv`, for every variant
(`vulnerable`/`patched`), for every configured model:

1. Finds the code to show the model — `pseudo-code/<sample>/<variant>.c` if
   it exists (primary representation, per the mentor's decision), else
   falls back to `ir/<sample>/<variant>.ll`.
2. Picks the prompt template matching the sample's `bug_class` (see
   `BUG_CLASS_TO_PROMPT` at the top of the script) and substitutes the code
   into its `<<<CODE>>>` placeholder.
3. Calls the model and writes the raw response to
   `results/runs/<cve_id>__<variant>__<model>.md`.

Run it with:

```bash
python3 scripts/run_benchmark.py
```

Currently `pseudo-code/` doesn't exist yet (Ghidra decompilation is still
pending), so it will fall back to the `ir/` files for all 5 samples until
that's done.

## `score.py`

Reads every file in `results/runs/`, extracts the `Vulnerable: yes/no`
line, compares it against the expected verdict (yes for `vulnerable`
variants, no for `patched` variants), and writes one row per run to
`results/scoring.csv` (cve_id, bug_class, model, variant, expected, actual,
hit, false_positive). Prints overall accuracy at the end.

```bash
python3 scripts/score.py
```
