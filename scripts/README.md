# scripts/

Automation for Stages 4-5 (prompt design + running the benchmark). Built
ahead of API access so everything is ready to run as soon as keys exist.

```
scripts/
├── requirements.txt   # pip dependencies
├── models.yaml         # which models to benchmark (edit to add/remove)
├── bug_classes.py       # shared bug_class <-> prompt-template mapping
├── run_benchmark.py    # calls each model on each sample x every prompt, saves raw output
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

Runs the **full cross-product**: for every sample in `samples/index.csv`,
for every variant (`vulnerable`/`patched`), for **every prompt template**
in `prompts/` (not just the one matching the sample's own bug class), for
every configured model. Running mismatched prompts too (e.g. the
use-after-free prompt against the NULL-deref sample) is what lets
`score.py` tell apart "the specialized prompt correctly found the real
bug" from "some unrelated prompt hallucinated a bug that isn't there."

1. Finds the code to show the model — `pseudo-code/<sample>/<variant>.c`
   (primary representation, per the mentor's decision), else falls back to
   `ir/<sample>/<variant>.ll`.
2. For each prompt template, substitutes the code into its `<<<CODE>>>`
   placeholder.
3. Calls the model and writes the raw response to
   `results/runs/<cve_id>__<variant>__<model>__<prompt-slug>.md`.

Run it with:

```bash
python3 scripts/run_benchmark.py
```

With 5 samples (9 valid sample/variant pairs — `CVE-2021-42386`'s patched
side has no code file, see `pseudo-code/README.md`), 5 prompt templates,
and N models, this is `9 x 5 x N` API calls — e.g. 90 calls for 2 models.

## `score.py`

Reads every file in `results/runs/`, extracts the `Vulnerable: yes/no`
line, and compares it against what's expected **given which prompt was
used**: a prompt only "should" say yes if the code is the vulnerable
variant *and* the prompt's bug class actually matches the sample's real
bug class (via the shared `bug_classes.BUG_CLASS_TO_PROMPT` mapping) —
every other combination (patched code with any prompt, or vulnerable code
analyzed with a mismatched-bug-class prompt) is expected to say no.

Writes one row per run to `results/scoring.csv` with a `category` column:

- `true_positive` — the specialized/matching prompt correctly found the
  real bug.
- `false_negative` — the specialized/matching prompt missed the real bug.
- `true_negative` — correctly stayed quiet (patched code, or a
  non-matching prompt on vulnerable code).
- `false_positive` — incorrectly said yes: either a matching prompt
  flagging patched code, or *any* prompt hallucinating a bug class that
  isn't actually present in that file.

Prints a breakdown by category, the specialized-prompt detection rate, and
lists every false positive with its reason.

```bash
python3 scripts/score.py
```
