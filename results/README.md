# results/

LLM outputs and scoring against the ground truth in `samples/index.csv`.

```
results/
├── runs/
│   └── <sample>__<model>__<prompt-template>.md   # raw LLM response
└── scoring.csv
```

## scoring.csv columns

`cve_id, model, prompt_template, hit (yes/no), false_positive (yes/no),
notes`

## Workflow (manual, until API access is set up)

1. Take a generated `.ll` file from `ir/`.
2. Paste it into the chat UI (claude.ai / chatgpt.com) using a template from
   `prompts/`.
3. Save the raw response under `results/runs/`.
4. Score it against `samples/index.csv` and log the row in `scoring.csv`.

Once API keys are available, this loop can be scripted — see `scripts/README.md`.
