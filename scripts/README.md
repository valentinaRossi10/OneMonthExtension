# scripts/

Automation scripts. Empty for now — the pipeline is run manually (see
`results/README.md`) until LLM API access is set up.

Planned, once API keys exist:
- `run_benchmark.py` — loop over `ir/*/*.ll` × `prompts/*.md` × configured
  models, call the API, save output to `results/runs/`.
- `score.py` — compare `results/runs/` output against `samples/index.csv`
  and populate `results/scoring.csv` automatically.
