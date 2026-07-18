# scripts/

Shared extraction tooling that is not owned by a benchmark skill.

```text
scripts/
└── ghidra/
    └── ExportAllFunctions.java   # headless bulk Ghidra decompilation
```

`ExportAllFunctions.java` exports decompiled functions from a binary for
codebase-level work. It remains relevant to the planned Tier B workflow, which
will consume a whole codebase while confirming one candidate from one specific
entry point.

Tier A automation does **not** live here. Use:

```text
classify-function-vulnerabilities/
├── SKILL.md
├── references/
└── scripts/
    ├── experiment_common.py
    ├── prepare_benchmark.py
    ├── run_benchmark.py
    ├── score_benchmark.py
    └── compare_runs.py
```

The old root-level model registry, provider requirements, prompt templates,
and benchmark/scoring scripts belonged to the superseded plain-text workflow
and were removed. They remain available in git history if historical
reproduction is needed.
