# prompts/

Prompt templates for LLM vulnerability analysis, one per bug class
("engineered skills" per the mentor's suggestion). Covers the 5 memory-
safety classes in the current sample set:

```
prompts/
├── memory-buffer-overflow.md
├── memory-use-after-free.md
├── memory-integer-overflow.md
├── memory-null-pointer-dereference.md
└── memory-out-of-bounds-read.md
```

`scripts/run_benchmark.py` maps each sample's `bug_class` (from
`samples/index.csv`) to one of these files via `BUG_CLASS_TO_PROMPT`.

## Template guidelines

Each template:
- Takes decompiled pseudo-C as the primary input (per the mentor's
  decision — see `PLAN.md`), with a note prepended when a sample falls
  back to LLVM IR instead (no pseudo-code available).
- Describes the specific bug pattern to look for **in pseudo-C terms**
  (e.g. for buffer overflow: a copy/write into a fixed-size local buffer
  driven by an attacker-controlled length with no bounds check;
  for use-after-free: a pointer used after a `free`-equivalent call with
  no intervening reassignment).
- Explicitly tells the model what *not* to flag, to keep scoring clean
  (e.g. the out-of-bounds-read template excludes write-based overflows).
- Requests a structured, parseable response:
  ```
  Vulnerable: yes/no
  Function/line: <...>
  Bug class: <specific-class> / none
  Confidence: low/medium/high
  Reasoning: <1-3 sentences>
  ```
  `scripts/score.py` parses the `Vulnerable:` line via regex to score runs.

## Model names

`scripts/models.yaml` lists the models actually being benchmarked. The
OpenAI entry is still a placeholder (`REPLACE_ME_CONFIRM_WITH_MENTOR`) —
confirm the exact model ID with the mentor before running (raised in an
earlier email, not yet answered).
