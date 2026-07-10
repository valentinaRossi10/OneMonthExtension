# prompts/

Prompt templates for LLM vulnerability analysis, one per vulnerability class
("engineered skills" per the mentor's suggestion).

```
prompts/
├── memory-buffer-overflow.md
├── memory-use-after-free.md
├── memory-double-free.md
├── integer-overflow.md
└── ...
```

## Template guidelines

Each template should:
- State the specific bug pattern to look for in LLVM IR terms (e.g. for
  buffer overflow: unchecked `getelementptr` offsets, `call @llvm.memcpy` /
  `strcpy` / `strcat` without a preceding bounds check).
- Take the `.ll` IR as input (optionally alongside the original source, to
  test IR-only vs IR+source performance — track this as a variable across
  runs).
- Request a **structured** response for easy scoring, e.g.:
  ```
  Vulnerable: yes/no
  Function/line:
  Bug class:
  Confidence (low/med/high):
  Reasoning (1-2 sentences):
  ```

## Model names

Confirm exact model identifiers with the mentor before running (he mentioned
"GPT-5.6" and "Claude 5" — verify the literal model/version strings before
committing to them in scripts, since assumed names may not resolve to real
API model IDs).
