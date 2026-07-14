"""
Shared bug-class <-> prompt-template mapping, used by both run_benchmark.py
and score.py so the two stay in sync.

Keys are the bug_class values found in samples/index.csv; values are the
matching prompt template filename in prompts/.
"""

BUG_CLASS_TO_PROMPT = {
    "heap-buffer-overflow": "memory-buffer-overflow.md",
    "buffer-overflow": "memory-buffer-overflow.md",
    "use-after-free": "memory-use-after-free.md",
    "integer-overflow": "memory-integer-overflow.md",
    "null-pointer-dereference": "memory-null-pointer-dereference.md",
    "out-of-bounds-read": "memory-out-of-bounds-read.md",
}

# Every distinct prompt template file, in a stable order — this is the set
# run_benchmark.py runs against every sample (the full cross-product), not
# just each sample's matching template.
ALL_PROMPT_FILES = sorted(set(BUG_CLASS_TO_PROMPT.values()))
