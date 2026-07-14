#!/usr/bin/env python3
"""
Scores results/runs/*.md output (from run_benchmark.py's full cross-product
of samples x prompt templates x models) against the ground truth in
samples/index.csv, writing results/scoring.csv.

Since every prompt template is run against every sample (not just the
template matching each sample's own bug class), "expected" depends on
whether the prompt used actually matches the sample's real bug class:

  - variant=vulnerable AND prompt matches the sample's bug class
      -> expected yes (the specialized prompt should find the real bug)
  - everything else (patched code, regardless of prompt; or vulnerable
    code analyzed with a prompt for a DIFFERENT bug class than the one
    it actually has)
      -> expected no

Each row is also labeled with a `category`:
  - true_positive:  matched prompt correctly found the real bug
  - false_negative: matched prompt missed the real bug
  - true_negative:  correctly stayed quiet (patched code, or a
                     non-matching prompt on vulnerable code)
  - false_positive: incorrectly said "yes" when it shouldn't have —
                     either a matching prompt flagging patched code, or
                     ANY prompt hallucinating a bug class that isn't
                     actually present in this file

Usage:
    python3 score.py
"""
import csv
import re
from pathlib import Path

from bug_classes import BUG_CLASS_TO_PROMPT

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLES_INDEX = REPO_ROOT / "samples" / "index.csv"
RESULTS_DIR = REPO_ROOT / "results" / "runs"
SCORING_OUT = REPO_ROOT / "results" / "scoring.csv"

VULN_LINE_RE = re.compile(r"Vulnerable:\s*(yes|no)", re.IGNORECASE)


def load_samples():
    with open(SAMPLES_INDEX, newline="") as f:
        return list(csv.DictReader(f))


def parse_verdict(text: str) -> str:
    m = VULN_LINE_RE.search(text)
    if not m:
        return "unparseable"
    return m.group(1).lower()


def categorize(expected: str, actual: str) -> str:
    if actual == "unparseable":
        return "unparseable"
    if expected == "yes":
        return "true_positive" if actual == "yes" else "false_negative"
    return "true_negative" if actual == "no" else "false_positive"


def main():
    samples = load_samples()
    sample_lookup = {s["cve_id"]: s for s in samples}

    rows = []
    for run_file in sorted(RESULTS_DIR.glob("*.md")):
        # filename format: <cve_id>__<variant>__<model>__<prompt-slug>.md
        stem = run_file.stem
        parts = stem.split("__")
        if len(parts) != 4:
            continue
        cve_id, variant, model, prompt_slug = parts

        sample = sample_lookup.get(cve_id)
        if sample is None:
            continue

        sample_bug_class = sample["bug_class"]
        matching_prompt_slug = Path(BUG_CLASS_TO_PROMPT[sample_bug_class]).stem
        prompt_matches_sample = prompt_slug == matching_prompt_slug

        text = run_file.read_text()
        actual = parse_verdict(text)
        expected = "yes" if (variant == "vulnerable" and prompt_matches_sample) else "no"
        category = categorize(expected, actual)

        rows.append(
            {
                "cve_id": cve_id,
                "bug_class": sample_bug_class,
                "model": model,
                "variant": variant,
                "prompt": prompt_slug,
                "prompt_matches_sample": prompt_matches_sample,
                "expected": expected,
                "actual": actual,
                "category": category,
            }
        )

    SCORING_OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(SCORING_OUT, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "cve_id",
                "bug_class",
                "model",
                "variant",
                "prompt",
                "prompt_matches_sample",
                "expected",
                "actual",
                "category",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    total = len(rows)
    counts = {}
    for r in rows:
        counts[r["category"]] = counts.get(r["category"], 0) + 1

    print(f"Scored {total} runs -> {SCORING_OUT}")
    for cat in ("true_positive", "false_negative", "true_negative", "false_positive", "unparseable"):
        n = counts.get(cat, 0)
        print(f"  {cat:15s} {n:4d} ({100 * n / total:.1f}%)" if total else f"  {cat}: 0")

    matched = [r for r in rows if r["prompt_matches_sample"] and r["variant"] == "vulnerable"]
    if matched:
        tp = sum(1 for r in matched if r["category"] == "true_positive")
        print(
            f"\nSpecialized-prompt detection rate (vulnerable samples, "
            f"matching prompt): {tp}/{len(matched)} ({100 * tp / len(matched):.1f}%)"
        )

    fps = [r for r in rows if r["category"] == "false_positive"]
    if fps:
        print(f"\nFalse positives ({len(fps)}):")
        for r in fps:
            reason = "patched code flagged" if r["variant"] == "patched" else "mismatched bug class flagged"
            print(f"  {r['cve_id']} / {r['variant']} / {r['model']} / prompt={r['prompt']} ({reason})")


if __name__ == "__main__":
    main()
