#!/usr/bin/env python3
"""
Scores results/runs/*.md output (from run_benchmark.py) against the ground
truth in samples/index.csv, writing results/scoring.csv.

Expected: the "vulnerable" variant should be flagged Vulnerable: yes;
the "patched" variant should be flagged Vulnerable: no. Anything else is
a miss (false negative on vulnerable, false positive on patched).

Usage:
    python3 score.py
"""
import csv
import re
from pathlib import Path

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


def main():
    samples = load_samples()
    sample_lookup = {s["cve_id"]: s for s in samples}

    rows = []
    for run_file in sorted(RESULTS_DIR.glob("*.md")):
        # filename format: <cve_id>__<variant>__<model>.md
        stem = run_file.stem
        parts = stem.split("__")
        if len(parts) != 3:
            continue
        cve_id, variant, model = parts

        sample = sample_lookup.get(cve_id)
        if sample is None:
            continue

        text = run_file.read_text()
        verdict = parse_verdict(text)
        expected = "yes" if variant == "vulnerable" else "no"
        hit = verdict == expected
        false_positive = variant == "patched" and verdict == "yes"

        rows.append(
            {
                "cve_id": cve_id,
                "bug_class": sample["bug_class"],
                "model": model,
                "variant": variant,
                "expected": expected,
                "actual": verdict,
                "hit": hit,
                "false_positive": false_positive,
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
                "expected",
                "actual",
                "hit",
                "false_positive",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    total = len(rows)
    hits = sum(1 for r in rows if r["hit"])
    print(f"Scored {total} runs -> {SCORING_OUT}")
    if total:
        print(f"Overall accuracy: {hits}/{total} ({100 * hits / total:.1f}%)")


if __name__ == "__main__":
    main()
