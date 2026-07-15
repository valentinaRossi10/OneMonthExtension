#!/usr/bin/env python3
"""
Scores results/runs-firmware/*.md output (from run_benchmark_firmware.py)
against the per-variant ground truth in
firmware/<cve_id>/ground_truth.csv.

Unlike the BusyBox benchmark (a handful of known samples), this is a
genuine discovery task: only ONE function among ~1900 across both
binary variants is actually expected to be flagged. Everything else,
in both the vulnerable and patched binary, is expected "no" - including
the patched variant's version of the real function (same logical
function, but the CVE's exploit path is neutralized there by added
guards, per firmware/CVE-2016-6277-netgear-r6400/info.md).

Categories, same meaning as score.py:
  - true_positive:  the one real vulnerable function got flagged
  - false_negative: the one real vulnerable function did NOT get flagged
  - true_negative:  correctly stayed quiet on an unrelated function
  - false_positive: incorrectly flagged a function that isn't the real bug
                     (this is the real signal for this phase - a low
                     false-positive rate across ~1900 real functions is
                     the actual test of discovery quality)

Usage:
    python3 score_firmware.py <cve_id>
"""
import csv
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FIRMWARE_DIR = REPO_ROOT / "firmware"
RESULTS_DIR = REPO_ROOT / "results" / "runs-firmware"

VULN_LINE_RE = re.compile(r"Vulnerable:\s*(yes|no)", re.IGNORECASE)


def load_ground_truth(cve_dir: Path) -> dict:
    gt_path = cve_dir / "ground_truth.csv"
    result = {}
    with open(gt_path, newline="") as f:
        for row in csv.DictReader(f):
            fn = row["vulnerable_function_file"].strip()
            result[row["variant"]] = fn if fn else None
    return result


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
    if len(sys.argv) != 2:
        print("Usage: score_firmware.py <cve_id>", file=sys.stderr)
        sys.exit(1)

    cve_id = sys.argv[1]
    cve_dir = FIRMWARE_DIR / cve_id
    ground_truth = load_ground_truth(cve_dir)
    scoring_out = cve_dir / "scoring.csv"

    rows = []
    for run_file in sorted(RESULTS_DIR.glob(f"{cve_id}__*.md")):
        # filename format: <cve_id>__<variant>__<model>__<func_name>.md
        stem = run_file.stem
        parts = stem.split("__")
        if len(parts) != 4:
            continue
        _cve_id, variant, model, func_name = parts

        func_file = f"{func_name}.c"
        expected_func = ground_truth.get(variant)
        expected = "yes" if func_file == expected_func else "no"

        text = run_file.read_text()
        actual = parse_verdict(text)
        category = categorize(expected, actual)

        rows.append(
            {
                "cve_id": cve_id,
                "variant": variant,
                "model": model,
                "function": func_name,
                "expected": expected,
                "actual": actual,
                "category": category,
            }
        )

    with open(scoring_out, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["cve_id", "variant", "model", "function", "expected", "actual", "category"],
        )
        writer.writeheader()
        writer.writerows(rows)

    total = len(rows)
    counts = {}
    for r in rows:
        counts[r["category"]] = counts.get(r["category"], 0) + 1

    print(f"Scored {total} runs -> {scoring_out}")
    for cat in ("true_positive", "false_negative", "true_negative", "false_positive", "unparseable"):
        n = counts.get(cat, 0)
        print(f"  {cat:15s} {n:5d} ({100 * n / total:.2f}%)" if total else f"  {cat}: 0")

    tps = [r for r in rows if r["category"] == "true_positive"]
    fns = [r for r in rows if r["category"] == "false_negative"]
    print(f"\nReal bug detected: {len(tps)} true positive(s), {len(fns)} false negative(s)")
    for r in tps:
        print(f"  FOUND by {r['model']} on {r['variant']}/{r['function']}")
    for r in fns:
        print(f"  MISSED by {r['model']} on {r['variant']}/{r['function']}")

    fps = [r for r in rows if r["category"] == "false_positive"]
    if fps:
        print(f"\nFalse positives: {len(fps)} (out of {total - len(tps) - len(fns)} non-bug functions checked)")
        for r in fps[:50]:
            print(f"  {r['variant']}/{r['function']} flagged by {r['model']}")
        if len(fps) > 50:
            print(f"  ... and {len(fps) - 50} more, see {scoring_out}")


if __name__ == "__main__":
    main()
