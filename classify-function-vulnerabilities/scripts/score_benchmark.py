#!/usr/bin/env python3
"""Score every Tier A manifest task without rewarding missing or failed output."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from experiment_common import load_metadata, utc_now, write_metadata
from tier_a_common import read_jsonl


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    return parser.parse_args()


def safe_div(numerator: int | float, denominator: int | float) -> float | None:
    return numerator / denominator if denominator else None


def categorize(task: dict[str, Any], result: dict[str, Any] | None) -> tuple[str, str | None]:
    if task["input_status"] != "ready":
        return task["input_status"], None
    if result is None:
        return "missing_output", None
    status = result.get("status", "invalid_output")
    if status != "ok":
        return status, None
    parsed = result.get("parsed_result") or {}
    verdict = parsed.get("verdict")
    if verdict == "indeterminate":
        return "abstention", verdict
    if verdict == "vulnerable":
        return (
            "true_positive" if task["expected_positive"] else "false_positive",
            verdict,
        )
    if verdict == "not_vulnerable":
        return (
            "false_negative" if task["expected_positive"] else "true_negative",
            verdict,
        )
    return "invalid_output", None


def compute_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    counts = Counter(row["category"] for row in rows)
    positives = sum(bool(row["expected_positive"]) for row in rows)
    negatives = len(rows) - positives
    tp = counts["true_positive"]
    fn = counts["false_negative"]
    tn = counts["true_negative"]
    fp = counts["false_positive"]
    decisive = tp + fn + tn + fp
    recall = safe_div(tp, positives)
    specificity = safe_div(tn, negatives)
    precision = safe_div(tp, tp + fp)
    f1 = None
    if precision is not None and recall is not None and precision + recall:
        f1 = 2 * precision * recall / (precision + recall)
    balanced = None
    if recall is not None and specificity is not None:
        balanced = (recall + specificity) / 2

    observable = [row for row in rows if not row["limited_observability_reason"]]
    observable_positives = sum(bool(row["expected_positive"]) for row in observable)
    observable_tp = sum(row["category"] == "true_positive" for row in observable)
    return {
        "tasks": len(rows),
        "expected_positives": positives,
        "expected_negatives": negatives,
        "counts": dict(sorted(counts.items())),
        "decision_coverage": safe_div(decisive, len(rows)),
        "end_to_end_recall": recall,
        "observable_positive_recall": safe_div(observable_tp, observable_positives),
        "precision": precision,
        "end_to_end_specificity": specificity,
        "false_positive_rate": safe_div(fp, negatives),
        "f1": f1,
        "balanced_accuracy": balanced,
        "strict_accuracy": safe_div(tp + tn, len(rows)),
    }


def pair_category(vulnerable: dict[str, Any], patched: dict[str, Any]) -> str:
    vulnerable_value = vulnerable["model_verdict"] or vulnerable["category"]
    patched_value = patched["model_verdict"] or patched["category"]
    if vulnerable["expected_positive"]:
        if vulnerable_value == "vulnerable" and patched_value == "not_vulnerable":
            return "correct_positive_to_negative_transition"
        return "incorrect_or_incomplete_matched_transition"
    if vulnerable_value == "not_vulnerable" and patched_value == "not_vulnerable":
        return "stable_negative"
    return "incorrect_or_incomplete_negative_pair"


def main() -> int:
    args = parse_args()
    run_dir = args.run_dir.resolve()
    metadata = load_metadata(run_dir)
    tasks = read_jsonl(run_dir / "manifest.jsonl")
    result_rows = read_jsonl(run_dir / "results.jsonl")
    latest: dict[str, dict[str, Any]] = {}
    for result in result_rows:
        latest[result.get("cache_key", "")] = result

    scored: list[dict[str, Any]] = []
    for task in tasks:
        result = latest.get(task["cache_key"])
        category, verdict = categorize(task, result)
        parsed = (result or {}).get("parsed_result") or {}
        usage = (result or {}).get("usage") or {}
        scored.append(
            {
                "task_id": task["task_id"],
                "cve_id": task["cve_id"],
                "project": task["project"],
                "variant": task["variant"],
                "representation": task["representation"],
                "indexed_bug_class": task["indexed_bug_class"],
                "target_class": task["target_class"],
                "expected_positive": bool(task["expected_positive"]),
                "limited_observability_reason": task.get("limited_observability_reason"),
                "input_status": task["input_status"],
                "response_status": (result or {}).get("status"),
                "category": category,
                "model_verdict": verdict,
                "confidence": parsed.get("confidence"),
                "evidence_lines": json.dumps(parsed.get("evidence_lines", [])),
                "summary": parsed.get("summary"),
                "model": task["model"],
                "input_tokens": usage.get("input_tokens"),
                "output_tokens": usage.get("output_tokens"),
                "actual_cost_usd": (result or {}).get("actual_cost_usd"),
                "error": (result or {}).get("error") or task.get("input_error"),
            }
        )

    output_dir = run_dir / "scoring"
    output_dir.mkdir(parents=True, exist_ok=True)
    scoring_path = output_dir / "scoring.csv"
    if scored:
        with scoring_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(scored[0]))
            writer.writeheader()
            writer.writerows(scored)

    per_class: dict[str, Any] = {}
    for target_class in sorted({row["target_class"] for row in scored}):
        per_class[target_class] = compute_metrics(
            [row for row in scored if row["target_class"] == target_class]
        )
    per_representation: dict[str, Any] = {}
    for representation in sorted({row["representation"] for row in scored}):
        per_representation[representation] = compute_metrics(
            [row for row in scored if row["representation"] == representation]
        )

    grouped: dict[tuple[str, str], dict[str, dict[str, Any]]] = defaultdict(dict)
    for row in scored:
        grouped[(row["cve_id"], row["target_class"])][row["variant"]] = row
    pairs: list[dict[str, Any]] = []
    for (cve_id, target_class), variants in sorted(grouped.items()):
        if "vulnerable" not in variants or "patched" not in variants:
            continue
        vulnerable = variants["vulnerable"]
        patched = variants["patched"]
        pairs.append(
            {
                "cve_id": cve_id,
                "target_class": target_class,
                "matched_ground_truth_class": vulnerable["expected_positive"],
                "vulnerable_variant_value": vulnerable["model_verdict"] or vulnerable["category"],
                "patched_variant_value": patched["model_verdict"] or patched["category"],
                "pair_category": pair_category(vulnerable, patched),
            }
        )
    pair_path = output_dir / "paired-transitions.csv"
    if pairs:
        with pair_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(pairs[0]))
            writer.writeheader()
            writer.writerows(pairs)

    summary = {
        "overall": compute_metrics(scored),
        "per_class": per_class,
        "per_representation": per_representation,
        "limited_observability_tasks": [
            {
                "task_id": row["task_id"],
                "category": row["category"],
                "reason": row["limited_observability_reason"],
            }
            for row in scored
            if row["limited_observability_reason"]
        ],
        "false_positives": [
            {
                "task_id": row["task_id"],
                "summary": row["summary"],
                "reason": (
                    "patched code flagged"
                    if row["variant"] == "patched"
                    else "mismatched target class flagged"
                ),
            }
            for row in scored
            if row["category"] == "false_positive"
        ],
        "false_negatives": [
            {
                "task_id": row["task_id"],
                "indexed_bug_class": row["indexed_bug_class"],
                "summary": row["summary"],
            }
            for row in scored
            if row["category"] == "false_negative"
        ],
    }
    summary_path = output_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    metadata["status"] = "scored"
    metadata["scored_at_utc"] = utc_now()
    metadata["metrics"] = summary["overall"]
    metadata["scored_tasks"] = len(scored)
    metadata["api_attempt_records"] = len(result_rows)
    metadata["recorded_cumulative_cost_usd"] = sum(
        float(
            result.get("actual_cost_usd")
            if result.get("actual_cost_usd") is not None
            else result.get("estimated_worst_case_cost_usd") or 0
        )
        for result in result_rows
    )
    write_metadata(run_dir, metadata)

    print(json.dumps(summary["overall"], indent=2, sort_keys=True))
    print(f"Scoring rows: {scoring_path}")
    print(f"Summary: {summary_path}")
    print(f"Paired transitions: {pair_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
