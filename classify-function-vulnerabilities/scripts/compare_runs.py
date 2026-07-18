#!/usr/bin/env python3
"""Compare two scored Tier A runs without making API calls."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

from experiment_common import load_metadata, utc_now


METRICS = (
    "decision_coverage",
    "end_to_end_recall",
    "observable_positive_recall",
    "precision",
    "end_to_end_specificity",
    "false_positive_rate",
    "balanced_accuracy",
    "strict_accuracy",
    "f1",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-run", type=Path, required=True)
    parser.add_argument("--candidate-run", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument(
        "--replace",
        action="store_true",
        help="Replace an existing derived comparison directory.",
    )
    return parser.parse_args()


def read_scoring(run_dir: Path) -> dict[str, dict[str, str]]:
    path = run_dir / "scoring" / "scoring.csv"
    if not path.is_file():
        raise FileNotFoundError(f"Score the run before comparing it: {path}")
    with path.open(newline="", encoding="utf-8") as handle:
        return {row["task_id"]: row for row in csv.DictReader(handle)}


def read_summary(run_dir: Path) -> dict[str, Any]:
    path = run_dir / "scoring" / "summary.json"
    if not path.is_file():
        raise FileNotFoundError(f"Score the run before comparing it: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def numeric_delta(previous: Any, current: Any) -> float | None:
    if isinstance(previous, (int, float)) and isinstance(current, (int, float)):
        return float(current) - float(previous)
    return None


def main() -> int:
    args = parse_args()
    baseline_dir = args.baseline_run.resolve()
    candidate_dir = args.candidate_run.resolve()
    if baseline_dir == candidate_dir:
        raise ValueError("Baseline and candidate runs must be different")
    baseline_meta = load_metadata(baseline_dir)
    candidate_meta = load_metadata(candidate_dir)
    baseline_metrics = baseline_meta.get("metrics")
    candidate_metrics = candidate_meta.get("metrics")
    if not isinstance(baseline_metrics, dict) or not isinstance(candidate_metrics, dict):
        raise ValueError("Both runs must be scored and contain metrics in run-metadata.json")

    baseline_rows = read_scoring(baseline_dir)
    candidate_rows = read_scoring(candidate_dir)
    baseline_summary = read_summary(baseline_dir)
    candidate_summary = read_summary(candidate_dir)
    if set(baseline_rows) != set(candidate_rows):
        missing_candidate = sorted(set(baseline_rows) - set(candidate_rows))
        missing_baseline = sorted(set(candidate_rows) - set(baseline_rows))
        raise ValueError(
            "Run task sets differ; missing from candidate="
            f"{missing_candidate}, missing from baseline={missing_baseline}"
        )
    identity_fields = (
        "cve_id",
        "project",
        "variant",
        "representation",
        "indexed_bug_class",
        "target_class",
        "expected_positive",
    )
    for task_id in baseline_rows:
        changed = [
            field
            for field in identity_fields
            if baseline_rows[task_id].get(field) != candidate_rows[task_id].get(field)
        ]
        if changed:
            raise ValueError(
                f"Ground-truth/task identity differs for {task_id}: {', '.join(changed)}"
            )

    default_root = candidate_dir.parent.parent / "comparisons"
    comparison_id = f"{baseline_meta['run_id']}__vs__{candidate_meta['run_id']}"
    output_dir = (args.output_dir or default_root / comparison_id).resolve()
    if output_dir.exists() and any(output_dir.iterdir()) and not args.replace:
        raise FileExistsError(
            f"Comparison already exists: {output_dir}; use --replace to regenerate it"
        )
    output_dir.mkdir(parents=True, exist_ok=True)

    metric_rows = []
    for metric in METRICS:
        baseline_value = baseline_metrics.get(metric)
        candidate_value = candidate_metrics.get(metric)
        metric_rows.append(
            {
                "metric": metric,
                "baseline": baseline_value,
                "candidate": candidate_value,
                "delta_candidate_minus_baseline": numeric_delta(
                    baseline_value, candidate_value
                ),
            }
        )
    for category in sorted(
        set((baseline_metrics.get("counts") or {}))
        | set((candidate_metrics.get("counts") or {}))
    ):
        baseline_value = (baseline_metrics.get("counts") or {}).get(category, 0)
        candidate_value = (candidate_metrics.get("counts") or {}).get(category, 0)
        metric_rows.append(
            {
                "metric": f"count.{category}",
                "baseline": baseline_value,
                "candidate": candidate_value,
                "delta_candidate_minus_baseline": candidate_value - baseline_value,
            }
        )
    metric_rows.append(
        {
            "metric": "cost.recorded_cumulative_usd",
            "baseline": baseline_meta.get("recorded_cumulative_cost_usd"),
            "candidate": candidate_meta.get("recorded_cumulative_cost_usd"),
            "delta_candidate_minus_baseline": numeric_delta(
                baseline_meta.get("recorded_cumulative_cost_usd"),
                candidate_meta.get("recorded_cumulative_cost_usd"),
            ),
        }
    )
    with (output_dir / "metrics.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(metric_rows[0]))
        writer.writeheader()
        writer.writerows(metric_rows)

    per_class_rows: list[dict[str, Any]] = []
    baseline_per_class = baseline_summary.get("per_class") or {}
    candidate_per_class = candidate_summary.get("per_class") or {}
    if set(baseline_per_class) != set(candidate_per_class):
        raise ValueError("Per-class scoring keys differ between runs")
    for target_class in sorted(baseline_per_class):
        for metric in METRICS:
            baseline_value = baseline_per_class[target_class].get(metric)
            candidate_value = candidate_per_class[target_class].get(metric)
            per_class_rows.append(
                {
                    "target_class": target_class,
                    "metric": metric,
                    "baseline": baseline_value,
                    "candidate": candidate_value,
                    "delta_candidate_minus_baseline": numeric_delta(
                        baseline_value, candidate_value
                    ),
                }
            )
    with (output_dir / "per-class-metrics.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=list(per_class_rows[0]))
        writer.writeheader()
        writer.writerows(per_class_rows)

    task_rows: list[dict[str, Any]] = []
    for task_id in sorted(baseline_rows):
        before = baseline_rows[task_id]
        after = candidate_rows[task_id]
        task_rows.append(
            {
                "task_id": task_id,
                "baseline_category": before["category"],
                "candidate_category": after["category"],
                "baseline_verdict": before["model_verdict"],
                "candidate_verdict": after["model_verdict"],
                "baseline_confidence": before["confidence"],
                "candidate_confidence": after["confidence"],
                "category_changed": before["category"] != after["category"],
                "verdict_changed": before["model_verdict"] != after["model_verdict"],
            }
        )
    with (output_dir / "task-changes.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(task_rows[0]))
        writer.writeheader()
        writer.writerows(task_rows)

    configuration_fields = (
        "model",
        "reasoning_effort",
        "policy_version",
        "prompt_version",
        "schema_version",
        "max_output_tokens",
        "hard_budget_ceiling_usd",
    )
    configuration_changes = [
        {
            "field": field,
            "baseline": baseline_meta.get(field),
            "candidate": candidate_meta.get(field),
        }
        for field in configuration_fields
        if baseline_meta.get(field) != candidate_meta.get(field)
    ]
    comparison = {
        "comparison_version": "tier-a-comparison-v1",
        "comparison_id": comparison_id,
        "generated_at_utc": utc_now(),
        "baseline_run_id": baseline_meta["run_id"],
        "candidate_run_id": candidate_meta["run_id"],
        "configuration_changes": configuration_changes,
        "metric_deltas": metric_rows,
        "tasks": len(task_rows),
        "category_changes": sum(row["category_changed"] for row in task_rows),
        "verdict_changes": sum(row["verdict_changed"] for row in task_rows),
        "per_class_metric_rows": len(per_class_rows),
    }
    (output_dir / "comparison.json").write_text(
        json.dumps(comparison, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    lines = [
        f"# Tier A comparison: {baseline_meta['run_id']} vs {candidate_meta['run_id']}",
        "",
        f"Generated at: `{comparison['generated_at_utc']}`.",
        "",
        "## Runs",
        "",
        "| Role | Date | Model | Reasoning |",
        "|---|---|---|---|",
        f"| Baseline | {baseline_meta.get('run_date_utc')} | `{baseline_meta.get('model')}` | `{baseline_meta.get('reasoning_effort')}` |",
        f"| Candidate | {candidate_meta.get('run_date_utc')} | `{candidate_meta.get('model')}` | `{candidate_meta.get('reasoning_effort')}` |",
        "",
        "## Configuration changes",
        "",
    ]
    if configuration_changes:
        lines.extend(["| Setting | Baseline | Candidate |", "|---|---|---|"])
        for change in configuration_changes:
            lines.append(
                f"| {change['field']} | {change['baseline']} | {change['candidate']} |"
            )
    else:
        lines.append("No tracked configuration setting changed.")
    lines.extend(["", "## Metric changes", "", "| Metric | Baseline | Candidate | Delta |", "|---|---:|---:|---:|"])
    for row in metric_rows:
        lines.append(
            f"| `{row['metric']}` | {row['baseline']} | {row['candidate']} | "
            f"{row['delta_candidate_minus_baseline']} |"
        )
    lines.extend(
        [
            "",
            "## Task-level changes",
            "",
            f"- Categories changed for {comparison['category_changes']} of {comparison['tasks']} tasks.",
            f"- Verdicts changed for {comparison['verdict_changes']} of {comparison['tasks']} tasks.",
            "- See `task-changes.csv` for the complete task-level comparison.",
            "- See `per-class-metrics.csv` for class-specific metric deltas.",
            "",
        ]
    )
    (output_dir / "README.md").write_text("\n".join(lines), encoding="utf-8")
    print(f"Comparison: {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
