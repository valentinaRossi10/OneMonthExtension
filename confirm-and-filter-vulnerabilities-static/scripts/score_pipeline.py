#!/usr/bin/env python3
"""Score recall-first Tier B dispositions without converting failures to negatives."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from filter_common import load_json, read_jsonl, sha256_file, utc_now, write_json
from stream_observability import accounted_spend


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--run-dir", required=True, type=Path)
    value.add_argument(
        "--labels-jsonl",
        type=Path,
        help=(
            "Optional evaluator-only case labels with case_id and "
            "expected_positive. Overrides labels recoverable from Tier A rows."
        ),
    )
    value.add_argument(
        "--output-dir",
        type=Path,
        help=(
            "Run-relative output directory for an append-only scoring snapshot. "
            "Defaults to scoring."
        ),
    )
    return value


def boolean(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    normalized = str(value).strip().lower()
    if normalized in {"true", "1", "yes"}:
        return True
    if normalized in {"false", "0", "no"}:
        return False
    return None


def derived_label(case: dict[str, Any]) -> bool | None:
    labels = {
        parsed
        for parsed in (
            boolean(row.get("expected_positive"))
            for row in case.get("source_rows", [])
        )
        if parsed is not None
    }
    if len(labels) == 1:
        return next(iter(labels))
    return None


def category(expected: bool | None, disposition: str) -> str:
    if expected is True:
        if disposition == "retain_confirmed":
            return "true_positive"
        if disposition == "suppress_proven_false_positive":
            return "false_suppression"
        return "unconfirmed_positive"
    if expected is False:
        if disposition == "retain_confirmed":
            return "false_positive"
        if disposition == "suppress_proven_false_positive":
            return "true_negative"
        return "surviving_negative"
    return "unlabeled"


def main() -> int:
    args = parser().parse_args()
    run_dir = args.run_dir.resolve()
    tasks = read_jsonl(run_dir / "manifest.jsonl")
    metadata = load_json(run_dir / "run-metadata.json")
    queue_dir = Path(metadata["queue_dir"])
    queue_rows = read_jsonl(queue_dir / "queue.jsonl")
    quarantine_rows = read_jsonl(queue_dir / "quarantine.jsonl")
    queue_by_id = {row["case_id"]: row for row in queue_rows}
    labels: dict[str, bool] = {}
    if args.labels_jsonl:
        for row in read_jsonl(args.labels_jsonl):
            parsed = boolean(row.get("expected_positive"))
            if parsed is None:
                raise ValueError(f"Invalid expected_positive label: {row}")
            case_id = str(row["case_id"])
            if case_id in labels:
                raise ValueError(f"Duplicate evaluator label: {case_id}")
            labels[case_id] = parsed

    results_path = run_dir / "results.jsonl"
    result_records = read_jsonl(results_path)
    latest: dict[str, dict[str, Any]] = {}
    for row in result_records:
        if row.get("terminal"):
            latest[row["cache_key"]] = row

    scored: list[dict[str, Any]] = []
    for task in tasks:
        case = queue_by_id[task["case_id"]]
        result_record = latest.get(task["cache_key"])
        if result_record is None:
            execution_status = "missing_output"
            disposition = "retain_and_escalate"
            semantic_status = "unresolved"
            summary = "No terminal result record exists."
        else:
            parsed = result_record.get("parsed_result") or {}
            execution_status = parsed.get(
                "execution_status", result_record.get("status", "invalid_output")
            )
            disposition = parsed.get(
                "pipeline_disposition", "retain_and_escalate"
            )
            semantic_status = parsed.get("semantic_status", "unresolved")
            summary = parsed.get("summary", result_record.get("error", ""))
        expected = labels.get(task["case_id"])
        if expected is None:
            expected = derived_label(case)
        scored.append(
            {
                "case_id": task["case_id"],
                "artifact_sha256": task["artifact_sha256"],
                "function_uid": task["function_uid"],
                "target_class": task["target_class"],
                "source_row_count": task["source_row_count"],
                "expected_positive": expected,
                "semantic_status": semantic_status,
                "pipeline_disposition": disposition,
                "execution_status": execution_status,
                "category": category(expected, disposition),
                "summary": summary,
            }
        )

    for quarantine in quarantine_rows:
        quarantine_id = quarantine["quarantine_id"]
        expected = labels.get(quarantine_id)
        if expected is None:
            expected = boolean(
                quarantine.get("source_row", {}).get("expected_positive")
            )
        scored.append(
            {
                "case_id": quarantine_id,
                "artifact_sha256": (
                    quarantine.get("binding") or {}
                ).get("artifact_sha256", ""),
                "function_uid": (
                    quarantine.get("binding") or {}
                ).get("function_uid", ""),
                "target_class": quarantine.get("source_row", {}).get(
                    "normalized_target_class", ""
                ),
                "source_row_count": 1,
                "expected_positive": expected,
                "semantic_status": "unresolved",
                "pipeline_disposition": "retain_and_escalate",
                "execution_status": "ingestion_quarantine",
                "category": category(expected, "retain_and_escalate"),
                "summary": quarantine["reason"],
            }
        )

    scoring_dir = (
        args.output_dir.resolve()
        if args.output_dir and args.output_dir.is_absolute()
        else run_dir / (args.output_dir or Path("scoring"))
    )
    scoring_dir = scoring_dir.resolve()
    if not scoring_dir.is_relative_to(run_dir):
        raise ValueError("Scoring output directory must remain inside the run")
    if scoring_dir.exists():
        raise FileExistsError(f"Refusing to replace existing scoring: {scoring_dir}")
    scoring_dir.mkdir()
    fields = [
        "case_id",
        "artifact_sha256",
        "function_uid",
        "target_class",
        "source_row_count",
        "expected_positive",
        "semantic_status",
        "pipeline_disposition",
        "execution_status",
        "category",
        "summary",
    ]
    with (scoring_dir / "scoring.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(scored)

    categories = Counter(row["category"] for row in scored)
    dispositions = Counter(row["pipeline_disposition"] for row in scored)
    executions = Counter(row["execution_status"] for row in scored)
    positives = sum(row["expected_positive"] is True for row in scored)
    negatives = sum(row["expected_positive"] is False for row in scored)
    confirmed_positives = categories["true_positive"]
    suppressed_negatives = categories["true_negative"]
    ledger_spend = accounted_spend(result_records)
    metadata_spend = float(metadata.get("accounted_spend_usd", 0.0))
    schema_version = metadata.get("schema_version")
    is_asymmetric = schema_version in {
        "tier-b-filter-result-v3",
        "tier-b-filter-result-v4",
    }
    acceptance_target = {
        "available_busybox_positive_cases": 5,
        "target_confirmation_count": 5,
        "target_false_suppression_count": 0,
        "limitation": (
            "Passing the five reviewed BusyBox positives does not establish "
            "universal recall or held-out generalization."
        ),
    }
    if is_asymmetric:
        acceptance_target = {
            "available_busybox_positive_cases": 5,
            "target_confirmation_count": 5,
            "target_false_suppression_count": 0,
            "target_kind": "observed_cohort_objective",
            "mathematical_guarantee": False,
            "limitation": (
                "The asymmetric gate is designed to approach zero false "
                "suppressions on the reviewed cohort. An LLM-only gate cannot "
                "guarantee universal recall, universal absence of false "
                "suppression, or held-out generalization."
            ),
        }
    summary = {
        "summary_version": (
            (
                "tier-b-filter-scoring-summary-v4"
                if schema_version == "tier-b-filter-result-v4"
                else "tier-b-filter-scoring-summary-v3"
            )
            if is_asymmetric
            else "tier-b-filter-scoring-summary-v2"
        ),
        "run_id": run_dir.name,
        "scored_at_utc": utc_now(),
        "manifest_sha256": sha256_file(run_dir / "manifest.jsonl"),
        "results_sha256": sha256_file(results_path),
        "results_record_count": len(result_records),
        "total_cases_including_quarantine": len(scored),
        "manifest_case_count": len(tasks),
        "quarantine_count": len(quarantine_rows),
        "labeled_positive_count": positives,
        "labeled_negative_count": negatives,
        "category_counts": dict(sorted(categories.items())),
        "disposition_counts": dict(sorted(dispositions.items())),
        "execution_status_counts": dict(sorted(executions.items())),
        "confirmation_recall": (
            confirmed_positives / positives if positives else None
        ),
        "false_suppression_count": categories["false_suppression"],
        "negative_suppression_rate": (
            suppressed_negatives / negatives if negatives else None
        ),
        "retained_for_downstream_dynamic_analysis": dispositions[
            "retain_and_escalate"
        ],
        "acceptance_target": acceptance_target,
        "accounted_spend_usd": ledger_spend,
        "metadata_accounted_spend_usd": metadata_spend,
        "metadata_spend_matches_ledger": abs(metadata_spend - ledger_spend) < 1e-9,
    }
    write_json(scoring_dir / "summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, AssertionError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)
