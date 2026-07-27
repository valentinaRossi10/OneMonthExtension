#!/usr/bin/env python3
"""Ingest Tier A scoring rows without dropping or over-coalescing cases."""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

from filter_common import (
    canonical_json,
    normalize_class,
    read_jsonl,
    require_new_directory,
    sha256_text,
    utc_now,
    write_json,
    write_jsonl,
)


FUNCTION_UID_RE = re.compile(r"^fn-[0-9a-f]{32}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(
        description=(
            "Coalesce only exact artifact-scoped function/class Tier A cases "
            "and preserve a complete audit map."
        )
    )
    value.add_argument("--scoring-csv", action="append", required=True, type=Path)
    value.add_argument("--bindings-jsonl", required=True, type=Path)
    value.add_argument("--output-dir", required=True, type=Path)
    value.add_argument(
        "--forward-verdict",
        action="append",
        choices=["vulnerable", "indeterminate"],
        help="Tier A verdict to forward; defaults to vulnerable and indeterminate.",
    )
    return value


def infer_run_id(path: Path) -> str:
    resolved = path.resolve()
    parts = resolved.parts
    if "runs" in parts:
        index = len(parts) - 1 - list(reversed(parts)).index("runs")
        if index + 1 < len(parts):
            return parts[index + 1]
    return resolved.parent.parent.name


def parse_evidence_lines(raw: str) -> list[int]:
    if not raw.strip():
        return []
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if not isinstance(value, list):
        return []
    return sorted({item for item in value if isinstance(item, int) and item >= 1})


def load_bindings(path: Path) -> tuple[dict[tuple[str, str], dict[str, Any]], set[str]]:
    bindings: dict[tuple[str, str], dict[str, Any]] = {}
    uid_artifacts: dict[str, set[str]] = defaultdict(set)
    for row_number, row in enumerate(read_jsonl(path), 1):
        required = {
            "source_run_id",
            "source_task_id",
            "artifact_sha256",
            "function_uid",
            "package_path",
            "entry_roots",
        }
        missing = required - set(row)
        if missing:
            raise ValueError(
                f"{path}:{row_number}: binding missing fields {sorted(missing)}"
            )
        key = (str(row["source_run_id"]), str(row["source_task_id"]))
        if key in bindings:
            raise ValueError(f"{path}:{row_number}: duplicate binding for {key}")
        artifact = str(row["artifact_sha256"])
        function_uid = str(row["function_uid"])
        if not SHA256_RE.fullmatch(artifact):
            raise ValueError(f"{path}:{row_number}: invalid artifact SHA-256")
        if not FUNCTION_UID_RE.fullmatch(function_uid):
            raise ValueError(f"{path}:{row_number}: invalid function UID")
        roots = row["entry_roots"]
        if not isinstance(roots, list) or any(
            not isinstance(root, str) or not FUNCTION_UID_RE.fullmatch(root)
            for root in roots
        ):
            raise ValueError(f"{path}:{row_number}: invalid entry_roots")
        bindings[key] = {
            **row,
            "artifact_sha256": artifact,
            "function_uid": function_uid,
            "entry_roots": sorted(set(roots)),
        }
        uid_artifacts[function_uid].add(artifact)
    conflicting_uids = {
        uid for uid, artifacts in uid_artifacts.items() if len(artifacts) > 1
    }
    return bindings, conflicting_uids


def source_record(
    row: dict[str, str],
    run_id: str,
    scoring_path: Path,
    row_number: int,
) -> dict[str, Any]:
    row_hash = sha256_text(canonical_json(row))
    return {
        "source_row_id": f"tier-a-source-{row_hash[:24]}",
        "source_row_sha256": row_hash,
        "source_run_id": run_id,
        "source_task_id": row.get("task_id", ""),
        "source_file": str(scoring_path.resolve()),
        "source_row_number": row_number,
        "model": row.get("model", ""),
        "response_status": row.get("response_status", ""),
        "model_verdict": row.get("model_verdict", ""),
        "confidence": row.get("confidence", ""),
        "evidence_lines": parse_evidence_lines(row.get("evidence_lines", "")),
        "summary": row.get("summary", ""),
        "target_class_raw": row.get("target_class", ""),
        "input_status": row.get("input_status", ""),
        "expected_positive": row.get("expected_positive", ""),
        "cve_id": row.get("cve_id", ""),
        "variant": row.get("variant", ""),
        "indexed_bug_class": row.get("indexed_bug_class", ""),
    }


def quarantine_record(
    source: dict[str, Any],
    reason: str,
    binding: dict[str, Any] | None,
) -> dict[str, Any]:
    return {
        "quarantine_id": f"tier-b-quarantine-{sha256_text(source['source_row_id'] + reason)[:24]}",
        "source_row": source,
        "binding": binding,
        "reason": reason,
        "pipeline_disposition": "retain_and_escalate",
    }


def main() -> int:
    args = parser().parse_args()
    forward_verdicts = set(args.forward_verdict or ["vulnerable", "indeterminate"])
    bindings, conflicting_uids = load_bindings(args.bindings_jsonl)

    raw_row_count = 0
    eligible: list[tuple[dict[str, Any], dict[str, Any] | None, str | None]] = []
    for scoring_path in args.scoring_csv:
        run_id = infer_run_id(scoring_path)
        with scoring_path.open(newline="", encoding="utf-8") as handle:
            for row_number, row in enumerate(csv.DictReader(handle), 2):
                raw_row_count += 1
                if row.get("model_verdict") not in forward_verdicts:
                    continue
                source = source_record(row, run_id, scoring_path, row_number)
                binding = bindings.get((run_id, row.get("task_id", "")))
                class_error: str | None = None
                try:
                    normalized = normalize_class(row.get("target_class", ""))
                    source["normalized_target_class"] = normalized
                except ValueError as exc:
                    class_error = str(exc)
                eligible.append((source, binding, class_error))

    output = require_new_directory(args.output_dir)
    quarantine: list[dict[str, Any]] = []
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    row_mapping: list[dict[str, Any]] = []

    for source, binding, class_error in eligible:
        reason: str | None = None
        if class_error:
            reason = class_error
        elif binding is None:
            reason = "No artifact-scoped function binding exists for the Tier A row"
        elif binding["function_uid"] in conflicting_uids:
            reason = "Function UID is bound to more than one artifact SHA-256"

        if reason:
            record = quarantine_record(source, reason, binding)
            quarantine.append(record)
            row_mapping.append(
                {
                    "source_row_id": source["source_row_id"],
                    "destination_type": "quarantine",
                    "destination_id": record["quarantine_id"],
                }
            )
            continue

        assert binding is not None
        target_class = source["normalized_target_class"]
        logical_key = (binding["function_uid"], target_class)
        existing = grouped.get(logical_key)
        if existing and (
            existing["artifact_sha256"] != binding["artifact_sha256"]
            or existing["package_path"] != binding["package_path"]
        ):
            record = quarantine_record(
                source,
                "Exact logical key has inconsistent artifact or package binding",
                binding,
            )
            quarantine.append(record)
            row_mapping.append(
                {
                    "source_row_id": source["source_row_id"],
                    "destination_type": "quarantine",
                    "destination_id": record["quarantine_id"],
                }
            )
            continue

        if existing is None:
            case_digest = sha256_text(
                "|".join(
                    [
                        binding["artifact_sha256"],
                        binding["function_uid"],
                        target_class,
                    ]
                )
            )
            existing = {
                "queue_version": "tier-b-filter-queue-v1",
                "case_id": f"tier-b-case-{case_digest[:24]}",
                "artifact_sha256": binding["artifact_sha256"],
                "function_uid": binding["function_uid"],
                "target_class": target_class,
                "package_path": str(binding["package_path"]),
                "entry_roots": set(),
                "source_rows": [],
                "evidence_by_hash": {},
                "verdicts": set(),
            }
            grouped[logical_key] = existing
        existing["entry_roots"].update(binding["entry_roots"])
        existing["source_rows"].append(source)
        existing["verdicts"].add(source["model_verdict"])
        evidence = {
            "model_verdict": source["model_verdict"],
            "evidence_lines": source["evidence_lines"],
            "summary": source["summary"],
        }
        evidence_hash = sha256_text(canonical_json(evidence))
        item = existing["evidence_by_hash"].setdefault(
            evidence_hash,
            {
                **evidence,
                "evidence_sha256": evidence_hash,
                "source_row_ids": [],
            },
        )
        item["source_row_ids"].append(source["source_row_id"])
        row_mapping.append(
            {
                "source_row_id": source["source_row_id"],
                "destination_type": "case",
                "destination_id": existing["case_id"],
            }
        )

    cases: list[dict[str, Any]] = []
    audit_rows: list[dict[str, Any]] = []
    for logical_key in sorted(grouped):
        raw = grouped[logical_key]
        sources = sorted(raw["source_rows"], key=lambda row: row["source_row_id"])
        evidence_items = sorted(
            raw["evidence_by_hash"].values(), key=lambda row: row["evidence_sha256"]
        )
        for item in evidence_items:
            item["source_row_ids"] = sorted(set(item["source_row_ids"]))
        case = {
            "queue_version": raw["queue_version"],
            "case_id": raw["case_id"],
            "artifact_sha256": raw["artifact_sha256"],
            "function_uid": raw["function_uid"],
            "target_class": raw["target_class"],
            "package_path": raw["package_path"],
            "entry_roots": sorted(raw["entry_roots"]),
            "source_row_count": len(sources),
            "source_rows": sources,
            "evidence_items": evidence_items,
            "has_conflicting_verdicts": len(raw["verdicts"]) > 1,
        }
        cases.append(case)
        audit_rows.append(
            {
                "case_id": case["case_id"],
                "artifact_sha256": case["artifact_sha256"],
                "function_uid": case["function_uid"],
                "target_class": case["target_class"],
                "source_row_count": case["source_row_count"],
                "source_run_ids": sorted(
                    {row["source_run_id"] for row in case["source_rows"]}
                ),
                "source_task_ids": sorted(
                    {row["source_task_id"] for row in case["source_rows"]}
                ),
                "source_row_ids": [
                    row["source_row_id"] for row in case["source_rows"]
                ],
                "source_row_hashes": [
                    row["source_row_sha256"] for row in case["source_rows"]
                ],
                "evidence_item_count": len(case["evidence_items"]),
                "has_conflicting_verdicts": case["has_conflicting_verdicts"],
            }
        )

    eligible_count = len(eligible)
    mapped_count = sum(case["source_row_count"] for case in cases) + len(quarantine)
    if mapped_count != eligible_count:
        raise AssertionError(
            f"Recall invariant failed: mapped {mapped_count} of {eligible_count} eligible rows"
        )
    if len(row_mapping) != eligible_count:
        raise AssertionError("Every eligible row must have exactly one audit mapping")
    if len({row["source_row_id"] for row in row_mapping}) != eligible_count:
        raise AssertionError("A source row was mapped more than once")

    write_jsonl(output / "queue.jsonl", cases)
    write_jsonl(output / "dedup-map.jsonl", audit_rows)
    write_jsonl(output / "quarantine.jsonl", quarantine)
    write_jsonl(
        output / "raw-row-map.jsonl",
        sorted(row_mapping, key=lambda row: row["source_row_id"]),
    )
    summary = {
        "queue_version": "tier-b-filter-queue-v1",
        "created_at_utc": utc_now(),
        "source_scoring_files": [str(path.resolve()) for path in args.scoring_csv],
        "bindings_file": str(args.bindings_jsonl.resolve()),
        "forward_verdicts": sorted(forward_verdicts),
        "raw_row_count": raw_row_count,
        "eligible_raw_row_count": eligible_count,
        "output_case_count": len(cases),
        "coalesced_duplicate_row_count": eligible_count
        - len(cases)
        - len(quarantine),
        "quarantine_count": len(quarantine),
        "mapped_raw_row_count": mapped_count,
        "invariants": {
            "every_eligible_row_mapped_once": True,
            "one_function_uid_per_case": True,
            "one_target_class_per_case": True,
            "artifact_scoped_uid_verified": True,
        },
    }
    write_json(output / "ingestion-summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, AssertionError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)
