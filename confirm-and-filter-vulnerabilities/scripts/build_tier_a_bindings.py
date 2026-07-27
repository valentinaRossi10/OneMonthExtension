#!/usr/bin/env python3
"""Resolve evaluator-reviewed Tier A task mappings to package function UIDs."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any

from filter_common import AnalysisPackage, load_policy, read_jsonl, write_jsonl
from ingest_tier_a_queue import infer_run_id


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--scoring-csv", required=True, type=Path)
    value.add_argument("--mapping-jsonl", required=True, type=Path)
    value.add_argument("--output-jsonl", required=True, type=Path)
    return value


def normalized_address(value: str) -> str:
    return value.lower().removeprefix("0x").lstrip("0") or "0"


def uid_for_address(package: AnalysisPackage, address: str) -> str:
    wanted = normalized_address(address)
    matches = [
        row["function_uid"]
        for row in package.function_rows
        if normalized_address(str(row["address"])) == wanted
    ]
    if len(matches) != 1:
        raise ValueError(
            f"Address {address!r} resolved to {len(matches)} functions "
            f"in {package.metadata['package_id']}"
        )
    return matches[0]


def main() -> int:
    args = parser().parse_args()
    scoring_path = args.scoring_csv.resolve()
    run_id = infer_run_id(scoring_path)
    policy = load_policy()
    mappings: dict[tuple[str, str], dict[str, Any]] = {}
    packages: dict[Path, AnalysisPackage] = {}
    for row_number, row in enumerate(read_jsonl(args.mapping_jsonl), 1):
        key = (str(row.get("cve_id", "")), str(row.get("variant", "")))
        if not all(key) or key in mappings:
            raise ValueError(
                f"{args.mapping_jsonl}:{row_number}: invalid or duplicate mapping {key}"
            )
        package_path = Path(str(row.get("package_path", ""))).resolve()
        package = packages.get(package_path)
        if package is None:
            package = AnalysisPackage(package_path, policy)
            package.verify_frozen_inputs()
            packages[package_path] = package
        candidate_uid = uid_for_address(
            package, str(row.get("candidate_address", ""))
        )
        root_addresses = row.get("entry_root_addresses")
        if not isinstance(root_addresses, list) or not root_addresses:
            raise ValueError(
                f"{args.mapping_jsonl}:{row_number}: entry roots must be non-empty"
            )
        mappings[key] = {
            "package_path": str(package_path),
            "artifact_sha256": package.metadata["artifact_sha256"],
            "function_uid": candidate_uid,
            "entry_roots": sorted(
                {uid_for_address(package, str(address)) for address in root_addresses}
            ),
        }

    output: list[dict[str, Any]] = []
    with scoring_path.open(newline="", encoding="utf-8") as handle:
        for row_number, row in enumerate(csv.DictReader(handle), 2):
            key = (row.get("cve_id", ""), row.get("variant", ""))
            mapping = mappings.get(key)
            if mapping is None:
                continue
            task_id = row.get("task_id", "")
            if not task_id:
                raise ValueError(f"{scoring_path}:{row_number}: missing task_id")
            output.append(
                {
                    "source_run_id": run_id,
                    "source_task_id": task_id,
                    **mapping,
                }
            )
    if not output:
        raise ValueError("No scoring rows matched the reviewed mappings")
    args.output_jsonl.parent.mkdir(parents=True, exist_ok=True)
    if args.output_jsonl.exists():
        raise ValueError(f"Refusing to overwrite {args.output_jsonl}")
    write_jsonl(args.output_jsonl, output)
    print(
        json.dumps(
            {
                "source_run_id": run_id,
                "binding_count": len(output),
                "mapping_count": len(mappings),
                "package_count": len(packages),
                "output_jsonl": str(args.output_jsonl.resolve()),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, AssertionError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)
