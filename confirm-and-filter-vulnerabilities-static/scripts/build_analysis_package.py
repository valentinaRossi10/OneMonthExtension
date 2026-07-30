#!/usr/bin/env python3
"""Build a hash-verified package from Ghidra program-analysis facts."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

from filter_common import (
    canonical_json,
    load_policy,
    read_jsonl,
    require_new_directory,
    sha256_file,
    sha256_text,
    utc_now,
    write_json,
    write_jsonl,
)


SOURCE_RE = re.compile(r"^FUN_([0-9a-fA-F]+)\.c$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
MD5_RE = re.compile(r"^[0-9a-f]{32}$")


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(
        description="Build the MVP Tier B package from a Ghidra JSONL export."
    )
    value.add_argument("--artifact", required=True, type=Path)
    value.add_argument("--corpus-root", required=True, type=Path)
    value.add_argument("--analysis-export", required=True, type=Path)
    value.add_argument("--output-dir", required=True, type=Path)
    value.add_argument("--package-id", required=True)
    return value


def normalize_address(value: str) -> str:
    raw = value.strip().lower().removeprefix("0x")
    if not re.fullmatch(r"[0-9a-f]+", raw):
        raise ValueError(f"Invalid analysis address: {value!r}")
    return raw.lstrip("0") or "0"


def corpus_sources(root: Path) -> dict[str, tuple[Path, str]]:
    result: dict[str, tuple[Path, str]] = {}
    for path in sorted(root.rglob("FUN_*.c")):
        match = SOURCE_RE.fullmatch(path.name)
        if not match:
            continue
        address = normalize_address(match.group(1))
        if address in result:
            raise ValueError(f"Duplicate corpus function address: {address}")
        result[address] = (path, path.read_text(encoding="utf-8"))
    if not result:
        raise ValueError(f"No FUN_<hex>.c files found under {root}")
    return result


def corpus_digest(root: Path, sources: dict[str, tuple[Path, str]]) -> str:
    rows = []
    for address, (path, text) in sorted(sources.items()):
        rows.append(
            {
                "address": address,
                "relative_path": str(path.relative_to(root)),
                "source_sha256": sha256_text(text),
            }
        )
    return sha256_text(canonical_json(rows))


def md5_file(path: Path) -> str:
    digest = hashlib.md5(usedforsecurity=False)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_export(
    path: Path,
) -> tuple[
    dict[str, Any],
    dict[str, dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    metadata: dict[str, Any] | None = None
    functions: dict[str, dict[str, Any]] = {}
    callsites: list[dict[str, Any]] = []
    blocks: list[dict[str, Any]] = []
    pcode: list[dict[str, Any]] = []
    references: list[dict[str, Any]] = []
    for row_number, row in enumerate(read_jsonl(path), 1):
        row_type = row.get("record_type")
        if row_type == "metadata":
            if metadata is not None:
                raise ValueError(f"{path}:{row_number}: duplicate metadata record")
            metadata = row
        elif row_type == "function":
            address = normalize_address(str(row.get("address", "")))
            if address in functions:
                raise ValueError(f"{path}:{row_number}: duplicate function {address}")
            for field in ("byte_sha256", "normalized_instruction_sha256"):
                if not SHA_RE.fullmatch(str(row.get(field, ""))):
                    raise ValueError(f"{path}:{row_number}: invalid {field}")
            functions[address] = row
        elif row_type == "callsite":
            callsites.append(row)
        elif row_type == "basic_block":
            blocks.append(row)
        elif row_type == "pcode":
            pcode.append(row)
        elif row_type == "reference":
            references.append(row)
        else:
            raise ValueError(f"{path}:{row_number}: unknown record_type {row_type!r}")
    if metadata is None:
        raise ValueError("Analysis export has no metadata record")
    if metadata.get("analysis_source") != "ghidra-program-model-static-v2":
        raise ValueError("Analysis export is not from the static-v2 Ghidra exporter")
    if not MD5_RE.fullmatch(str(metadata.get("executable_md5", "")).lower()):
        raise ValueError("Analysis export has no valid executable_md5 binding")
    if not blocks or not pcode or not references:
        raise ValueError("Static-v2 export lacks block, p-code, or reference facts")
    return metadata, functions, callsites, blocks, pcode, references


def function_uid(
    artifact_sha256: str,
    address: str,
    byte_sha256: str,
) -> str:
    digest = sha256_text("|".join([artifact_sha256, address, byte_sha256]))
    return f"fn-{digest[:32]}"


def main() -> int:
    args = parser().parse_args()
    policy = load_policy()
    artifact = args.artifact.resolve()
    corpus_root = args.corpus_root.resolve()
    analysis_export = args.analysis_export.resolve()
    if not artifact.is_file():
        raise ValueError(f"Artifact is not a file: {artifact}")
    if not corpus_root.is_dir():
        raise ValueError(f"Corpus root is not a directory: {corpus_root}")
    if not analysis_export.is_file():
        raise ValueError(f"Analysis export is not a file: {analysis_export}")
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", args.package_id):
        raise ValueError("package-id must contain lowercase letters, digits, ., _, or -")

    sources = corpus_sources(corpus_root)
    (
        metadata,
        analysis_functions,
        analysis_callsites,
        analysis_blocks,
        analysis_pcode,
        analysis_references,
    ) = parse_export(analysis_export)
    missing = sorted(set(sources) - set(analysis_functions))
    if missing:
        preview = ", ".join(missing[:10])
        raise ValueError(
            f"Ghidra export lacks {len(missing)} corpus functions; first: {preview}"
        )
    if len(sources) > policy["limits"]["max_package_functions"]:
        raise ValueError("Package exceeds the configured function-count guard")

    artifact_sha = sha256_file(artifact)
    analysis_artifact_md5 = str(metadata["executable_md5"]).lower()
    if md5_file(artifact) != analysis_artifact_md5:
        raise ValueError(
            "Analysis export executable digest does not match the supplied artifact"
        )
    total_chars = sum(len(text) for _, text in sources.values())
    if total_chars > policy["limits"]["max_package_total_chars"]:
        raise ValueError("Package exceeds the configured source-size guard")

    address_to_uid: dict[str, str] = {}
    function_rows: list[dict[str, Any]] = []
    for address, (source_path, source) in sorted(sources.items()):
        fact = analysis_functions[address]
        uid = function_uid(
            artifact_sha,
            address,
            str(fact["byte_sha256"]),
        )
        address_to_uid[address] = uid
        function_rows.append(
            {
                "function_uid": uid,
                "address": address,
                "source_relpath": str(source_path.relative_to(corpus_root)),
                "source_sha256": sha256_text(source),
                "source_chars": len(source),
                "byte_sha256": fact["byte_sha256"],
                "normalized_instruction_sha256": fact[
                    "normalized_instruction_sha256"
                ],
                "body_ranges": fact.get("body_ranges", []),
                "size_bytes": int(fact.get("size_bytes", 0)),
                "block_count": int(fact.get("block_count", 0)),
                "strings": sorted(set(fact.get("strings", []))),
                "data_references": sorted(set(fact.get("data_references", []))),
            }
        )

    callsite_rows: list[dict[str, Any]] = []
    seen_callsites: set[str] = set()
    function_reference_candidates: dict[str, set[str]] = {}
    for raw_reference in analysis_references:
        function_address = normalize_address(
            str(raw_reference.get("function_address", ""))
        )
        target_raw = raw_reference.get("target_function_address")
        if not isinstance(target_raw, str) or not target_raw:
            continue
        target_address = normalize_address(target_raw)
        if target_address in address_to_uid:
            function_reference_candidates.setdefault(function_address, set()).add(
                target_address
            )
    for raw in analysis_callsites:
        caller_address = normalize_address(str(raw.get("caller_address", "")))
        caller_uid = address_to_uid.get(caller_address)
        if caller_uid is None:
            continue
        kind = str(raw.get("call_kind", ""))
        if kind not in {"direct", "indirect"}:
            raise ValueError(f"Invalid call kind: {kind!r}")
        site_address = normalize_address(str(raw.get("site_address", "")))
        target_address_raw = raw.get("target_address")
        target_address = (
            normalize_address(str(target_address_raw))
            if isinstance(target_address_raw, str) and target_address_raw
            else None
        )
        target_uid = address_to_uid.get(target_address) if target_address else None
        candidate_addresses = sorted(
            {
                normalize_address(str(value))
                for value in raw.get("candidate_target_addresses", [])
                if isinstance(value, str) and value
            }
        )
        if kind == "indirect" and not candidate_addresses:
            candidate_addresses = sorted(
                function_reference_candidates.get(caller_address, set())
            )
        candidate_uids = sorted(
            {
                address_to_uid[address]
                for address in candidate_addresses
                if address in address_to_uid
            }
        )
        if kind == "indirect" and target_uid:
            resolution = "resolved_reference"
        elif kind == "indirect" and candidate_uids:
            # Function-wide references are useful candidates, but they do not
            # prove which value reaches this specific CALLIND site. Only the
            # p-code resolver may promote one after a site-local backward slice.
            resolution = (
                "candidate_reference" if len(candidate_uids) == 1 else "ambiguous"
            )
            target_uid = None
        elif kind == "indirect":
            resolution = "unresolved"
            target_uid = None
        elif target_uid:
            resolution = "resolved"
        else:
            resolution = "external_or_unindexed"
        row = {
            "caller_uid": caller_uid,
            "site_address": site_address,
            "call_kind": kind,
            "resolution_status": resolution,
            "target_uid": target_uid,
            "target_address": target_address,
            "candidate_target_uids": candidate_uids,
            "candidate_target_addresses": candidate_addresses,
            "evidence": str(raw.get("evidence", ""))[:2000],
        }
        identity = canonical_json(row)
        if identity not in seen_callsites:
            seen_callsites.add(identity)
            callsite_rows.append(row)
    callsite_rows.sort(
        key=lambda row: (
            row["caller_uid"],
            int(row["site_address"], 16),
            row["call_kind"],
            row["target_uid"] or "",
        )
    )

    block_rows: list[dict[str, Any]] = []
    for raw in analysis_blocks:
        function_address = normalize_address(str(raw.get("function_address", "")))
        function_uid_value = address_to_uid.get(function_address)
        if function_uid_value is None:
            continue
        block_rows.append(
            {
                "function_uid": function_uid_value,
                "block_start": normalize_address(str(raw["block_start"])),
                "block_end": normalize_address(str(raw["block_end"])),
                "successors": sorted(
                    {
                        normalize_address(str(value))
                        for value in raw.get("successors", [])
                    }
                ),
            }
        )
    block_rows.sort(
        key=lambda row: (row["function_uid"], int(row["block_start"], 16))
    )

    pcode_rows: list[dict[str, Any]] = []
    for raw in analysis_pcode:
        function_address = normalize_address(str(raw.get("function_address", "")))
        function_uid_value = address_to_uid.get(function_address)
        if function_uid_value is None:
            continue
        pcode_rows.append(
            {
                "function_uid": function_uid_value,
                "pcode_seq": int(raw["pcode_seq"]),
                "instruction_address": normalize_address(
                    str(raw["instruction_address"])
                ),
                "block_start": normalize_address(str(raw["block_start"])),
                "opcode": str(raw["opcode"]),
                "output": raw.get("output"),
                "inputs": raw.get("inputs", []),
            }
        )
    pcode_rows.sort(key=lambda row: (row["function_uid"], row["pcode_seq"]))

    reference_rows: list[dict[str, Any]] = []
    for raw in analysis_references:
        function_address = normalize_address(str(raw.get("function_address", "")))
        function_uid_value = address_to_uid.get(function_address)
        if function_uid_value is None:
            continue
        target_address = normalize_address(str(raw["target_address"]))
        target_function_raw = raw.get("target_function_address")
        target_function_address = (
            normalize_address(str(target_function_raw))
            if isinstance(target_function_raw, str) and target_function_raw
            else None
        )
        reference_rows.append(
            {
                "function_uid": function_uid_value,
                "site_address": normalize_address(str(raw["site_address"])),
                "reference_type": str(raw["reference_type"]),
                "target_address": target_address,
                "target_function_uid": address_to_uid.get(target_function_address),
            }
        )
    reference_rows.sort(
        key=lambda row: (
            row["function_uid"],
            int(row["site_address"], 16),
            row["reference_type"],
            row["target_address"],
        )
    )

    output = require_new_directory(args.output_dir)
    write_jsonl(output / "functions.jsonl", function_rows)
    write_jsonl(output / "callsites.jsonl", callsite_rows)
    write_jsonl(output / "blocks.jsonl", block_rows)
    write_jsonl(output / "pcode.jsonl", pcode_rows)
    write_jsonl(output / "references.jsonl", reference_rows)
    functions_sha = sha256_file(output / "functions.jsonl")
    callsites_sha = sha256_file(output / "callsites.jsonl")
    blocks_sha = sha256_file(output / "blocks.jsonl")
    pcode_sha = sha256_file(output / "pcode.jsonl")
    references_sha = sha256_file(output / "references.jsonl")
    package = {
        "package_version": "tier-b-filter-static-package-v2",
        "package_id": args.package_id,
        "created_at_utc": utc_now(),
        "artifact_path": str(artifact),
        "artifact_sha256": artifact_sha,
        "analysis_artifact_md5": analysis_artifact_md5,
        "analysis_image_base": normalize_address(str(metadata["image_base"])),
        "corpus_root": str(corpus_root),
        "corpus_sha256": corpus_digest(corpus_root, sources),
        "analysis_export_sha256": sha256_file(analysis_export),
        "analysis_tool": str(metadata.get("analysis_tool", "Ghidra")),
        "analysis_version": str(metadata.get("analysis_version", "unknown")),
        "function_count": len(function_rows),
        "callsite_count": len(callsite_rows),
        "unresolved_indirect_callsite_count": sum(
            row["call_kind"] == "indirect"
            and row["resolution_status"] != "resolved_reference"
            for row in callsite_rows
        ),
        "block_count": len(block_rows),
        "pcode_operation_count": len(pcode_rows),
        "reference_count": len(reference_rows),
        "total_source_chars": total_chars,
        "functions_index": "functions.jsonl",
        "callsites_index": "callsites.jsonl",
        "blocks_index": "blocks.jsonl",
        "pcode_index": "pcode.jsonl",
        "references_index": "references.jsonl",
        "functions_sha256": functions_sha,
        "callsites_sha256": callsites_sha,
        "blocks_sha256": blocks_sha,
        "pcode_sha256": pcode_sha,
        "references_sha256": references_sha,
    }
    write_json(output / "package.json", package)
    print(json.dumps(package, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, AssertionError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)
