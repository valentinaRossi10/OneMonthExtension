#!/usr/bin/env python3
"""Prepare an immutable recall-first Tier B run without provider calls."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from filter_common import (
    AnalysisPackage,
    api_tools,
    canonical_json,
    load_json,
    projection_for_case,
    read_jsonl,
    require_new_directory,
    sha256_file,
    sha256_text,
    utc_now,
    validate_strict_json_schema,
    write_json,
    write_jsonl,
)
from filter_v4 import (
    V3_COMPARISON_SCOPE_VERSION,
    V3_DEFENSIVE_RETRY_POLICY_VERSION,
    V3_DEFENSIVE_RETRY_SCOPE_VERSION,
    V3_OUTPUT_CAP_POLICY_VERSION,
    V3_OUTPUT_CAP_RETRY_SCOPE_VERSION,
    V3_RETRY_SCOPE_VERSION,
    V4_COMPARISON_SCOPE_VERSION,
    V4_CVE_2021_42374_POLICY_VERSION,
    V4_CVE_2021_42374_SCOPE_VERSION,
    load_policy_for_protocol,
    load_v3_reviewed_scope,
    load_v4_reviewed_scope,
    prompt_template_path,
    reviewed_scope_path_for_protocol,
    result_schema_path,
)
from runner_context import projection_context_reserve_chars


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--queue-dir", required=True, type=Path)
    value.add_argument("--results-root", required=True, type=Path)
    value.add_argument("--run-label", required=True)
    value.add_argument("--input-price-per-million", required=True, type=float)
    value.add_argument("--output-price-per-million", required=True, type=float)
    value.add_argument(
        "--reasoning-effort",
        choices=("low", "medium", "high"),
        help="Override only the model reasoning effort frozen into this run.",
    )
    value.add_argument(
        "--case-id",
        action="append",
        default=[],
        help=(
            "Select one exact case ID from the frozen queue. Repeat for a "
            "reviewed subset; omit to prepare the complete queue."
        ),
    )
    value.add_argument("--experiment-note", action="append", default=[])
    value.add_argument(
        "--protocol-version",
        choices=("v2", "v3", "v4"),
        default="v2",
        help="Select the additive protocol version; v2 remains the default.",
    )
    value.add_argument(
        "--reviewed-terminal-response-retry-scope",
        action="store_true",
        help=(
            "For protocol v3 only, select the separately reviewed exact "
            "two-case terminal-response infrastructure retry scope."
        ),
    )
    value.add_argument(
        "--reviewed-output-cap-retry-scope",
        action="store_true",
        help=(
            "For protocol v3 only, select the exact two-case retry scope "
            "whose prior terminals reached max_output_tokens."
        ),
    )
    value.add_argument(
        "--reviewed-defensive-framing-retry-scope",
        action="store_true",
        help=(
            "For protocol v3 only, select the exact one-case retry scope "
            "whose prior terminal was a cyber_policy provider failure."
        ),
    )
    value.add_argument(
        "--reviewed-v4-cve-2021-42374-scope",
        action="store_true",
        help=(
            "For protocol v4 only, select the exact reviewed one-case "
            "CVE-2021-42374 contradiction-evidence comparison scope."
        ),
    )
    return value


def run_id(label: str, policy: dict[str, Any]) -> str:
    safe = re.sub(r"[^a-z0-9-]+", "-", label.lower()).strip("-")
    if not safe:
        raise ValueError("run-label must contain a letter or digit")
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dt%H%M%Sz")
    model = policy["model_settings"]["model"]
    reasoning = policy["model_settings"]["reasoning_effort"]
    return f"{timestamp}__{model}__{reasoning}__{safe}"


def build_prompt(
    case: dict[str, Any],
    package: AnalysisPackage,
    policy: dict[str, Any],
    protocol_version: str,
) -> str:
    template = prompt_template_path(protocol_version).read_text(encoding="utf-8")
    hypotheses = [
        {
            "model_verdict": item.get("model_verdict"),
            "evidence_lines": item.get("evidence_lines", []),
            "summary": item.get("summary", ""),
        }
        for item in case["evidence_items"]
    ]
    replacements = {
        "{{FUNCTION_UID}}": case["function_uid"],
        "{{TARGET_CLASS}}": case["target_class"],
        "{{ARTIFACT_SHA256}}": case["artifact_sha256"],
        "{{PACKAGE_ID}}": package.metadata["package_id"],
        "{{ENTRY_ROOTS}}": json.dumps(case["entry_roots"], sort_keys=True),
        "{{TIER_A_HYPOTHESES}}": json.dumps(hypotheses, sort_keys=True),
        "{{BASE_TOOL_CALLS}}": str(policy["limits"]["base_tool_calls"]),
        "{{EXTENSION_TOOL_CALLS}}": str(
            policy["limits"]["extension_tool_calls"]
        ),
    }
    for marker, replacement in replacements.items():
        template = template.replace(marker, replacement)
    if "{{" in template or "}}" in template:
        raise ValueError("Prompt template contains an unresolved marker")
    return template


def validate_retry_scope_source(
    scope: dict[str, Any], results_root: Path
) -> None:
    source_run_dir = results_root / scope["source_run_id"]
    source_manifest_path = source_run_dir / "manifest.jsonl"
    source_results_path = source_run_dir / "results.jsonl"
    if not source_manifest_path.is_file() or not source_results_path.is_file():
        raise ValueError("V3 retry source run is unavailable")
    if sha256_file(source_manifest_path) != scope["source_manifest_sha256"]:
        raise ValueError("V3 retry source manifest hash differs")
    if sha256_file(source_results_path) != scope["source_results_sha256"]:
        raise ValueError("V3 retry source results hash differs")
    source_manifest = {
        task["case_id"]: task for task in read_jsonl(source_manifest_path)
    }
    latest_terminals: dict[str, dict[str, Any]] = {}
    for row in read_jsonl(source_results_path):
        if row.get("terminal"):
            latest_terminals[row["case_id"]] = row
    for scoped in scope["cases"]:
        case_id = scoped["case_id"]
        source_task = source_manifest.get(case_id)
        if source_task is None:
            raise ValueError(f"V3 retry source task is missing: {case_id}")
        if (
            source_task["artifact_sha256"],
            source_task["function_uid"],
            source_task["target_class"],
        ) != (
            scoped["artifact_sha256"],
            scoped["function_uid"],
            scoped["target_class"],
        ):
            raise ValueError(f"V3 retry source identity differs: {case_id}")
        terminal = latest_terminals.get(case_id)
        if terminal is None:
            raise ValueError(f"V3 retry source terminal is missing: {case_id}")
        if terminal.get("cache_key") != source_task.get("cache_key"):
            raise ValueError(f"V3 retry source cache key differs: {case_id}")
        if terminal.get("status") != scope["required_prior_terminal_status"]:
            raise ValueError(
                f"V3 retry source status differs: {case_id}"
            )
        parsed = terminal.get("parsed_result") or {}
        required_execution = scope.get("required_prior_execution_status")
        if required_execution is None:
            required_execution = "infrastructure_error"
        if parsed.get("execution_status") != required_execution:
            raise ValueError(
                f"V3 retry source execution status differs: {case_id}"
            )
        required_error = scope.get("required_prior_error_contains")
        if required_error is not None and required_error not in (
            terminal.get("error") or ""
        ):
            raise ValueError(
                f"V3 retry source terminal error differs: {case_id}"
            )
        required_outcome = scope.get("required_prior_stream_outcome")
        if (
            required_outcome is not None
            and terminal.get("stream_outcome") != required_outcome
        ):
            raise ValueError(
                f"V3 retry source stream outcome differs: {case_id}"
            )
        required_reason = scope.get("required_prior_incomplete_reason")
        if (
            required_reason is not None
            and terminal.get("provider_incomplete_reason") != required_reason
        ):
            raise ValueError(
                f"V3 retry source incomplete reason differs: {case_id}"
            )


def main() -> int:
    args = parser().parse_args()
    if args.input_price_per_million <= 0 or args.output_price_per_million <= 0:
        raise ValueError("Prices must be positive")
    retry_scope_flags = (
        int(args.reviewed_terminal_response_retry_scope)
        + int(args.reviewed_output_cap_retry_scope)
        + int(args.reviewed_defensive_framing_retry_scope)
    )
    if retry_scope_flags > 1:
        raise ValueError("Select only one reviewed retry scope")
    if retry_scope_flags and args.protocol_version != "v3":
        raise ValueError("The reviewed retry scope requires protocol v3")
    if (
        args.reviewed_v4_cve_2021_42374_scope
        and args.protocol_version != "v4"
    ):
        raise ValueError(
            "The reviewed CVE-2021-42374 v4 scope requires protocol v4"
        )
    selected_policy_version: str | None = None
    if args.reviewed_v4_cve_2021_42374_scope:
        selected_policy_version = V4_CVE_2021_42374_POLICY_VERSION
    elif args.reviewed_defensive_framing_retry_scope:
        selected_policy_version = V3_DEFENSIVE_RETRY_POLICY_VERSION
    elif args.reviewed_output_cap_retry_scope:
        selected_policy_version = V3_OUTPUT_CAP_POLICY_VERSION
    policy = load_policy_for_protocol(
        args.protocol_version, selected_policy_version
    )
    if args.reasoning_effort is not None:
        policy["model_settings"]["reasoning_effort"] = args.reasoning_effort
    queue_dir = args.queue_dir.resolve()
    queue_path = queue_dir / "queue.jsonl"
    summary_path = queue_dir / "ingestion-summary.json"
    quarantine_path = queue_dir / "quarantine.jsonl"
    if not queue_path.is_file() or not summary_path.is_file():
        raise ValueError("queue-dir lacks queue.jsonl or ingestion-summary.json")
    source_queue = read_jsonl(queue_path)
    if not source_queue:
        raise ValueError("Queue contains no valid cases")
    ingestion_summary = load_json(summary_path)
    quarantine = read_jsonl(quarantine_path) if quarantine_path.is_file() else []
    if ingestion_summary["output_case_count"] != len(source_queue):
        raise ValueError("Queue count differs from ingestion summary")
    if ingestion_summary["quarantine_count"] != len(quarantine):
        raise ValueError("Quarantine count differs from ingestion summary")
    source_by_case_id = {case["case_id"]: case for case in source_queue}
    if len(source_by_case_id) != len(source_queue):
        raise ValueError("Source queue contains duplicate case IDs")
    if len(args.case_id) != len(set(args.case_id)):
        raise ValueError("The reviewed case selection contains duplicate IDs")
    reviewed_scope: dict[str, Any] | None = None
    active_reviewed_scope_path: Path | None = None
    results_root = args.results_root.resolve()
    if args.protocol_version == "v3":
        if args.reviewed_terminal_response_retry_scope:
            scope_version = V3_RETRY_SCOPE_VERSION
        elif args.reviewed_output_cap_retry_scope:
            scope_version = V3_OUTPUT_CAP_RETRY_SCOPE_VERSION
        elif args.reviewed_defensive_framing_retry_scope:
            scope_version = V3_DEFENSIVE_RETRY_SCOPE_VERSION
        else:
            scope_version = V3_COMPARISON_SCOPE_VERSION
        reviewed_scope = load_v3_reviewed_scope(scope_version)
        active_reviewed_scope_path = reviewed_scope_path_for_protocol(
            "v3", scope_version
        )
        reviewed_ids = {
            case["case_id"] for case in reviewed_scope["cases"]
        }
        if set(args.case_id) != reviewed_ids or len(args.case_id) != len(
            reviewed_ids
        ):
            if scope_version == V3_COMPARISON_SCOPE_VERSION:
                raise ValueError(
                    "V3 preparation is restricted to the exact reviewed "
                    "six-case comparison scope"
                )
            raise ValueError(
                "V3 retry preparation is restricted to its exact reviewed "
                "case set"
            )
        if retry_scope_flags:
            validate_retry_scope_source(reviewed_scope, results_root)
    elif args.protocol_version == "v4":
        scope_version = (
            V4_CVE_2021_42374_SCOPE_VERSION
            if args.reviewed_v4_cve_2021_42374_scope
            else V4_COMPARISON_SCOPE_VERSION
        )
        reviewed_scope = load_v4_reviewed_scope(scope_version)
        active_reviewed_scope_path = reviewed_scope_path_for_protocol(
            "v4", scope_version
        )
        reviewed_ids = {
            case["case_id"] for case in reviewed_scope["cases"]
        }
        if set(args.case_id) != reviewed_ids or len(args.case_id) != len(
            reviewed_ids
        ):
            if scope_version == V4_COMPARISON_SCOPE_VERSION:
                raise ValueError(
                    "V4 preparation is restricted to the exact reviewed "
                    "six-case comparison scope"
                )
            raise ValueError(
                "V4 targeted preparation is restricted to its exact "
                "reviewed one-case scope"
            )
    if args.case_id:
        missing_case_ids = sorted(set(args.case_id) - set(source_by_case_id))
        if missing_case_ids:
            raise ValueError(
                f"Reviewed case selection is absent from the queue: {missing_case_ids}"
            )
        queue = [source_by_case_id[case_id] for case_id in args.case_id]
    else:
        queue = source_queue
    if reviewed_scope is not None:
        scope_by_id = {
            case["case_id"]: case for case in reviewed_scope["cases"]
        }
        for case in queue:
            scoped = scope_by_id[case["case_id"]]
            actual_identity = (
                case["artifact_sha256"],
                case["function_uid"],
                case["target_class"],
            )
            scoped_identity = (
                scoped["artifact_sha256"],
                scoped["function_uid"],
                scoped["target_class"],
            )
            if actual_identity != scoped_identity:
                raise ValueError(
                    f"{args.protocol_version.upper()} reviewed identity tuple "
                    f"differs for {case['case_id']}"
                )

    schema_path = result_schema_path(args.protocol_version)
    result_schema = load_json(schema_path)
    validate_strict_json_schema(result_schema)
    if (
        result_schema["properties"]["schema_version"]["const"]
        != policy["schema_version"]
    ):
        raise ValueError("Result schema version differs from the active policy")
    result_schema_sha = sha256_file(schema_path)
    api_schema = {
        key: value
        for key, value in result_schema.items()
        if key not in {"$schema", "title"}
    }
    validate_strict_json_schema(api_schema)
    fixed_request_text = canonical_json(
        {"tools": api_tools(policy), "response_schema": api_schema}
    )
    current_request_reserve_chars = 0
    replay_context_reserve_chars = 0
    if policy.get("cost_projection", {}).get(
        "include_reinforced_runner_context"
    ):
        (
            current_request_reserve_chars,
            replay_context_reserve_chars,
        ) = projection_context_reserve_chars()

    results_root.mkdir(parents=True, exist_ok=True)
    identifier = run_id(args.run_label, policy)
    run_dir = require_new_directory(results_root / identifier)
    prompts_dir = run_dir / "prompts"
    prompts_dir.mkdir()

    package_cache: dict[Path, AnalysisPackage] = {}
    manifest: list[dict[str, Any]] = []
    case_ids: set[str] = set()
    cache_keys: set[str] = set()
    for case in queue:
        case_id = case["case_id"]
        if case_id in case_ids:
            raise ValueError(f"Duplicate case ID in queue: {case_id}")
        case_ids.add(case_id)
        package_path = Path(case["package_path"])
        if not package_path.is_absolute():
            package_path = (queue_dir / package_path).resolve()
        package = package_cache.get(package_path)
        if package is None:
            package = AnalysisPackage(package_path, policy)
            package.verify_frozen_inputs()
            package_cache[package_path] = package
        if package.metadata["artifact_sha256"] != case["artifact_sha256"]:
            raise ValueError(f"Artifact binding mismatch: {case_id}")
        if case["function_uid"] not in package.functions:
            raise ValueError(f"Candidate UID is absent from its package: {case_id}")
        missing_roots = sorted(set(case["entry_roots"]) - set(package.functions))
        if missing_roots:
            raise ValueError(f"Entry roots absent from package for {case_id}: {missing_roots}")

        prompt = build_prompt(case, package, policy, args.protocol_version)
        prompt_path = prompts_dir / f"{case_id}.txt"
        prompt_path.write_text(prompt, encoding="utf-8")
        base_projection = projection_for_case(
            prompt,
            policy,
            args.input_price_per_million,
            args.output_price_per_million,
            fixed_request_text,
            include_extension=False,
            current_request_reserve_chars=current_request_reserve_chars,
            replay_context_reserve_chars=replay_context_reserve_chars,
        )
        extension_projection = projection_for_case(
            prompt,
            policy,
            args.input_price_per_million,
            args.output_price_per_million,
            fixed_request_text,
            include_extension=True,
            current_request_reserve_chars=current_request_reserve_chars,
            replay_context_reserve_chars=replay_context_reserve_chars,
        )
        if (
            extension_projection["projected_max_cost_usd"]
            > policy["limits"]["max_budget_usd_per_case"]
        ):
            raise ValueError(
                f"Adaptive projection exceeds per-case ceiling: {case_id}"
            )
        package_sha = sha256_file(package_path / "package.json")
        cache_key = sha256_text(
            canonical_json(
                {
                    "case_id": case_id,
                    "artifact_sha256": case["artifact_sha256"],
                    "function_uid": case["function_uid"],
                    "target_class": case["target_class"],
                    "package_sha256": package_sha,
                    "prompt_sha256": sha256_text(prompt),
                    "result_schema_sha256": result_schema_sha,
                    "policy": policy,
                }
            )
        )
        if cache_key in cache_keys:
            raise ValueError("Two cases have the same cache key")
        cache_keys.add(cache_key)
        manifest.append(
            {
                "case_id": case_id,
                "artifact_sha256": case["artifact_sha256"],
                "function_uid": case["function_uid"],
                "target_class": case["target_class"],
                "entry_roots": case["entry_roots"],
                "source_row_count": case["source_row_count"],
                "queue_path": str(queue_path),
                "queue_sha256": sha256_file(queue_path),
                "package_path": str(package_path),
                "package_id": package.metadata["package_id"],
                "package_manifest_sha256": package_sha,
                "package_functions_sha256": package.metadata["functions_sha256"],
                "package_callsites_sha256": package.metadata["callsites_sha256"],
                "package_function_count": package.metadata["function_count"],
                "package_callsite_count": package.metadata["callsite_count"],
                "package_unresolved_indirect_count": package.metadata[
                    "unresolved_indirect_callsite_count"
                ],
                "prompt_path": str(prompt_path.relative_to(run_dir)),
                "prompt_sha256": sha256_text(prompt),
                "cache_key": cache_key,
                "model": policy["model_settings"]["model"],
                "reasoning_effort": policy["model_settings"]["reasoning_effort"],
                "experiment_version": policy["experiment_version"],
                "policy_version": policy["policy_version"],
                "prompt_version": policy["prompt_version"],
                "schema_version": policy["schema_version"],
                "result_schema_sha256": result_schema_sha,
                "protocol_version": args.protocol_version,
                "decision_priority": policy.get("decision_priority"),
                "reviewed_scope_version": (
                    reviewed_scope["scope_version"] if reviewed_scope else None
                ),
                "reviewed_scope_sha256": (
                    sha256_file(active_reviewed_scope_path)
                    if active_reviewed_scope_path
                    else None
                ),
                "reviewed_scope_kind": (
                    reviewed_scope.get("scope_kind", "comparison")
                    if reviewed_scope
                    else None
                ),
                "comparison_source_run_id": (
                    reviewed_scope["source_run_id"] if reviewed_scope else None
                ),
                "comparison_source_manifest_sha256": (
                    reviewed_scope["source_manifest_sha256"]
                    if reviewed_scope
                    else None
                ),
                "package_version": policy["package_version"],
                "queue_version": policy["queue_version"],
                "transport_mode": policy["transport"]["mode"],
                "sdk_max_retries": policy["transport"]["sdk_max_retries"],
                "base_model_calls": policy["limits"]["base_model_calls"],
                "base_tool_calls": policy["limits"]["base_tool_calls"],
                "extension_model_calls": policy["limits"]["extension_model_calls"],
                "extension_tool_calls": policy["limits"]["extension_tool_calls"],
                "max_output_tokens_per_call": policy["limits"][
                    "max_output_tokens_per_call"
                ],
                "per_case_ceiling_usd": policy["limits"][
                    "max_budget_usd_per_case"
                ],
                "input_price_per_million": args.input_price_per_million,
                "output_price_per_million": args.output_price_per_million,
                "base_projection": base_projection,
                "adaptive_projection": extension_projection,
            }
        )

    manifest.sort(key=lambda row: row["case_id"])
    manifest_path = run_dir / "manifest.jsonl"
    write_jsonl(manifest_path, manifest)
    manifest_sha = sha256_file(manifest_path)
    aggregate_projection = sum(
        task["adaptive_projection"]["projected_max_cost_usd"] for task in manifest
    )
    aggregate_ceiling = sum(task["per_case_ceiling_usd"] for task in manifest)
    run_summary = {
        "summary_version": "tier-b-filter-manifest-summary-v1",
        "run_id": identifier,
        "case_count": len(manifest),
        "source_queue_case_count": len(source_queue),
        "selected_case_ids": sorted(case["case_id"] for case in queue),
        "quarantine_count": len(quarantine),
        "package_count": len(package_cache),
        "base_projected_max_cost_usd": sum(
            task["base_projection"]["projected_max_cost_usd"] for task in manifest
        ),
        "adaptive_projected_max_cost_usd": aggregate_projection,
        "aggregate_hard_ceiling_usd": aggregate_ceiling,
        "within_aggregate_ceiling": aggregate_projection <= aggregate_ceiling,
        "manifest_sha256": manifest_sha,
        "result_schema_sha256": result_schema_sha,
        "queue_sha256": sha256_file(queue_path),
        "ingestion_summary_sha256": sha256_file(summary_path),
        "provider_api_calls_made_during_preparation": 0,
        "reviewed_scope_version": (
            reviewed_scope["scope_version"] if reviewed_scope else None
        ),
        "reviewed_scope_sha256": (
            sha256_file(active_reviewed_scope_path)
            if active_reviewed_scope_path
            else None
        ),
        "reviewed_scope_kind": (
            reviewed_scope.get("scope_kind", "comparison")
            if reviewed_scope
            else None
        ),
        "comparison_source_run_id": (
            reviewed_scope["source_run_id"] if reviewed_scope else None
        ),
        "comparison_source_manifest_sha256": (
            reviewed_scope["source_manifest_sha256"] if reviewed_scope else None
        ),
    }
    if not run_summary["within_aggregate_ceiling"]:
        raise ValueError("Aggregate projection exceeds aggregate hard ceiling")
    write_json(run_dir / "manifest-summary.json", run_summary)
    metadata = {
        "metadata_version": "tier-b-filter-run-v1",
        "run_id": identifier,
        "created_at_utc": utc_now(),
        "status": "prepared_not_executed",
        "manifest_sha256": manifest_sha,
        "queue_dir": str(queue_dir),
        "model": policy["model_settings"]["model"],
        "reasoning_effort": policy["model_settings"]["reasoning_effort"],
        "source_queue_case_count": len(source_queue),
        "selected_case_ids": sorted(case["case_id"] for case in queue),
        "experiment_version": policy["experiment_version"],
        "policy_version": policy["policy_version"],
        "prompt_version": policy["prompt_version"],
        "schema_version": policy["schema_version"],
        "result_schema_sha256": result_schema_sha,
        "protocol_version": args.protocol_version,
        "decision_priority": policy.get("decision_priority"),
        "reviewed_scope_version": (
            reviewed_scope["scope_version"] if reviewed_scope else None
        ),
        "reviewed_scope_sha256": (
            sha256_file(active_reviewed_scope_path)
            if active_reviewed_scope_path
            else None
        ),
        "reviewed_scope_kind": (
            reviewed_scope.get("scope_kind", "comparison")
            if reviewed_scope
            else None
        ),
        "comparison_source_run_id": (
            reviewed_scope["source_run_id"] if reviewed_scope else None
        ),
        "comparison_source_manifest_sha256": (
            reviewed_scope["source_manifest_sha256"] if reviewed_scope else None
        ),
        "package_version": policy["package_version"],
        "queue_version": policy["queue_version"],
        "input_price_per_million": args.input_price_per_million,
        "output_price_per_million": args.output_price_per_million,
        "experiment_notes": args.experiment_note,
        "provider_api_calls_made": 0,
        "accounted_spend_usd": 0.0,
    }
    write_json(run_dir / "run-metadata.json", metadata)
    (run_dir / "results.jsonl").touch()
    readme = f"""# Recall-first Tier B prepared run

Run ID: `{identifier}`

Status: prepared; no provider calls made.

| Item | Value |
|---|---:|
| Valid exact cases | {len(manifest)} |
| Quarantined ingestion rows | {len(quarantine)} |
| Packages | {len(package_cache)} |
| Base projected maximum | ${run_summary['base_projected_max_cost_usd']:.6f} |
| Adaptive projected maximum | ${aggregate_projection:.6f} |
| Aggregate hard ceiling | ${aggregate_ceiling:.6f} |
| Manifest SHA-256 | `{manifest_sha}` |

Execution requires explicit approval naming this run ID, manifest SHA-256, and
an aggregate budget no smaller than the adaptive projection and no greater
than the frozen aggregate ceiling.
"""
    (run_dir / "README.md").write_text(readme, encoding="utf-8")
    print(json.dumps({"run_dir": str(run_dir), **run_summary}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, AssertionError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)
