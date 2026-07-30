#!/usr/bin/env python3
"""Dry-run or execute an explicitly approved recall-first Tier B manifest."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

from filter_common import (
    AnalysisPackage,
    api_tools,
    canonical_json,
    estimate_cost_usd,
    load_json,
    read_jsonl,
    sha256_file,
    sha256_text,
    utc_now,
    validate_strict_json_schema,
    write_json,
)
from filter_v4 import (
    V3_RETRY_SCOPE_VERSION,
    V4_SCHEMA_VERSION,
    fallback_result_for_task,
    load_policy_for_protocol,
    load_v3_reviewed_scope,
    load_v4_reviewed_scope,
    protocol_version_for_schema,
    reviewed_scope_path_for_protocol,
    result_schema_path,
    validate_and_normalize_model_result_for_task,
)
from stream_observability import (
    LEDGER_SCHEMA_VERSION,
    accounted_spend,
    observe_response_stream,
    orphaned_provider_calls,
    provider_generation_call_count,
    provider_retrieval_call_count,
    recover_response,
    should_attempt_recovery,
)
from runner_context import (
    DEFENSIVE_CONTEXT_REMINDER,
    FINAL_SYNTHESIS_INSTRUCTION,
    REINFORCED_LIFETIME_CONTEXT_REMINDER,
    V2_INTERIM_CONTINUATION,
    V2_NO_TEXT_CONTINUATION,
    V3_INTERIM_CONTINUATION,
    V3_NO_TEXT_CONTINUATION,
)


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--run-dir", required=True, type=Path)
    value.add_argument("--budget-usd", required=True, type=float)
    value.add_argument("--approved-manifest-sha256")
    value.add_argument("--api-key-env", default="OPENAI_API_KEY")
    value.add_argument(
        "--retry-reviewed-infrastructure-case",
        action="append",
        default=[],
        metavar="CASE_ID",
    )
    value.add_argument("--execute", action="store_true")
    return value


def append_record(path: Path, record: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(canonical_json(record) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def response_items(response: Any) -> list[dict[str, Any]]:
    def clean(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                key: clean(item)
                for key, item in value.items()
                if key != "parsed_arguments"
            }
        if isinstance(value, list):
            return [clean(item) for item in value]
        return value

    result = []
    for item in getattr(response, "output", []) or []:
        if hasattr(item, "model_dump"):
            excluded = set(getattr(item, "__api_exclude__", set()))
            dumped = item.model_dump(
                mode="json",
                exclude_none=True,
                exclude=excluded | {"parsed_arguments"},
            )
            result.append(clean(dumped))
        elif isinstance(item, dict):
            result.append(clean(item))
        else:
            raise ValueError("Provider returned an unserializable output item")
    return result


def response_refusal(response: Any) -> str | None:
    for item in getattr(response, "output", []) or []:
        for content in getattr(item, "content", []) or []:
            if getattr(content, "type", None) == "refusal":
                return getattr(content, "refusal", None) or "provider refusal"
    return None


def usage(response: Any) -> dict[str, int | None]:
    value = getattr(response, "usage", None)
    return {
        "input_tokens": getattr(value, "input_tokens", None),
        "output_tokens": getattr(value, "output_tokens", None),
        "total_tokens": getattr(value, "total_tokens", None),
    }


def usage_cost(
    value: dict[str, Any], input_price: float, output_price: float
) -> float | None:
    if not isinstance(value.get("input_tokens"), int):
        return None
    if not isinstance(value.get("output_tokens"), int):
        return None
    return estimate_cost_usd(
        value["input_tokens"], value["output_tokens"], input_price, output_price
    )


def tool_call_satisfies_coverage(
    tool_name: str | None,
    tool_result: dict[str, Any],
) -> bool:
    """Count only completed analysis, not a failed or unavailable invocation."""
    if not tool_name or "error" in tool_result:
        return False
    if tool_name == "query_angr":
        return tool_result.get("backend_status") != "unavailable"
    return True


def missing_required_tool_names(
    required_tool_names: list[str],
    successful_tool_names: set[str],
) -> list[str]:
    """Preserve the reviewed order when reporting or forcing coverage."""
    return [
        name
        for name in required_tool_names
        if name not in successful_tool_names
    ]


def required_tool_choice(
    missing_tool_names: list[str],
    *,
    remaining_tool_slots: int,
    coverage_gate_active: bool,
) -> str | None:
    """Force coverage at the latest safe point or after a blocked terminal."""
    if not missing_tool_names:
        return None
    if coverage_gate_active or len(missing_tool_names) >= remaining_tool_slots:
        return missing_tool_names[0]
    return None


def should_grant_required_tool_retry_extension(
    tool_name: str | None,
    tool_result: dict[str, Any],
    *,
    required_tool_names: list[str],
    extension_policy: str | None,
    extension_granted: bool,
) -> bool:
    """Grant the frozen adaptive stage for an oversized required result."""
    return (
        not extension_granted
        and extension_policy == "tool-result-too-large-v1"
        and tool_name in required_tool_names
        and tool_result.get("error") == "tool_result_too_large"
    )


def final_text(response: Any) -> str:
    return (getattr(response, "output_text", "") or "").strip()


def user_text_message(text: str) -> dict[str, Any]:
    return {
        "role": "user",
        "content": [{"type": "input_text", "text": text}],
    }


def append_tool_result_context(
    conversation: list[dict[str, Any]],
    call_id: str,
    tool_result: dict[str, Any],
    *,
    defensive_reminder: str = DEFENSIVE_CONTEXT_REMINDER,
) -> None:
    conversation.append(
        {
            "type": "function_call_output",
            "call_id": call_id,
            "output": json.dumps(tool_result, sort_keys=True),
        }
    )
    conversation.append(user_text_message(defensive_reminder))


def request_input_for_call(
    conversation: list[dict[str, Any]],
    *,
    can_call_tools: bool,
    defensive_reminder: str = DEFENSIVE_CONTEXT_REMINDER,
    repeat_defensive_reminder: bool = False,
) -> list[dict[str, Any]]:
    request_input = list(conversation)
    if not can_call_tools:
        request_input.append(
            user_text_message(
                defensive_reminder
                + " "
                + FINAL_SYNTHESIS_INSTRUCTION
            )
        )
    elif repeat_defensive_reminder:
        reminder_message = user_text_message(defensive_reminder)
        if not request_input or request_input[-1] != reminder_message:
            request_input.append(reminder_message)
    return request_input


def information_fact_keys(
    tool_name: str | None,
    tool_result: dict[str, Any],
) -> set[str]:
    """Return stable evidence facts; empty/no-hit results are not progress."""
    if "error" in tool_result:
        return set()
    facts: list[Any] = []
    if tool_name == "get_function":
        function_uid = tool_result.get("function_uid")
        for line in str(tool_result.get("code") or "").splitlines():
            if line.strip():
                facts.append(("code", function_uid, line.strip()))
    elif tool_name == "search_code":
        facts.extend(
            ("search_hit", hit)
            for hit in tool_result.get("hits", [])
            if isinstance(hit, dict)
        )
    elif tool_name == "get_callers":
        facts.extend(
            ("caller", caller)
            for caller in tool_result.get("callers", [])
        )
    elif tool_name == "get_callsites":
        facts.extend(
            ("callsite", callsite)
            for callsite in tool_result.get("callsites", [])
            if isinstance(callsite, dict)
        )
    elif tool_name == "get_function_identity":
        identity = {
            key: value
            for key, value in tool_result.items()
            if key not in {"truncated"}
            and value is not None
            and value != ""
            and value != []
        }
        if identity:
            facts.append(("identity", identity))
    else:
        material = {
            key: value
            for key, value in tool_result.items()
            if key not in {"truncated"}
            and value is not None
            and value != ""
            and value != []
        }
        if material:
            facts.append(("tool_result", tool_name, material))
    return {sha256_text(canonical_json(fact)) for fact in facts}


def append_interim_fallback(
    result_path: Path,
    task: dict[str, Any],
    latest_valid_interim: dict[str, Any] | None,
    *,
    failed_call_index: int,
    failure_status: str,
    failure_reason: str,
) -> bool:
    if latest_valid_interim is None:
        return False
    append_record(
        result_path,
        {
            "recorded_at_utc": utc_now(),
            "case_id": task["case_id"],
            "cache_key": task["cache_key"],
            "model_call_index": failed_call_index,
            "provider_call_made": False,
            "terminal": True,
            "status": "interim_result_fallback",
            "error": None,
            "fallback_after_status": failure_status,
            "fallback_after_reason": failure_reason,
            "interim_model_call_index": latest_valid_interim[
                "model_call_index"
            ],
            "raw_response_text": latest_valid_interim["raw_response_text"],
            "parsed_result": latest_valid_interim["parsed_result"],
            "validator_adjustments": latest_valid_interim.get(
                "validator_adjustments", []
            ),
            "progress_events": latest_valid_interim["progress_events"],
        },
    )
    return True


def append_interim_result(
    result_path: Path,
    base: dict[str, Any],
    *,
    model_call_index: int,
    raw_response_text: str,
    parsed_result: dict[str, Any],
    extension_granted: bool,
    progress_events: list[str],
    validator_adjustments: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Persist a valid unresolved response before asking for continuation."""
    validator_adjustments = list(validator_adjustments or [])
    snapshot = {
        "model_call_index": model_call_index,
        "raw_response_text": raw_response_text,
        "parsed_result": parsed_result,
        "validator_adjustments": validator_adjustments,
        "progress_events": list(progress_events),
    }
    append_record(
        result_path,
        {
            **base,
            "terminal": False,
            "status": "interim_result",
            "error": None,
            "raw_response_text": raw_response_text,
            "parsed_result": parsed_result,
            "validator_adjustments": validator_adjustments,
            "extension_granted": extension_granted,
            "progress_events": list(progress_events),
        },
    )
    return snapshot


def validate_run(
    run_dir: Path,
    tasks: list[dict[str, Any]],
    metadata: dict[str, Any],
    summary: dict[str, Any],
    policy: dict[str, Any],
    approved_hash: str | None,
    budget: float,
) -> None:
    manifest_path = run_dir / "manifest.jsonl"
    actual_hash = sha256_file(manifest_path)
    if approved_hash is not None and approved_hash != actual_hash:
        raise ValueError("Manifest differs from the explicitly approved SHA-256")
    if metadata["manifest_sha256"] != actual_hash:
        raise ValueError("Manifest differs from run metadata")
    if summary["manifest_sha256"] != actual_hash:
        raise ValueError("Manifest differs from its summary")
    if metadata["run_id"] != run_dir.name or summary["run_id"] != run_dir.name:
        raise ValueError("Run ID differs from the run directory")
    if metadata["policy_version"] != policy["policy_version"]:
        raise ValueError("Run policy differs from the active MVP policy")
    if not 0 < budget <= summary["aggregate_hard_ceiling_usd"]:
        raise ValueError("Budget is outside the frozen aggregate ceiling")
    if summary["adaptive_projected_max_cost_usd"] > budget:
        raise ValueError("Adaptive projection exceeds the approved budget")
    if len(tasks) != summary["case_count"]:
        raise ValueError("Manifest case count mismatch")
    case_ids = [task["case_id"] for task in tasks]
    cache_keys = [task["cache_key"] for task in tasks]
    if len(case_ids) != len(set(case_ids)):
        raise ValueError("Duplicate case ID in manifest")
    if len(cache_keys) != len(set(cache_keys)):
        raise ValueError("Duplicate cache key in manifest")
    asymmetric_schema = policy["schema_version"] in {
        "tier-b-filter-result-v3",
        V4_SCHEMA_VERSION,
    }
    if asymmetric_schema:
        reviewed_scope_version = metadata.get("reviewed_scope_version")
        if policy["schema_version"] == V4_SCHEMA_VERSION:
            reviewed_scope = load_v4_reviewed_scope(
                reviewed_scope_version
            )
            if reviewed_scope_version != reviewed_scope["scope_version"]:
                raise ValueError("V4 reviewed scope version differs")
            scope_protocol = "v4"
        else:
            reviewed_scope = load_v3_reviewed_scope(reviewed_scope_version)
            scope_protocol = "v3"
        reviewed_by_id = {
            case["case_id"]: case for case in reviewed_scope["cases"]
        }
        if set(case_ids) != set(reviewed_by_id):
            raise ValueError(
                f"{scope_protocol.upper()} manifest differs from its "
                "reviewed scope"
            )
        scope_sha = sha256_file(
            reviewed_scope_path_for_protocol(
                scope_protocol, reviewed_scope_version
            )
        )
        schema_sha = sha256_file(result_schema_path(scope_protocol))
        for frozen in (metadata, summary):
            if frozen.get("reviewed_scope_version") != reviewed_scope[
                "scope_version"
            ]:
                raise ValueError(
                    f"{scope_protocol.upper()} reviewed scope version differs"
                )
            if frozen.get("reviewed_scope_sha256") != scope_sha:
                raise ValueError(
                    f"{scope_protocol.upper()} reviewed scope hash differs"
                )
            if frozen.get("comparison_source_run_id") != reviewed_scope[
                "source_run_id"
            ]:
                raise ValueError(
                    f"{scope_protocol.upper()} comparison source run differs"
                )
            if frozen.get("comparison_source_manifest_sha256") != reviewed_scope[
                "source_manifest_sha256"
            ]:
                raise ValueError(
                    f"{scope_protocol.upper()} comparison source manifest "
                    "differs"
                )
            if frozen.get(
                "reviewed_scope_kind", "comparison"
            ) != reviewed_scope.get(
                "scope_kind", "comparison"
            ):
                raise ValueError(
                    f"{scope_protocol.upper()} reviewed scope kind differs"
                )
            if frozen.get("result_schema_sha256") != schema_sha:
                raise ValueError(
                    f"{scope_protocol.upper()} result schema hash differs"
                )
            if frozen.get("request_defensive_reminder") != policy.get(
                "request_defensive_reminder"
            ):
                raise ValueError(
                    f"{scope_protocol.upper()} request reminder policy differs"
                )
            if frozen.get("required_tool_retry_extension") != policy.get(
                "required_tool_retry_extension"
            ):
                raise ValueError(
                    f"{scope_protocol.upper()} retry extension policy differs"
                )
        if reviewed_scope.get("scope_kind") == "retry_only":
            source_run_dir = run_dir.parent / reviewed_scope["source_run_id"]
            if sha256_file(source_run_dir / "manifest.jsonl") != (
                reviewed_scope["source_manifest_sha256"]
            ):
                raise ValueError("V3 retry source manifest hash differs")
            if sha256_file(source_run_dir / "results.jsonl") != (
                reviewed_scope["source_results_sha256"]
            ):
                raise ValueError("V3 retry source results hash differs")
        if reviewed_scope.get("scope_kind") == "static_required_tools_round3":
            source_run_dir = run_dir.parent / reviewed_scope["source_run_id"]
            if sha256_file(source_run_dir / "manifest.jsonl") != (
                reviewed_scope["source_manifest_sha256"]
            ):
                raise ValueError("V4 round-3 source manifest hash differs")
            if sha256_file(source_run_dir / "results.jsonl") != (
                reviewed_scope["source_results_sha256"]
            ):
                raise ValueError("V4 round-3 source results hash differs")
        required_scope_tools = reviewed_scope.get(
            "required_tool_names", []
        )
        for task in tasks:
            if task.get("required_tool_names", []) != required_scope_tools:
                raise ValueError(
                    "Manifest required-tool coverage differs from its "
                    "reviewed scope"
                )
            if bool(required_scope_tools) != bool(
                task.get("tool_coverage_enforcement")
            ):
                raise ValueError(
                    "Manifest tool-coverage enforcement is inconsistent"
                )
            if task.get("request_defensive_reminder") != policy.get(
                "request_defensive_reminder"
            ):
                raise ValueError(
                    "Manifest request reminder policy is inconsistent"
                )
            if task.get("required_tool_retry_extension") != policy.get(
                "required_tool_retry_extension"
            ):
                raise ValueError(
                    "Manifest retry extension policy is inconsistent"
                )
    for task in tasks:
        if task.get("schema_version") != metadata["schema_version"]:
            raise ValueError("Task schema differs from metadata")
        if asymmetric_schema:
            if task.get("protocol_version") != scope_protocol:
                raise ValueError(
                    f"{scope_protocol.upper()} task lacks explicit protocol "
                    "binding"
                )
            if task.get("decision_priority") != policy["decision_priority"]:
                raise ValueError(
                    f"{scope_protocol.upper()} task confirmation-priority "
                    "policy differs"
                )
            if metadata.get("decision_priority") != policy["decision_priority"]:
                raise ValueError(
                    f"{scope_protocol.upper()} metadata confirmation-priority "
                    "policy differs"
                )
            scoped = reviewed_by_id[task["case_id"]]
            if (
                task["artifact_sha256"],
                task["function_uid"],
                task["target_class"],
            ) != (
                scoped["artifact_sha256"],
                scoped["function_uid"],
                scoped["target_class"],
            ):
                raise ValueError(
                    f"{scope_protocol.upper()} task differs from its reviewed "
                    "identity tuple"
                )
            if task.get("reviewed_scope_sha256") != scope_sha:
                raise ValueError(
                    f"{scope_protocol.upper()} task reviewed scope hash differs"
                )
            if task.get(
                "reviewed_scope_kind", "comparison"
            ) != reviewed_scope.get(
                "scope_kind", "comparison"
            ):
                raise ValueError(
                    f"{scope_protocol.upper()} task reviewed scope kind differs"
                )
            if task.get("result_schema_sha256") != schema_sha:
                raise ValueError(
                    f"{scope_protocol.upper()} task result schema hash differs"
                )
        if task["model"] != metadata["model"]:
            raise ValueError("Task model differs from metadata")
        if task["reasoning_effort"] != metadata["reasoning_effort"]:
            raise ValueError("Task reasoning differs from metadata")
        prompt_path = (run_dir / task["prompt_path"]).resolve()
        if not prompt_path.is_relative_to(run_dir):
            raise ValueError("Prompt escapes the run directory")
        if sha256_text(prompt_path.read_text(encoding="utf-8")) != task["prompt_sha256"]:
            raise ValueError("Prompt hash mismatch")
        package_path = Path(task["package_path"]).resolve()
        package = AnalysisPackage(package_path, policy)
        package.verify_frozen_inputs()
        if sha256_file(package_path / "package.json") != task[
            "package_manifest_sha256"
        ]:
            raise ValueError("Package manifest hash mismatch")
        if package.metadata["artifact_sha256"] != task["artifact_sha256"]:
            raise ValueError("Package artifact mismatch")
        if task["function_uid"] not in package.functions:
            raise ValueError("Task function UID is absent")
        if any(root not in package.functions for root in task["entry_roots"]):
            raise ValueError("Task entry root is absent")


def latest_terminals(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    result = {}
    for row in records:
        if row.get("terminal"):
            result[row["cache_key"]] = row
    return result


def next_case_attempt_index(
    records: list[dict[str, Any]], cache_key: str
) -> int:
    matching = [row for row in records if row.get("cache_key") == cache_key]
    versioned = [
        row["case_attempt_index"]
        for row in matching
        if isinstance(row.get("case_attempt_index"), int)
    ]
    if versioned:
        return max(versioned) + 1
    legacy_attempts = sum(bool(row.get("terminal")) for row in matching)
    return legacy_attempts + 1


def provider_call_identity(
    run_id: str,
    task: dict[str, Any],
    case_attempt_index: int,
    call_index: int,
    request: dict[str, Any],
) -> dict[str, Any]:
    request_sha256 = sha256_text(canonical_json(request))
    call_attempt_id = sha256_text(
        canonical_json(
            {
                "run_id": run_id,
                "cache_key": task["cache_key"],
                "case_attempt_index": case_attempt_index,
                "model_call_index": call_index,
                "request_sha256": request_sha256,
            }
        )
    )
    return {
        "ledger_schema_version": LEDGER_SCHEMA_VERSION,
        "run_id": run_id,
        "case_id": task["case_id"],
        "cache_key": task["cache_key"],
        "case_attempt_index": case_attempt_index,
        "model_call_index": call_index,
        "call_attempt_id": call_attempt_id,
        "request_sha256": request_sha256,
    }


def observation_failure(
    stream_outcome: str,
    incomplete_reason: str | None,
) -> tuple[str, str, str]:
    if stream_outcome == "incomplete_max_output_tokens":
        return (
            "provider_incomplete_max_output_tokens",
            "resource_exhausted",
            "Provider response was incomplete because max_output_tokens was reached",
        )
    if stream_outcome == "incomplete_content_filter":
        return (
            "provider_incomplete_content_filter",
            "provider_refusal",
            "Provider response was incomplete because of content filtering",
        )
    if stream_outcome == "incomplete_other":
        return (
            "provider_incomplete_other",
            "infrastructure_error",
            "Provider response was incomplete"
            + (
                f": {incomplete_reason}"
                if incomplete_reason
                else " with no reported reason"
            ),
        )
    return (
        "infrastructure_error",
        "infrastructure_error",
        f"Provider stream outcome: {stream_outcome}",
    )


def fallback_terminal(
    result_path: Path,
    task: dict[str, Any],
    status: str,
    execution_status: str,
    reason: str,
    *,
    call_index: int,
    progress_events: list[str],
    provider_call_made: bool = False,
    reserved_cost_usd: float | None = None,
) -> None:
    append_record(
        result_path,
        {
            "recorded_at_utc": utc_now(),
            "case_id": task["case_id"],
            "cache_key": task["cache_key"],
            "model_call_index": call_index,
            "provider_call_made": provider_call_made,
            "terminal": True,
            "status": status,
            "error": reason,
            "reserved_cost_usd": reserved_cost_usd,
            "parsed_result": fallback_result_for_task(
                task, execution_status, reason, progress_events
            ),
        },
    )


def main() -> int:
    args = parser().parse_args()
    run_dir = args.run_dir.resolve()
    tasks = read_jsonl(run_dir / "manifest.jsonl")
    metadata = load_json(run_dir / "run-metadata.json")
    summary = load_json(run_dir / "manifest-summary.json")
    protocol_version = protocol_version_for_schema(metadata["schema_version"])
    policy = load_policy_for_protocol(
        protocol_version, metadata.get("policy_version")
    )
    schema = load_json(result_schema_path(protocol_version))
    validate_strict_json_schema(schema)
    if schema["properties"]["schema_version"]["const"] != metadata["schema_version"]:
        raise ValueError("Result schema version differs from frozen run metadata")
    api_schema = {
        key: value for key, value in schema.items() if key not in {"$schema", "title"}
    }
    validate_strict_json_schema(api_schema)
    if args.execute and not args.approved_manifest_sha256:
        raise ValueError("Execution requires the explicitly approved manifest SHA-256")
    validate_run(
        run_dir,
        tasks,
        metadata,
        summary,
        policy,
        args.approved_manifest_sha256,
        args.budget_usd,
    )
    result_path = run_dir / "results.jsonl"
    records = read_jsonl(result_path)
    spent = accounted_spend(records)
    latest = latest_terminals(records)
    orphans = orphaned_provider_calls(records)
    orphan_cache_keys = {row["cache_key"] for row in orphans}
    task_by_id = {task["case_id"]: task for task in tasks}
    task_by_cache_key = {task["cache_key"]: task for task in tasks}
    retry_ids = set(args.retry_reviewed_infrastructure_case)
    if retry_ids - set(task_by_id):
        raise ValueError(f"Unknown retry case IDs: {sorted(retry_ids - set(task_by_id))}")
    for case_id in retry_ids:
        prior = latest.get(task_by_id[case_id]["cache_key"])
        if prior is None or prior.get("status") != "infrastructure_error":
            raise ValueError(
                f"Reviewed retry is allowed only after infrastructure_error: {case_id}"
            )
        if task_by_id[case_id]["cache_key"] in orphan_cache_keys:
            raise ValueError(
                "An orphaned provider call must be retrieved and classified "
                f"before any reviewed retry: {case_id}"
            )
    pending = [
        task
        for task in tasks
        if (
            task["cache_key"] not in latest
            and task["cache_key"] not in orphan_cache_keys
        )
        or task["case_id"] in retry_ids
    ]
    pending_projection = sum(
        task["adaptive_projection"]["projected_max_cost_usd"] for task in pending
    )
    if spent + pending_projection > args.budget_usd:
        raise ValueError(
            f"Accounted ${spent:.6f} plus pending projection "
            f"${pending_projection:.6f} exceeds approved ${args.budget_usd:.6f}"
        )
    report = {
        "run_id": run_dir.name,
        "pending_cases": len(pending),
        "accounted_spend_usd": spent,
        "pending_adaptive_projection_usd": pending_projection,
        "approved_budget_usd": args.budget_usd,
        "approved_manifest_sha256": args.approved_manifest_sha256,
        "reviewed_infrastructure_retries": sorted(retry_ids),
        "orphaned_provider_calls": len(orphans),
        "would_make_provider_calls": bool(
            args.execute and (pending or orphans)
        ),
    }
    if not args.execute:
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0

    api_key = os.environ.get(args.api_key_env)
    if not api_key:
        raise ValueError(f"API key environment variable is absent: {args.api_key_env}")
    from openai import OpenAI

    client = OpenAI(api_key=api_key, max_retries=0)
    metadata["status"] = "executing"
    metadata["approved_budget_usd"] = args.budget_usd
    metadata["approved_manifest_sha256"] = args.approved_manifest_sha256
    metadata["last_executed_at_utc"] = utc_now()
    write_json(run_dir / "run-metadata.json", metadata)

    tools = api_tools(policy)
    limits = policy["limits"]
    input_price = metadata["input_price_per_million"]
    output_price = metadata["output_price_per_million"]

    for orphan in orphans:
        task = task_by_cache_key[orphan["cache_key"]]
        call_identity = {
            key: orphan[key]
            for key in (
                "ledger_schema_version",
                "run_id",
                "case_id",
                "cache_key",
                "case_attempt_index",
                "model_call_index",
                "call_attempt_id",
                "request_sha256",
            )
        }

        def record_orphan_retrieval(fields: dict[str, Any]) -> None:
            append_record(
                result_path,
                {
                    **call_identity,
                    "record_kind": "provider_retrieval_attempt",
                    "recorded_at_utc": utc_now(),
                    "provider_call_made": False,
                    "provider_response_id": orphan[
                        "provider_response_id"
                    ],
                    "terminal": False,
                    "status": "provider_retrieval_attempt",
                    **fields,
                },
            )

        observation = recover_response(
            client,
            orphan["provider_response_id"],
            record_orphan_retrieval,
        )
        observation.last_sequence_number = orphan.get(
            "last_sequence_number"
        )
        response = observation.response
        usage_value = usage(response) if response is not None else {}
        actual = (
            usage_cost(usage_value, input_price, output_price)
            if response is not None
            else None
        )
        base = {
            **call_identity,
            "record_kind": "model_call_outcome",
            "recorded_at_utc": utc_now(),
            "provider_call_made": True,
            **observation.ledger_fields(),
            "usage": usage_value,
            "actual_cost_usd": actual,
            "reserved_cost_usd": (
                orphan.get("reserved_cost_usd")
                if actual is None
                else None
            ),
            "latency_seconds": None,
        }
        if observation.stream_outcome != "completed_recovered":
            status, execution_status, reason = observation_failure(
                observation.stream_outcome,
                observation.provider_incomplete_reason,
            )
            append_record(
                result_path,
                {
                    **base,
                    "terminal": True,
                    "status": status,
                    "error": reason,
                    "parsed_result": fallback_result_for_task(
                        task, execution_status, reason, []
                    ),
                },
            )
            continue
        refusal = response_refusal(response)
        if refusal:
            append_record(
                result_path,
                {
                    **base,
                    "terminal": True,
                    "status": "provider_refusal",
                    "error": refusal,
                    "parsed_result": fallback_result_for_task(
                        task, "provider_refusal", refusal, []
                    ),
                },
            )
            continue
        items = response_items(response)
        if any(item.get("type") == "function_call" for item in items):
            reason = (
                "Recovered original response contains a tool call, but "
                "the exact in-memory conversation is unavailable after "
                "restart; no new generation was attempted"
            )
            append_record(
                result_path,
                {
                    **base,
                    "terminal": True,
                    "status": "infrastructure_error",
                    "error": reason,
                    "parsed_result": fallback_result_for_task(
                        task, "infrastructure_error", reason, []
                    ),
                },
            )
            continue
        text = final_text(response)
        try:
            raw_parsed = json.loads(text) if text else None
            if raw_parsed is None:
                parsed = None
                errors = ["Recovered response has no final JSON"]
                validator_adjustments: list[dict[str, Any]] = []
            else:
                (
                    parsed,
                    errors,
                    validator_adjustments,
                ) = validate_and_normalize_model_result_for_task(
                    raw_parsed,
                    task,
                    AnalysisPackage(Path(task["package_path"]), policy),
                )
        except Exception as exc:
            parsed = None
            errors = [f"{type(exc).__name__}: {exc}"]
            validator_adjustments = []
        if errors:
            reason = "; ".join(errors)
            append_record(
                result_path,
                {
                    **base,
                    "terminal": True,
                    "status": "invalid_output",
                    "error": reason,
                    "raw_response_text": text,
                    "validator_adjustments": validator_adjustments,
                    "parsed_result": fallback_result_for_task(
                        task, "invalid_output", reason, []
                    ),
                },
            )
        else:
            append_record(
                result_path,
                {
                    **base,
                    "terminal": True,
                    "status": "ok",
                    "error": None,
                    "raw_response_text": text,
                    "parsed_result": parsed,
                    "validator_adjustments": validator_adjustments,
                    "extension_granted": False,
                    "progress_events": [],
                },
            )

    records = read_jsonl(result_path)
    spent = accounted_spend(records)

    for task in pending:
        package = AnalysisPackage(Path(task["package_path"]), policy)
        package.verify_frozen_inputs()
        prompt = (run_dir / task["prompt_path"]).read_text(encoding="utf-8")
        case_attempt_index = next_case_attempt_index(
            records, task["cache_key"]
        )
        conversation: list[dict[str, Any]] = [
            {"role": "user", "content": [{"type": "input_text", "text": prompt}]}
        ]
        tool_calls = 0
        angr_queries = 0
        required_tool_names = list(task.get("required_tool_names", []))
        defensive_reminder = (
            REINFORCED_LIFETIME_CONTEXT_REMINDER
            if task.get("tool_coverage_enforcement")
            else DEFENSIVE_CONTEXT_REMINDER
        )
        repeat_defensive_reminder = (
            task.get("request_defensive_reminder")
            == "every-provider-request-v1"
        )
        required_tool_retry_extension = task.get(
            "required_tool_retry_extension"
        )
        successful_tool_names: set[str] = set()
        coverage_gate_active = False
        extension_granted = False
        progress_events: list[str] = []
        observed_information_facts: set[str] = set()
        latest_valid_interim: dict[str, Any] | None = None
        max_calls = limits["base_model_calls"] + limits["extension_model_calls"]
        case_terminal = False

        for call_index in range(1, max_calls + 1):
            if call_index > limits["base_model_calls"] and not extension_granted:
                if progress_events:
                    extension_granted = True
                    append_record(
                        result_path,
                        {
                            "recorded_at_utc": utc_now(),
                            "case_id": task["case_id"],
                            "cache_key": task["cache_key"],
                            "model_call_index": call_index,
                            "provider_call_made": False,
                            "terminal": False,
                            "status": "extension_granted",
                            "progress_events": progress_events,
                        },
                    )
                else:
                    fallback_terminal(
                        result_path,
                        task,
                        "resource_exhausted",
                        "resource_exhausted",
                        "Base investigation ended without qualifying progress",
                        call_index=call_index,
                        progress_events=progress_events,
                    )
                    case_terminal = True
                    break

            projection = task["adaptive_projection"]
            projected_inputs = projection["projected_input_tokens_by_call"]
            input_bound = projected_inputs[min(call_index, len(projected_inputs)) - 1]
            worst_call = estimate_cost_usd(
                input_bound,
                task["max_output_tokens_per_call"],
                input_price,
                output_price,
            )
            if spent + worst_call > args.budget_usd:
                reason = (
                    "Conservative next-call bound would exceed the approved ceiling"
                )
                fallback_terminal(
                    result_path,
                    task,
                    "budget_stop",
                    "resource_exhausted",
                    reason,
                    call_index=call_index,
                    progress_events=progress_events,
                )
                append_interim_fallback(
                    result_path,
                    task,
                    latest_valid_interim,
                    failed_call_index=call_index,
                    failure_status="budget_stop",
                    failure_reason=reason,
                )
                case_terminal = True
                break

            allowed_tools = limits["base_tool_calls"]
            if extension_granted:
                allowed_tools += limits["extension_tool_calls"]
            can_call_tools = tool_calls < allowed_tools and call_index < max_calls
            missing_required_tools = missing_required_tool_names(
                required_tool_names, successful_tool_names
            )
            remaining_tool_slots = min(
                max(0, allowed_tools - tool_calls),
                max(0, max_calls - call_index),
            )
            if missing_required_tools and remaining_tool_slots == 0:
                reason = (
                    "Required static-tool coverage could not be completed "
                    f"before the frozen call limit: {missing_required_tools}"
                )
                fallback_terminal(
                    result_path,
                    task,
                    "resource_exhausted",
                    "resource_exhausted",
                    reason,
                    call_index=call_index,
                    progress_events=progress_events,
                )
                case_terminal = True
                break
            force_tool_name = required_tool_choice(
                missing_required_tools,
                remaining_tool_slots=remaining_tool_slots,
                coverage_gate_active=coverage_gate_active,
            )
            request: dict[str, Any] = {
                "model": task["model"],
                "input": request_input_for_call(
                    conversation,
                    can_call_tools=can_call_tools,
                    defensive_reminder=defensive_reminder,
                    repeat_defensive_reminder=repeat_defensive_reminder,
                ),
                "reasoning": {"effort": task["reasoning_effort"]},
                "max_output_tokens": task["max_output_tokens_per_call"],
                "text": {
                    "format": {
                        "type": "json_schema",
                        "name": "tier_b_filter_result",
                        "strict": True,
                        "schema": api_schema,
                    }
                },
                "tools": tools,
                "parallel_tool_calls": False,
            }
            if can_call_tools:
                request["max_tool_calls"] = 1
                if force_tool_name is not None:
                    request["tool_choice"] = {
                        "type": "function",
                        "name": force_tool_name,
                    }
            else:
                request["tool_choice"] = "none"

            call_identity = provider_call_identity(
                run_dir.name,
                task,
                case_attempt_index,
                call_index,
                request,
            )
            started = time.monotonic()

            def record_created(fields: dict[str, Any]) -> None:
                append_record(
                    result_path,
                    {
                        **call_identity,
                        "record_kind": "provider_response_created",
                        "recorded_at_utc": utc_now(),
                        "provider_call_made": True,
                        "reserved_cost_usd": worst_call,
                        "terminal": False,
                        "status": "provider_response_created",
                        **fields,
                    },
                )

            observation = observe_response_stream(
                client, request, record_created
            )

            if should_attempt_recovery(observation):

                def record_retrieval(fields: dict[str, Any]) -> None:
                    append_record(
                        result_path,
                        {
                            **call_identity,
                            "record_kind": "provider_retrieval_attempt",
                            "recorded_at_utc": utc_now(),
                            "provider_call_made": False,
                            "provider_response_id": observation.response_id,
                            "terminal": False,
                            "status": "provider_retrieval_attempt",
                            **fields,
                        },
                    )

                recovered = recover_response(
                    client,
                    observation.response_id,
                    record_retrieval,
                )
                recovered.event_type_counts = observation.event_type_counts
                recovered.last_sequence_number = (
                    observation.last_sequence_number
                )
                recovered.stream_exception = observation.stream_exception
                if recovered.provider_error is None:
                    recovered.provider_error = observation.provider_error
                if not recovered.partial_output_text:
                    recovered.partial_output_text = (
                        observation.partial_output_text
                    )
                if not recovered.partial_output_item_types:
                    recovered.partial_output_item_types = (
                        observation.partial_output_item_types
                    )
                observation = recovered

            response = observation.response
            usage_value = usage(response) if response is not None else {}
            actual = (
                usage_cost(usage_value, input_price, output_price)
                if response is not None
                else None
            )
            charged = actual if actual is not None else worst_call
            spent += charged
            base = {
                **call_identity,
                "record_kind": "model_call_outcome",
                "recorded_at_utc": utc_now(),
                "provider_call_made": True,
                **observation.ledger_fields(),
                "usage": usage_value,
                "actual_cost_usd": actual,
                "reserved_cost_usd": (
                    worst_call if actual is None else None
                ),
                "latency_seconds": round(time.monotonic() - started, 6),
            }
            if observation.stream_outcome not in {
                "completed",
                "completed_recovered",
            }:
                status, execution_status, reason = observation_failure(
                    observation.stream_outcome,
                    observation.provider_incomplete_reason,
                )
                if observation.provider_error:
                    reason += f"; provider_error={observation.provider_error}"
                if observation.stream_exception:
                    reason += (
                        f"; stream_exception={observation.stream_exception}"
                    )
                append_record(
                    result_path,
                    {
                        **base,
                        "terminal": True,
                        "status": status,
                        "error": reason,
                        "parsed_result": fallback_result_for_task(
                            task,
                            execution_status,
                            reason,
                            progress_events,
                        ),
                    },
                )
                append_interim_fallback(
                    result_path,
                    task,
                    latest_valid_interim,
                    failed_call_index=call_index,
                    failure_status=status,
                    failure_reason=reason,
                )
                case_terminal = True
                break

            if (
                isinstance(usage_value.get("output_tokens"), int)
                and usage_value["output_tokens"] > task["max_output_tokens_per_call"]
            ):
                raise ValueError("Provider-reported output exceeded the frozen cap")
            refusal = response_refusal(response)
            if refusal:
                append_record(
                    result_path,
                    {
                        **base,
                        "terminal": True,
                        "status": "provider_refusal",
                        "error": refusal,
                        "parsed_result": fallback_result_for_task(
                            task, "provider_refusal", refusal, progress_events
                        ),
                    },
                )
                append_interim_fallback(
                    result_path,
                    task,
                    latest_valid_interim,
                    failed_call_index=call_index,
                    failure_status="provider_refusal",
                    failure_reason=refusal,
                )
                case_terminal = True
                break

            items = response_items(response)
            function_calls = [
                item for item in items if item.get("type") == "function_call"
            ]
            if function_calls:
                if len(function_calls) != 1 or not can_call_tools:
                    reason = "Invalid, parallel, or excess tool call"
                    append_record(
                        result_path,
                        {
                            **base,
                            "terminal": True,
                            "status": "resource_exhausted",
                            "error": reason,
                            "parsed_result": fallback_result_for_task(
                                task, "resource_exhausted", reason, progress_events
                            ),
                        },
                    )
                    append_interim_fallback(
                        result_path,
                        task,
                        latest_valid_interim,
                        failed_call_index=call_index,
                        failure_status="resource_exhausted",
                        failure_reason=reason,
                    )
                    case_terminal = True
                    break
                call = function_calls[0]
                arguments: dict[str, Any] | None = None
                try:
                    arguments = json.loads(call.get("arguments") or "{}")
                    if not isinstance(arguments, dict):
                        raise ValueError("Tool arguments are not an object")
                    if call["name"] == "query_angr":
                        if angr_queries >= limits["max_angr_queries_per_case"]:
                            raise ValueError(
                                "Per-case targeted angr query limit reached"
                            )
                        angr_queries += 1
                    tool_result = package.execute_tool(call["name"], arguments)
                except Exception as exc:
                    tool_result = {"error": f"{type(exc).__name__}: {exc}"}
                if tool_call_satisfies_coverage(
                    call.get("name"), tool_result
                ):
                    successful_tool_names.add(str(call.get("name")))
                retry_extension_granted = (
                    should_grant_required_tool_retry_extension(
                        call.get("name"),
                        tool_result,
                        required_tool_names=required_tool_names,
                        extension_policy=required_tool_retry_extension,
                        extension_granted=extension_granted,
                    )
                )
                if retry_extension_granted:
                    extension_granted = True
                tool_calls += 1
                information_facts = information_fact_keys(
                    call.get("name"), tool_result
                )
                new_information_facts = (
                    information_facts - observed_information_facts
                )
                new_progress = bool(new_information_facts)
                if new_progress:
                    observed_information_facts.update(new_information_facts)
                    progress_key = sha256_text(
                        canonical_json(sorted(new_information_facts))
                    )
                    progress_events.append(
                        f"{call.get('name')} produced "
                        f"{len(new_information_facts)} new information facts "
                        f"{progress_key[:16]}"
                    )
                append_record(
                    result_path,
                    {
                        **base,
                        "terminal": False,
                        "status": "tool_call",
                        "error": None,
                        "tool_name": call.get("name"),
                        "tool_arguments": arguments,
                        "tool_result": tool_result,
                        "angr_query_index": (
                            angr_queries if call.get("name") == "query_angr" else None
                        ),
                        "required_tool_call": (
                            call.get("name") in required_tool_names
                        ),
                        "required_tool_coverage_complete": (
                            set(required_tool_names)
                            <= successful_tool_names
                        ),
                        "remaining_required_tool_names": [
                            name
                            for name in required_tool_names
                            if name not in successful_tool_names
                        ],
                        "required_tool_retry_extension_granted": (
                            retry_extension_granted
                        ),
                        "qualifying_progress": new_progress,
                        "parsed_result": None,
                    },
                )
                if retry_extension_granted:
                    append_record(
                        result_path,
                        {
                            "recorded_at_utc": utc_now(),
                            "case_id": task["case_id"],
                            "cache_key": task["cache_key"],
                            "model_call_index": call_index,
                            "provider_call_made": False,
                            "terminal": False,
                            "status": "extension_granted",
                            "extension_reason": (
                                "required_tool_result_too_large"
                            ),
                            "required_tool_name": call.get("name"),
                            "progress_events": progress_events,
                        },
                    )
                conversation.extend(items)
                append_tool_result_context(
                    conversation,
                    call["call_id"],
                    tool_result,
                    defensive_reminder=defensive_reminder,
                )
                continue

            text = final_text(response)
            if not text:
                if call_index < limits["base_model_calls"] and progress_events:
                    conversation.extend(items)
                    continuation = (
                        V3_NO_TEXT_CONTINUATION
                        if task["schema_version"] in {
                            "tier-b-filter-result-v3",
                            V4_SCHEMA_VERSION,
                        }
                        else V2_NO_TEXT_CONTINUATION
                    )
                    conversation.append(
                        user_text_message(
                            defensive_reminder + " " + continuation
                        )
                    )
                    continue
                reason = "Provider returned neither a tool call nor final JSON"
                append_record(
                    result_path,
                    {
                        **base,
                        "terminal": True,
                        "status": "invalid_output",
                        "error": reason,
                        "parsed_result": fallback_result_for_task(
                            task, "invalid_output", reason, progress_events
                        ),
                    },
                )
                append_interim_fallback(
                    result_path,
                    task,
                    latest_valid_interim,
                    failed_call_index=call_index,
                    failure_status="invalid_output",
                    failure_reason=reason,
                )
                case_terminal = True
                break
            try:
                raw_parsed = json.loads(text)
                (
                    parsed,
                    errors,
                    validator_adjustments,
                ) = validate_and_normalize_model_result_for_task(
                    raw_parsed, task, package
                )
            except Exception as exc:
                parsed = None
                errors = [f"{type(exc).__name__}: {exc}"]
                validator_adjustments = []
            if errors:
                reason = "; ".join(errors)
                append_record(
                    result_path,
                    {
                        **base,
                        "terminal": True,
                        "status": "invalid_output",
                        "error": reason,
                        "raw_response_text": text,
                        "validator_adjustments": validator_adjustments,
                        "parsed_result": fallback_result_for_task(
                            task, "invalid_output", reason, progress_events
                        ),
                    },
                )
                append_interim_fallback(
                    result_path,
                    task,
                    latest_valid_interim,
                    failed_call_index=call_index,
                    failure_status="invalid_output",
                    failure_reason=reason,
                )
                case_terminal = True
                break
            missing_required_tools = missing_required_tool_names(
                required_tool_names, successful_tool_names
            )
            if missing_required_tools:
                append_interim_result(
                    result_path,
                    base,
                    model_call_index=call_index,
                    raw_response_text=text,
                    parsed_result=parsed,
                    validator_adjustments=validator_adjustments,
                    extension_granted=extension_granted,
                    progress_events=progress_events,
                )
                append_record(
                    result_path,
                    {
                        "recorded_at_utc": utc_now(),
                        "case_id": task["case_id"],
                        "cache_key": task["cache_key"],
                        "model_call_index": call_index,
                        "provider_call_made": False,
                        "terminal": False,
                        "status": "required_tool_coverage_blocked_terminal",
                        "proposed_pipeline_disposition": parsed[
                            "pipeline_disposition"
                        ],
                        "missing_required_tool_names": missing_required_tools,
                    },
                )
                coverage_gate_active = True
                conversation.extend(items)
                conversation.append(
                    user_text_message(
                        defensive_reminder
                        + " The proposed terminal result is preserved but "
                        "cannot finish this reviewed rerun yet. Use the "
                        "remaining required analysis tools on material "
                        "unresolved obligations: "
                        + ", ".join(missing_required_tools)
                        + "."
                    )
                )
                continue
            if (
                parsed["pipeline_disposition"] == "retain_and_escalate"
                and progress_events
                and call_index < max_calls
            ):
                latest_valid_interim = append_interim_result(
                    result_path,
                    base,
                    model_call_index=call_index,
                    raw_response_text=text,
                    parsed_result=parsed,
                    validator_adjustments=validator_adjustments,
                    extension_granted=extension_granted,
                    progress_events=progress_events,
                )
                conversation.extend(items)
                continuation = (
                    V3_INTERIM_CONTINUATION
                    if task["schema_version"] in {
                        "tier-b-filter-result-v3",
                        V4_SCHEMA_VERSION,
                    }
                    else V2_INTERIM_CONTINUATION
                )
                conversation.append(
                    user_text_message(
                        defensive_reminder + " " + continuation
                    )
                )
                continue
            append_record(
                result_path,
                {
                    **base,
                    "terminal": True,
                    "status": "ok",
                    "error": None,
                    "raw_response_text": text,
                    "parsed_result": parsed,
                    "validator_adjustments": validator_adjustments,
                    "extension_granted": extension_granted,
                    "progress_events": progress_events,
                    "required_tool_names": required_tool_names,
                    "successful_required_tool_names": [
                        name
                        for name in required_tool_names
                        if name in successful_tool_names
                    ],
                    "required_tool_coverage_complete": (
                        set(required_tool_names) <= successful_tool_names
                    ),
                },
            )
            case_terminal = True
            break

        if not case_terminal:
            reason = "No decisive result before the adaptive model-call limit"
            fallback_terminal(
                result_path,
                task,
                "resource_exhausted",
                "resource_exhausted",
                reason,
                call_index=max_calls,
                progress_events=progress_events,
            )
            append_interim_fallback(
                result_path,
                task,
                latest_valid_interim,
                failed_call_index=max_calls,
                failure_status="resource_exhausted",
                failure_reason=reason,
            )

    final_records = read_jsonl(result_path)
    final_latest = latest_terminals(final_records)
    metadata["provider_generation_calls_made"] = (
        provider_generation_call_count(final_records)
    )
    metadata["provider_retrieval_calls_made"] = (
        provider_retrieval_call_count(final_records)
    )
    metadata["provider_api_calls_made"] = (
        metadata["provider_generation_calls_made"]
        + metadata["provider_retrieval_calls_made"]
    )
    metadata["accounted_spend_usd"] = accounted_spend(final_records)
    metadata["status"] = (
        "completed"
        if all(task["cache_key"] in final_latest for task in tasks)
        else "stopped"
    )
    write_json(run_dir / "run-metadata.json", metadata)
    print(
        json.dumps(
            {
                "status": metadata["status"],
                "accounted_spend_usd": metadata["accounted_spend_usd"],
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
