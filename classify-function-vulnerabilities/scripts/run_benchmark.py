#!/usr/bin/env python3
"""Run a prepared Tier A manifest with compatibility and spending gates."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from experiment_common import load_metadata, write_metadata
from tier_a_common import (
    build_prompt,
    estimate_cost_usd,
    estimate_tokens,
    load_policy,
    load_result_schema,
    read_jsonl,
    sha256_text,
    validate_model_result,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--input-price-per-million", type=float, required=True)
    parser.add_argument("--output-price-per-million", type=float, required=True)
    parser.add_argument("--budget-usd", type=float, default=5.0)
    parser.add_argument("--api-key-env", default="OPENAI_API_KEY")
    parser.add_argument("--max-tasks", type=int)
    parser.add_argument(
        "--retry-reviewed-invalid-preflight",
        action="store_true",
        help=(
            "Retry a cached invalid compatibility preflight after explicit review; "
            "refusals remain non-retryable and all prior cost stays in the ledger."
        ),
    )
    parser.add_argument(
        "--retry-reviewed-invalid-task",
        action="append",
        default=[],
        metavar="TASK_ID",
        help=(
            "Retry one specifically reviewed cached invalid task. Repeat the option "
            "to authorize additional task IDs."
        ),
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Make paid API calls; without this flag the command is a dry run.",
    )
    return parser.parse_args()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def response_text_and_refusal(response: Any) -> tuple[str, str | None]:
    refusal = None
    for item in getattr(response, "output", []) or []:
        for content in getattr(item, "content", []) or []:
            if getattr(content, "type", None) == "refusal":
                refusal = getattr(content, "refusal", None) or "provider refusal"
    return (getattr(response, "output_text", "") or "").strip(), refusal


def usage_dict(response: Any) -> dict[str, int | None]:
    usage = getattr(response, "usage", None)
    return {
        "input_tokens": getattr(usage, "input_tokens", None),
        "output_tokens": getattr(usage, "output_tokens", None),
        "total_tokens": getattr(usage, "total_tokens", None),
    }


def append_result(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def classify_exception(exc: Exception) -> tuple[str, bool]:
    name = type(exc).__name__.lower()
    message = str(exc).lower()
    if "insufficient_quota" in message or "quota" in name or "quota" in message:
        return "quota_error", False
    transient = any(
        marker in name or marker in message
        for marker in ("timeout", "connection", "ratelimit", "rate limit", "server error", "503")
    )
    return "api_error", transient


def call_openai(
    client: Any,
    task: dict[str, Any],
    prompt: str,
    max_output_tokens: int,
    reasoning_effort: str | None,
) -> dict[str, Any]:
    schema = load_result_schema()
    api_schema = {key: value for key, value in schema.items() if key not in {"$schema", "title"}}
    started = time.monotonic()
    request: dict[str, Any] = {
        "model": task["model"],
        "input": [
            {
                "role": "user",
                "content": [{"type": "input_text", "text": prompt}],
            }
        ],
        "max_output_tokens": max_output_tokens,
        "text": {
            "format": {
                "type": "json_schema",
                "name": "tier_a_result",
                "strict": True,
                "schema": api_schema,
            }
        },
    }
    if reasoning_effort:
        request["reasoning"] = {"effort": reasoning_effort}
    response = client.responses.create(**request)
    latency = time.monotonic() - started
    text, refusal = response_text_and_refusal(response)
    usage = usage_dict(response)
    base = {
        "provider_response_id": getattr(response, "id", None),
        "provider_response_status": getattr(response, "status", None),
        "latency_seconds": round(latency, 6),
        "usage": usage,
        "raw_response_text": text,
    }
    if refusal:
        return {**base, "status": "refusal", "error": refusal, "parsed_result": None}
    if not text:
        return {
            **base,
            "status": "invalid_output",
            "error": "provider returned no text and no explicit refusal",
            "parsed_result": None,
        }
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        return {
            **base,
            "status": "invalid_output",
            "error": f"response is not strict JSON: {exc}",
            "parsed_result": None,
        }
    errors = validate_model_result(
        parsed, task["target_class"], max_line=int(task["normalized_code_lines"])
    )
    if errors:
        return {
            **base,
            "status": "invalid_output",
            "error": "; ".join(errors),
            "parsed_result": parsed,
        }
    return {**base, "status": "ok", "error": None, "parsed_result": parsed}


def choose_preflight(tasks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    chosen: list[dict[str, Any]] = []
    for representation in ("ghidra_pseudo_c", "llvm_ir"):
        candidates = [task for task in tasks if task["representation"] == representation]
        if not candidates:
            continue
        matched = [
            task for task in candidates if task["target_class"] == task["indexed_bug_class"]
        ]
        chosen.append((matched or candidates)[0])
    return chosen


def main() -> int:
    args = parse_args()
    policy = load_policy()
    limits = policy["limits"]
    reviewed_invalid_task_ids = set(args.retry_reviewed_invalid_task)
    run_dir = args.run_dir.resolve()
    metadata = load_metadata(run_dir)
    manifest_path = run_dir / "manifest.jsonl"
    results_path = run_dir / "results.jsonl"
    manifest_dir = manifest_path.parent

    if not 0 < args.budget_usd <= limits["max_budget_usd"]:
        raise ValueError(
            f"--budget-usd must be > 0 and <= {limits['max_budget_usd']:.2f}"
        )
    if args.input_price_per_million <= 0 or args.output_price_per_million <= 0:
        raise ValueError("Current positive input and output prices are required")

    tasks = read_jsonl(manifest_path)
    if not tasks:
        raise ValueError("Manifest is empty")
    reasoning_values = {task.get("reasoning_effort") for task in tasks}
    if len(reasoning_values) != 1 or next(iter(reasoning_values)) not in {
        "low",
        "medium",
        "high",
    }:
        raise ValueError("Manifest must freeze one reasoning effort: low, medium, or high")
    reasoning_effort = next(iter(reasoning_values))
    output_token_values = {task.get("estimated_max_output_tokens") for task in tasks}
    if len(output_token_values) != 1:
        raise ValueError("Manifest must freeze one maximum output-token setting")
    max_output_tokens = next(iter(output_token_values))
    if not isinstance(max_output_tokens, int) or not 0 < max_output_tokens <= limits["max_output_tokens"]:
        raise ValueError("Manifest output-token setting exceeds the active safety policy")
    if metadata.get("reasoning_effort") != reasoning_effort:
        raise ValueError("Run metadata and manifest reasoning effort do not match")
    models = {task.get("model") for task in tasks}
    if len(models) != 1 or metadata.get("model") != next(iter(models)):
        raise ValueError("Run metadata and manifest model do not match")
    for field in ("policy_version", "prompt_version", "schema_version"):
        values = {task.get(field) for task in tasks}
        if len(values) != 1 or metadata.get(field) != next(iter(values)):
            raise ValueError(f"Run metadata and manifest {field} do not match")
    if metadata.get("max_output_tokens") != max_output_tokens:
        raise ValueError("Run metadata and manifest output-token setting do not match")
    for field, supplied in (
        ("input_price_per_million", args.input_price_per_million),
        ("output_price_per_million", args.output_price_per_million),
    ):
        recorded = metadata.get(field)
        if not isinstance(recorded, (int, float)) or abs(float(recorded) - supplied) > 1e-12:
            raise ValueError(
                f"{field} differs from the prepared run; create a new run for changed pricing"
            )
    manifest_task_ids = {task["task_id"] for task in tasks}
    unknown_reviewed_ids = reviewed_invalid_task_ids - manifest_task_ids
    if unknown_reviewed_ids:
        raise ValueError(
            "Reviewed invalid task IDs are not in the manifest: "
            + ", ".join(sorted(unknown_reviewed_ids))
        )
    if len(tasks) > limits["max_requests"]:
        raise ValueError(
            f"Manifest has {len(tasks)} tasks, above max_requests={limits['max_requests']}"
        )
    ready = [task for task in tasks if task.get("input_status") == "ready"]
    if args.max_tasks is not None:
        if args.max_tasks < 1:
            raise ValueError("--max-tasks must be positive")
        required_preflight = choose_preflight(ready)
        if args.max_tasks < len(required_preflight):
            raise ValueError(
                f"--max-tasks must be at least {len(required_preflight)} "
                "to include pseudo-C and LLVM compatibility preflights"
            )
        selected_ids = [task["task_id"] for task in required_preflight]
        selected_ids.extend(
            task["task_id"]
            for task in ready
            if task["task_id"] not in selected_ids
        )
        selected = set(selected_ids[: args.max_tasks])
        ready = [task for task in ready if task["task_id"] in selected]

    prepared: list[tuple[dict[str, Any], str, float]] = []
    for task in ready:
        code_path = manifest_dir / task["code_path"]
        code = code_path.read_text(encoding="utf-8")
        if sha256_text(code) != task["code_sha256"]:
            raise ValueError(f"Code hash changed for {task['task_id']}")
        if len(code) > limits["max_code_chars"]:
            raise ValueError(f"Code guard exceeded for {task['task_id']}")
        prompt = build_prompt(code, task["representation"], task["target_class"])
        if sha256_text(prompt) != task["prompt_sha256"]:
            raise ValueError(f"Prompt hash changed for {task['task_id']}; rebuild manifest")
        prompt_tokens, _ = estimate_tokens(prompt, task["model"])
        if prompt_tokens > limits["max_estimated_input_tokens"]:
            raise ValueError(f"Token guard exceeded for {task['task_id']}")
        task["normalized_code_lines"] = len(code.splitlines())
        worst_cost = estimate_cost_usd(
            prompt_tokens,
            max_output_tokens,
            args.input_price_per_million,
            args.output_price_per_million,
        )
        assert worst_cost is not None
        prepared.append((task, prompt, worst_cost))

    preflight_tasks = choose_preflight([item[0] for item in prepared])
    preflight_ids = {task["task_id"] for task in preflight_tasks}

    prior_rows = read_jsonl(results_path)
    latest_by_cache: dict[str, dict[str, Any]] = {}
    cumulative_cost = 0.0
    for row in prior_rows:
        latest_by_cache[row.get("cache_key", "")] = row
        recorded_cost = row.get("actual_cost_usd")
        if recorded_cost is None:
            recorded_cost = row.get("estimated_worst_case_cost_usd")
        if recorded_cost is None:
            raise ValueError(
                "A prior result has neither actual nor worst-case cost; "
                "cumulative spending cannot be bounded safely"
            )
        cumulative_cost += float(recorded_cost)

    def is_terminal_cache(task: dict[str, Any], cached: dict[str, Any] | None) -> bool:
        status = (cached or {}).get("status")
        if (
            status == "invalid_output"
            and (
                task["task_id"] in reviewed_invalid_task_ids
                or (
                    args.retry_reviewed_invalid_preflight
                    and task["task_id"] in preflight_ids
                )
            )
        ):
            return False
        return status in {"ok", "refusal", "invalid_output"}

    remaining_projected_cost = sum(
        worst_cost
        for task, _, worst_cost in prepared
        if not is_terminal_cache(task, latest_by_cache.get(task["cache_key"]))
    )
    projected_cost = cumulative_cost + remaining_projected_cost
    print(f"Selected tasks: {len(prepared)}")
    print(f"Recorded cumulative cost: ${cumulative_cost:.4f}")
    print(f"Worst-case remaining cost: ${remaining_projected_cost:.4f}")
    print(f"Worst-case cumulative cost: ${projected_cost:.4f}")
    print(f"Hard run ceiling: ${args.budget_usd:.2f}")
    if projected_cost > args.budget_usd:
        print("BLOCKED: projected cost exceeds the run ceiling.", file=sys.stderr)
        return 2
    if not args.execute:
        metadata["status"] = "dry-run"
        metadata["last_dry_run_at_utc"] = utc_now()
        metadata["last_projected_cumulative_cost_usd"] = projected_cost
        metadata["approved_budget_usd"] = args.budget_usd
        write_metadata(run_dir, metadata)
        print("Dry run only; no API calls were made. Add --execute after review.")
        return 0

    api_key = os.environ.get(args.api_key_env)
    if not api_key:
        raise RuntimeError(f"API key environment variable {args.api_key_env} is not set")
    try:
        from openai import OpenAI  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            "Install classify-function-vulnerabilities/scripts/requirements.txt before execution"
        ) from exc
    client = OpenAI(api_key=api_key)

    prepared_by_id = {task["task_id"]: (task, prompt, cost) for task, prompt, cost in prepared}
    ordered_ids = [task["task_id"] for task in preflight_tasks]
    ordered_ids.extend(task["task_id"] for task, _, _ in prepared if task["task_id"] not in ordered_ids)

    spent_or_committed = cumulative_cost
    api_requests = 0
    preflight_complete: set[str] = set()

    for task_id in ordered_ids:
        task, prompt, worst_cost = prepared_by_id[task_id]
        cached = latest_by_cache.get(task["cache_key"])
        reviewed_retry = bool(
            cached
            and cached.get("status") == "invalid_output"
            and (
                task_id in reviewed_invalid_task_ids
                or (args.retry_reviewed_invalid_preflight and task_id in preflight_ids)
            )
        )
        if reviewed_retry:
            print(f"REVIEWED RETRY {task_id}: prior invalid_output")
        if cached and cached.get("status") in {"ok", "refusal", "invalid_output"}:
            if reviewed_retry:
                cached = None
            else:
                print(f"CACHE {task_id}: {cached['status']}")
                if cached["status"] != "ok":
                    print("BLOCKED: cached refusal or invalid output requires review.", file=sys.stderr)
                    return 3
                if task_id in preflight_ids:
                    preflight_complete.add(task_id)
                continue

        if task_id not in preflight_ids and preflight_complete != preflight_ids:
            print("BLOCKED: compatibility preflight is incomplete.", file=sys.stderr)
            return 3

        attempts = 0
        while True:
            attempts += 1
            if api_requests >= limits["max_requests"]:
                print("BLOCKED: maximum API request count reached.", file=sys.stderr)
                return 4
            if spent_or_committed + worst_cost > args.budget_usd:
                print("BLOCKED: next request could exceed the run ceiling.", file=sys.stderr)
                return 4

            api_requests += 1
            print(f"CALL {task_id} (attempt {attempts})")
            try:
                outcome = call_openai(
                    client,
                    task,
                    prompt,
                    max_output_tokens,
                    reasoning_effort,
                )
                transient = False
            except Exception as exc:  # Provider exceptions vary by SDK version.
                status, transient = classify_exception(exc)
                outcome = {
                    "status": status,
                    "error": str(exc),
                    "provider_response_id": None,
                    "provider_response_status": None,
                    "latency_seconds": None,
                    "usage": {"input_tokens": None, "output_tokens": None, "total_tokens": None},
                    "raw_response_text": "",
                    "parsed_result": None,
                }

            usage = outcome["usage"]
            actual_cost = None
            if usage.get("input_tokens") is not None and usage.get("output_tokens") is not None:
                actual_cost = estimate_cost_usd(
                    int(usage["input_tokens"]),
                    int(usage["output_tokens"]),
                    args.input_price_per_million,
                    args.output_price_per_million,
                )
            charged_estimate = actual_cost if actual_cost is not None else worst_cost
            spent_or_committed += charged_estimate
            record = {
                "recorded_at": utc_now(),
                "task_id": task_id,
                "cache_key": task["cache_key"],
                "model": task["model"],
                "provider": task["provider"],
                "reasoning_effort": reasoning_effort,
                "prompt_version": task["prompt_version"],
                "code_sha256": task["code_sha256"],
                "attempt": attempts,
                "preflight": task_id in preflight_ids,
                "reviewed_retry": reviewed_retry,
                "estimated_worst_case_cost_usd": worst_cost,
                "actual_cost_usd": actual_cost,
                **outcome,
            }
            append_result(results_path, record)
            latest_by_cache[task["cache_key"]] = record
            print(f"RESULT {task_id}: {outcome['status']}")

            if outcome["status"] == "ok":
                if task_id in preflight_ids:
                    preflight_complete.add(task_id)
                break
            if task_id in preflight_ids:
                print("BLOCKED: compatibility preflight failed; full run was not released.", file=sys.stderr)
                return 3
            if outcome["status"] in {"refusal", "invalid_output", "quota_error"}:
                return 3 if outcome["status"] == "refusal" else 4
            if not transient or attempts >= limits["max_retries"]:
                break
            time.sleep(min(2**attempts, 8))

    print(f"Completed. API requests this invocation: {api_requests}")
    print(f"Observed/committed cumulative cost estimate: ${spent_or_committed:.4f}")
    print(f"Results: {results_path}")
    metadata["status"] = "executed"
    metadata["last_executed_at_utc"] = utc_now()
    metadata["recorded_cumulative_cost_usd"] = spent_or_committed
    metadata["approved_budget_usd"] = args.budget_usd
    metadata["api_attempt_records"] = len(read_jsonl(results_path))
    write_metadata(run_dir, metadata)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
