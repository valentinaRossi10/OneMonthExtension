#!/usr/bin/env python3
"""Prepare the complete guarded Tier A task manifest without API calls."""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from experiment_common import (
    configuration_differences,
    latest_previous_run,
    load_metadata,
    make_run_id,
    write_metadata,
)

from tier_a_common import (
    build_prompt,
    estimate_cost_usd,
    estimate_tokens,
    load_policy,
    normalize_bug_class,
    resolve_and_normalize_input,
    sha256_text,
    slug,
    write_jsonl,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--results-root", type=Path, default=Path("results/tier-a"))
    parser.add_argument("--run-id")
    parser.add_argument("--run-label")
    parser.add_argument(
        "--experiment-note",
        action="append",
        default=[],
        help="Describe the hypothesis or change; repeat for multiple notes.",
    )
    parser.add_argument(
        "--previous-run",
        type=Path,
        help="Run directory to compare configuration against; defaults to latest run.",
    )
    parser.add_argument("--model", default="gpt-5.6-sol")
    parser.add_argument("--reasoning-effort", choices=("low", "medium", "high"))
    parser.add_argument("--input-price-per-million", type=float, required=True)
    parser.add_argument("--output-price-per-million", type=float, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    policy = load_policy()
    limits = policy["limits"]
    reasoning_effort = args.reasoning_effort or policy.get("model_settings", {}).get(
        "reasoning_effort"
    )
    if reasoning_effort not in {"low", "medium", "high"}:
        raise ValueError("A reasoning effort of low, medium, or high is required")
    results_root = args.results_root.resolve()
    runs_dir = results_root / "runs"
    run_id = args.run_id or make_run_id(args.model, reasoning_effort, args.run_label)
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", run_id):
        raise ValueError(
            "--run-id must start with a lowercase letter or digit and contain only "
            "lowercase letters, digits, dots, underscores, and hyphens"
        )
    output_dir = runs_dir / run_id
    if output_dir.exists():
        raise FileExistsError(
            f"Run directory already exists and will not be overwritten: {output_dir}"
        )

    if args.input_price_per_million <= 0 or args.output_price_per_million <= 0:
        raise ValueError("Current positive input and output prices are required")

    index_path = repo_root / "samples" / "index.csv"
    if not index_path.is_file():
        raise FileNotFoundError(f"Ground-truth index not found: {index_path}")

    previous_dir = args.previous_run.resolve() if args.previous_run else latest_previous_run(runs_dir)
    previous_metadata = load_metadata(previous_dir) if previous_dir else None
    created_at = datetime.now(timezone.utc).isoformat()
    metadata = {
        "metadata_version": "tier-a-run-v1",
        "run_id": run_id,
        "run_date_utc": created_at[:10],
        "created_at_utc": created_at,
        "status": "preparing",
        "model": args.model,
        "reasoning_effort": reasoning_effort,
        "policy_version": policy["policy_version"],
        "prompt_version": policy["prompt_version"],
        "schema_version": policy["schema_version"],
        "max_output_tokens": limits["max_output_tokens"],
        "hard_budget_ceiling_usd": limits["max_budget_usd"],
        "input_price_per_million": args.input_price_per_million,
        "output_price_per_million": args.output_price_per_million,
        "experiment_notes": args.experiment_note,
        "previous_run_id": previous_metadata.get("run_id") if previous_metadata else None,
        "previous_run_path": str(previous_dir) if previous_dir else None,
    }
    metadata["differences_from_previous"] = configuration_differences(
        previous_metadata, metadata
    )
    write_metadata(output_dir, metadata)
    inputs_dir = output_dir / "inputs"
    inputs_dir.mkdir(exist_ok=True)
    tasks: list[dict[str, Any]] = []
    input_records: list[dict[str, Any]] = []

    with index_path.open(newline="", encoding="utf-8") as handle:
        samples = list(csv.DictReader(handle))

    for sample in samples:
        cve_id = sample["cve_id"].strip()
        project = sample["project"].strip()
        indexed_class = normalize_bug_class(sample["bug_class"])
        for variant in ("vulnerable", "patched"):
            input_id = f"{cve_id}__{variant}"
            input_status = "ready"
            error = None
            code = ""
            representation = "unavailable"
            source_path = None
            try:
                code, representation, source = resolve_and_normalize_input(
                    repo_root,
                    cve_id,
                    project,
                    variant,
                    sample["function"].strip(),
                )
                source_path = str(source.relative_to(repo_root))
            except (FileNotFoundError, ValueError) as exc:
                input_status = "unavailable"
                error = str(exc)

            code_chars = len(code)
            code_tokens, code_estimator = estimate_tokens(code, args.model) if code else (0, "none")
            if input_status == "ready" and code_chars > limits["max_code_chars"]:
                input_status = "guard_skip"
                error = f"normalized code has {code_chars} characters"

            code_hash = sha256_text(code) if code else None
            code_path = None
            if code:
                suffix = ".c" if representation == "ghidra_pseudo_c" else ".ll"
                stored = inputs_dir / f"{slug(cve_id)}__{variant}{suffix}"
                stored.write_text(code, encoding="utf-8")
                code_path = str(stored.relative_to(output_dir))

            input_records.append(
                {
                    "input_id": input_id,
                    "status": input_status,
                    "representation": representation,
                    "source_path": source_path,
                    "normalized_code_path": code_path,
                    "code_sha256": code_hash,
                    "code_chars": code_chars,
                    "estimated_code_tokens": code_tokens,
                    "token_estimator": code_estimator,
                    "error": error,
                }
            )

            for target_class in policy["classes"]:
                task_id = f"{cve_id}__{variant}__{target_class}"
                expected_positive = variant == "vulnerable" and target_class == indexed_class
                limitation = next(
                    (
                        entry["reason"]
                        for entry in policy["known_limited_observability"]
                        if entry["cve_id"] == cve_id
                        and entry["target_class"] == target_class
                        and expected_positive
                    ),
                    None,
                )
                prompt_tokens = 0
                prompt_hash = None
                estimated_cost = None
                task_status = input_status
                task_error = error
                if code and input_status == "ready":
                    prompt = build_prompt(code, representation, target_class)
                    prompt_tokens, estimator = estimate_tokens(prompt, args.model)
                    prompt_hash = sha256_text(prompt)
                    if prompt_tokens > limits["max_estimated_input_tokens"]:
                        task_status = "guard_skip"
                        task_error = f"prompt estimate is {prompt_tokens} input tokens"
                    estimated_cost = estimate_cost_usd(
                        prompt_tokens,
                        limits["max_output_tokens"],
                        args.input_price_per_million,
                        args.output_price_per_million,
                    )
                else:
                    estimator = code_estimator

                cache_key_material = "|".join(
                    [
                        task_id,
                        args.model,
                        policy["policy_version"],
                        policy["prompt_version"],
                        policy["schema_version"],
                        reasoning_effort,
                        str(limits["max_output_tokens"]),
                        code_hash or "no-code",
                    ]
                )
                tasks.append(
                    {
                        "task_id": task_id,
                        "cache_key": sha256_text(cache_key_material),
                        "cve_id": cve_id,
                        "project": project,
                        "variant": variant,
                        "indexed_bug_class": indexed_class,
                        "target_class": target_class,
                        "expected_positive": expected_positive,
                        "limited_observability_reason": limitation,
                        "representation": representation,
                        "input_status": task_status,
                        "input_error": task_error,
                        "code_path": code_path,
                        "code_sha256": code_hash,
                        "code_chars": code_chars,
                        "estimated_input_tokens": prompt_tokens,
                        "estimated_max_output_tokens": limits["max_output_tokens"],
                        "token_estimator": estimator,
                        "estimated_worst_case_cost_usd": estimated_cost,
                        "model": args.model,
                        "provider": "openai",
                        "reasoning_effort": reasoning_effort,
                        "policy_version": policy["policy_version"],
                        "prompt_version": policy["prompt_version"],
                        "schema_version": policy["schema_version"],
                        "prompt_sha256": prompt_hash,
                    }
                )

    if len(tasks) > limits["max_requests"]:
        raise RuntimeError(
            f"Manifest has {len(tasks)} tasks, above max_requests={limits['max_requests']}"
        )

    manifest_path = output_dir / "manifest.jsonl"
    write_jsonl(manifest_path, tasks)
    ready = [task for task in tasks if task["input_status"] == "ready"]
    known_costs = [task["estimated_worst_case_cost_usd"] for task in ready]
    projected = sum(cost for cost in known_costs if cost is not None)
    summary = {
        "run_id": run_id,
        "created_at_utc": created_at,
        "policy_version": policy["policy_version"],
        "model": args.model,
        "reasoning_effort": reasoning_effort,
        "samples": len(samples),
        "variants": len(input_records),
        "classes": len(policy["classes"]),
        "tasks": len(tasks),
        "ready_tasks": len(ready),
        "expected_positives": sum(bool(task["expected_positive"]) for task in tasks),
        "guarded_or_unavailable_tasks": len(tasks) - len(ready),
        "largest_code_chars": max((record["code_chars"] for record in input_records), default=0),
        "largest_estimated_input_tokens": max(
            (task["estimated_input_tokens"] for task in tasks), default=0
        ),
        "estimated_worst_case_cost_usd": projected if len(known_costs) == len(ready) else None,
        "pricing_complete": len(known_costs) == len(ready),
        "hard_budget_ceiling_usd": limits["max_budget_usd"],
        "input_price_per_million": args.input_price_per_million,
        "output_price_per_million": args.output_price_per_million,
        "inputs": input_records,
    }
    (output_dir / "manifest-summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    metadata["status"] = (
        "blocked-cost-projection"
        if projected > limits["max_budget_usd"]
        else "prepared"
    )
    metadata["prepared_at_utc"] = datetime.now(timezone.utc).isoformat()
    metadata["manifest_summary"] = {
        key: summary[key]
        for key in (
            "tasks",
            "ready_tasks",
            "guarded_or_unavailable_tasks",
            "estimated_worst_case_cost_usd",
            "pricing_complete",
        )
    }
    write_metadata(output_dir, metadata)

    print(json.dumps(summary, indent=2, sort_keys=True))
    print(f"\nManifest: {manifest_path}")
    print("No API calls were made.")
    if summary["estimated_worst_case_cost_usd"] is None:
        print("WARNING: provide both pricing arguments before any paid run.", file=sys.stderr)
    elif projected > limits["max_budget_usd"]:
        print(
            f"BLOCKED: projected cost ${projected:.4f} exceeds the ${limits['max_budget_usd']:.2f} ceiling.",
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
