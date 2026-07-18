#!/usr/bin/env python3
"""Run-directory metadata and README helpers for Tier A experiments."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


METADATA_NAME = "run-metadata.json"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def make_run_id(model: str, reasoning_effort: str, label: str | None = None) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dt%H%M%Sz")
    parts = [timestamp, safe_slug(model), safe_slug(reasoning_effort)]
    if label:
        parts.append(safe_slug(label))
    return "__".join(part for part in parts if part)


def load_metadata(run_dir: Path) -> dict[str, Any]:
    path = run_dir / METADATA_NAME
    if not path.is_file():
        raise FileNotFoundError(f"Run metadata not found: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Run metadata must be an object: {path}")
    return value


def write_metadata(run_dir: Path, metadata: dict[str, Any]) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / METADATA_NAME).write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    write_run_readme(run_dir, metadata)


def latest_previous_run(runs_dir: Path) -> Path | None:
    candidates: list[tuple[str, Path]] = []
    if not runs_dir.is_dir():
        return None
    for metadata_path in runs_dir.glob(f"*/{METADATA_NAME}"):
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        candidates.append((str(metadata.get("created_at_utc") or ""), metadata_path.parent))
    return max(candidates, default=("", None), key=lambda item: item[0])[1]


def configuration_differences(
    previous: dict[str, Any] | None, current: dict[str, Any]
) -> list[dict[str, Any]]:
    if previous is None:
        return [{"field": "baseline", "previous": None, "current": "first recorded run"}]
    fields = (
        "model",
        "reasoning_effort",
        "policy_version",
        "prompt_version",
        "schema_version",
        "max_output_tokens",
        "hard_budget_ceiling_usd",
        "input_price_per_million",
        "output_price_per_million",
    )
    differences = [
        {"field": field, "previous": previous.get(field), "current": current.get(field)}
        for field in fields
        if previous.get(field) != current.get(field)
    ]
    if not differences:
        differences.append(
            {"field": "configuration", "previous": "unchanged", "current": "unchanged"}
        )
    return differences


def _format_value(value: Any) -> str:
    if value is None:
        return "not available"
    if isinstance(value, float):
        return f"{value:.6f}"
    return str(value)


def _format_usd(value: Any) -> str:
    if not isinstance(value, (int, float)):
        return "not available"
    return f"${float(value):.6f}"


def write_run_readme(run_dir: Path, metadata: dict[str, Any]) -> None:
    notes = metadata.get("experiment_notes") or []
    differences = metadata.get("differences_from_previous") or []
    lines = [
        f"# Tier A run: {metadata['run_id']}",
        "",
        "This directory is one self-contained Tier A experiment. API attempts are",
        "append-only within this run; a changed model or reasoning setting must use a",
        "new run directory.",
        "Interpret this run under the canonical protocol in",
        "[`EXPERIMENT.md`](../../../../EXPERIMENT.md).",
        "",
        "## Run configuration",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Run date (UTC) | {_format_value(metadata.get('run_date_utc'))} |",
        f"| Created at (UTC) | {_format_value(metadata.get('created_at_utc'))} |",
        f"| Last executed at (UTC) | {_format_value(metadata.get('last_executed_at_utc'))} |",
        f"| Scored at (UTC) | {_format_value(metadata.get('scored_at_utc'))} |",
        f"| Model | `{_format_value(metadata.get('model'))}` |",
        f"| Reasoning effort | `{_format_value(metadata.get('reasoning_effort'))}` |",
        f"| Status | `{_format_value(metadata.get('status'))}` |",
        f"| Policy | `{_format_value(metadata.get('policy_version'))}` |",
        f"| Prompt | `{_format_value(metadata.get('prompt_version'))}` |",
        f"| Schema | `{_format_value(metadata.get('schema_version'))}` |",
        f"| Maximum output tokens | {_format_value(metadata.get('max_output_tokens'))} |",
        f"| Hard spending ceiling | {_format_usd(metadata.get('hard_budget_ceiling_usd'))} |",
        f"| Approved run budget | {_format_usd(metadata.get('approved_budget_usd'))} |",
        "",
        "## Experiment purpose",
        "",
    ]
    lines.extend(f"- {note}" for note in notes)
    if not notes:
        lines.append("- No researcher-supplied experiment note.")
    lines.extend(
        [
            "",
            "## Difference from the previous experiment",
            "",
            f"Previous run: `{metadata.get('previous_run_id') or 'none (baseline)'}`",
            "",
            "| Setting | Previous | This run |",
            "|---|---|---|",
        ]
    )
    for difference in differences:
        lines.append(
            "| {field} | {previous} | {current} |".format(
                field=difference["field"],
                previous=_format_value(difference.get("previous")),
                current=_format_value(difference.get("current")),
            )
        )

    metrics = metadata.get("metrics")
    if isinstance(metrics, dict):
        lines.extend(["", "## Scored outcome", "", "| Metric | Value |", "|---|---|"])
        for name in (
            "tasks",
            "decision_coverage",
            "end_to_end_recall",
            "observable_positive_recall",
            "precision",
            "end_to_end_specificity",
            "false_positive_rate",
            "balanced_accuracy",
            "strict_accuracy",
            "f1",
        ):
            lines.append(f"| `{name}` | {_format_value(metrics.get(name))} |")
        counts = metrics.get("counts") or {}
        if counts:
            lines.extend(
                [
                    "",
                    "Outcome counts: "
                    + ", ".join(f"`{key}`={value}" for key, value in sorted(counts.items()))
                    + ".",
                ]
            )

    lines.extend(
        [
            "",
            "## Pipeline interpretation",
            "",
            "Tier A scoring is strict: `indeterminate` remains an abstention with no",
            "correctness credit. The later cascade forwards both `vulnerable` and",
            "`indeterminate` to Tier B; forwarding does not relabel the Tier A result.",
            "",
            "## Artifacts",
            "",
            "- `run-metadata.json`: machine-readable experiment metadata.",
            "- `manifest.jsonl` and `manifest-summary.json`: frozen task/configuration plan.",
            "- `inputs/`: normalized isolated function inputs for this run.",
            "- `results.jsonl`: append-only API attempts for this run.",
            "- `scoring/`: task-level scores, summary metrics, and paired transitions.",
            "",
        ]
    )
    (run_dir / "README.md").write_text("\n".join(lines), encoding="utf-8")
