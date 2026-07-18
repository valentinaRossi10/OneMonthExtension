#!/usr/bin/env python3
"""Shared, dependency-light helpers for the Tier A benchmark."""

from __future__ import annotations

import hashlib
import json
import math
import re
from pathlib import Path
from typing import Any, Iterable


SKILL_ROOT = Path(__file__).resolve().parents[1]
REFERENCES = SKILL_ROOT / "references"


def load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def load_policy() -> dict[str, Any]:
    return load_json(REFERENCES / "benchmark-policy.json")


def load_rubrics() -> dict[str, Any]:
    return load_json(REFERENCES / "classification-rubrics.json")


def load_result_schema() -> dict[str, Any]:
    return load_json(REFERENCES / "result-schema.json")


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def normalize_bug_class(value: str) -> str:
    normalized = slug(value.removeprefix("memory-").replace("null", "NULL").lower())
    aliases = {
        "heap-buffer-overflow": "heap-buffer-overflow",
        "buffer-overflow": "heap-buffer-overflow",
        "use-after-free": "use-after-free",
        "integer-overflow": "integer-overflow",
        "null-pointer-dereference": "null-pointer-dereference",
        "null-dereference": "null-pointer-dereference",
        "out-of-bounds-read": "out-of-bounds-read",
        "command-injection": "command-injection",
    }
    if normalized not in aliases:
        raise ValueError(f"Unsupported bug class: {value!r}")
    return aliases[normalized]


def estimate_tokens(text: str, model: str | None = None) -> tuple[int, str]:
    """Return a token estimate; fall back conservatively for punctuation-heavy IR."""
    try:
        import tiktoken  # type: ignore
    except ImportError:
        return math.ceil(len(text) / 2), "conservative_chars_div_2"

    try:
        encoding = tiktoken.encoding_for_model(model or "")
    except KeyError:
        return math.ceil(len(text) / 2), "conservative_chars_div_2"
    return len(encoding.encode(text)), "tiktoken"


def estimate_cost_usd(
    input_tokens: int,
    output_tokens: int,
    input_price_per_million: float | None,
    output_price_per_million: float | None,
) -> float | None:
    if input_price_per_million is None or output_price_per_million is None:
        return None
    return (
        input_tokens * input_price_per_million
        + output_tokens * output_price_per_million
    ) / 1_000_000


def _signature_name(pseudo_c: str, indexed_name: str) -> str:
    opening = pseudo_c.find("{")
    header = pseudo_c[: opening if opening >= 0 else min(len(pseudo_c), 500)]
    if re.search(rf"\b{re.escape(indexed_name)}\s*\(", header):
        return indexed_name
    candidates = re.findall(r"\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\(", header)
    if not candidates:
        raise ValueError("Could not identify the pseudo-C target function signature")
    return candidates[-1]


def normalize_pseudo_c(text: str, indexed_name: str) -> str:
    actual_name = _signature_name(text, indexed_name)
    normalized = re.sub(
        rf"\b{re.escape(actual_name)}\b", "TARGET_FUNCTION", text
    )
    return normalized.strip() + "\n"


def _extract_llvm_type_declarations(module: str, body: str) -> list[str]:
    declarations: dict[str, tuple[int, str]] = {}
    for index, line in enumerate(module.splitlines()):
        match = re.match(r"^(%[^=]+?)\s*=\s*type\b", line)
        if match:
            declarations[match.group(1).strip()] = (index, line)

    needed = set(re.findall(r'%(?:"[^"]+"|[-A-Za-z$._][A-Za-z0-9$._-]*)', body))
    selected: set[str] = set()
    changed = True
    while changed:
        changed = False
        for name in sorted(needed - selected):
            if name not in declarations:
                continue
            selected.add(name)
            needed.update(
                re.findall(
                    r'%(?:"[^"]+"|[-A-Za-z$._][A-Za-z0-9$._-]*)',
                    declarations[name][1],
                )
            )
            changed = True
    return [declarations[name][1] for name in sorted(selected, key=lambda n: declarations[n][0])]


def extract_llvm_function(module: str, indexed_name: str) -> str:
    lines = module.splitlines()
    target_patterns = (
        re.compile(rf'@{re.escape(indexed_name)}\s*\('),
        re.compile(rf'@"{re.escape(indexed_name)}"\s*\('),
    )
    start = None
    for index, line in enumerate(lines):
        if line.startswith("define ") and any(p.search(line) for p in target_patterns):
            start = index
            break
    if start is None:
        raise ValueError(f"LLVM function {indexed_name!r} was not found")

    depth = 0
    saw_opening = False
    end = None
    for index in range(start, len(lines)):
        line = lines[index]
        depth += line.count("{")
        if "{" in line:
            saw_opening = True
        depth -= line.count("}")
        if saw_opening and depth == 0:
            end = index
            break
    if end is None:
        raise ValueError(f"LLVM function {indexed_name!r} has no balanced body")

    body_lines = lines[start : end + 1]
    cleaned: list[str] = []
    for line in body_lines:
        if "@llvm.dbg." in line:
            continue
        line = re.sub(r",?\s*![A-Za-z0-9_.-]+\s+!\d+", "", line)
        line = re.sub(rf'@"?{re.escape(indexed_name)}"?(?=\s*\()', "@TARGET_FUNCTION", line)
        cleaned.append(line.rstrip())
    body = "\n".join(cleaned)
    declarations = _extract_llvm_type_declarations(module, body)
    prefix = "\n".join(declarations)
    if prefix:
        body = prefix + "\n\n" + body
    return body.strip() + "\n"


def resolve_and_normalize_input(
    repo_root: Path, cve_id: str, project: str, variant: str, function_name: str
) -> tuple[str, str, Path]:
    sample_dir = f"{cve_id}-{project}"
    pseudo_path = repo_root / "pseudo-code" / sample_dir / f"{variant}.c"
    if pseudo_path.is_file():
        return (
            normalize_pseudo_c(pseudo_path.read_text(encoding="utf-8"), function_name),
            "ghidra_pseudo_c",
            pseudo_path,
        )

    ir_path = repo_root / "ir" / sample_dir / f"{variant}.ll"
    if not ir_path.is_file():
        raise FileNotFoundError(
            f"Neither pseudo-C nor LLVM IR exists for {sample_dir}/{variant}"
        )
    return (
        extract_llvm_function(ir_path.read_text(encoding="utf-8"), function_name),
        "llvm_ir",
        ir_path,
    )


def number_code(code: str) -> str:
    return "\n".join(f"{index:04d}: {line}" for index, line in enumerate(code.splitlines(), 1))


def build_prompt(code: str, representation: str, target_class: str) -> str:
    rubrics = load_rubrics()
    if target_class not in rubrics:
        raise ValueError(f"No rubric for {target_class}")
    rubric = rubrics[target_class]
    template = (REFERENCES / "prompt-template.txt").read_text(encoding="utf-8")
    bullets = lambda items: "\n".join(f"- {item}" for item in items)
    return template.format(
        target_class=target_class,
        definition=rubric["definition"],
        positive_evidence=bullets(rubric["positive_evidence"]),
        exclusions=bullets(rubric["exclusions"]),
        representation=representation,
        language="c" if representation == "ghidra_pseudo_c" else "llvm",
        numbered_code=number_code(code),
    )


def validate_model_result(value: Any, target_class: str, max_line: int) -> list[str]:
    errors: list[str] = []
    required = {
        "schema_version",
        "target_class",
        "verdict",
        "confidence",
        "evidence_lines",
        "summary",
    }
    if not isinstance(value, dict):
        return ["result is not an object"]
    if set(value) != required:
        errors.append(f"result keys must be exactly {sorted(required)}")
    if value.get("schema_version") != "tier-a-result-v1":
        errors.append("unexpected schema_version")
    if value.get("target_class") != target_class:
        errors.append("target_class does not match the requested class")
    if value.get("verdict") not in {
        "vulnerable",
        "not_vulnerable",
        "indeterminate",
    }:
        errors.append("invalid verdict")
    confidence = value.get("confidence")
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        errors.append("confidence must be numeric")
    elif not 0 <= confidence <= 1:
        errors.append("confidence must be between 0 and 1")
    evidence = value.get("evidence_lines")
    if not isinstance(evidence, list) or any(
        isinstance(item, bool) or not isinstance(item, int) for item in evidence
    ):
        errors.append("evidence_lines must be an integer array")
    elif len(evidence) != len(set(evidence)) or any(
        item < 1 or item > max_line for item in evidence
    ):
        errors.append("evidence_lines contain duplicates or out-of-range values")
    summary = value.get("summary")
    if not isinstance(summary, str) or not summary.strip() or len(summary) > 800:
        errors.append("summary must contain 1-800 characters")
    return errors


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSONL at {path}:{line_number}: {exc}") from exc
            if not isinstance(value, dict):
                raise ValueError(f"Expected object at {path}:{line_number}")
            rows.append(value)
    return rows


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
