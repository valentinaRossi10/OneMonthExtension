#!/usr/bin/env python3
"""Shared deterministic helpers for the recall-first Tier B MVP."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


SKILL_ROOT = Path(__file__).resolve().parents[1]
REFERENCES = SKILL_ROOT / "references"

SUPPORTED_CLASSES = {
    "command-injection",
    "heap-buffer-overflow",
    "integer-overflow",
    "null-pointer-dereference",
    "out-of-bounds-read",
    "use-after-free",
}

CLASS_ALIASES = {
    "command injection": "command-injection",
    "heap buffer overflow": "heap-buffer-overflow",
    "heap-buffer-overflow": "heap-buffer-overflow",
    "integer overflow": "integer-overflow",
    "null pointer dereference": "null-pointer-dereference",
    "null-pointer-dereference": "null-pointer-dereference",
    "out of bounds read": "out-of-bounds-read",
    "out-of-bounds-read": "out-of-bounds-read",
    "use after free": "use-after-free",
    "use-after-free": "use-after-free",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_text(value: str) -> str:
    return sha256_bytes(value.encode("utf-8"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, raw in enumerate(handle, 1):
            if not raw.strip():
                continue
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_number}: expected JSON object")
            rows.append(value)
    return rows


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    text = "".join(canonical_json(row) + "\n" for row in rows)
    path.write_text(text, encoding="utf-8")


def normalize_class(value: str) -> str:
    normalized = value.strip().lower().replace("_", "-")
    normalized = " ".join(normalized.split())
    result = CLASS_ALIASES.get(normalized, normalized)
    if result not in SUPPORTED_CLASSES:
        raise ValueError(f"Unsupported target class: {value!r}")
    return result


def load_policy() -> dict[str, Any]:
    policy = load_json(REFERENCES / "tier-b-filter-policy.json")
    if set(policy["supported_classes"]) != SUPPORTED_CLASSES:
        raise ValueError("Policy supported classes differ from the implementation")
    return policy


OPENAI_STRUCTURED_OUTPUT_MAX_PROPERTIES = 5_000
OPENAI_STRUCTURED_OUTPUT_MAX_NESTING = 10
OPENAI_STRUCTURED_OUTPUT_MAX_SCHEMA_STRING_CHARS = 120_000
OPENAI_STRUCTURED_OUTPUT_MAX_ENUM_VALUES = 1_000
OPENAI_STRUCTURED_OUTPUT_LARGE_ENUM_THRESHOLD = 250
OPENAI_STRUCTURED_OUTPUT_MAX_LARGE_ENUM_STRING_CHARS = 15_000

_SUPPORTED_SCHEMA_TYPES = {
    "string",
    "number",
    "boolean",
    "integer",
    "object",
    "array",
    "null",
}
_COMMON_SCHEMA_KEYWORDS = {
    "$ref",
    "$defs",
    "type",
    "enum",
    "const",
    "description",
    "title",
    "anyOf",
}
_TYPE_SCHEMA_KEYWORDS = {
    "object": {"properties", "required", "additionalProperties"},
    "array": {"items", "minItems", "maxItems"},
    "string": {"minLength", "maxLength", "pattern", "format"},
    "number": {
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "multipleOf",
    },
    "integer": {
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "multipleOf",
    },
    "boolean": set(),
    "null": set(),
}
_UNSUPPORTED_COMPOSITION_KEYWORDS = {
    "allOf",
    "not",
    "dependentRequired",
    "dependentSchemas",
    "if",
    "then",
    "else",
}
_FINE_TUNED_UNSUPPORTED_KEYWORDS = {
    "minLength",
    "maxLength",
    "pattern",
    "format",
    "minimum",
    "maximum",
    "multipleOf",
    "patternProperties",
    "minItems",
    "maxItems",
}
_SUPPORTED_STRING_FORMATS = {
    "date-time",
    "time",
    "date",
    "duration",
    "email",
    "hostname",
    "ipv4",
    "ipv6",
    "uuid",
}


def audit_strict_json_schema(
    node: Any,
    *,
    fine_tuned_model: bool = False,
) -> dict[str, Any]:
    """Audit one schema against OpenAI's documented Structured Outputs subset.

    The returned report contains every violation found in one pass.  Root
    ``$schema`` and ``title`` metadata are accepted because the harness removes
    those two annotations before sending the otherwise identical schema to the
    Responses API.
    """
    errors: list[str] = []
    property_count = 0
    enum_value_count = 0
    schema_string_chars = 0
    maximum_object_nesting = 0

    if not isinstance(node, dict):
        return {
            "errors": ["$: schema node must be an object"],
            "property_count": 0,
            "maximum_object_nesting": 0,
            "schema_string_chars": 0,
            "enum_value_count": 0,
        }
    if node.get("type") != "object":
        errors.append("$: root schema must declare type object")
    if "anyOf" in node:
        errors.append("$: root schema must not use anyOf")

    def schema_types(value: Any, path: str) -> set[str]:
        if isinstance(value, str):
            values = {value}
        elif (
            isinstance(value, list)
            and value
            and all(isinstance(item, str) for item in value)
            and len(value) == len(set(value))
        ):
            values = set(value)
        else:
            errors.append(f"{path}.type: type must be a string or unique string array")
            return set()
        unsupported = sorted(values - _SUPPORTED_SCHEMA_TYPES)
        if unsupported:
            errors.append(
                f"{path}.type: unsupported schema types: {', '.join(unsupported)}"
            )
        if "null" in values and len(values) == 1:
            errors.append(f"{path}.type: null is supported only in a union")
        return values

    def walk(value: Any, path: str, object_depth: int) -> None:
        nonlocal property_count
        nonlocal enum_value_count
        nonlocal schema_string_chars
        nonlocal maximum_object_nesting

        if not isinstance(value, dict):
            errors.append(f"{path}: schema node must be an object")
            return

        declared_types: set[str] = set()
        if "type" in value:
            declared_types = schema_types(value["type"], path)
        elif "$ref" not in value and "anyOf" not in value:
            errors.append(f"{path}: schema node must declare an explicit type")

        if ("const" in value or "enum" in value) and "type" not in value:
            errors.append(f"{path}: const/enum schema must declare an explicit type")

        allowed = set(_COMMON_SCHEMA_KEYWORDS)
        for declared_type in declared_types:
            allowed.update(_TYPE_SCHEMA_KEYWORDS.get(declared_type, set()))
        if path == "$":
            allowed.add("$schema")
        for keyword in value:
            keyword_path = f"{path}.{keyword}"
            if keyword in _UNSUPPORTED_COMPOSITION_KEYWORDS:
                errors.append(
                    f"{keyword_path}: unsupported Structured Outputs composition keyword"
                )
            elif keyword == "uniqueItems":
                errors.append(
                    f"{keyword_path}: unsupported Structured Outputs array keyword"
                )
            elif keyword not in allowed:
                errors.append(
                    f"{keyword_path}: unsupported or misplaced Structured Outputs keyword"
                )
            if fine_tuned_model and keyword in _FINE_TUNED_UNSUPPORTED_KEYWORDS:
                errors.append(
                    f"{keyword_path}: unsupported for fine-tuned Structured Outputs"
                )

        if "$schema" in value and path != "$":
            errors.append(f"{path}.$schema: metadata keyword is allowed only at root")
        if "$ref" in value:
            ref = value["$ref"]
            if not isinstance(ref, str) or not ref.startswith("#"):
                errors.append(f"{path}.$ref: only local references are supported")

        if "enum" in value:
            enum = value["enum"]
            if not isinstance(enum, list) or not enum:
                errors.append(f"{path}.enum: enum must be a non-empty array")
            else:
                enum_value_count += len(enum)
                string_chars = sum(
                    len(item) for item in enum if isinstance(item, str)
                )
                schema_string_chars += string_chars
                if (
                    len(enum) > OPENAI_STRUCTURED_OUTPUT_LARGE_ENUM_THRESHOLD
                    and string_chars
                    > OPENAI_STRUCTURED_OUTPUT_MAX_LARGE_ENUM_STRING_CHARS
                ):
                    errors.append(
                        f"{path}.enum: string values exceed "
                        f"{OPENAI_STRUCTURED_OUTPUT_MAX_LARGE_ENUM_STRING_CHARS} "
                        "characters for an enum with more than "
                        f"{OPENAI_STRUCTURED_OUTPUT_LARGE_ENUM_THRESHOLD} values"
                    )
        if isinstance(value.get("const"), str):
            schema_string_chars += len(value["const"])

        if "format" in value and value["format"] not in _SUPPORTED_STRING_FORMATS:
            errors.append(
                f"{path}.format: unsupported string format {value['format']!r}"
            )

        if "object" in declared_types:
            next_depth = object_depth + 1
            maximum_object_nesting = max(maximum_object_nesting, next_depth)
            properties = value.get("properties")
            required = value.get("required")
            if not isinstance(properties, dict):
                errors.append(f"{path}: object schema must declare properties")
                properties = {}
            if value.get("additionalProperties") is not False:
                errors.append(f"{path}: object schema must forbid additional properties")
            if not isinstance(required, list) or set(required) != set(properties):
                errors.append(f"{path}: every object property must be required")
            elif len(required) != len(set(required)):
                errors.append(f"{path}: required contains duplicate property names")
            property_count += len(properties)
            schema_string_chars += sum(len(name) for name in properties)
            for name, child in properties.items():
                walk(child, f"{path}.properties.{name}", next_depth)

        if "array" in declared_types:
            items = value.get("items")
            if not isinstance(items, dict):
                errors.append(f"{path}: array schema must declare one items schema")
            else:
                walk(items, f"{path}.items", object_depth)

        any_of = value.get("anyOf")
        if any_of is not None:
            if not isinstance(any_of, list) or not any_of:
                errors.append(f"{path}.anyOf: anyOf must be a non-empty array")
            else:
                for index, child in enumerate(any_of):
                    walk(child, f"{path}.anyOf[{index}]", object_depth)

        definitions = value.get("$defs")
        if definitions is not None:
            if not isinstance(definitions, dict):
                errors.append(f"{path}.$defs: definitions must be an object")
            else:
                schema_string_chars += sum(len(name) for name in definitions)
                for name, child in definitions.items():
                    walk(child, f"{path}.$defs.{name}", object_depth)

    walk(node, "$", 0)
    if property_count > OPENAI_STRUCTURED_OUTPUT_MAX_PROPERTIES:
        errors.append(
            "$: schema has "
            f"{property_count} object properties; maximum is "
            f"{OPENAI_STRUCTURED_OUTPUT_MAX_PROPERTIES}"
        )
    if maximum_object_nesting > OPENAI_STRUCTURED_OUTPUT_MAX_NESTING:
        errors.append(
            "$: schema has "
            f"{maximum_object_nesting} object nesting levels; maximum is "
            f"{OPENAI_STRUCTURED_OUTPUT_MAX_NESTING}"
        )
    if schema_string_chars > OPENAI_STRUCTURED_OUTPUT_MAX_SCHEMA_STRING_CHARS:
        errors.append(
            "$: schema property/definition/enum/const strings total "
            f"{schema_string_chars} characters; maximum is "
            f"{OPENAI_STRUCTURED_OUTPUT_MAX_SCHEMA_STRING_CHARS}"
        )
    if enum_value_count > OPENAI_STRUCTURED_OUTPUT_MAX_ENUM_VALUES:
        errors.append(
            "$: schema has "
            f"{enum_value_count} enum values; maximum is "
            f"{OPENAI_STRUCTURED_OUTPUT_MAX_ENUM_VALUES}"
        )
    return {
        "errors": errors,
        "property_count": property_count,
        "maximum_object_nesting": maximum_object_nesting,
        "schema_string_chars": schema_string_chars,
        "enum_value_count": enum_value_count,
        "fine_tuned_model": fine_tuned_model,
    }


def validate_strict_json_schema(
    node: Any,
    path: str = "$",
    *,
    fine_tuned_model: bool = False,
) -> None:
    """Reject every detected Structured Outputs incompatibility offline."""
    if path != "$":
        raise ValueError("Structured Outputs audit must start at the schema root")
    report = audit_strict_json_schema(
        node,
        fine_tuned_model=fine_tuned_model,
    )
    if report["errors"]:
        raise ValueError(
            "Structured Outputs schema is invalid:\n- "
            + "\n- ".join(report["errors"])
        )


def estimate_tokens(text: str, chars_per_token: int) -> int:
    return max(1, math.ceil(len(text) / chars_per_token))


def estimate_cost_usd(
    input_tokens: int,
    output_tokens: int,
    input_price_per_million: float,
    output_price_per_million: float,
) -> float:
    return (
        input_tokens * input_price_per_million
        + output_tokens * output_price_per_million
    ) / 1_000_000


def projection_for_case(
    prompt: str,
    policy: dict[str, Any],
    input_price_per_million: float,
    output_price_per_million: float,
    fixed_request_text: str,
    *,
    include_extension: bool,
    current_request_reserve_chars: int = 0,
    replay_context_reserve_chars: int = 0,
) -> dict[str, Any]:
    limits = policy["limits"]
    chars_per_token = limits["chars_per_estimated_token"]
    prompt_tokens = estimate_tokens(prompt, chars_per_token)
    fixed_tokens = estimate_tokens(fixed_request_text, chars_per_token)
    tool_tokens = math.ceil(limits["max_tool_result_chars"] / chars_per_token)
    current_request_reserve_tokens = math.ceil(
        current_request_reserve_chars / chars_per_token
    )
    replay_context_reserve_tokens = math.ceil(
        replay_context_reserve_chars / chars_per_token
    )
    calls = limits["base_model_calls"]
    if include_extension:
        calls += limits["extension_model_calls"]
    output_cap = limits["max_output_tokens_per_call"]
    input_by_call = [
        fixed_tokens
        + prompt_tokens
        + current_request_reserve_tokens
        + index
        * (
            tool_tokens
            + output_cap
            + replay_context_reserve_tokens
        )
        for index in range(calls)
    ]
    if max(input_by_call) > 272_000:
        raise ValueError(
            "Projection enters the model long-context pricing tier; "
            "use an explicitly tier-aware pricing policy"
        )
    total_input = sum(input_by_call)
    total_output = calls * output_cap
    return {
        "estimated_prompt_tokens": prompt_tokens,
        "estimated_fixed_request_tokens_per_call": fixed_tokens,
        "reserved_tool_result_tokens_per_tool_call": tool_tokens,
        "reserved_runner_current_request_tokens_per_call":
            current_request_reserve_tokens,
        "reserved_runner_replay_tokens_per_prior_call":
            replay_context_reserve_tokens,
        "projected_input_tokens_by_call": input_by_call,
        "projected_max_input_tokens": total_input,
        "projected_max_output_tokens": total_output,
        "projected_max_cost_usd": estimate_cost_usd(
            total_input,
            total_output,
            input_price_per_million,
            output_price_per_million,
        ),
    }


def require_new_directory(path: Path) -> Path:
    resolved = path.resolve()
    if resolved.exists():
        raise FileExistsError(f"Refusing to replace existing directory: {resolved}")
    resolved.mkdir(parents=True)
    return resolved


def api_tools(policy: dict[str, Any]) -> list[dict[str, Any]]:
    max_hits = policy["limits"]["max_search_hits"]
    return [
        {
            "type": "function",
            "name": "get_function",
            "description": "Read numbered pseudo-C lines for one artifact-scoped function UID.",
            "strict": True,
            "parameters": {
                "type": "object",
                "additionalProperties": False,
                "required": ["function_uid", "start_line", "end_line"],
                "properties": {
                    "function_uid": {"type": "string"},
                    "start_line": {"type": "integer", "minimum": 1},
                    "end_line": {"type": "integer", "minimum": 1},
                },
            },
        },
        {
            "type": "function",
            "name": "get_callsites",
            "description": "Get analyzed direct and explicit unresolved indirect call sites for a function.",
            "strict": True,
            "parameters": {
                "type": "object",
                "additionalProperties": False,
                "required": ["function_uid"],
                "properties": {"function_uid": {"type": "string"}},
            },
        },
        {
            "type": "function",
            "name": "get_callers",
            "description": "Get analyzed direct callers of one function UID.",
            "strict": True,
            "parameters": {
                "type": "object",
                "additionalProperties": False,
                "required": ["function_uid"],
                "properties": {"function_uid": {"type": "string"}},
            },
        },
        {
            "type": "function",
            "name": "get_function_identity",
            "description": "Get artifact-scoped identity fingerprints and neutral references.",
            "strict": True,
            "parameters": {
                "type": "object",
                "additionalProperties": False,
                "required": ["function_uid"],
                "properties": {"function_uid": {"type": "string"}},
            },
        },
        {
            "type": "function",
            "name": "search_code",
            "description": "Search all packaged pseudo-C functions for a literal text fragment.",
            "strict": True,
            "parameters": {
                "type": "object",
                "additionalProperties": False,
                "required": ["query"],
                "properties": {
                    "query": {"type": "string", "minLength": 1, "maxLength": 200}
                },
            },
        },
    ]


class AnalysisPackage:
    """Hash-verifying access to one MVP analysis package."""

    REQUIRED_METADATA = {
        "package_version",
        "package_id",
        "created_at_utc",
        "artifact_path",
        "artifact_sha256",
        "analysis_artifact_md5",
        "corpus_root",
        "corpus_sha256",
        "analysis_export_sha256",
        "analysis_tool",
        "analysis_version",
        "function_count",
        "callsite_count",
        "unresolved_indirect_callsite_count",
        "total_source_chars",
        "functions_index",
        "callsites_index",
        "functions_sha256",
        "callsites_sha256",
    }

    def __init__(self, package_dir: Path, policy: dict[str, Any]):
        self.package_dir = package_dir.resolve()
        self.policy = policy
        self.metadata = load_json(self.package_dir / "package.json")
        if set(self.metadata) != self.REQUIRED_METADATA:
            raise ValueError("Package metadata fields are not exact")
        if self.metadata["package_version"] != policy["package_version"]:
            raise ValueError("Package version differs from policy")
        functions_path = self.package_dir / self.metadata["functions_index"]
        callsites_path = self.package_dir / self.metadata["callsites_index"]
        if sha256_file(functions_path) != self.metadata["functions_sha256"]:
            raise ValueError("Function index hash mismatch")
        if sha256_file(callsites_path) != self.metadata["callsites_sha256"]:
            raise ValueError("Call-site index hash mismatch")
        self.function_rows = read_jsonl(functions_path)
        self.callsite_rows = read_jsonl(callsites_path)
        if len(self.function_rows) != self.metadata["function_count"]:
            raise ValueError("Function count mismatch")
        if len(self.callsite_rows) != self.metadata["callsite_count"]:
            raise ValueError("Call-site count mismatch")
        self.functions = {row["function_uid"]: row for row in self.function_rows}
        if len(self.functions) != len(self.function_rows):
            raise ValueError("Duplicate function UID")
        self.callsites_by_caller: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.callers_by_target: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in self.callsite_rows:
            caller = row.get("caller_uid")
            if caller not in self.functions:
                raise ValueError("Call site names an unknown caller")
            self.callsites_by_caller[caller].append(row)
            target = row.get("target_uid")
            if target:
                if target not in self.functions:
                    raise ValueError("Call site names an unknown target")
                self.callers_by_target[target].append(row)
        unresolved = sum(
            row.get("resolution_status") == "unresolved"
            for row in self.callsite_rows
        )
        if unresolved != self.metadata["unresolved_indirect_callsite_count"]:
            raise ValueError("Unresolved indirect-call count mismatch")
        self.corpus_root = Path(self.metadata["corpus_root"]).resolve()
        self.artifact_path = Path(self.metadata["artifact_path"]).resolve()

    def verify_frozen_inputs(self) -> None:
        if not self.artifact_path.is_file():
            raise ValueError("Frozen artifact is missing")
        if sha256_file(self.artifact_path) != self.metadata["artifact_sha256"]:
            raise ValueError("Frozen artifact hash mismatch")
        artifact_md5 = hashlib.md5(usedforsecurity=False)
        with self.artifact_path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                artifact_md5.update(chunk)
        if artifact_md5.hexdigest() != self.metadata["analysis_artifact_md5"]:
            raise ValueError("Frozen artifact no longer matches the analysis export")
        if not self.corpus_root.is_dir():
            raise ValueError("Frozen corpus root is missing")
        corpus_rows = []
        total_chars = 0
        for row in sorted(self.function_rows, key=lambda item: item["address"]):
            source_path = (self.corpus_root / row["source_relpath"]).resolve()
            if not source_path.is_relative_to(self.corpus_root):
                raise ValueError("Function source escapes the corpus root")
            text = source_path.read_text(encoding="utf-8")
            if sha256_text(text) != row["source_sha256"]:
                raise ValueError(f"Source hash mismatch: {row['function_uid']}")
            if len(text) != row["source_chars"]:
                raise ValueError(f"Source length mismatch: {row['function_uid']}")
            total_chars += len(text)
            corpus_rows.append(
                {
                    "address": row["address"],
                    "relative_path": row["source_relpath"],
                    "source_sha256": row["source_sha256"],
                }
            )
        if sha256_text(canonical_json(corpus_rows)) != self.metadata["corpus_sha256"]:
            raise ValueError("Corpus hash mismatch")
        if total_chars != self.metadata["total_source_chars"]:
            raise ValueError("Corpus character count mismatch")

    def _function_text(self, function_uid: str) -> str:
        row = self.functions.get(function_uid)
        if row is None:
            raise ValueError("Unknown function UID")
        path = (self.corpus_root / row["source_relpath"]).resolve()
        if not path.is_relative_to(self.corpus_root):
            raise ValueError("Function source escapes the corpus root")
        text = path.read_text(encoding="utf-8")
        if sha256_text(text) != row["source_sha256"]:
            raise ValueError("Function source hash mismatch")
        if len(text) > self.policy["limits"]["max_function_chars"]:
            raise ValueError("Function exceeds the configured size guard")
        return text

    def has_any_unresolved_indirect(self) -> bool:
        return bool(self.metadata["unresolved_indirect_callsite_count"])

    def execute_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        max_chars = self.policy["limits"]["max_tool_result_chars"]
        max_hits = self.policy["limits"]["max_search_hits"]
        if name == "get_function":
            uid = str(arguments["function_uid"])
            start = int(arguments["start_line"])
            end = int(arguments["end_line"])
            if end < start or end - start > 400:
                raise ValueError("Invalid function line range")
            lines = self._function_text(uid).splitlines()
            selected = [
                f"{index}: {lines[index - 1]}"
                for index in range(start, min(end, len(lines)) + 1)
            ]
            result: dict[str, Any] = {
                "function_uid": uid,
                "start_line": start,
                "end_line": min(end, len(lines)),
                "total_lines": len(lines),
                "code": "\n".join(selected),
            }
        elif name == "get_callsites":
            uid = str(arguments["function_uid"])
            if uid not in self.functions:
                raise ValueError("Unknown function UID")
            result = {
                "function_uid": uid,
                "callsites": self.callsites_by_caller.get(uid, [])[:max_hits],
                "truncated": len(self.callsites_by_caller.get(uid, [])) > max_hits,
            }
        elif name == "get_callers":
            uid = str(arguments["function_uid"])
            if uid not in self.functions:
                raise ValueError("Unknown function UID")
            result = {
                "function_uid": uid,
                "callers": self.callers_by_target.get(uid, [])[:max_hits],
                "truncated": len(self.callers_by_target.get(uid, [])) > max_hits,
            }
        elif name == "get_function_identity":
            uid = str(arguments["function_uid"])
            row = self.functions.get(uid)
            if row is None:
                raise ValueError("Unknown function UID")
            result = {
                "function_uid": uid,
                "artifact_sha256": self.metadata["artifact_sha256"],
                "address": row["address"],
                "byte_sha256": row["byte_sha256"],
                "normalized_instruction_sha256": row[
                    "normalized_instruction_sha256"
                ],
                "size_bytes": row["size_bytes"],
                "block_count": row["block_count"],
                "strings": row["strings"],
                "data_references": row["data_references"],
            }
        elif name == "search_code":
            query = str(arguments["query"])
            if not query or len(query) > 200:
                raise ValueError("Invalid search query")
            hits = []
            for uid in sorted(self.functions):
                for line, text in enumerate(self._function_text(uid).splitlines(), 1):
                    if query in text:
                        hits.append(
                            {"function_uid": uid, "line": line, "text": text[:1000]}
                        )
                        if len(hits) >= max_hits:
                            break
                if len(hits) >= max_hits:
                    break
            result = {"query": query, "hits": hits, "truncated": len(hits) >= max_hits}
        else:
            raise ValueError(f"Unknown tool: {name}")
        encoded = canonical_json(result)
        if len(encoded) > max_chars:
            return {
                "error": "tool_result_too_large",
                "result_sha256": sha256_text(encoded),
                "result_chars": len(encoded),
            }
        return result


def fallback_result(
    task: dict[str, Any],
    execution_status: str,
    reason: str,
    progress_events: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": task.get("schema_version", "tier-b-filter-result-v2"),
        "target_class": task["target_class"],
        "semantic_status": "unresolved",
        "pipeline_disposition": "retain_and_escalate",
        "execution_status": execution_status,
        "candidate_identity": {
            "status": "present",
            "function_uid": task["function_uid"],
            "artifact_sha256": task["artifact_sha256"],
            "evidence": "The prepared package binds this artifact-scoped function UID.",
        },
        "hypotheses": [
            {
                "hypothesis": "The requested class remains unresolved.",
                "status": "unresolved",
                "evidence": [],
            }
        ],
        "proof_obligations": [
            {
                "obligation": "Complete the requested class proof obligations.",
                "status": "unresolved",
                "evidence": [],
            }
        ],
        "reachability": "unresolved",
        "evidence": [],
        "blocking_controls": [],
        "unresolved_facts": [reason],
        "progress_events": progress_events or [],
        "summary": reason,
    }


def validate_model_result(
    value: Any,
    task: dict[str, Any],
    package: AnalysisPackage,
) -> list[str]:
    errors: list[str] = []
    if not isinstance(value, dict):
        return ["Result is not a JSON object"]
    required = {
        "schema_version",
        "target_class",
        "semantic_status",
        "pipeline_disposition",
        "execution_status",
        "candidate_identity",
        "hypotheses",
        "proof_obligations",
        "reachability",
        "evidence",
        "blocking_controls",
        "unresolved_facts",
        "progress_events",
        "summary",
    }
    if set(value) != required:
        errors.append("Result fields are not exact")
    if value.get("schema_version") != task.get(
        "schema_version", "tier-b-filter-result-v2"
    ):
        errors.append("schema_version is invalid")
    if value.get("target_class") != task["target_class"]:
        errors.append("target_class differs from the task")
    semantic = value.get("semantic_status")
    disposition = value.get("pipeline_disposition")
    execution = value.get("execution_status")
    valid_mapping = {
        ("confirmed", "retain_confirmed"),
        ("safety_proven", "suppress_proven_false_positive"),
        ("unresolved", "retain_and_escalate"),
    }
    if (semantic, disposition) not in valid_mapping:
        errors.append("Semantic status and pipeline disposition are inconsistent")
    if execution != "completed":
        errors.append("A model-returned result must use execution_status=completed")
    identity = value.get("candidate_identity")
    if not isinstance(identity, dict):
        errors.append("candidate_identity is invalid")
        identity = {}
    else:
        if identity.get("function_uid") != task["function_uid"]:
            errors.append("candidate function UID differs from the task")
        if identity.get("artifact_sha256") != task["artifact_sha256"]:
            errors.append("candidate artifact hash differs from the task")
        if identity.get("status") not in {"present", "absent", "ambiguous"}:
            errors.append("candidate identity status is invalid")
    hypotheses = value.get("hypotheses")
    obligations = value.get("proof_obligations")
    if not isinstance(hypotheses, list) or not hypotheses:
        errors.append("At least one hypothesis is required")
        hypotheses = []
    if not isinstance(obligations, list) or not obligations:
        errors.append("At least one proof obligation is required")
        obligations = []
    allowed_state = {"satisfied", "contradicted", "unresolved"}
    for label, rows in (("hypothesis", hypotheses), ("proof obligation", obligations)):
        for row in rows:
            if not isinstance(row, dict) or row.get("status") not in allowed_state:
                errors.append(f"{label} status is invalid")
    if disposition == "retain_confirmed":
        if identity.get("status") != "present":
            errors.append("Confirmation requires a present candidate")
        if value.get("reachability") != "reachable":
            errors.append("Confirmation requires evidenced reachability")
        if any(row.get("status") != "satisfied" for row in obligations):
            errors.append("Confirmation requires every proof obligation satisfied")
    if disposition == "suppress_proven_false_positive":
        if identity.get("status") == "ambiguous":
            errors.append("Suppression is forbidden for ambiguous identity")
        if any(row.get("status") == "unresolved" for row in hypotheses + obligations):
            errors.append("Suppression is forbidden with unresolved proof states")
        if not all(row.get("status") == "contradicted" for row in hypotheses):
            errors.append("Suppression requires every relevant hypothesis contradicted")
        if (
            value.get("reachability") == "unreachable"
            and package.has_any_unresolved_indirect()
        ):
            errors.append(
                "Unreachability suppression is forbidden while the MVP package "
                "contains unresolved indirect calls"
            )
    if disposition == "retain_and_escalate" and semantic != "unresolved":
        errors.append("Escalation must use unresolved semantic status")
    return errors
