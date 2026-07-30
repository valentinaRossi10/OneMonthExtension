#!/usr/bin/env python3
"""Additive v4 contradiction-evidence gate for recall-first Tier B."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import filter_v3 as v3
from filter_common import (
    REFERENCES,
    SUPPORTED_CLASSES,
    AnalysisPackage,
    load_json,
    sha256_file,
)


V4_REFERENCES = REFERENCES / "v4"
V4_SCHEMA_VERSION = "tier-b-filter-result-v4"
V4_POLICY_VERSION = "tier-b-filter-policy-v4"
V4_PROMPT_VERSION = "tier-b-filter-prompt-v4"
V4_COMPARISON_SCOPE_VERSION = (
    "tier-b-filter-v4-six-case-comparison-scope-v1"
)
V4_CVE_2021_42374_SCOPE_VERSION = (
    "tier-b-filter-v4-cve-2021-42374-contradiction-gate-scope-v1"
)
V4_CVE_2021_42374_POLICY_VERSION = (
    "tier-b-filter-policy-v4-cve-2021-42374-8192-v1"
)
V4_STATIC_PRIMARY_SCOPE_VERSION = (
    "tier-b-filter-v4-static-primary-three-case-scope-v1"
)
V4_STATIC_PRIMARY_POLICY_VERSION = (
    "tier-b-filter-policy-v4-static-primary-v1"
)
V4_STATIC_REQUIRED_TOOLS_SCOPE_VERSION = (
    "tier-b-filter-v4-static-primary-required-tools-three-case-scope-v2"
)
V4_STATIC_REQUIRED_TOOLS_POLICY_VERSION = (
    "tier-b-filter-policy-v4-static-required-tools-v2"
)
V4_STATIC_REQUIRED_TOOLS_PROMPT_VERSION = (
    "tier-b-filter-prompt-v5-required-static-tools"
)
V4_STATIC_ROUND3_SCOPE_VERSION = (
    "tier-b-filter-v4-static-required-tools-two-case-round3-scope-v3"
)
V4_STATIC_ROUND3_POLICY_VERSION = (
    "tier-b-filter-policy-v4-static-round3-v3"
)
V4_STATIC_ROUND3_PROMPT_VERSION = (
    "tier-b-filter-prompt-v6-uniform-defensive-retry-extension"
)
V4_REQUIRED_STATIC_TOOLS = {
    "get_reaching_definitions",
    "slice_pcode",
    "get_dominance",
    "query_angr",
}

CONTRADICTION_BASIS_KINDS = {
    "guard",
    "range_check",
    "type_or_size_fact",
    "data_flow_fact",
    "control_flow_fact",
    "lifetime_fact",
    "not_applicable",
}
CONTRADICTION_VALUE_RELATIONS = {
    "exact_same_value_state",
    "explicitly_proven_equivalent",
    "non_value_fact_directly_excludes",
    "unresolved",
    "not_applicable",
}
CONTRADICTION_PROOF_FIELDS = {
    "applicability",
    "basis_kind",
    "claim",
    "value_relation",
    "citations",
    "equivalence_evidence",
}
CONTRADICTION_CITATION_FIELDS = {
    "function_uid",
    "line",
    "evidence",
}
V4_HYPOTHESIS_FIELDS = {
    "hypothesis_id",
    "target_class",
    "hypothesis",
    "result",
    "evidence",
    "contradiction_proof",
}


def neutral_contradiction_proof() -> dict[str, Any]:
    return {
        "applicability": "not_applicable",
        "basis_kind": "not_applicable",
        "claim": "",
        "value_relation": "not_applicable",
        "citations": [],
        "equivalence_evidence": [],
    }


def load_policy_for_protocol(
    protocol_version: str,
    policy_version: str | None = None,
) -> dict[str, Any]:
    if protocol_version != "v4":
        return v3.load_policy_for_protocol(protocol_version, policy_version)
    if policy_version in {None, V4_POLICY_VERSION}:
        policy_path = V4_REFERENCES / "tier-b-filter-policy.json"
        expected_scope = V4_COMPARISON_SCOPE_VERSION
        expected_prompt = V4_PROMPT_VERSION
    elif policy_version == V4_CVE_2021_42374_POLICY_VERSION:
        policy_path = (
            V4_REFERENCES
            / "tier-b-filter-policy-cve-2021-42374-8192-v1.json"
        )
        expected_scope = V4_CVE_2021_42374_SCOPE_VERSION
        expected_prompt = V4_PROMPT_VERSION
    elif policy_version == V4_STATIC_PRIMARY_POLICY_VERSION:
        policy_path = (
            V4_REFERENCES
            / "tier-b-filter-policy-static-primary-v1.json"
        )
        expected_scope = V4_STATIC_PRIMARY_SCOPE_VERSION
        expected_prompt = V4_PROMPT_VERSION
    elif policy_version == V4_STATIC_REQUIRED_TOOLS_POLICY_VERSION:
        policy_path = (
            V4_REFERENCES
            / "tier-b-filter-policy-static-required-tools-v2.json"
        )
        expected_scope = V4_STATIC_REQUIRED_TOOLS_SCOPE_VERSION
        expected_prompt = V4_STATIC_REQUIRED_TOOLS_PROMPT_VERSION
    elif policy_version == V4_STATIC_ROUND3_POLICY_VERSION:
        policy_path = (
            V4_REFERENCES / "tier-b-filter-policy-static-round3-v3.json"
        )
        expected_scope = V4_STATIC_ROUND3_SCOPE_VERSION
        expected_prompt = V4_STATIC_ROUND3_PROMPT_VERSION
    else:
        raise ValueError(f"Unsupported V4 policy version: {policy_version}")
    policy = load_json(policy_path)
    if policy.get("policy_version") not in {
        V4_POLICY_VERSION,
        V4_CVE_2021_42374_POLICY_VERSION,
        V4_STATIC_PRIMARY_POLICY_VERSION,
        V4_STATIC_REQUIRED_TOOLS_POLICY_VERSION,
        V4_STATIC_ROUND3_POLICY_VERSION,
    }:
        raise ValueError("V4 policy version is invalid")
    if policy.get("prompt_version") != expected_prompt:
        raise ValueError("V4 prompt version is invalid")
    if policy.get("schema_version") != V4_SCHEMA_VERSION:
        raise ValueError("V4 policy has the wrong schema version")
    if policy.get("reviewed_scope") != expected_scope:
        raise ValueError("V4 policy is not bound to its reviewed scope")
    if set(policy.get("supported_classes", [])) != SUPPORTED_CLASSES:
        raise ValueError("V4 policy supported classes differ from the implementation")
    required_priority = {
        "primary_objective": "retain_confirmed",
        "secondary_objective": "suppress_proven_false_positive",
        "confirmation_has_full_base_allowance": True,
        "confirmation_has_full_adaptive_allowance_after_progress": True,
        "suppression_must_not_override_completed_confirmation": True,
        "incomplete_suppression_disposition": "retain_and_escalate",
    }
    if policy.get("decision_priority") != required_priority:
        raise ValueError("V4 policy does not preserve confirmation priority")
    if policy_version == V4_STATIC_REQUIRED_TOOLS_POLICY_VERSION:
        if (
            policy.get("tool_coverage_enforcement")
            != "required-before-completed-retention-v1"
        ):
            raise ValueError("Required-tool coverage enforcement is invalid")
    if policy_version == V4_STATIC_ROUND3_POLICY_VERSION:
        if (
            policy.get("tool_coverage_enforcement")
            != "required-before-completed-retention-v2"
        ):
            raise ValueError("Round-3 tool coverage enforcement is invalid")
        if (
            policy.get("request_defensive_reminder")
            != "every-provider-request-v1"
        ):
            raise ValueError("Round-3 defensive reminder policy is invalid")
        if (
            policy.get("required_tool_retry_extension")
            != "tool-result-too-large-v1"
        ):
            raise ValueError("Round-3 retry extension policy is invalid")
    return policy


def load_v4_reviewed_scope(
    scope_version: str = V4_COMPARISON_SCOPE_VERSION,
) -> dict[str, Any]:
    if scope_version == V4_COMPARISON_SCOPE_VERSION:
        scope_path = V4_REFERENCES / "reviewed-scope.json"
        expected_count = 6
    elif scope_version == V4_CVE_2021_42374_SCOPE_VERSION:
        scope_path = (
            V4_REFERENCES
            / "cve-2021-42374-contradiction-gate-scope-v1.json"
        )
        expected_count = 1
    elif scope_version == V4_STATIC_PRIMARY_SCOPE_VERSION:
        scope_path = V4_REFERENCES / "static-primary-scope-v1.json"
        expected_count = 3
    elif scope_version == V4_STATIC_REQUIRED_TOOLS_SCOPE_VERSION:
        scope_path = (
            V4_REFERENCES / "static-primary-required-tools-scope-v2.json"
        )
        expected_count = 3
    elif scope_version == V4_STATIC_ROUND3_SCOPE_VERSION:
        scope_path = (
            V4_REFERENCES / "static-required-tools-round3-scope-v3.json"
        )
        expected_count = 2
    else:
        raise ValueError(f"Unsupported V4 reviewed scope: {scope_version}")
    scope = load_json(scope_path)
    if scope.get("scope_version") != scope_version:
        raise ValueError("V4 reviewed scope version is invalid")
    cases = scope.get("cases")
    if not isinstance(cases, list) or len(cases) != expected_count:
        raise ValueError(
            f"V4 reviewed scope must contain exactly {expected_count} cases"
        )
    case_ids = [
        case.get("case_id") for case in cases if isinstance(case, dict)
    ]
    if len(case_ids) != expected_count or len(set(case_ids)) != expected_count:
        raise ValueError("V4 reviewed scope case IDs are invalid")
    if scope_version not in {
        V4_STATIC_PRIMARY_SCOPE_VERSION,
        V4_STATIC_REQUIRED_TOOLS_SCOPE_VERSION,
        V4_STATIC_ROUND3_SCOPE_VERSION,
    }:
        v3_scope = v3.load_v3_reviewed_scope()
        v3_by_id = {case["case_id"]: case for case in v3_scope["cases"]}
        if (
            scope_version == V4_COMPARISON_SCOPE_VERSION
            and set(case_ids) != set(v3_by_id)
        ):
            raise ValueError(
                "V4 reviewed scope differs from the reviewed v3 cohort"
            )
        for case in cases:
            if case != v3_by_id.get(case["case_id"]):
                raise ValueError(
                    "V4 reviewed identity differs from the v3 cohort"
                )
    if scope_version == V4_CVE_2021_42374_SCOPE_VERSION:
        parent_path = V4_REFERENCES / "reviewed-scope.json"
        if scope.get("scope_kind") != "comparison_subset":
            raise ValueError("V4 targeted scope kind is invalid")
        if scope.get("parent_scope_version") != V4_COMPARISON_SCOPE_VERSION:
            raise ValueError("V4 targeted parent scope version differs")
        if scope.get("parent_scope_sha256") != sha256_file(parent_path):
            raise ValueError("V4 targeted parent scope hash differs")
    elif scope_version == V4_STATIC_PRIMARY_SCOPE_VERSION:
        if scope.get("scope_kind") != "static_primary":
            raise ValueError("V4 static primary scope kind is invalid")
    elif scope_version == V4_STATIC_REQUIRED_TOOLS_SCOPE_VERSION:
        parent_path = V4_REFERENCES / "static-primary-scope-v1.json"
        if scope.get("scope_kind") != "static_primary_required_tools":
            raise ValueError("V4 required-tools scope kind is invalid")
        if scope.get("parent_scope_version") != V4_STATIC_PRIMARY_SCOPE_VERSION:
            raise ValueError("V4 required-tools parent scope differs")
        if scope.get("parent_scope_sha256") != sha256_file(parent_path):
            raise ValueError("V4 required-tools parent scope hash differs")
        if set(scope.get("required_tool_names", [])) != V4_REQUIRED_STATIC_TOOLS:
            raise ValueError("V4 required-tools coverage set differs")
        parent = load_json(parent_path)
        parent_by_id = {case["case_id"]: case for case in parent["cases"]}
        for case in cases:
            if case != parent_by_id.get(case["case_id"]):
                raise ValueError("V4 required-tools identity differs from parent")
    elif scope_version == V4_STATIC_ROUND3_SCOPE_VERSION:
        parent_path = (
            V4_REFERENCES / "static-primary-required-tools-scope-v2.json"
        )
        if scope.get("scope_kind") != "static_required_tools_round3":
            raise ValueError("V4 round-3 scope kind is invalid")
        if (
            scope.get("parent_scope_version")
            != V4_STATIC_REQUIRED_TOOLS_SCOPE_VERSION
        ):
            raise ValueError("V4 round-3 parent scope differs")
        if scope.get("parent_scope_sha256") != sha256_file(parent_path):
            raise ValueError("V4 round-3 parent scope hash differs")
        if set(scope.get("required_tool_names", [])) != V4_REQUIRED_STATIC_TOOLS:
            raise ValueError("V4 round-3 required-tools coverage set differs")
        parent = load_json(parent_path)
        parent_by_id = {case["case_id"]: case for case in parent["cases"]}
        for case in cases:
            if case != parent_by_id.get(case["case_id"]):
                raise ValueError("V4 round-3 identity differs from parent")
        expected_ids = set(case_ids)
        status_by_case = scope.get(
            "required_prior_terminal_status_by_case", {}
        )
        missing_by_case = scope.get(
            "required_prior_missing_tool_names_by_case", {}
        )
        if set(status_by_case) != expected_ids:
            raise ValueError("V4 round-3 prior-status cases differ")
        if set(missing_by_case) != expected_ids:
            raise ValueError("V4 round-3 prior-coverage cases differ")
        if set(status_by_case.values()) != {
            "infrastructure_error",
            "resource_exhausted",
        }:
            raise ValueError("V4 round-3 prior statuses differ")
        required_set = set(scope["required_tool_names"])
        for missing in missing_by_case.values():
            if (
                not isinstance(missing, list)
                or not missing
                or not set(missing) <= required_set
            ):
                raise ValueError("V4 round-3 prior missing tools are invalid")
    return scope


def reviewed_scope_path_for_protocol(
    protocol_version: str,
    scope_version: str | None = None,
) -> Path:
    if protocol_version == "v4":
        if scope_version in {None, V4_COMPARISON_SCOPE_VERSION}:
            return V4_REFERENCES / "reviewed-scope.json"
        if scope_version == V4_CVE_2021_42374_SCOPE_VERSION:
            return (
                V4_REFERENCES
                / "cve-2021-42374-contradiction-gate-scope-v1.json"
            )
        if scope_version == V4_STATIC_PRIMARY_SCOPE_VERSION:
            return V4_REFERENCES / "static-primary-scope-v1.json"
        if scope_version == V4_STATIC_REQUIRED_TOOLS_SCOPE_VERSION:
            return (
                V4_REFERENCES
                / "static-primary-required-tools-scope-v2.json"
            )
        if scope_version == V4_STATIC_ROUND3_SCOPE_VERSION:
            return V4_REFERENCES / "static-required-tools-round3-scope-v3.json"
        else:
            raise ValueError(f"Unsupported V4 reviewed scope: {scope_version}")
    return v3.reviewed_scope_path(
        scope_version or v3.V3_COMPARISON_SCOPE_VERSION
    )


def protocol_version_for_schema(schema_version: str) -> str:
    if schema_version == V4_SCHEMA_VERSION:
        return "v4"
    return v3.protocol_version_for_schema(schema_version)


def result_schema_path(protocol_version: str) -> Path:
    if protocol_version == "v4":
        return V4_REFERENCES / "result-schema.json"
    return v3.result_schema_path(protocol_version)


def prompt_template_path(
    protocol_version: str,
    policy_version: str | None = None,
) -> Path:
    if protocol_version == "v4":
        if policy_version == V4_STATIC_PRIMARY_POLICY_VERSION:
            return V4_REFERENCES / "prompt-template-static-primary.txt"
        if policy_version == V4_STATIC_REQUIRED_TOOLS_POLICY_VERSION:
            return V4_REFERENCES / "prompt-template-static-required-tools.txt"
        if policy_version == V4_STATIC_ROUND3_POLICY_VERSION:
            return V4_REFERENCES / "prompt-template-static-round3.txt"
        return V4_REFERENCES / "prompt-template.txt"
    return v3.prompt_template_path(protocol_version)


def fallback_result_v4(
    task: dict[str, Any],
    execution_status: str,
    reason: str,
    progress_events: list[str] | None = None,
) -> dict[str, Any]:
    result = v3.fallback_result_v3(
        task, execution_status, reason, progress_events
    )
    result["schema_version"] = V4_SCHEMA_VERSION
    for hypothesis in result["hypotheses"]:
        hypothesis["contradiction_proof"] = neutral_contradiction_proof()
    return result


def fallback_result_for_task(
    task: dict[str, Any],
    execution_status: str,
    reason: str,
    progress_events: list[str] | None = None,
) -> dict[str, Any]:
    if task.get("schema_version") == V4_SCHEMA_VERSION:
        return fallback_result_v4(
            task, execution_status, reason, progress_events
        )
    return v3.fallback_result_for_task(
        task, execution_status, reason, progress_events
    )


def _nonempty_strings(value: Any) -> bool:
    return (
        isinstance(value, list)
        and bool(value)
        and all(
            isinstance(item, str) and bool(item.strip())
            for item in value
        )
    )


def _citation_errors(
    citation: Any,
    package: AnalysisPackage,
) -> list[str]:
    if not isinstance(citation, dict):
        return ["citation is not an object"]
    errors: list[str] = []
    if set(citation) != CONTRADICTION_CITATION_FIELDS:
        errors.append("citation fields are not exact")
    function_uid = citation.get("function_uid")
    line = citation.get("line")
    evidence = citation.get("evidence")
    functions = getattr(package, "functions", {})
    if not isinstance(function_uid, str) or function_uid not in functions:
        errors.append("citation function UID is absent from the package")
    if not isinstance(line, int) or isinstance(line, bool) or line < 1:
        errors.append("citation line is invalid")
    elif isinstance(function_uid, str) and function_uid in functions:
        try:
            if hasattr(package, "_function_text"):
                line_count = len(package._function_text(function_uid).splitlines())
            else:
                row = functions[function_uid]
                line_count = int(
                    row.get("total_lines")
                    or row.get("source_line_count")
                    or 0
                )
        except Exception as exc:
            errors.append(
                f"citation source could not be verified: {type(exc).__name__}"
            )
        else:
            if line_count < 1 or line > line_count:
                errors.append("citation line is outside the packaged function")
    if not isinstance(evidence, str) or not evidence.strip():
        errors.append("citation evidence is empty")
    return errors


def _contradiction_errors(
    proof: Any,
    package: AnalysisPackage,
) -> list[str]:
    if not isinstance(proof, dict):
        return ["contradiction_proof is not an object"]
    errors: list[str] = []
    if set(proof) != CONTRADICTION_PROOF_FIELDS:
        errors.append("contradiction_proof fields are not exact")
    if proof.get("applicability") != "required":
        errors.append("contradiction proof applicability is not required")
    basis_kind = proof.get("basis_kind")
    if basis_kind not in CONTRADICTION_BASIS_KINDS - {"not_applicable"}:
        errors.append("contradiction proof basis_kind is not evidentiary")
    claim = proof.get("claim")
    if not isinstance(claim, str) or not claim.strip():
        errors.append("contradiction proof claim is empty")
    relation = proof.get("value_relation")
    if relation not in {
        "exact_same_value_state",
        "explicitly_proven_equivalent",
        "non_value_fact_directly_excludes",
    }:
        errors.append("contradiction proof value relation is insufficient")
    if (
        relation == "non_value_fact_directly_excludes"
        and basis_kind != "control_flow_fact"
    ):
        errors.append(
            "non-value contradiction is allowed only for a direct "
            "control-flow fact"
        )
    equivalence = proof.get("equivalence_evidence")
    if relation == "explicitly_proven_equivalent":
        if not _nonempty_strings(equivalence):
            errors.append(
                "explicit equivalence requires nonempty equivalence evidence"
            )
    elif not isinstance(equivalence, list):
        errors.append("equivalence evidence is not an array")
    citations = proof.get("citations")
    if not isinstance(citations, list) or not citations:
        errors.append("contradiction proof requires at least one citation")
    else:
        for index, citation in enumerate(citations):
            for error in _citation_errors(citation, package):
                errors.append(f"citation {index + 1}: {error}")
    return errors


def _neutral_proof_errors(proof: Any) -> list[str]:
    if proof != neutral_contradiction_proof():
        return [
            "supported or unresolved hypothesis requires the neutral "
            "not_applicable contradiction proof"
        ]
    return []


def _adjustment(
    hypothesis_id: Any,
    claimed_result: Any,
    effective_result: str,
    reasons: list[str],
) -> dict[str, Any]:
    return {
        "kind": "hypothesis_result_adjustment",
        "hypothesis_id": (
            hypothesis_id if isinstance(hypothesis_id, str) else ""
        ),
        "claimed_result": (
            claimed_result if isinstance(claimed_result, str) else ""
        ),
        "effective_result": effective_result,
        "reasons": list(reasons),
    }


def normalize_model_result_v4(
    value: Any,
    task: dict[str, Any],
    package: AnalysisPackage,
) -> tuple[Any, list[dict[str, Any]]]:
    """Return a safe effective result without changing the raw model object."""
    normalized = copy.deepcopy(value)
    adjustments: list[dict[str, Any]] = []
    if not isinstance(normalized, dict):
        return normalized, adjustments
    hypotheses = normalized.get("hypotheses")
    if not isinstance(hypotheses, list):
        return normalized, adjustments

    downgraded_ids: list[str] = []
    for row in hypotheses:
        if not isinstance(row, dict):
            continue
        result = row.get("result")
        hypothesis_id = row.get("hypothesis_id")
        if result == "contradicted":
            errors = _contradiction_errors(
                row.get("contradiction_proof"), package
            )
            if errors:
                row["result"] = "unresolved"
                row["contradiction_proof"] = neutral_contradiction_proof()
                adjustments.append(
                    _adjustment(
                        hypothesis_id,
                        "contradicted",
                        "unresolved",
                        errors,
                    )
                )
                if isinstance(hypothesis_id, str):
                    downgraded_ids.append(hypothesis_id)
        elif result in {"supported", "unresolved"}:
            errors = _neutral_proof_errors(
                row.get("contradiction_proof")
            )
            if errors:
                row["contradiction_proof"] = neutral_contradiction_proof()
                adjustments.append(
                    _adjustment(
                        hypothesis_id,
                        result,
                        result,
                        errors,
                    )
                )

    if (
        downgraded_ids
        and normalized.get("pipeline_disposition")
        == "suppress_proven_false_positive"
    ):
        normalized["semantic_status"] = "unresolved"
        normalized["pipeline_disposition"] = "retain_and_escalate"
        suppression = normalized.get("suppression_proof")
        if isinstance(suppression, dict):
            suppression["claim"] = "not_claimed"
            suppression["completion"] = "unresolved"
            unresolved_items = suppression.get("unresolved_items")
            if not isinstance(unresolved_items, list):
                unresolved_items = []
                suppression["unresolved_items"] = unresolved_items
            unresolved_items.extend(
                f"Hypothesis contradiction lacked sufficient proof: {item}"
                for item in downgraded_ids
            )
        unresolved_facts = normalized.get("unresolved_facts")
        if not isinstance(unresolved_facts, list):
            unresolved_facts = []
            normalized["unresolved_facts"] = unresolved_facts
        unresolved_facts.extend(
            f"Effective hypothesis result is unresolved: {item}"
            for item in downgraded_ids
        )
        summary = normalized.get("summary")
        suffix = (
            " Unsupported contradiction claims were treated as unresolved; "
            "suppression was blocked."
        )
        normalized["summary"] = (
            (summary.rstrip() if isinstance(summary, str) else "") + suffix
        ).strip()
        adjustments.append(
            {
                "kind": "pipeline_disposition_adjustment",
                "claimed_disposition": "suppress_proven_false_positive",
                "effective_disposition": "retain_and_escalate",
                "reasons": [
                    "At least one contradicted hypothesis lacked a valid "
                    "contradiction proof."
                ],
            }
        )
    return normalized, adjustments


def _v3_projection(
    value: dict[str, Any],
    task: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    projected = copy.deepcopy(value)
    projected["schema_version"] = v3.V3_SCHEMA_VERSION
    for row in projected.get("hypotheses", []):
        if isinstance(row, dict):
            row.pop("contradiction_proof", None)
    projected_task = dict(task)
    projected_task["schema_version"] = v3.V3_SCHEMA_VERSION
    return projected, projected_task


def _validate_normalized_result_v4(
    value: Any,
    task: dict[str, Any],
    package: AnalysisPackage,
) -> list[str]:
    if not isinstance(value, dict):
        return ["Result is not a JSON object"]
    errors: list[str] = []
    if value.get("schema_version") != V4_SCHEMA_VERSION:
        errors.append("schema_version is invalid")
    if task.get("schema_version") != V4_SCHEMA_VERSION:
        errors.append("Task is not bound to the v4 result schema")
    hypotheses = value.get("hypotheses")
    if not isinstance(hypotheses, list):
        errors.append("Hypotheses are invalid")
        hypotheses = []
    for row in hypotheses:
        if not isinstance(row, dict):
            errors.append("Hypothesis is invalid")
            continue
        hypothesis_id = row.get("hypothesis_id")
        prefix = f"Hypothesis {hypothesis_id!r}"
        if set(row) != V4_HYPOTHESIS_FIELDS:
            errors.append(f"{prefix} fields are not exact")
        result = row.get("result")
        proof = row.get("contradiction_proof")
        if result == "contradicted":
            for error in _contradiction_errors(proof, package):
                errors.append(f"{prefix}: {error}")
        elif result in {"supported", "unresolved"}:
            for error in _neutral_proof_errors(proof):
                errors.append(f"{prefix}: {error}")
    projected, projected_task = _v3_projection(value, task)
    errors.extend(
        v3.validate_model_result_v3(projected, projected_task, package)
    )
    return errors


def validate_and_normalize_model_result_v4(
    value: Any,
    task: dict[str, Any],
    package: AnalysisPackage,
) -> tuple[Any, list[str], list[dict[str, Any]]]:
    normalized, adjustments = normalize_model_result_v4(
        value, task, package
    )
    errors = _validate_normalized_result_v4(normalized, task, package)
    return normalized, errors, adjustments


def validate_model_result_v4(
    value: Any,
    task: dict[str, Any],
    package: AnalysisPackage,
) -> list[str]:
    _, errors, _ = validate_and_normalize_model_result_v4(
        value, task, package
    )
    return errors


def validate_and_normalize_model_result_for_task(
    value: Any,
    task: dict[str, Any],
    package: AnalysisPackage,
) -> tuple[Any, list[str], list[dict[str, Any]]]:
    if task.get("schema_version") == V4_SCHEMA_VERSION:
        return validate_and_normalize_model_result_v4(value, task, package)
    errors = v3.validate_model_result_for_task(value, task, package)
    return value, errors, []


def validate_model_result_for_task(
    value: Any,
    task: dict[str, Any],
    package: AnalysisPackage,
) -> list[str]:
    _, errors, _ = validate_and_normalize_model_result_for_task(
        value, task, package
    )
    return errors


# Re-export immutable v3 constants used by the existing preparation UI.
V3_COMPARISON_SCOPE_VERSION = v3.V3_COMPARISON_SCOPE_VERSION
V3_RETRY_SCOPE_VERSION = v3.V3_RETRY_SCOPE_VERSION
V3_OUTPUT_CAP_RETRY_SCOPE_VERSION = v3.V3_OUTPUT_CAP_RETRY_SCOPE_VERSION
V3_DEFENSIVE_RETRY_SCOPE_VERSION = v3.V3_DEFENSIVE_RETRY_SCOPE_VERSION
V3_OUTPUT_CAP_POLICY_VERSION = v3.V3_OUTPUT_CAP_POLICY_VERSION
V3_DEFENSIVE_RETRY_POLICY_VERSION = v3.V3_DEFENSIVE_RETRY_POLICY_VERSION
load_v3_reviewed_scope = v3.load_v3_reviewed_scope
v3_reviewed_scope_path = v3.reviewed_scope_path
