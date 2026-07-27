#!/usr/bin/env python3
"""Additive v3 protocol helpers for the asymmetric recall-first Tier B gate."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from filter_common import (
    REFERENCES,
    SUPPORTED_CLASSES,
    AnalysisPackage,
    load_json,
    load_policy,
    sha256_file,
)


V3_REFERENCES = REFERENCES / "v3"
V3_SCHEMA_VERSION = "tier-b-filter-result-v3"
V3_COMPARISON_SCOPE_VERSION = (
    "tier-b-filter-v3-six-case-comparison-scope-v1"
)
V3_RETRY_SCOPE_VERSION = (
    "tier-b-filter-v3-terminal-response-retry-scope-v1"
)
V3_OUTPUT_CAP_RETRY_SCOPE_VERSION = (
    "tier-b-filter-v3-output-cap-retry-scope-v1"
)
V3_DEFENSIVE_RETRY_SCOPE_VERSION = (
    "tier-b-filter-v3-defensive-framing-retry-scope-v1"
)
V3_OUTPUT_CAP_POLICY_VERSION = (
    "tier-b-filter-policy-v3-output-cap-8192-v1"
)
V3_DEFENSIVE_RETRY_POLICY_VERSION = (
    "tier-b-filter-policy-v3-defensive-framing-retry-8192-v1"
)
V3_RETRY_CASE_IDS = {
    "tier-b-case-599ba94926f0028709065453",
    "tier-b-case-b99dc78d5275592661bdc5b9",
}
V3_DEFENSIVE_RETRY_CASE_IDS = {
    "tier-b-case-b99dc78d5275592661bdc5b9",
}

HYPOTHESIS_RESULTS = {"supported", "contradicted", "unresolved"}
OBLIGATION_COMPLETIONS = {"satisfied", "unsatisfied", "unresolved"}
CHALLENGE_OUTCOMES = {
    "confirmation_survives",
    "confirmation_defeated",
    "unresolved",
    "not_applicable",
}
REQUIRED_CONFIRMATION_OBLIGATION_KINDS = {
    "identity",
    "reachability",
    "target_operation",
    "feasible_value_or_lifetime_constraints",
    "contextual_path",
    "class_specific",
}
CONFIRMATION_OBLIGATION_KINDS = REQUIRED_CONFIRMATION_OBLIGATION_KINDS | {
    "other"
}
TRANSFORMATION_EFFECTS = {
    "preserves_value_and_state",
    "changes_value_preserves_proven_invariant",
    "changes_value_and_requires_recheck",
    "reestablishes_guarded_invariant",
    "invalidates_guarded_invariant",
    "unresolved",
}
EARLIER_GUARD_PRESERVING_EFFECTS = {
    "preserves_value_and_state",
    "changes_value_preserves_proven_invariant",
}
SUPPRESSION_CLAIMS = {
    "not_claimed",
    "candidate_absent",
    "unreachable",
    "all_relevant_hypotheses_contradicted",
}


def load_policy_for_protocol(
    protocol_version: str,
    policy_version: str | None = None,
) -> dict[str, Any]:
    if protocol_version == "v2":
        return load_policy()
    if protocol_version != "v3":
        raise ValueError(f"Unsupported protocol version: {protocol_version}")
    if policy_version in {None, "tier-b-filter-policy-v3"}:
        policy_path = V3_REFERENCES / "tier-b-filter-policy.json"
        expected_scope = V3_COMPARISON_SCOPE_VERSION
    elif policy_version == V3_OUTPUT_CAP_POLICY_VERSION:
        policy_path = (
            V3_REFERENCES / "tier-b-filter-policy-output-cap-8192-v1.json"
        )
        expected_scope = V3_OUTPUT_CAP_RETRY_SCOPE_VERSION
    elif policy_version == V3_DEFENSIVE_RETRY_POLICY_VERSION:
        policy_path = (
            V3_REFERENCES
            / "tier-b-filter-policy-defensive-framing-retry-8192-v1.json"
        )
        expected_scope = V3_DEFENSIVE_RETRY_SCOPE_VERSION
    else:
        raise ValueError(f"Unsupported V3 policy version: {policy_version}")
    policy = load_json(policy_path)
    if set(policy["supported_classes"]) != SUPPORTED_CLASSES:
        raise ValueError("V3 policy supported classes differ from the implementation")
    if policy["schema_version"] != V3_SCHEMA_VERSION:
        raise ValueError("V3 policy has the wrong schema version")
    if policy.get("reviewed_scope") != expected_scope:
        raise ValueError("V3 policy is not bound to its reviewed scope")
    priority = policy.get("decision_priority", {})
    required_priority = {
        "primary_objective": "retain_confirmed",
        "secondary_objective": "suppress_proven_false_positive",
        "confirmation_has_full_base_allowance": True,
        "confirmation_has_full_adaptive_allowance_after_progress": True,
        "suppression_must_not_override_completed_confirmation": True,
        "incomplete_suppression_disposition": "retain_and_escalate",
    }
    if priority != required_priority:
        raise ValueError("V3 policy does not preserve confirmation priority")
    return policy


def load_v3_reviewed_scope(
    scope_version: str = V3_COMPARISON_SCOPE_VERSION,
) -> dict[str, Any]:
    scope = load_json(reviewed_scope_path(scope_version))
    if scope.get("scope_version") != scope_version:
        raise ValueError("V3 reviewed scope version is invalid")
    cases = scope.get("cases")
    expected_count = {
        V3_COMPARISON_SCOPE_VERSION: 6,
        V3_RETRY_SCOPE_VERSION: 2,
        V3_OUTPUT_CAP_RETRY_SCOPE_VERSION: 2,
        V3_DEFENSIVE_RETRY_SCOPE_VERSION: 1,
    }.get(scope_version)
    if expected_count is None:
        raise ValueError(f"Unsupported V3 reviewed scope: {scope_version}")
    if not isinstance(cases, list) or len(cases) != expected_count:
        raise ValueError(
            f"V3 reviewed scope must contain exactly {expected_count} cases"
        )
    case_ids = [case.get("case_id") for case in cases if isinstance(case, dict)]
    if len(case_ids) != expected_count or len(set(case_ids)) != expected_count:
        raise ValueError("V3 reviewed scope case IDs are invalid")
    if scope_version in {
        V3_RETRY_SCOPE_VERSION,
        V3_OUTPUT_CAP_RETRY_SCOPE_VERSION,
        V3_DEFENSIVE_RETRY_SCOPE_VERSION,
    }:
        if scope.get("scope_kind") != "retry_only":
            raise ValueError("V3 retry scope kind is invalid")
        expected_case_ids = (
            V3_DEFENSIVE_RETRY_CASE_IDS
            if scope_version == V3_DEFENSIVE_RETRY_SCOPE_VERSION
            else V3_RETRY_CASE_IDS
        )
        if set(case_ids) != expected_case_ids:
            raise ValueError("V3 retry scope case IDs are invalid")
        parent = load_v3_reviewed_scope()
        if scope.get("parent_scope_version") != parent["scope_version"]:
            raise ValueError("V3 retry parent scope version differs")
        if scope.get("parent_scope_sha256") != sha256_file(
            reviewed_scope_path()
        ):
            raise ValueError("V3 retry parent scope hash differs")
        parent_by_id = {case["case_id"]: case for case in parent["cases"]}
        for case in cases:
            if case != parent_by_id.get(case["case_id"]):
                raise ValueError(
                    "V3 retry identity differs from its parent scope"
                )
        if scope_version == V3_RETRY_SCOPE_VERSION:
            if scope.get("required_prior_terminal_status") != (
                "infrastructure_error"
            ):
                raise ValueError("V3 retry prior terminal status is invalid")
            if scope.get("required_prior_error_contains") != (
                "Didn't receive a `response.completed` event."
            ):
                raise ValueError("V3 retry prior error binding is invalid")
        elif scope_version == V3_OUTPUT_CAP_RETRY_SCOPE_VERSION:
            required = {
                "required_prior_terminal_status":
                    "provider_incomplete_max_output_tokens",
                "required_prior_execution_status": "resource_exhausted",
                "required_prior_stream_outcome":
                    "incomplete_max_output_tokens",
                "required_prior_incomplete_reason": "max_output_tokens",
            }
            for key, value in required.items():
                if scope.get(key) != value:
                    raise ValueError(
                        f"V3 output-cap retry binding is invalid: {key}"
                    )
        else:
            required = {
                "required_prior_terminal_status": "infrastructure_error",
                "required_prior_execution_status": "infrastructure_error",
                "required_prior_stream_outcome": "provider_failed",
                "required_prior_error_contains": "cyber_policy",
            }
            for key, value in required.items():
                if scope.get(key) != value:
                    raise ValueError(
                        f"V3 defensive retry binding is invalid: {key}"
                    )
    return scope


def reviewed_scope_path(
    scope_version: str = V3_COMPARISON_SCOPE_VERSION,
) -> Path:
    if scope_version == V3_COMPARISON_SCOPE_VERSION:
        return V3_REFERENCES / "reviewed-scope.json"
    if scope_version == V3_RETRY_SCOPE_VERSION:
        return V3_REFERENCES / "terminal-response-retry-scope-v1.json"
    if scope_version == V3_OUTPUT_CAP_RETRY_SCOPE_VERSION:
        return V3_REFERENCES / "output-cap-retry-scope-v1.json"
    if scope_version == V3_DEFENSIVE_RETRY_SCOPE_VERSION:
        return V3_REFERENCES / "defensive-framing-retry-scope-v1.json"
    raise ValueError(f"Unsupported V3 reviewed scope: {scope_version}")


def protocol_version_for_schema(schema_version: str) -> str:
    if schema_version == "tier-b-filter-result-v2":
        return "v2"
    if schema_version == V3_SCHEMA_VERSION:
        return "v3"
    raise ValueError(f"Unsupported result schema version: {schema_version}")


def result_schema_path(protocol_version: str) -> Path:
    if protocol_version == "v2":
        return REFERENCES / "result-schema.json"
    if protocol_version == "v3":
        return V3_REFERENCES / "result-schema.json"
    raise ValueError(f"Unsupported protocol version: {protocol_version}")


def prompt_template_path(protocol_version: str) -> Path:
    if protocol_version == "v2":
        return REFERENCES / "prompt-template.txt"
    if protocol_version == "v3":
        return V3_REFERENCES / "prompt-template.txt"
    raise ValueError(f"Unsupported protocol version: {protocol_version}")


def fallback_result_v3(
    task: dict[str, Any],
    execution_status: str,
    reason: str,
    progress_events: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": V3_SCHEMA_VERSION,
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
                "hypothesis_id": "fallback-unresolved",
                "target_class": task["target_class"],
                "hypothesis": "The requested class remains unresolved.",
                "result": "unresolved",
                "evidence": [],
            }
        ],
        "confirmation_obligations": [],
        "adversarial_challenge": {
            "applicability": "not_applicable",
            "hypothesis_id": "",
            "challenge": "",
            "outcome": "not_applicable",
            "evidence": [],
        },
        "suppression_proof": {
            "claim": "not_claimed",
            "completion": "unresolved",
            "hypothesis_coverage": [],
            "sink_inventory": {
                "completion": "unresolved",
                "enumeration_evidence": [],
                "sinks": [],
            },
            "unresolved_items": [reason],
        },
        "reachability": "unresolved",
        "evidence": [],
        "blocking_controls": [],
        "unresolved_facts": [reason],
        "progress_events": progress_events or [],
        "summary": reason,
    }


def fallback_result_for_task(
    task: dict[str, Any],
    execution_status: str,
    reason: str,
    progress_events: list[str] | None = None,
) -> dict[str, Any]:
    if task.get("schema_version") == V3_SCHEMA_VERSION:
        return fallback_result_v3(task, execution_status, reason, progress_events)
    from filter_common import fallback_result

    return fallback_result(task, execution_status, reason, progress_events)


def _nonempty_evidence(value: Any) -> bool:
    return (
        isinstance(value, list)
        and bool(value)
        and all(isinstance(item, str) and bool(item.strip()) for item in value)
    )


def _ordered_one_based(rows: list[Any]) -> bool:
    orders = [
        row.get("order")
        for row in rows
        if isinstance(row, dict) and isinstance(row.get("order"), int)
    ]
    return len(orders) == len(rows) and orders == list(range(1, len(rows) + 1))


def _validate_sink(sink: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(sink, dict):
        return ["Suppression sink is invalid"]
    sink_id = sink.get("sink_id")
    prefix = f"Suppression sink {sink_id!r}"
    if sink.get("conclusion") != "safe":
        errors.append(f"{prefix} must conclude safe")
    origin = sink.get("origin")
    if not isinstance(origin, dict) or not _nonempty_evidence(origin.get("evidence")):
        errors.append(f"{prefix} requires evidenced value/lifetime origin")

    transformations = sink.get("transformations")
    if not isinstance(transformations, list):
        errors.append(f"{prefix} transformations are invalid")
        transformations = []
    if not _ordered_one_based(transformations):
        errors.append(f"{prefix} transformations must be consecutive and ordered")
    for transformation in transformations:
        if not isinstance(transformation, dict):
            continue
        effect = transformation.get("effect")
        if effect not in TRANSFORMATION_EFFECTS:
            errors.append(f"{prefix} has an invalid transformation effect")
        if effect == "unresolved":
            errors.append(f"{prefix} has an unresolved transformation")
        invariant_ids = transformation.get("invariant_ids")
        if not isinstance(invariant_ids, list) or any(
            not isinstance(item, str) or not item for item in invariant_ids
        ):
            errors.append(f"{prefix} has invalid transformation invariant IDs")
        elif len(invariant_ids) != len(set(invariant_ids)):
            errors.append(f"{prefix} has duplicate transformation invariant IDs")
        if not _nonempty_evidence(transformation.get("evidence")):
            errors.append(f"{prefix} has an unevidenced transformation")

    final_order = len(transformations)
    guard = sink.get("guard")
    if not isinstance(guard, dict):
        errors.append(f"{prefix} guard is invalid")
        guard = {}
    position = guard.get("position")
    guarded_after = guard.get("after_transformation_order")
    value_relation = guard.get("value_relation")
    if position not in {
        "post_last_transformation",
        "earlier_with_complete_preservation_proof",
    }:
        errors.append(f"{prefix} lacks an acceptable guard position")
    if value_relation not in {
        "exact_same_value_state",
        "explicitly_proven_equivalent",
    }:
        errors.append(f"{prefix} guard does not protect the same value/state")
    if not _nonempty_evidence(guard.get("evidence")):
        errors.append(f"{prefix} guard requires evidence")
    if (
        guard.get("function_uid") == sink.get("function_uid")
        and isinstance(guard.get("line"), int)
        and isinstance(sink.get("line"), int)
        and guard["line"] >= sink["line"]
    ):
        errors.append(f"{prefix} guard is not positioned before the sink")

    dependencies = sink.get("invariant_dependencies")
    if not isinstance(dependencies, list):
        errors.append(f"{prefix} invariant dependencies are invalid")
        dependencies = []
    dependency_ids: set[str] = set()
    for dependency in dependencies:
        if not isinstance(dependency, dict):
            errors.append(f"{prefix} has an invalid invariant dependency")
            continue
        dependency_id = dependency.get("invariant_id")
        if not isinstance(dependency_id, str) or not dependency_id:
            errors.append(f"{prefix} has an invalid invariant ID")
        elif dependency_id in dependency_ids:
            errors.append(f"{prefix} repeats invariant ID {dependency_id!r}")
        else:
            dependency_ids.add(dependency_id)
        if dependency.get("used_at_sink_id") != sink_id:
            errors.append(f"{prefix} has an invariant bound to another sink")
        if dependency.get("conclusion") != "preserved":
            errors.append(f"{prefix} has an unpreserved invariant")
        if not _nonempty_evidence(dependency.get("evidence")):
            errors.append(f"{prefix} has an unevidenced invariant")
        mutations = dependency.get("intervening_mutations")
        if not isinstance(mutations, list):
            errors.append(f"{prefix} intervening mutations are invalid")
            mutations = []
        if not _ordered_one_based(mutations):
            errors.append(
                f"{prefix} intervening mutations must be consecutive and ordered"
            )
        for mutation in mutations:
            if not isinstance(mutation, dict):
                continue
            if mutation.get("preservation") != "preserved":
                errors.append(f"{prefix} has an unaddressed intervening mutation")
            if not _nonempty_evidence(mutation.get("evidence")):
                errors.append(f"{prefix} has an unevidenced intervening mutation")

    for transformation in transformations:
        if not isinstance(transformation, dict):
            continue
        effect = transformation.get("effect")
        referenced = transformation.get("invariant_ids")
        referenced_ids = set(referenced) if isinstance(referenced, list) else set()
        if effect in {
            "changes_value_preserves_proven_invariant",
            "reestablishes_guarded_invariant",
            "invalidates_guarded_invariant",
        } and not referenced_ids:
            errors.append(
                f"{prefix} transformation effect requires a named invariant"
            )
        if not referenced_ids <= dependency_ids:
            errors.append(
                f"{prefix} transformation references an unknown invariant"
            )

    if position == "post_last_transformation":
        if guarded_after != final_order:
            errors.append(f"{prefix} guard must follow the last transformation")
    elif position == "earlier_with_complete_preservation_proof":
        if (
            not isinstance(guarded_after, int)
            or guarded_after < 0
            or guarded_after >= final_order
        ):
            errors.append(f"{prefix} earlier-guard position is inconsistent")
        else:
            later_effects = {
                row.get("effect")
                for row in transformations[guarded_after:]
                if isinstance(row, dict)
            }
            if not later_effects <= EARLIER_GUARD_PRESERVING_EFFECTS:
                errors.append(
                    f"{prefix} earlier guard is invalidated by a later transformation"
                )
        if not dependencies:
            errors.append(
                f"{prefix} earlier guard lacks a complete invariant-preservation proof"
            )
    return errors


def validate_model_result_v3(
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
        "confirmation_obligations",
        "adversarial_challenge",
        "suppression_proof",
        "reachability",
        "evidence",
        "blocking_controls",
        "unresolved_facts",
        "progress_events",
        "summary",
    }
    if set(value) != required:
        errors.append("Result fields are not exact")
    if value.get("schema_version") != V3_SCHEMA_VERSION:
        errors.append("schema_version is invalid")
    if task.get("schema_version") != V3_SCHEMA_VERSION:
        errors.append("Task is not bound to the v3 result schema")
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
    if not isinstance(hypotheses, list) or not hypotheses:
        errors.append("At least one hypothesis is required")
        hypotheses = []
    hypothesis_by_id: dict[str, dict[str, Any]] = {}
    for row in hypotheses:
        if not isinstance(row, dict):
            errors.append("Hypothesis is invalid")
            continue
        hypothesis_id = row.get("hypothesis_id")
        if not isinstance(hypothesis_id, str) or not hypothesis_id:
            errors.append("Hypothesis ID is invalid")
        elif hypothesis_id in hypothesis_by_id:
            errors.append(f"Hypothesis ID is duplicated: {hypothesis_id}")
        else:
            hypothesis_by_id[hypothesis_id] = row
        if row.get("target_class") != task["target_class"]:
            errors.append("Hypothesis target class differs from the task")
        if row.get("result") not in HYPOTHESIS_RESULTS:
            errors.append("Hypothesis result is invalid")

    obligations = value.get("confirmation_obligations")
    if not isinstance(obligations, list):
        errors.append("Confirmation obligations are invalid")
        obligations = []
    obligation_ids: set[str] = set()
    for row in obligations:
        if not isinstance(row, dict):
            errors.append("Confirmation obligation is invalid")
            continue
        obligation_id = row.get("obligation_id")
        if not isinstance(obligation_id, str) or not obligation_id:
            errors.append("Confirmation obligation ID is invalid")
        elif obligation_id in obligation_ids:
            errors.append(f"Confirmation obligation ID is duplicated: {obligation_id}")
        else:
            obligation_ids.add(obligation_id)
        if row.get("kind") not in CONFIRMATION_OBLIGATION_KINDS:
            errors.append("Confirmation obligation kind is invalid")
        if row.get("completion") not in OBLIGATION_COMPLETIONS:
            errors.append("Confirmation obligation completion is invalid")

    challenge = value.get("adversarial_challenge")
    if not isinstance(challenge, dict):
        errors.append("Adversarial challenge is invalid")
        challenge = {}
    if challenge.get("outcome") not in CHALLENGE_OUTCOMES:
        errors.append("Adversarial challenge outcome is invalid")

    suppression = value.get("suppression_proof")
    if not isinstance(suppression, dict):
        errors.append("Suppression proof is invalid")
        suppression = {}
    if suppression.get("claim") not in SUPPRESSION_CLAIMS:
        errors.append("Suppression claim is invalid")
    if suppression.get("completion") not in OBLIGATION_COMPLETIONS:
        errors.append("Suppression proof completion is invalid")

    supported = [
        row
        for row in hypotheses
        if isinstance(row, dict)
        and row.get("target_class") == task["target_class"]
        and row.get("result") == "supported"
    ]
    if disposition == "retain_confirmed":
        if identity.get("status") != "present":
            errors.append("Confirmation requires a present candidate")
        if value.get("reachability") != "reachable":
            errors.append("Confirmation requires evidenced reachability")
        if not supported:
            errors.append(
                "Confirmation requires a supported class-consistent hypothesis"
            )
        if not obligations:
            errors.append("Confirmation requires confirmation obligations")
        if any(
            not isinstance(row, dict) or row.get("completion") != "satisfied"
            for row in obligations
        ):
            errors.append("Confirmation requires every obligation satisfied")
        satisfied_kinds = {
            row.get("kind")
            for row in obligations
            if isinstance(row, dict) and row.get("completion") == "satisfied"
        }
        missing_kinds = sorted(
            REQUIRED_CONFIRMATION_OBLIGATION_KINDS - satisfied_kinds
        )
        if missing_kinds:
            errors.append(
                "Confirmation lacks required obligation kinds: "
                + ", ".join(missing_kinds)
            )
        selected_id = challenge.get("hypothesis_id")
        selected = hypothesis_by_id.get(selected_id)
        if challenge.get("applicability") != "required":
            errors.append("Confirmation requires an adversarial challenge")
        if selected is None or selected.get("result") != "supported":
            errors.append(
                "Adversarial challenge must target a supported hypothesis"
            )
        if challenge.get("outcome") != "confirmation_survives":
            errors.append("Confirmation must survive the adversarial challenge")
        if not _nonempty_evidence(challenge.get("evidence")):
            errors.append("Adversarial challenge requires evidence")

    if disposition == "suppress_proven_false_positive":
        if supported:
            errors.append("Suppression cannot override a supported positive hypothesis")
        if any(
            not isinstance(row, dict) or row.get("result") != "contradicted"
            for row in hypotheses
        ):
            errors.append("Suppression requires every hypothesis contradicted")
        if any(
            not isinstance(row, dict) or row.get("completion") != "satisfied"
            for row in obligations
        ):
            errors.append(
                "Suppression is forbidden with an incomplete returned obligation"
            )
        if identity.get("status") == "ambiguous":
            errors.append("Suppression is forbidden for ambiguous identity")
        if challenge.get("applicability") != "not_applicable":
            errors.append("Suppression must not masquerade as a confirmation challenge")
        if suppression.get("completion") != "satisfied":
            errors.append("Suppression requires a satisfied suppression proof")
        if suppression.get("unresolved_items"):
            errors.append("Suppression is forbidden with unresolved proof items")
        if value.get("unresolved_facts"):
            errors.append("Suppression is forbidden with unresolved material facts")
        coverage = suppression.get("hypothesis_coverage")
        if isinstance(coverage, list) and len(coverage) != len(set(coverage)):
            errors.append("Suppression hypothesis coverage contains duplicates")
        if not isinstance(coverage, list) or set(coverage) != set(hypothesis_by_id):
            errors.append("Suppression must cover every hypothesis exactly")
        inventory = suppression.get("sink_inventory")
        if not isinstance(inventory, dict):
            errors.append("Suppression sink inventory is invalid")
            inventory = {}
        if inventory.get("completion") != "satisfied":
            errors.append("Suppression requires a complete sink inventory")
        if not _nonempty_evidence(inventory.get("enumeration_evidence")):
            errors.append("Suppression sink inventory requires enumeration evidence")
        sinks = inventory.get("sinks")
        if not isinstance(sinks, list):
            errors.append("Suppression sinks are invalid")
            sinks = []
        sink_ids: set[str] = set()
        for sink in sinks:
            if isinstance(sink, dict):
                sink_id = sink.get("sink_id")
                if not isinstance(sink_id, str) or not sink_id:
                    errors.append("Suppression sink ID is invalid")
                elif sink_id in sink_ids:
                    errors.append(f"Suppression sink ID is duplicated: {sink_id}")
                else:
                    sink_ids.add(sink_id)
            errors.extend(_validate_sink(sink))

        claim = suppression.get("claim")
        if claim == "candidate_absent":
            if identity.get("status") != "absent":
                errors.append("Candidate-absence suppression requires absent identity")
        elif claim == "unreachable":
            if identity.get("status") != "present":
                errors.append("Unreachability suppression requires present identity")
            if value.get("reachability") != "unreachable":
                errors.append("Unreachability suppression requires unreachable status")
            if package.has_any_unresolved_indirect():
                errors.append(
                    "Unreachability suppression is forbidden while the package "
                    "contains unresolved indirect calls"
                )
        elif claim == "all_relevant_hypotheses_contradicted":
            if identity.get("status") != "present":
                errors.append("Semantic suppression requires present identity")
            if value.get("reachability") != "reachable":
                errors.append("Semantic suppression requires evidenced reachability")
            if not sinks:
                errors.append("Semantic suppression requires per-sink proof records")
        else:
            errors.append("Suppression requires a concrete suppression claim")

    if disposition == "retain_and_escalate" and semantic != "unresolved":
        errors.append("Escalation must use unresolved semantic status")
    return errors


def validate_model_result_for_task(
    value: Any,
    task: dict[str, Any],
    package: AnalysisPackage,
) -> list[str]:
    if task.get("schema_version") == V3_SCHEMA_VERSION:
        return validate_model_result_v3(value, task, package)
    from filter_common import validate_model_result

    return validate_model_result(value, task, package)
