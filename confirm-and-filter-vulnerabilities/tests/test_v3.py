from __future__ import annotations

import copy
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


SKILL = Path(__file__).resolve().parents[1]
SCRIPTS = SKILL / "scripts"
sys.path.insert(0, str(SCRIPTS))

from filter_common import (  # noqa: E402
    audit_strict_json_schema,
    read_jsonl,
    validate_strict_json_schema,
)
from filter_v3 import (  # noqa: E402
    TRANSFORMATION_EFFECTS,
    V3_DEFENSIVE_RETRY_CASE_IDS,
    V3_DEFENSIVE_RETRY_POLICY_VERSION,
    V3_DEFENSIVE_RETRY_SCOPE_VERSION,
    V3_OUTPUT_CAP_POLICY_VERSION,
    V3_OUTPUT_CAP_RETRY_SCOPE_VERSION,
    V3_RETRY_CASE_IDS,
    V3_RETRY_SCOPE_VERSION,
    load_policy_for_protocol,
    load_v3_reviewed_scope,
    validate_model_result_v3,
)
import test_mvp as mvp_helpers  # noqa: E402


class DummyPackage:
    def __init__(self, unresolved_indirect: bool = False) -> None:
        self.unresolved_indirect = unresolved_indirect

    def has_any_unresolved_indirect(self) -> bool:
        return self.unresolved_indirect


class V3ValidatorTest(unittest.TestCase):
    task = {
        "schema_version": "tier-b-filter-result-v3",
        "target_class": "null-pointer-dereference",
        "function_uid": "fn-candidate",
        "artifact_sha256": "a" * 64,
    }

    def confirmation(self) -> dict:
        kinds = [
            "identity",
            "reachability",
            "target_operation",
            "feasible_value_or_lifetime_constraints",
            "contextual_path",
            "class_specific",
        ]
        return {
            "schema_version": "tier-b-filter-result-v3",
            "target_class": "null-pointer-dereference",
            "semantic_status": "confirmed",
            "pipeline_disposition": "retain_confirmed",
            "execution_status": "completed",
            "candidate_identity": {
                "status": "present",
                "function_uid": "fn-candidate",
                "artifact_sha256": "a" * 64,
                "evidence": "Exact artifact binding.",
            },
            "hypotheses": [
                {
                    "hypothesis_id": "H-supported",
                    "target_class": "null-pointer-dereference",
                    "hypothesis": "The post-advance pointer can be NULL.",
                    "result": "supported",
                    "evidence": ["The next array item is the NULL terminator."],
                },
                {
                    "hypothesis_id": "H-alternative",
                    "target_class": "null-pointer-dereference",
                    "hypothesis": "A different helper-zero path reaches the sink.",
                    "result": "contradicted",
                    "evidence": ["That path dereferences earlier instead."],
                },
            ],
            "confirmation_obligations": [
                {
                    "obligation_id": f"O-{kind}",
                    "kind": kind,
                    "obligation": f"Complete {kind}.",
                    "completion": "satisfied",
                    "evidence": [f"Evidence for {kind}."],
                }
                for kind in kinds
            ],
            "adversarial_challenge": {
                "applicability": "required",
                "hypothesis_id": "H-supported",
                "challenge": "Could a later guard dominate the sink?",
                "outcome": "confirmation_survives",
                "evidence": ["The guard executes after the sink."],
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
                "unresolved_items": [],
            },
            "reachability": "reachable",
            "evidence": [],
            "blocking_controls": [],
            "unresolved_facts": [],
            "progress_events": [],
            "summary": "Confirmed.",
        }

    def suppression(self) -> dict:
        value = self.confirmation()
        value["semantic_status"] = "safety_proven"
        value["pipeline_disposition"] = "suppress_proven_false_positive"
        for hypothesis in value["hypotheses"]:
            hypothesis["result"] = "contradicted"
        value["confirmation_obligations"] = []
        value["adversarial_challenge"] = {
            "applicability": "not_applicable",
            "hypothesis_id": "",
            "challenge": "",
            "outcome": "not_applicable",
            "evidence": [],
        }
        value["suppression_proof"] = {
            "claim": "all_relevant_hypotheses_contradicted",
            "completion": "satisfied",
            "hypothesis_coverage": ["H-supported", "H-alternative"],
            "sink_inventory": {
                "completion": "satisfied",
                "enumeration_evidence": ["Enumerated every class-relevant sink."],
                "sinks": [
                    {
                        "sink_id": "fn-candidate:20:dereference",
                        "function_uid": "fn-candidate",
                        "line": 20,
                        "operation": "pointer dereference",
                        "conclusion": "safe",
                        "origin": {
                            "description": "Pointer originates from argument one.",
                            "evidence": ["Argument load at line 10."],
                        },
                        "transformations": [
                            {
                                "order": 1,
                                "function_uid": "fn-candidate",
                                "line": 14,
                                "operation": "advance to next array item",
                                "effect": "changes_value_and_requires_recheck",
                                "invariant_ids": [],
                                "evidence": ["Pointer increment at line 14."],
                            }
                        ],
                        "guard": {
                            "position": "post_last_transformation",
                            "function_uid": "fn-candidate",
                            "line": 18,
                            "after_transformation_order": 1,
                            "value_relation": "exact_same_value_state",
                            "evidence": ["Line 18 checks the advanced pointer."],
                        },
                        "invariant_dependencies": [],
                    }
                ],
            },
            "unresolved_items": [],
        }
        return value

    def test_v3_schema_and_closed_transformation_effect_enum(self) -> None:
        schema = json.loads(
            (SKILL / "references" / "v3" / "result-schema.json").read_text()
        )
        validate_strict_json_schema(schema)
        effect_schema = (
            schema["properties"]["suppression_proof"]["properties"][
                "sink_inventory"
            ]["properties"]["sinks"]["items"]["properties"]["transformations"][
                "items"
            ]["properties"]["effect"]
        )
        self.assertEqual(set(effect_schema["enum"]), TRANSFORMATION_EFFECTS)
        self.assertEqual(effect_schema["type"], "string")

    def test_offline_schema_audit_reports_every_unique_items_violation(self) -> None:
        schema = json.loads(
            (SKILL / "references" / "v3" / "result-schema.json").read_text()
        )
        suppression = schema["properties"]["suppression_proof"]["properties"]
        suppression["hypothesis_coverage"]["uniqueItems"] = True
        invariant_ids = (
            suppression["sink_inventory"]["properties"]["sinks"]["items"][
                "properties"
            ]["transformations"]["items"]["properties"]["invariant_ids"]
        )
        invariant_ids["uniqueItems"] = True
        report = audit_strict_json_schema(schema)
        unique_errors = [
            error for error in report["errors"] if "uniqueItems" in error
        ]
        self.assertEqual(len(unique_errors), 2, report["errors"])
        with self.assertRaisesRegex(ValueError, "uniqueItems"):
            validate_strict_json_schema(schema)

    def test_v3_schema_is_within_all_documented_size_limits(self) -> None:
        schema = json.loads(
            (SKILL / "references" / "v3" / "result-schema.json").read_text()
        )
        report = audit_strict_json_schema(schema)
        self.assertEqual(report["errors"], [])
        self.assertEqual(report["property_count"], 84)
        self.assertEqual(report["maximum_object_nesting"], 6)
        self.assertEqual(report["schema_string_chars"], 2221)
        self.assertEqual(report["enum_value_count"], 81)

    def test_v3_scope_is_exactly_the_preserved_six_case_v2_pilot(self) -> None:
        scope = load_v3_reviewed_scope()
        self.assertEqual(len(scope["cases"]), 6)
        self.assertEqual(
            {case["case_id"] for case in scope["cases"]},
            {
                "tier-b-case-2c9d598a0c5bd4a130256014",
                "tier-b-case-599ba94926f0028709065453",
                "tier-b-case-84084944b11533d3cc97e9e3",
                "tier-b-case-b99dc78d5275592661bdc5b9",
                "tier-b-case-ed8d3e93cf81e67af2b96876",
                "tier-b-case-f9bab0a472e5f866be2c60c4",
            },
        )
        self.assertEqual(
            scope["source_manifest_sha256"],
            "a088ed5d30f51a7c76f0585563b48f73f132a234f81b9b2bafe720fe59fe801c",
        )

    def test_v3_terminal_response_retry_scope_is_exact_and_preparable(
        self,
    ) -> None:
        scope = load_v3_reviewed_scope(V3_RETRY_SCOPE_VERSION)
        self.assertEqual(scope["scope_kind"], "retry_only")
        self.assertEqual(
            {case["case_id"] for case in scope["cases"]},
            V3_RETRY_CASE_IDS,
        )
        repository = SKILL.parent
        source_runs = repository / "results" / "tier-b" / "filter-runs"
        source_run = source_runs / scope["source_run_id"]
        queue_dir = (
            repository
            / "results"
            / "tier-b"
            / "filter-preparation"
            / "2026-07-26__tier-a-mixed-recovered-cascade"
            / "queue"
        )
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            results_root = root / "runs"
            copied_source = results_root / scope["source_run_id"]
            copied_source.mkdir(parents=True)
            shutil.copyfile(
                source_run / "manifest.jsonl",
                copied_source / "manifest.jsonl",
            )
            shutil.copyfile(
                source_run / "results.jsonl",
                copied_source / "results.jsonl",
            )
            command = [
                "prepare_run.py",
                "--queue-dir",
                str(queue_dir),
                "--results-root",
                str(results_root),
                "--run-label",
                "reviewed-terminal-retry-test",
                "--input-price-per-million",
                "5",
                "--output-price-per-million",
                "30",
                "--reasoning-effort",
                "medium",
                "--protocol-version",
                "v3",
                "--reviewed-terminal-response-retry-scope",
            ]
            for case_id in sorted(V3_RETRY_CASE_IDS):
                command.extend(["--case-id", case_id])
            prepared = mvp_helpers.run_script(*command)
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            report = json.loads(prepared.stdout)
            self.assertEqual(report["case_count"], 2)
            self.assertEqual(report["reviewed_scope_kind"], "retry_only")
            self.assertEqual(report["aggregate_hard_ceiling_usd"], 20.14)
            run_dir = Path(report["run_dir"])
            self.assertEqual(
                {
                    row["case_id"]
                    for row in read_jsonl(run_dir / "manifest.jsonl")
                },
                V3_RETRY_CASE_IDS,
            )

    def test_v3_output_cap_retry_scope_and_policy_are_exact(self) -> None:
        scope = load_v3_reviewed_scope(V3_OUTPUT_CAP_RETRY_SCOPE_VERSION)
        self.assertEqual(scope["scope_kind"], "retry_only")
        self.assertEqual(
            {case["case_id"] for case in scope["cases"]},
            V3_RETRY_CASE_IDS,
        )
        self.assertEqual(
            scope["required_prior_terminal_status"],
            "provider_incomplete_max_output_tokens",
        )
        self.assertEqual(
            scope["required_prior_stream_outcome"],
            "incomplete_max_output_tokens",
        )
        self.assertEqual(
            scope["required_prior_incomplete_reason"],
            "max_output_tokens",
        )
        policy = load_policy_for_protocol(
            "v3", V3_OUTPUT_CAP_POLICY_VERSION
        )
        self.assertEqual(
            policy["reviewed_scope"], V3_OUTPUT_CAP_RETRY_SCOPE_VERSION
        )
        self.assertEqual(policy["limits"]["max_output_tokens_per_call"], 8192)
        self.assertEqual(policy["limits"]["max_budget_usd_per_case"], 14.46)
        self.assertEqual(policy["limits"]["base_model_calls"], 13)
        self.assertEqual(policy["limits"]["extension_model_calls"], 4)

    def test_v3_defensive_retry_scope_is_exact_and_preparable(self) -> None:
        scope = load_v3_reviewed_scope(V3_DEFENSIVE_RETRY_SCOPE_VERSION)
        self.assertEqual(scope["scope_kind"], "retry_only")
        self.assertEqual(
            {case["case_id"] for case in scope["cases"]},
            V3_DEFENSIVE_RETRY_CASE_IDS,
        )
        self.assertEqual(
            scope["required_prior_stream_outcome"], "provider_failed"
        )
        self.assertEqual(
            scope["required_prior_error_contains"], "cyber_policy"
        )
        policy = load_policy_for_protocol(
            "v3", V3_DEFENSIVE_RETRY_POLICY_VERSION
        )
        self.assertEqual(
            policy["reviewed_scope"], V3_DEFENSIVE_RETRY_SCOPE_VERSION
        )
        self.assertEqual(policy["limits"]["max_output_tokens_per_call"], 8192)
        self.assertEqual(policy["limits"]["max_budget_usd_per_case"], 14.70)
        self.assertTrue(
            policy["cost_projection"][
                "include_reinforced_runner_context"
            ]
        )

        repository = SKILL.parent
        source_runs = repository / "results" / "tier-b" / "filter-runs"
        source_run = source_runs / scope["source_run_id"]
        queue_dir = (
            repository
            / "results"
            / "tier-b"
            / "filter-preparation"
            / "2026-07-26__tier-a-mixed-recovered-cascade"
            / "queue"
        )
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            results_root = root / "runs"
            copied_source = results_root / scope["source_run_id"]
            copied_source.mkdir(parents=True)
            shutil.copyfile(
                source_run / "manifest.jsonl",
                copied_source / "manifest.jsonl",
            )
            shutil.copyfile(
                source_run / "results.jsonl",
                copied_source / "results.jsonl",
            )
            prepared = mvp_helpers.run_script(
                "prepare_run.py",
                "--queue-dir",
                str(queue_dir),
                "--results-root",
                str(results_root),
                "--run-label",
                "defensive-framing-retry-test",
                "--input-price-per-million",
                "5",
                "--output-price-per-million",
                "30",
                "--reasoning-effort",
                "medium",
                "--protocol-version",
                "v3",
                "--reviewed-defensive-framing-retry-scope",
                "--case-id",
                next(iter(V3_DEFENSIVE_RETRY_CASE_IDS)),
            )
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            report = json.loads(prepared.stdout)
            self.assertEqual(report["case_count"], 1)
            self.assertEqual(report["aggregate_hard_ceiling_usd"], 14.70)
            self.assertEqual(
                report["adaptive_projected_max_cost_usd"], 14.689445
            )
            task = read_jsonl(
                Path(report["run_dir"]) / "manifest.jsonl"
            )[0]
            self.assertGreater(
                task["adaptive_projection"][
                    "reserved_runner_replay_tokens_per_prior_call"
                ],
                0,
            )

    def test_contradicted_alternative_does_not_block_confirmation(self) -> None:
        errors = validate_model_result_v3(
            self.confirmation(), self.task, DummyPackage()
        )
        self.assertEqual(errors, [])

    def test_identity_reachability_and_obligations_remain_hard_gates(self) -> None:
        absent = self.confirmation()
        absent["candidate_identity"]["status"] = "absent"
        self.assertTrue(
            any(
                "present candidate" in error
                for error in validate_model_result_v3(
                    absent, self.task, DummyPackage()
                )
            )
        )
        unreachable = self.confirmation()
        unreachable["reachability"] = "unreachable"
        self.assertTrue(
            any(
                "evidenced reachability" in error
                for error in validate_model_result_v3(
                    unreachable, self.task, DummyPackage()
                )
            )
        )
        unsatisfied = self.confirmation()
        unsatisfied["confirmation_obligations"][0]["completion"] = "unsatisfied"
        self.assertTrue(
            any(
                "every obligation satisfied" in error
                for error in validate_model_result_v3(
                    unsatisfied, self.task, DummyPackage()
                )
            )
        )

    def test_complete_post_transform_sink_proof_is_accepted(self) -> None:
        errors = validate_model_result_v3(
            self.suppression(), self.task, DummyPackage()
        )
        self.assertEqual(errors, [])

    def test_duplicate_suppression_coverage_and_invariant_ids_are_rejected(
        self,
    ) -> None:
        duplicate_coverage = self.suppression()
        duplicate_coverage["suppression_proof"]["hypothesis_coverage"].append(
            "H-supported"
        )
        errors = validate_model_result_v3(
            duplicate_coverage, self.task, DummyPackage()
        )
        self.assertTrue(
            any("coverage contains duplicates" in error for error in errors),
            errors,
        )

        duplicate_invariants = self.suppression()
        sink = duplicate_invariants["suppression_proof"]["sink_inventory"][
            "sinks"
        ][0]
        sink["transformations"][0]["invariant_ids"] = ["I1", "I1"]
        sink["invariant_dependencies"] = [
            {
                "invariant_id": "I1",
                "invariant": "The guarded range remains valid.",
                "established_function_uid": "fn-candidate",
                "established_line": 12,
                "used_at_sink_id": sink["sink_id"],
                "intervening_mutations": [],
                "conclusion": "preserved",
                "evidence": ["No mutation changes the range."],
            }
        ]
        errors = validate_model_result_v3(
            duplicate_invariants, self.task, DummyPackage()
        )
        self.assertTrue(
            any("duplicate transformation invariant IDs" in error for error in errors),
            errors,
        )

    def test_guard_from_before_value_change_cannot_suppress(self) -> None:
        value = self.suppression()
        guard = value["suppression_proof"]["sink_inventory"]["sinks"][0]["guard"]
        guard["position"] = "earlier_with_complete_preservation_proof"
        guard["after_transformation_order"] = 0
        errors = validate_model_result_v3(value, self.task, DummyPackage())
        self.assertTrue(
            any("invalidated by a later transformation" in error for error in errors),
            errors,
        )
        self.assertTrue(
            any("lacks a complete invariant-preservation proof" in error for error in errors),
            errors,
        )

    def test_unresolved_mutation_and_supported_hypothesis_block_suppression(self) -> None:
        value = self.suppression()
        sink = value["suppression_proof"]["sink_inventory"]["sinks"][0]
        sink["guard"]["position"] = "earlier_with_complete_preservation_proof"
        sink["guard"]["after_transformation_order"] = 0
        sink["transformations"][0]["effect"] = (
            "changes_value_preserves_proven_invariant"
        )
        sink["transformations"][0]["invariant_ids"] = ["I1"]
        sink["invariant_dependencies"] = [
            {
                "invariant_id": "I1",
                "invariant": "Pointer remains non-NULL.",
                "established_function_uid": "fn-candidate",
                "established_line": 12,
                "used_at_sink_id": sink["sink_id"],
                "intervening_mutations": [
                    {
                        "order": 1,
                        "function_uid": "fn-candidate",
                        "line": 14,
                        "mutation": "Pointer advances.",
                        "preservation": "unresolved",
                        "evidence": ["The next entry was not checked."],
                    }
                ],
                "conclusion": "unresolved",
                "evidence": ["Preservation could not be established."],
            }
        ]
        errors = validate_model_result_v3(value, self.task, DummyPackage())
        self.assertTrue(
            any("unaddressed intervening mutation" in error for error in errors),
            errors,
        )

        supported = copy.deepcopy(self.suppression())
        supported["hypotheses"][0]["result"] = "supported"
        errors = validate_model_result_v3(supported, self.task, DummyPackage())
        self.assertTrue(
            any("cannot override a supported positive" in error for error in errors),
            errors,
        )

    def test_unresolved_indirect_call_blocks_unreachability_suppression(self) -> None:
        value = self.suppression()
        value["suppression_proof"]["claim"] = "unreachable"
        value["reachability"] = "unreachable"
        value["suppression_proof"]["sink_inventory"]["sinks"] = []
        errors = validate_model_result_v3(value, self.task, DummyPackage(True))
        self.assertTrue(
            any("unresolved indirect calls" in error for error in errors), errors
        )

    def test_v3_prepare_rejects_any_scope_beyond_reviewed_six_cases(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            package_path = mvp_helpers.MvpTest(methodName="runTest").make_package(
                root
            )
            from filter_common import AnalysisPackage, load_policy

            package = AnalysisPackage(package_path, load_policy())
            target = next(
                row for row in package.function_rows if row["address"] == "1000"
            )
            queue_dir = root / "queue"
            queue_dir.mkdir()
            case = {
                "queue_version": "tier-b-filter-queue-v1",
                "case_id": "tier-b-case-" + "3" * 24,
                "artifact_sha256": package.metadata["artifact_sha256"],
                "function_uid": target["function_uid"],
                "target_class": "null-pointer-dereference",
                "package_path": str(package_path),
                "entry_roots": [target["function_uid"]],
                "source_row_count": 1,
                "source_rows": [],
                "evidence_items": [
                    {
                        "model_verdict": "vulnerable",
                        "evidence_lines": [2],
                        "summary": "pointer dereference",
                    }
                ],
                "has_conflicting_verdicts": False,
            }
            mvp_helpers.jsonl(queue_dir / "queue.jsonl", [case])
            mvp_helpers.jsonl(queue_dir / "quarantine.jsonl", [])
            (queue_dir / "ingestion-summary.json").write_text(
                json.dumps({"output_case_count": 1, "quarantine_count": 0}),
                encoding="utf-8",
            )
            results_root = root / "runs"
            prepared = mvp_helpers.run_script(
                "prepare_run.py",
                "--queue-dir",
                str(queue_dir),
                "--results-root",
                str(results_root),
                "--run-label",
                "v3-test",
                "--input-price-per-million",
                "1",
                "--output-price-per-million",
                "1",
                "--protocol-version",
                "v3",
                "--case-id",
                case["case_id"],
            )
            self.assertEqual(prepared.returncode, 2)
            self.assertIn(
                "restricted to the exact reviewed six-case comparison scope",
                prepared.stderr,
            )
            self.assertFalse(results_root.exists())


if __name__ == "__main__":
    unittest.main()
