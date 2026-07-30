from __future__ import annotations

import copy
import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


SKILL = Path(__file__).resolve().parents[1]
SCRIPTS = SKILL / "scripts"
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from filter_common import (  # noqa: E402
    audit_strict_json_schema,
    read_jsonl,
    validate_strict_json_schema,
)
from filter_v3 import validate_model_result_v3  # noqa: E402
from filter_v4 import (  # noqa: E402
    CONTRADICTION_BASIS_KINDS,
    CONTRADICTION_VALUE_RELATIONS,
    V4_CVE_2021_42374_POLICY_VERSION,
    V4_CVE_2021_42374_SCOPE_VERSION,
    V4_REQUIRED_STATIC_TOOLS,
    V4_STATIC_PRIMARY_POLICY_VERSION,
    V4_STATIC_PRIMARY_SCOPE_VERSION,
    V4_STATIC_ROUND3_POLICY_VERSION,
    V4_STATIC_ROUND3_SCOPE_VERSION,
    V4_STATIC_REQUIRED_TOOLS_POLICY_VERSION,
    V4_STATIC_REQUIRED_TOOLS_SCOPE_VERSION,
    V4_SCHEMA_VERSION,
    fallback_result_v4,
    load_policy_for_protocol,
    load_v4_reviewed_scope,
    neutral_contradiction_proof,
    validate_and_normalize_model_result_v4,
)
from run_investigation import (  # noqa: E402
    append_interim_fallback,
    append_interim_result,
    missing_required_tool_names,
    required_tool_choice,
    should_grant_required_tool_retry_extension,
    tool_call_satisfies_coverage,
)
import test_v3 as v3_test_helpers  # noqa: E402
import test_mvp as mvp_helpers  # noqa: E402


V3_SCHEMA_SHA256 = (
    "c87fb2421f88d32cd34c10474565ce6b382c6d558da1aa5152e2e3896fa70400"
)
V3_VALIDATOR_SHA256 = (
    "93cbccd618ab2f7e19d518a55d33c8a254d18cb5e23f8baedac2b617fd9cf65b"
)


class DummyPackage:
    functions = {
        "fn-candidate": {"total_lines": 100},
        "fn-guard": {"total_lines": 80},
    }

    def has_any_unresolved_indirect(self) -> bool:
        return False


class V4ValidatorTest(unittest.TestCase):
    def test_static_primary_scope_and_policy_are_exact(self) -> None:
        policy = load_policy_for_protocol(
            "v4", V4_STATIC_PRIMARY_POLICY_VERSION
        )
        scope = load_v4_reviewed_scope(V4_STATIC_PRIMARY_SCOPE_VERSION)
        self.assertEqual(
            policy["reviewed_scope"], V4_STATIC_PRIMARY_SCOPE_VERSION
        )
        self.assertEqual(
            policy["package_version"], "tier-b-filter-static-package-v2"
        )
        self.assertEqual(scope["scope_kind"], "static_primary")
        self.assertEqual(len(scope["cases"]), 3)
        self.assertEqual(
            {case["target_class"] for case in scope["cases"]},
            {"integer-overflow", "out-of-bounds-read", "use-after-free"},
        )

    def test_static_required_tools_scope_policy_and_gate_are_exact(self) -> None:
        policy = load_policy_for_protocol(
            "v4", V4_STATIC_REQUIRED_TOOLS_POLICY_VERSION
        )
        scope = load_v4_reviewed_scope(
            V4_STATIC_REQUIRED_TOOLS_SCOPE_VERSION
        )
        required = scope["required_tool_names"]
        self.assertEqual(
            required,
            [
                "get_reaching_definitions",
                "slice_pcode",
                "get_dominance",
                "query_angr",
            ],
        )
        self.assertEqual(set(required), V4_REQUIRED_STATIC_TOOLS)
        self.assertEqual(policy["reviewed_scope"], scope["scope_version"])
        self.assertEqual(
            policy["tool_coverage_enforcement"],
            "required-before-completed-retention-v1",
        )
        successful = {"get_reaching_definitions", "slice_pcode"}
        missing = missing_required_tool_names(required, successful)
        self.assertEqual(missing, ["get_dominance", "query_angr"])
        self.assertIsNone(
            required_tool_choice(
                missing,
                remaining_tool_slots=3,
                coverage_gate_active=False,
            )
        )
        self.assertEqual(
            required_tool_choice(
                missing,
                remaining_tool_slots=2,
                coverage_gate_active=False,
            ),
            "get_dominance",
        )
        self.assertTrue(
            tool_call_satisfies_coverage(
                "get_dominance", {"dominators": ["block-1"]}
            )
        )
        self.assertFalse(
            tool_call_satisfies_coverage(
                "query_angr", {"backend_status": "unavailable"}
            )
        )
        self.assertFalse(
            tool_call_satisfies_coverage(
                "slice_pcode", {"error": "invalid source"}
            )
        )
        self.assertTrue(
            should_grant_required_tool_retry_extension(
                "slice_pcode",
                {"error": "tool_result_too_large"},
                required_tool_names=required,
                extension_policy="tool-result-too-large-v1",
                extension_granted=False,
            )
        )
        self.assertFalse(
            should_grant_required_tool_retry_extension(
                "get_pcode",
                {"error": "tool_result_too_large"},
                required_tool_names=required,
                extension_policy="tool-result-too-large-v1",
                extension_granted=False,
            )
        )

    def test_static_round3_scope_and_policy_are_exact(self) -> None:
        policy = load_policy_for_protocol(
            "v4", V4_STATIC_ROUND3_POLICY_VERSION
        )
        scope = load_v4_reviewed_scope(V4_STATIC_ROUND3_SCOPE_VERSION)
        self.assertEqual(scope["scope_kind"], "static_required_tools_round3")
        self.assertEqual(len(scope["cases"]), 2)
        self.assertEqual(
            {case["target_class"] for case in scope["cases"]},
            {"integer-overflow", "out-of-bounds-read"},
        )
        self.assertEqual(policy["reviewed_scope"], scope["scope_version"])
        self.assertEqual(
            policy["request_defensive_reminder"],
            "every-provider-request-v1",
        )
        self.assertEqual(
            policy["required_tool_retry_extension"],
            "tool-result-too-large-v1",
        )

    def test_static_round3_zero_api_preparation_is_exact(self) -> None:
        repository = SKILL.parent
        queue_dir = (
            repository
            / "results"
            / "tier-b"
            / "static-preparation"
            / "2026-07-29__three-primary"
            / "queue"
        )
        source_id = (
            "2026-07-30t040248z__gpt-5.6-sol__medium__"
            "tier-a-mixed-recovered-static-required-tools-rerun-v2"
        )
        source_dir = (
            repository / "results" / "tier-b" / "filter-runs" / source_id
        )
        case_ids = [
            "tier-b-case-b111eb91e1a79ebe60c176fc",
            "tier-b-case-b458bbf5b4ee3b7538c0ab0e",
        ]
        with tempfile.TemporaryDirectory() as raw:
            results_root = Path(raw)
            copied_source = results_root / source_id
            copied_source.mkdir()
            shutil.copy2(
                source_dir / "manifest.jsonl",
                copied_source / "manifest.jsonl",
            )
            shutil.copy2(
                source_dir / "results.jsonl",
                copied_source / "results.jsonl",
            )
            command = [
                "prepare_run.py",
                "--queue-dir",
                str(queue_dir),
                "--results-root",
                raw,
                "--run-label",
                "round3-preparation-test",
                "--input-price-per-million",
                "5",
                "--output-price-per-million",
                "30",
                "--reasoning-effort",
                "medium",
                "--protocol-version",
                "v4",
                "--reviewed-static-round3-scope",
            ]
            for case_id in case_ids:
                command.extend(["--case-id", case_id])
            prepared = mvp_helpers.run_script(*command)
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            report = json.loads(prepared.stdout)
            self.assertEqual(report["case_count"], 2)
            self.assertEqual(
                report["adaptive_projected_max_cost_usd"], 33.04557
            )
            self.assertEqual(report["aggregate_hard_ceiling_usd"], 33.06)
            self.assertEqual(
                report["manifest_sha256"],
                "5115f7d615a636be10013c7db2464b85"
                "e42c37fbb314979bdc83658ace62ebc4",
            )
            self.assertEqual(
                report["provider_api_calls_made_during_preparation"], 0
            )
            tasks = read_jsonl(Path(report["run_dir"]) / "manifest.jsonl")
            for task in tasks:
                self.assertEqual(
                    task["request_defensive_reminder"],
                    "every-provider-request-v1",
                )
                self.assertEqual(
                    task["required_tool_retry_extension"],
                    "tool-result-too-large-v1",
                )

    def test_static_required_tools_zero_api_preparation_is_exact(self) -> None:
        repository = SKILL.parent
        queue_dir = (
            repository
            / "results"
            / "tier-b"
            / "static-preparation"
            / "2026-07-29__three-primary"
            / "queue"
        )
        case_ids = [
            "tier-b-case-b458bbf5b4ee3b7538c0ab0e",
            "tier-b-case-b111eb91e1a79ebe60c176fc",
            "tier-b-case-e110a030eba0d95e170ac7de",
        ]
        with tempfile.TemporaryDirectory() as raw:
            command = [
                "prepare_run.py",
                "--queue-dir",
                str(queue_dir),
                "--results-root",
                raw,
                "--run-label",
                "required-tools-preparation-test",
                "--input-price-per-million",
                "5",
                "--output-price-per-million",
                "30",
                "--reasoning-effort",
                "medium",
                "--protocol-version",
                "v4",
                "--reviewed-static-required-tools-scope",
            ]
            for case_id in case_ids:
                command.extend(["--case-id", case_id])
            prepared = mvp_helpers.run_script(*command)
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            report = json.loads(prepared.stdout)
            self.assertEqual(report["case_count"], 3)
            self.assertEqual(
                report["adaptive_projected_max_cost_usd"], 49.53411
            )
            self.assertEqual(report["aggregate_hard_ceiling_usd"], 49.56)
            self.assertEqual(
                report["manifest_sha256"],
                "6d22e60043790394bfca512928d15d397"
                "84633e64781d4a7282f976e661f5cf2",
            )
            self.assertEqual(
                report["provider_api_calls_made_during_preparation"], 0
            )
            tasks = read_jsonl(Path(report["run_dir"]) / "manifest.jsonl")
            self.assertEqual(len(tasks), 3)
            for task in tasks:
                self.assertEqual(
                    task["required_tool_names"],
                    [
                        "get_reaching_definitions",
                        "slice_pcode",
                        "get_dominance",
                        "query_angr",
                    ],
                )
                self.assertEqual(
                    task["tool_coverage_enforcement"],
                    "required-before-completed-retention-v1",
                )

    task = {
        "schema_version": V4_SCHEMA_VERSION,
        "target_class": "null-pointer-dereference",
        "function_uid": "fn-candidate",
        "artifact_sha256": "a" * 64,
    }

    def valid_contradiction_proof(
        self,
        *,
        basis_kind: str = "range_check",
        value_relation: str = "exact_same_value_state",
    ) -> dict:
        return {
            "applicability": "required",
            "basis_kind": basis_kind,
            "claim": "The post-transform value is rejected before this sink.",
            "value_relation": value_relation,
            "citations": [
                {
                    "function_uid": "fn-candidate",
                    "line": 18,
                    "evidence": (
                        "The cited comparison checks the same post-transform "
                        "value used by the sink."
                    ),
                }
            ],
            "equivalence_evidence": (
                ["The assignment is a direct copy with no intervening mutation."]
                if value_relation == "explicitly_proven_equivalent"
                else []
            ),
        }

    def confirmation(self) -> dict:
        value = v3_test_helpers.V3ValidatorTest().confirmation()
        value["schema_version"] = V4_SCHEMA_VERSION
        for hypothesis in value["hypotheses"]:
            hypothesis["contradiction_proof"] = (
                self.valid_contradiction_proof()
                if hypothesis["result"] == "contradicted"
                else neutral_contradiction_proof()
            )
        return value

    def suppression(self) -> dict:
        value = v3_test_helpers.V3ValidatorTest().suppression()
        value["schema_version"] = V4_SCHEMA_VERSION
        for hypothesis in value["hypotheses"]:
            hypothesis["contradiction_proof"] = (
                self.valid_contradiction_proof()
            )
        return value

    def normalize(self, value: dict):
        return validate_and_normalize_model_result_v4(
            value, self.task, DummyPackage()
        )

    def test_v4_schema_is_strict_and_has_closed_contradiction_enums(self) -> None:
        schema = json.loads(
            (SKILL / "references" / "v4" / "result-schema.json").read_text()
        )
        validate_strict_json_schema(schema)
        report = audit_strict_json_schema(schema)
        self.assertEqual(report["errors"], [])
        self.assertEqual(report["property_count"], 94)
        proof = schema["properties"]["hypotheses"]["items"]["properties"][
            "contradiction_proof"
        ]
        self.assertIn(
            "contradiction_proof",
            schema["properties"]["hypotheses"]["items"]["required"],
        )
        self.assertEqual(
            set(proof["properties"]["basis_kind"]["enum"]),
            CONTRADICTION_BASIS_KINDS,
        )
        self.assertEqual(
            set(proof["properties"]["value_relation"]["enum"]),
            CONTRADICTION_VALUE_RELATIONS,
        )

    def test_targeted_scope_policy_and_zero_api_preparation_are_exact(
        self,
    ) -> None:
        case_id = "tier-b-case-b99dc78d5275592661bdc5b9"
        scope = load_v4_reviewed_scope(V4_CVE_2021_42374_SCOPE_VERSION)
        self.assertEqual(scope["scope_kind"], "comparison_subset")
        self.assertEqual(
            {case["case_id"] for case in scope["cases"]}, {case_id}
        )
        policy = load_policy_for_protocol(
            "v4", V4_CVE_2021_42374_POLICY_VERSION
        )
        self.assertEqual(policy["reviewed_scope"], scope["scope_version"])
        self.assertEqual(policy["limits"]["max_output_tokens_per_call"], 8192)
        self.assertEqual(policy["limits"]["max_budget_usd_per_case"], 14.77)
        self.assertTrue(
            policy["cost_projection"]["include_reinforced_runner_context"]
        )

        repository = SKILL.parent
        queue_dir = (
            repository
            / "results"
            / "tier-b"
            / "filter-preparation"
            / "2026-07-26__tier-a-mixed-recovered-cascade"
            / "queue"
        )
        with tempfile.TemporaryDirectory() as raw:
            command = [
                "prepare_run.py",
                "--queue-dir",
                str(queue_dir),
                "--results-root",
                raw,
                "--run-label",
                "v4-targeted-preparation-test",
                "--input-price-per-million",
                "5",
                "--output-price-per-million",
                "30",
                "--reasoning-effort",
                "medium",
                "--protocol-version",
                "v4",
                "--reviewed-v4-cve-2021-42374-scope",
                "--case-id",
                case_id,
            ]
            prepared = mvp_helpers.run_script(*command)
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            report = json.loads(prepared.stdout)
            self.assertEqual(report["case_count"], 1)
            self.assertEqual(
                report["base_projected_max_cost_usd"], 9.403095
            )
            self.assertEqual(
                report["adaptive_projected_max_cost_usd"], 14.763055
            )
            self.assertEqual(report["aggregate_hard_ceiling_usd"], 14.77)
            task = read_jsonl(Path(report["run_dir"]) / "manifest.jsonl")[0]
            self.assertEqual(task["case_id"], case_id)
            self.assertEqual(task["protocol_version"], "v4")

    def test_exact_same_value_state_contradiction_is_accepted(self) -> None:
        normalized, errors, adjustments = self.normalize(self.confirmation())
        self.assertEqual(errors, [])
        self.assertEqual(adjustments, [])
        self.assertEqual(
            normalized["hypotheses"][1]["result"], "contradicted"
        )

    def test_explicit_equivalence_requires_and_accepts_evidence(self) -> None:
        value = self.confirmation()
        proof = self.valid_contradiction_proof(
            value_relation="explicitly_proven_equivalent"
        )
        value["hypotheses"][1]["contradiction_proof"] = proof
        _, errors, adjustments = self.normalize(value)
        self.assertEqual(errors, [])
        self.assertEqual(adjustments, [])

        proof["equivalence_evidence"] = []
        normalized, errors, adjustments = self.normalize(value)
        self.assertEqual(errors, [])
        self.assertEqual(
            normalized["hypotheses"][1]["result"], "unresolved"
        )
        self.assertTrue(
            any(
                "equivalence requires" in reason
                for item in adjustments
                for reason in item.get("reasons", [])
            )
        )

    def test_unsupported_contradiction_downgrades_and_blocks_suppression(
        self,
    ) -> None:
        value = self.suppression()
        value["hypotheses"][0]["contradiction_proof"] = (
            neutral_contradiction_proof()
        )
        normalized, errors, adjustments = self.normalize(value)
        self.assertEqual(errors, [])
        self.assertEqual(normalized["hypotheses"][0]["result"], "unresolved")
        self.assertEqual(normalized["semantic_status"], "unresolved")
        self.assertEqual(
            normalized["pipeline_disposition"], "retain_and_escalate"
        )
        self.assertEqual(
            normalized["suppression_proof"]["completion"], "unresolved"
        )
        self.assertTrue(
            any(
                item["kind"] == "pipeline_disposition_adjustment"
                for item in adjustments
            )
        )

    def test_unsupported_alternative_does_not_block_supported_confirmation(
        self,
    ) -> None:
        value = self.confirmation()
        value["hypotheses"][1]["contradiction_proof"] = (
            neutral_contradiction_proof()
        )
        normalized, errors, adjustments = self.normalize(value)
        self.assertEqual(errors, [])
        self.assertEqual(
            normalized["pipeline_disposition"], "retain_confirmed"
        )
        self.assertEqual(normalized["semantic_status"], "confirmed")
        self.assertEqual(
            normalized["hypotheses"][0]["result"], "supported"
        )
        self.assertEqual(
            normalized["hypotheses"][1]["result"], "unresolved"
        )
        self.assertTrue(adjustments)

    def test_non_value_exclusion_is_only_for_direct_control_flow(self) -> None:
        value = self.confirmation()
        value["hypotheses"][1]["contradiction_proof"] = (
            self.valid_contradiction_proof(
                basis_kind="range_check",
                value_relation="non_value_fact_directly_excludes",
            )
        )
        normalized, errors, adjustments = self.normalize(value)
        self.assertEqual(errors, [])
        self.assertEqual(
            normalized["hypotheses"][1]["result"], "unresolved"
        )
        self.assertTrue(
            any(
                "only for a direct control-flow fact" in reason
                for item in adjustments
                for reason in item.get("reasons", [])
            )
        )

        value = self.confirmation()
        value["hypotheses"][1]["contradiction_proof"] = (
            self.valid_contradiction_proof(
                basis_kind="control_flow_fact",
                value_relation="non_value_fact_directly_excludes",
            )
        )
        normalized, errors, adjustments = self.normalize(value)
        self.assertEqual(errors, [])
        self.assertEqual(adjustments, [])
        self.assertEqual(
            normalized["hypotheses"][1]["result"], "contradicted"
        )

    def test_invalid_basis_and_unsupported_bounded_assertion_downgrade(
        self,
    ) -> None:
        value = self.confirmation()
        proof = value["hypotheses"][1]["contradiction_proof"]
        proof["basis_kind"] = "not_applicable"
        proof["claim"] = "The value must already be bounded."
        proof["citations"] = []
        normalized, errors, adjustments = self.normalize(value)
        self.assertEqual(errors, [])
        self.assertEqual(
            normalized["hypotheses"][1]["result"], "unresolved"
        )
        reasons = [
            reason
            for item in adjustments
            for reason in item.get("reasons", [])
        ]
        self.assertTrue(
            any("basis_kind is not evidentiary" in reason for reason in reasons)
        )
        self.assertTrue(
            any("requires at least one citation" in reason for reason in reasons)
        )

    def test_missing_unknown_and_out_of_range_citations_downgrade(self) -> None:
        mutations = [
            lambda proof: proof.update(citations=[]),
            lambda proof: proof["citations"][0].update(
                function_uid="fn-unknown"
            ),
            lambda proof: proof["citations"][0].update(line=101),
        ]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                value = self.confirmation()
                proof = value["hypotheses"][1]["contradiction_proof"]
                mutate(proof)
                normalized, errors, adjustments = self.normalize(value)
                self.assertEqual(errors, [])
                self.assertEqual(
                    normalized["hypotheses"][1]["result"], "unresolved"
                )
                self.assertTrue(adjustments)

    def test_supported_and_unresolved_use_exact_neutral_form(self) -> None:
        value = self.confirmation()
        value["hypotheses"][0]["contradiction_proof"] = (
            self.valid_contradiction_proof()
        )
        normalized, errors, adjustments = self.normalize(value)
        self.assertEqual(errors, [])
        self.assertEqual(
            normalized["hypotheses"][0]["result"], "supported"
        )
        self.assertEqual(
            normalized["hypotheses"][0]["contradiction_proof"],
            neutral_contradiction_proof(),
        )
        self.assertTrue(adjustments)

    def test_identity_reachability_and_obligations_remain_hard_gates(
        self,
    ) -> None:
        mutations = [
            ("present candidate", lambda value: value["candidate_identity"].update(status="absent")),
            ("evidenced reachability", lambda value: value.update(reachability="unreachable")),
            (
                "every obligation satisfied",
                lambda value: value["confirmation_obligations"][0].update(
                    completion="unsatisfied"
                ),
            ),
        ]
        for expected, mutate in mutations:
            with self.subTest(expected=expected):
                value = self.confirmation()
                mutate(value)
                _, errors, _ = self.normalize(value)
                self.assertTrue(
                    any(expected in error for error in errors), errors
                )

    def test_fallback_has_neutral_proof_on_every_hypothesis(self) -> None:
        task = dict(self.task)
        task["hypotheses"] = [
            {
                "hypothesis_id": "H1",
                "target_class": task["target_class"],
                "hypothesis": "Candidate hypothesis.",
            }
        ]
        result = fallback_result_v4(
            task, "infrastructure_error", "stream failed"
        )
        self.assertEqual(result["schema_version"], V4_SCHEMA_VERSION)
        self.assertTrue(result["hypotheses"])
        self.assertTrue(
            all(
                row["contradiction_proof"]
                == neutral_contradiction_proof()
                for row in result["hypotheses"]
            )
        )

    def test_runner_persists_adjustments_through_interim_fallback(self) -> None:
        adjustments = [
            {
                "kind": "hypothesis_result_adjustment",
                "hypothesis_id": "H-alternative",
                "claimed_result": "contradicted",
                "effective_result": "unresolved",
                "reasons": ["contradiction proof requires at least one citation"],
            }
        ]
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "ledger.jsonl"
            latest = append_interim_result(
                path,
                {
                    "case_id": "case-v4",
                    "cache_key": "cache-v4",
                    "model_call_index": 2,
                },
                model_call_index=2,
                raw_response_text="{}",
                parsed_result=self.confirmation(),
                extension_granted=False,
                progress_events=["new fact"],
                validator_adjustments=adjustments,
            )
            self.assertEqual(
                latest["validator_adjustments"], adjustments
            )
            self.assertTrue(
                append_interim_fallback(
                    path,
                    {"case_id": "case-v4", "cache_key": "cache-v4"},
                    latest,
                    failed_call_index=3,
                    failure_status="infrastructure_error",
                    failure_reason="stream ended",
                )
            )
            rows = [
                json.loads(line)
                for line in path.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["validator_adjustments"], adjustments)
            self.assertEqual(rows[1]["validator_adjustments"], adjustments)

    def test_v3_schema_validator_and_behavior_are_preserved(self) -> None:
        schema_path = SKILL / "references" / "v3" / "result-schema.json"
        validator_path = SKILL / "scripts" / "filter_v3.py"
        self.assertEqual(
            hashlib.sha256(schema_path.read_bytes()).hexdigest(),
            V3_SCHEMA_SHA256,
        )
        self.assertEqual(
            hashlib.sha256(validator_path.read_bytes()).hexdigest(),
            V3_VALIDATOR_SHA256,
        )
        old = v3_test_helpers.V3ValidatorTest()
        self.assertEqual(
            validate_model_result_v3(
                old.confirmation(), old.task, DummyPackage()
            ),
            [],
        )


if __name__ == "__main__":
    unittest.main()
