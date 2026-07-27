from __future__ import annotations

import csv
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SKILL = Path(__file__).resolve().parents[1]
SCRIPTS = SKILL / "scripts"
sys.path.insert(0, str(SCRIPTS))

from filter_common import (  # noqa: E402
    AnalysisPackage,
    load_policy,
    validate_model_result,
    validate_strict_json_schema,
)


def jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def run_script(name: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPTS / name), *args],
        text=True,
        capture_output=True,
        check=False,
    )


class MvpTest(unittest.TestCase):
    def make_package(
        self,
        root: Path,
        *,
        executable_md5: str | None = None,
        expected_returncode: int = 0,
    ) -> Path:
        artifact = root / "program.bin"
        artifact.write_bytes(b"\x01\x02\x03\x04")
        corpus = root / "corpus"
        corpus.mkdir()
        (corpus / "FUN_1000.c").write_text(
            "int f(int *p) {\n  return *p;\n}\n", encoding="utf-8"
        )
        (corpus / "FUN_2000.c").write_text(
            "int g(int *p) {\n  return f(p);\n}\n", encoding="utf-8"
        )
        export = root / "analysis.jsonl"
        jsonl(
            export,
            [
                {
                    "record_type": "metadata",
                    "analysis_source": "ghidra-program-model",
                    "analysis_tool": "Ghidra",
                    "analysis_version": "test",
                    "executable_md5": executable_md5
                    or hashlib.md5(
                        artifact.read_bytes(), usedforsecurity=False
                    ).hexdigest(),
                },
                {
                    "record_type": "function",
                    "address": "1000",
                    "byte_sha256": hashlib.sha256(b"f").hexdigest(),
                    "normalized_instruction_sha256": hashlib.sha256(
                        b"load-return"
                    ).hexdigest(),
                    "body_ranges": ["1000-1010"],
                    "size_bytes": 17,
                    "block_count": 1,
                    "strings": [],
                    "data_references": [],
                },
                {
                    "record_type": "function",
                    "address": "2000",
                    "byte_sha256": hashlib.sha256(b"g").hexdigest(),
                    "normalized_instruction_sha256": hashlib.sha256(
                        b"call-return"
                    ).hexdigest(),
                    "body_ranges": ["2000-2010"],
                    "size_bytes": 17,
                    "block_count": 1,
                    "strings": [],
                    "data_references": [],
                },
                {
                    "record_type": "callsite",
                    "caller_address": "2000",
                    "site_address": "2004",
                    "call_kind": "direct",
                    "target_address": "1000",
                    "evidence": "UNCONDITIONAL_CALL",
                },
                {
                    "record_type": "callsite",
                    "caller_address": "2000",
                    "site_address": "2008",
                    "call_kind": "indirect",
                    "target_address": None,
                    "evidence": "CALLIND",
                },
            ],
        )
        package = root / "package"
        result = run_script(
            "build_analysis_package.py",
            "--artifact",
            str(artifact),
            "--corpus-root",
            str(corpus),
            "--analysis-export",
            str(export),
            "--output-dir",
            str(package),
            "--package-id",
            "test-package",
        )
        self.assertEqual(result.returncode, expected_returncode, result.stderr)
        return package

    def test_analysis_export_must_match_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            package = self.make_package(
                Path(temporary),
                executable_md5="0" * 32,
                expected_returncode=2,
            )
            self.assertFalse(package.exists())

    def write_scoring(
        self, path: Path, rows: list[dict[str, str]]
    ) -> None:
        path.parent.mkdir(parents=True)
        fields = [
            "task_id",
            "cve_id",
            "variant",
            "indexed_bug_class",
            "target_class",
            "expected_positive",
            "input_status",
            "response_status",
            "model_verdict",
            "confidence",
            "evidence_lines",
            "summary",
            "model",
        ]
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)

    def test_exact_case_coalescing_preserves_classes_and_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            artifact = "a" * 64
            uid = "fn-" + "1" * 32
            run_a = root / "runs" / "run-a" / "scoring" / "scoring.csv"
            run_b = root / "runs" / "run-b" / "scoring" / "scoring.csv"
            base = {
                "cve_id": "CVE-X",
                "variant": "vulnerable",
                "indexed_bug_class": "null-pointer-dereference",
                "expected_positive": "True",
                "input_status": "ready",
                "response_status": "ok",
                "confidence": "0.8",
                "model": "test",
            }
            self.write_scoring(
                run_a,
                [
                    {
                        **base,
                        "task_id": "task-null-a",
                        "target_class": "null-pointer-dereference",
                        "model_verdict": "vulnerable",
                        "evidence_lines": "[3]",
                        "summary": "first hypothesis",
                    },
                    {
                        **base,
                        "task_id": "task-oob-a",
                        "target_class": "out-of-bounds-read",
                        "model_verdict": "vulnerable",
                        "evidence_lines": "[4]",
                        "summary": "different class",
                    },
                ],
            )
            self.write_scoring(
                run_b,
                [
                    {
                        **base,
                        "task_id": "task-null-b",
                        "target_class": "null-pointer-dereference",
                        "model_verdict": "indeterminate",
                        "evidence_lines": "[5]",
                        "summary": "second hypothesis",
                    },
                    {
                        **base,
                        "task_id": "missing-binding",
                        "target_class": "integer-overflow",
                        "model_verdict": "vulnerable",
                        "evidence_lines": "[]",
                        "summary": "must quarantine",
                    },
                ],
            )
            bindings = root / "bindings.jsonl"
            jsonl(
                bindings,
                [
                    {
                        "source_run_id": "run-a",
                        "source_task_id": "task-null-a",
                        "artifact_sha256": artifact,
                        "function_uid": uid,
                        "package_path": "package",
                        "entry_roots": [],
                    },
                    {
                        "source_run_id": "run-a",
                        "source_task_id": "task-oob-a",
                        "artifact_sha256": artifact,
                        "function_uid": uid,
                        "package_path": "package",
                        "entry_roots": [],
                    },
                    {
                        "source_run_id": "run-b",
                        "source_task_id": "task-null-b",
                        "artifact_sha256": artifact,
                        "function_uid": uid,
                        "package_path": "package",
                        "entry_roots": [],
                    },
                ],
            )
            output = root / "queue"
            result = run_script(
                "ingest_tier_a_queue.py",
                "--scoring-csv",
                str(run_a),
                "--scoring-csv",
                str(run_b),
                "--bindings-jsonl",
                str(bindings),
                "--output-dir",
                str(output),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            cases = [
                json.loads(line)
                for line in (output / "queue.jsonl").read_text().splitlines()
            ]
            self.assertEqual(len(cases), 2)
            by_class = {case["target_class"]: case for case in cases}
            self.assertEqual(
                by_class["null-pointer-dereference"]["source_row_count"], 2
            )
            self.assertEqual(
                len(by_class["null-pointer-dereference"]["evidence_items"]), 2
            )
            self.assertEqual(by_class["out-of-bounds-read"]["source_row_count"], 1)
            summary = json.loads((output / "ingestion-summary.json").read_text())
            self.assertEqual(summary["eligible_raw_row_count"], 4)
            self.assertEqual(summary["mapped_raw_row_count"], 4)
            self.assertEqual(summary["quarantine_count"], 1)
            self.assertEqual(summary["coalesced_duplicate_row_count"], 1)

    def test_package_uses_analyzed_calls_and_blocks_unreachable_suppression(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            package_path = self.make_package(root)
            package = AnalysisPackage(package_path, load_policy())
            package.verify_frozen_inputs()
            self.assertEqual(package.metadata["callsite_count"], 2)
            self.assertEqual(package.metadata["unresolved_indirect_callsite_count"], 1)
            functions = package.function_rows
            target = next(row for row in functions if row["address"] == "1000")
            caller = next(row for row in functions if row["address"] == "2000")
            direct = package.execute_tool(
                "get_callsites", {"function_uid": caller["function_uid"]}
            )
            self.assertEqual(len(direct["callsites"]), 2)
            task = {
                "target_class": "null-pointer-dereference",
                "function_uid": target["function_uid"],
                "artifact_sha256": package.metadata["artifact_sha256"],
            }
            result = {
                "schema_version": "tier-b-filter-result-v2",
                "target_class": "null-pointer-dereference",
                "semantic_status": "safety_proven",
                "pipeline_disposition": "suppress_proven_false_positive",
                "execution_status": "completed",
                "candidate_identity": {
                    "status": "present",
                    "function_uid": target["function_uid"],
                    "artifact_sha256": package.metadata["artifact_sha256"],
                    "evidence": "bound",
                },
                "hypotheses": [
                    {
                        "hypothesis": "candidate is unreachable",
                        "status": "contradicted",
                        "evidence": [],
                    }
                ],
                "proof_obligations": [
                    {
                        "obligation": "reachability",
                        "status": "contradicted",
                        "evidence": [],
                    }
                ],
                "reachability": "unreachable",
                "evidence": [],
                "blocking_controls": [],
                "unresolved_facts": [],
                "progress_events": [],
                "summary": "unreachable",
            }
            errors = validate_model_result(result, task, package)
            self.assertTrue(
                any("unresolved indirect calls" in error for error in errors), errors
            )

    def test_structured_output_schema_requires_explicit_types(self) -> None:
        schema = json.loads(
            (SKILL / "references" / "result-schema.json").read_text(
                encoding="utf-8"
            )
        )
        validate_strict_json_schema(schema)
        schema["properties"]["reachability"].pop("type")
        with self.assertRaisesRegex(ValueError, "explicit type"):
            validate_strict_json_schema(schema)

    def test_prepare_and_dry_run_make_no_provider_calls(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            package_path = self.make_package(root)
            package = AnalysisPackage(package_path, load_policy())
            target = next(
                row for row in package.function_rows if row["address"] == "1000"
            )
            queue_dir = root / "queue"
            queue_dir.mkdir()
            case = {
                "queue_version": "tier-b-filter-queue-v1",
                "case_id": "tier-b-case-" + "2" * 24,
                "artifact_sha256": package.metadata["artifact_sha256"],
                "function_uid": target["function_uid"],
                "target_class": "null-pointer-dereference",
                "package_path": str(package_path),
                "entry_roots": [target["function_uid"]],
                "source_row_count": 1,
                "source_rows": [
                    {
                        "source_row_id": "source",
                        "expected_positive": "True",
                    }
                ],
                "evidence_items": [
                    {
                        "model_verdict": "vulnerable",
                        "evidence_lines": [2],
                        "summary": "pointer dereference",
                    }
                ],
                "has_conflicting_verdicts": False,
            }
            jsonl(queue_dir / "queue.jsonl", [case])
            jsonl(queue_dir / "quarantine.jsonl", [])
            (queue_dir / "ingestion-summary.json").write_text(
                json.dumps({"output_case_count": 1, "quarantine_count": 0}),
                encoding="utf-8",
            )
            results_root = root / "runs"
            prepared = run_script(
                "prepare_run.py",
                "--queue-dir",
                str(queue_dir),
                "--results-root",
                str(results_root),
                "--run-label",
                "test",
                "--input-price-per-million",
                "5",
                "--output-price-per-million",
                "30",
                "--reasoning-effort",
                "medium",
                "--case-id",
                case["case_id"],
            )
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            run_dir = next(results_root.iterdir())
            summary = json.loads((run_dir / "manifest-summary.json").read_text())
            metadata = json.loads((run_dir / "run-metadata.json").read_text())
            manifest = [
                json.loads(line)
                for line in (run_dir / "manifest.jsonl").read_text().splitlines()
            ]
            self.assertEqual(metadata["reasoning_effort"], "medium")
            self.assertEqual(metadata["source_queue_case_count"], 1)
            self.assertEqual(metadata["selected_case_ids"], [case["case_id"]])
            self.assertEqual(manifest[0]["reasoning_effort"], "medium")
            self.assertEqual(summary["source_queue_case_count"], 1)
            self.assertEqual(summary["selected_case_ids"], [case["case_id"]])
            self.assertEqual(summary["provider_api_calls_made_during_preparation"], 0)
            dry = run_script(
                "run_investigation.py",
                "--run-dir",
                str(run_dir),
                "--budget-usd",
                str(summary["adaptive_projected_max_cost_usd"]),
            )
            self.assertEqual(dry.returncode, 0, dry.stderr)
            report = json.loads(dry.stdout)
            self.assertFalse(report["would_make_provider_calls"])
            self.assertEqual((run_dir / "results.jsonl").read_text(), "")


if __name__ == "__main__":
    unittest.main()
