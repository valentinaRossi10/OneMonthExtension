from __future__ import annotations

import json
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


SKILL = Path(__file__).resolve().parents[1]
SCRIPTS = SKILL / "scripts"
sys.path.insert(0, str(SCRIPTS))

from stream_observability import (  # noqa: E402
    LEDGER_SCHEMA_VERSION,
    LedgerPersistenceError,
    STREAM_OUTCOMES,
    accounted_spend,
    observe_response_stream,
    orphaned_provider_calls,
    provider_generation_call_count,
    provider_retrieval_call_count,
    recover_response,
    should_attempt_recovery,
)
from run_investigation import (  # noqa: E402
    DEFENSIVE_CONTEXT_REMINDER,
    FINAL_SYNTHESIS_INSTRUCTION,
    append_interim_fallback,
    append_interim_result,
    append_tool_result_context,
    information_fact_keys,
    observation_failure,
    request_input_for_call,
)


def response(
    status: str,
    *,
    response_id: str = "resp-test",
    incomplete_reason: str | None = None,
    error: object | None = None,
    output_text: str = "",
    output: list[object] | None = None,
) -> SimpleNamespace:
    details = (
        SimpleNamespace(reason=incomplete_reason)
        if incomplete_reason is not None
        else None
    )
    return SimpleNamespace(
        id=response_id,
        status=status,
        incomplete_details=details,
        error=error,
        output_text=output_text,
        output=list(output or []),
    )


def event(
    event_type: str,
    *,
    event_response: object | None = None,
    sequence_number: int = 1,
    code: str | None = None,
    message: str | None = None,
    param: str | None = None,
    delta: str | None = None,
    item: object | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        type=event_type,
        response=event_response,
        sequence_number=sequence_number,
        code=code,
        message=message,
        param=param,
        delta=delta,
        item=item,
    )


class FakeStream:
    def __init__(
        self,
        events: list[object],
        *,
        iteration_error: BaseException | None = None,
    ) -> None:
        self.events = events
        self.iteration_error = iteration_error

    def __enter__(self) -> FakeStream:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def __iter__(self):
        yield from self.events
        if self.iteration_error is not None:
            raise self.iteration_error

    def get_final_response(self) -> None:
        raise AssertionError("get_final_response must never be used")


class FakeResponses:
    def __init__(
        self,
        *,
        stream: FakeStream | None = None,
        retrieved: list[object] | None = None,
    ) -> None:
        self.fake_stream = stream
        self.retrieved = list(retrieved or [])
        self.stream_calls = 0
        self.retrieve_calls: list[str] = []

    def stream(self, **request: object) -> FakeStream:
        self.stream_calls += 1
        if self.fake_stream is None:
            raise AssertionError("No generation stream was configured")
        return self.fake_stream

    def retrieve(self, response_id: str) -> object:
        self.retrieve_calls.append(response_id)
        if not self.retrieved:
            raise AssertionError("Unexpected retrieval")
        value = self.retrieved.pop(0)
        if isinstance(value, BaseException):
            raise value
        return value


class FakeClient:
    def __init__(self, responses: FakeResponses) -> None:
        self.responses = responses


class StreamClassificationTest(unittest.TestCase):
    def observe(
        self,
        events: list[object],
        *,
        iteration_error: BaseException | None = None,
    ):
        created: list[dict] = []
        client = FakeClient(
            FakeResponses(
                stream=FakeStream(events, iteration_error=iteration_error)
            )
        )
        observation = observe_response_stream(client, {}, created.append)
        return observation, created, client

    def test_completed_is_typed_and_created_is_captured_immediately(self) -> None:
        created_response = response("in_progress")
        completed_response = response("completed")
        observation, created, client = self.observe(
            [
                event(
                    "response.created",
                    event_response=created_response,
                    sequence_number=0,
                ),
                event(
                    "response.completed",
                    event_response=completed_response,
                    sequence_number=9,
                ),
            ]
        )
        self.assertEqual(observation.stream_outcome, "completed")
        self.assertEqual(
            observation.provider_terminal_event_type,
            "response.completed",
        )
        self.assertEqual(observation.last_sequence_number, 9)
        self.assertEqual(created[0]["provider_response_id"], "resp-test")
        self.assertEqual(client.responses.stream_calls, 1)

    def test_created_ledger_failure_is_not_misclassified_as_stream_failure(
        self,
    ) -> None:
        client = FakeClient(
            FakeResponses(
                stream=FakeStream(
                    [
                        event(
                            "response.created",
                            event_response=response("in_progress"),
                        )
                    ]
                )
            )
        )

        def fail_to_persist(_: dict) -> None:
            raise OSError("disk full")

        with self.assertRaises(LedgerPersistenceError):
            observe_response_stream(client, {}, fail_to_persist)

    def test_every_incomplete_classification(self) -> None:
        expected = {
            "max_output_tokens": "incomplete_max_output_tokens",
            "content_filter": "incomplete_content_filter",
            "future_reason": "incomplete_other",
            None: "incomplete_other",
        }
        for reason, outcome in expected.items():
            with self.subTest(reason=reason):
                observation, _, _ = self.observe(
                    [
                        event(
                            "response.created",
                            event_response=response("in_progress"),
                        ),
                        event(
                            "response.incomplete",
                            event_response=response(
                                "incomplete",
                                incomplete_reason=reason,
                            ),
                        ),
                    ]
                )
                self.assertEqual(observation.stream_outcome, outcome)
                self.assertFalse(should_attempt_recovery(observation))

    def test_max_output_is_resource_exhaustion_and_not_retryable(self) -> None:
        observation, _, client = self.observe(
            [
                event(
                    "response.created",
                    event_response=response("in_progress"),
                ),
                event(
                    "response.incomplete",
                    event_response=response(
                        "incomplete",
                        incomplete_reason="max_output_tokens",
                    ),
                ),
            ]
        )
        status, execution_status, _ = observation_failure(
            observation.stream_outcome,
            observation.provider_incomplete_reason,
        )
        self.assertEqual(
            status, "provider_incomplete_max_output_tokens"
        )
        self.assertEqual(execution_status, "resource_exhausted")
        self.assertFalse(should_attempt_recovery(observation))
        self.assertEqual(client.responses.retrieve_calls, [])

    def test_failed_and_error_event_classifications(self) -> None:
        provider_failure = SimpleNamespace(
            code="server_error", message="failed"
        )
        failed, _, _ = self.observe(
            [
                event(
                    "response.created",
                    event_response=response("in_progress"),
                ),
                event(
                    "response.failed",
                    event_response=response(
                        "failed", error=provider_failure
                    ),
                ),
            ]
        )
        self.assertEqual(failed.stream_outcome, "provider_failed")
        self.assertTrue(should_attempt_recovery(failed))
        self.assertEqual(failed.provider_error["code"], "server_error")

        typed_error, _, _ = self.observe(
            [
                event(
                    "response.created",
                    event_response=response("in_progress"),
                ),
                event(
                    "error",
                    code="server_error",
                    message="stream error",
                    param="input",
                ),
            ]
        )
        self.assertEqual(
            typed_error.stream_outcome, "provider_error_event"
        )
        self.assertTrue(should_attempt_recovery(typed_error))

    def test_interruption_and_clean_eof_classifications(self) -> None:
        interrupted, _, _ = self.observe(
            [
                event(
                    "response.created",
                    event_response=response("in_progress"),
                )
            ],
            iteration_error=ConnectionError("socket closed"),
        )
        self.assertEqual(
            interrupted.stream_outcome,
            "stream_interrupted_after_created",
        )
        self.assertTrue(should_attempt_recovery(interrupted))

        ended, _, _ = self.observe(
            [
                event(
                    "response.created",
                    event_response=response("in_progress"),
                )
            ]
        )
        self.assertEqual(
            ended.stream_outcome, "stream_ended_without_terminal"
        )
        self.assertTrue(should_attempt_recovery(ended))

        before_created, created, _ = self.observe(
            [], iteration_error=ConnectionError("connect failed")
        )
        self.assertEqual(
            before_created.stream_outcome, "stream_failed_before_created"
        )
        self.assertFalse(should_attempt_recovery(before_created))
        self.assertEqual(created, [])

    def test_partial_output_is_preserved_when_stream_fails(self) -> None:
        observation, _, _ = self.observe(
            [
                event(
                    "response.created",
                    event_response=response("in_progress"),
                ),
                event(
                    "response.output_item.added",
                    item=SimpleNamespace(type="message"),
                    sequence_number=2,
                ),
                event(
                    "response.output_text.delta",
                    delta='{"semantic_status":',
                    sequence_number=3,
                ),
                event(
                    "response.output_text.delta",
                    delta='"unresolved"',
                    sequence_number=4,
                ),
            ],
            iteration_error=ConnectionError("socket closed"),
        )
        self.assertEqual(
            observation.partial_output_text,
            '{"semantic_status":"unresolved"',
        )
        self.assertEqual(
            observation.partial_output_item_types, ["message"]
        )
        fields = observation.ledger_fields()
        self.assertEqual(
            fields["partial_output_text"],
            '{"semantic_status":"unresolved"',
        )

    def test_bounded_retrieval_recovers_completed_response_without_generation(
        self,
    ) -> None:
        responses = FakeResponses(
            retrieved=[
                response("queued"),
                response("in_progress"),
                response("completed"),
            ]
        )
        client = FakeClient(responses)
        attempts: list[dict] = []
        sleeps: list[float] = []
        recovered = recover_response(
            client,
            "resp-test",
            attempts.append,
            delays=(0, 2, 5, 10),
            sleep=sleeps.append,
        )
        self.assertEqual(
            recovered.stream_outcome, "completed_recovered"
        )
        self.assertEqual(responses.stream_calls, 0)
        self.assertEqual(responses.retrieve_calls, ["resp-test"] * 3)
        self.assertEqual(sleeps, [2, 5])
        self.assertEqual(len(attempts), 3)

    def test_retrieval_stays_bounded_when_response_never_finishes(self) -> None:
        responses = FakeResponses(
            retrieved=[
                response("in_progress"),
                response("in_progress"),
                response("in_progress"),
                response("in_progress"),
            ]
        )
        attempts: list[dict] = []
        recovered = recover_response(
            FakeClient(responses),
            "resp-test",
            attempts.append,
            delays=(0, 0, 0, 0),
            sleep=lambda _: None,
        )
        self.assertEqual(
            recovered.stream_outcome, "recovery_unresolved"
        )
        self.assertEqual(len(attempts), 4)


class LedgerTest(unittest.TestCase):
    def test_orphan_detection_requires_created_without_outcome(self) -> None:
        records = [
            {
                "record_kind": "provider_response_created",
                "call_attempt_id": "a" * 64,
                "cache_key": "cache-a",
            },
            {
                "record_kind": "provider_response_created",
                "call_attempt_id": "b" * 64,
                "cache_key": "cache-b",
            },
            {
                "record_kind": "provider_retrieval_attempt",
                "call_attempt_id": "a" * 64,
                "cache_key": "cache-a",
            },
            {
                "record_kind": "model_call_outcome",
                "call_attempt_id": "b" * 64,
                "cache_key": "cache-b",
            },
        ]
        self.assertEqual(
            [row["cache_key"] for row in orphaned_provider_calls(records)],
            ["cache-a"],
        )

    def test_orphan_is_recovered_by_retrieval_without_generation(self) -> None:
        records = [
            {
                "record_kind": "provider_response_created",
                "call_attempt_id": "a" * 64,
                "cache_key": "cache-a",
                "provider_response_id": "resp-orphan",
            }
        ]
        orphan = orphaned_provider_calls(records)[0]
        responses = FakeResponses(retrieved=[response("completed")])
        recovered = recover_response(
            FakeClient(responses),
            orphan["provider_response_id"],
            lambda _: None,
            delays=(0,),
            sleep=lambda _: None,
        )
        self.assertEqual(
            recovered.stream_outcome, "completed_recovered"
        )
        self.assertEqual(responses.stream_calls, 0)
        self.assertEqual(responses.retrieve_calls, ["resp-orphan"])

    def test_call_attempt_cost_is_deduplicated(self) -> None:
        records = [
            {
                "record_kind": "provider_response_created",
                "call_attempt_id": "a" * 64,
                "provider_call_made": True,
                "reserved_cost_usd": 1.0,
            },
            {
                "record_kind": "provider_retrieval_attempt",
                "call_attempt_id": "a" * 64,
                "provider_call_made": False,
            },
            {
                "record_kind": "model_call_outcome",
                "call_attempt_id": "a" * 64,
                "provider_call_made": True,
                "actual_cost_usd": 0.25,
            },
            {
                "record_kind": "provider_response_created",
                "call_attempt_id": "b" * 64,
                "provider_call_made": True,
                "reserved_cost_usd": 2.0,
            },
        ]
        self.assertEqual(accounted_spend(records), 2.25)
        self.assertEqual(provider_generation_call_count(records), 2)
        self.assertEqual(provider_retrieval_call_count(records), 1)

    def test_legacy_cost_accounting_is_unchanged(self) -> None:
        records = [
            {"provider_call_made": True, "actual_cost_usd": 0.5},
            {"provider_call_made": True, "reserved_cost_usd": 1.5},
            {"provider_call_made": False, "actual_cost_usd": 100.0},
        ]
        self.assertEqual(accounted_spend(records), 2.0)
        self.assertEqual(provider_generation_call_count(records), 2)

    def test_ledger_schema_outcomes_match_runtime_closed_set(self) -> None:
        schema = json.loads(
            (
                SKILL
                / "references"
                / "provider-call-ledger-schema-v3.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(
            schema["properties"]["ledger_schema_version"]["const"],
            LEDGER_SCHEMA_VERSION,
        )
        self.assertEqual(
            set(schema["properties"]["stream_outcome"]["enum"]),
            STREAM_OUTCOMES,
        )
        required = schema["allOf"][2]["then"]["required"]
        self.assertIn("partial_output_text", required)
        self.assertIn("partial_output_item_types", required)

    def test_historical_v2_ledger_schema_remains_versioned_v2(self) -> None:
        schema = json.loads(
            (
                SKILL
                / "references"
                / "provider-call-ledger-schema-v2.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(
            schema["properties"]["ledger_schema_version"]["const"],
            "tier-b-provider-call-ledger-v2",
        )
        self.assertNotIn("partial_output_text", schema["properties"])


class ContinuationSafetyTest(unittest.TestCase):
    def test_defensive_reminder_is_adjacent_to_each_tool_result(self) -> None:
        conversation: list[dict] = []
        append_tool_result_context(
            conversation,
            "call-1",
            {"function_uid": "artifact:function", "code": "return x;"},
        )
        self.assertEqual(conversation[-2]["type"], "function_call_output")
        reminder = conversation[-1]["content"][0]["text"]
        self.assertEqual(reminder, DEFENSIVE_CONTEXT_REMINDER)
        self.assertIn(
            "not a request to operationalize the weakness", reminder
        )
        self.assertIn(
            "Describe feasibility only as symbolic code conditions",
            reminder,
        )

    def test_final_request_has_adjacent_defensive_concise_synthesis(self) -> None:
        conversation = [
            {
                "type": "function_call_output",
                "call_id": "call-1",
                "output": "{}",
            }
        ]
        request_input = request_input_for_call(
            conversation, can_call_tools=False
        )
        final_text = request_input[-1]["content"][0]["text"]
        self.assertIn(DEFENSIVE_CONTEXT_REMINDER, final_text)
        self.assertIn(FINAL_SYNTHESIS_INSTRUCTION, final_text)
        self.assertIn("Do not perform another investigation", final_text)

    def test_tool_enabled_request_does_not_duplicate_adjacent_reminder(
        self,
    ) -> None:
        conversation: list[dict] = []
        append_tool_result_context(conversation, "call-1", {"hits": []})
        request_input = request_input_for_call(
            conversation, can_call_tools=True
        )
        self.assertEqual(request_input[-1], conversation[-1])
        self.assertEqual(
            request_input[-1]["content"][0]["text"],
            DEFENSIVE_CONTEXT_REMINDER,
        )

    def test_progress_requires_new_information_bearing_facts(self) -> None:
        self.assertEqual(
            information_fact_keys("search_code", {"hits": []}), set()
        )
        first = information_fact_keys(
            "search_code",
            {"hits": [{"function_uid": "a:f", "line": 7, "text": "x"}]},
        )
        repeated = information_fact_keys(
            "search_code",
            {"hits": [{"function_uid": "a:f", "line": 7, "text": "x"}]},
        )
        second = information_fact_keys(
            "search_code",
            {"hits": [{"function_uid": "a:f", "line": 8, "text": "y"}]},
        )
        self.assertTrue(first)
        self.assertFalse(repeated - first)
        self.assertTrue(second - first)
        self.assertEqual(
            information_fact_keys(
                "get_function", {"error": "not available"}
            ),
            set(),
        )

    def test_interim_is_persisted_and_can_become_terminal_fallback(
        self,
    ) -> None:
        task = {
            "case_id": "case-1",
            "cache_key": "cache-1",
        }
        parsed = {
            "semantic_status": "unresolved",
            "pipeline_disposition": "retain_and_escalate",
            "execution_status": "completed",
        }
        base = {
            "record_kind": "model_call_outcome",
            "case_id": "case-1",
            "cache_key": "cache-1",
            "model_call_index": 3,
            "provider_call_made": True,
            "actual_cost_usd": 0.25,
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "results.jsonl"
            latest = append_interim_result(
                path,
                base,
                model_call_index=3,
                raw_response_text='{"pipeline_disposition":"retain_and_escalate"}',
                parsed_result=parsed,
                extension_granted=False,
                progress_events=["new code fact"],
            )
            appended = append_interim_fallback(
                path,
                task,
                latest,
                failed_call_index=4,
                failure_status="infrastructure_error",
                failure_reason="stream interrupted",
            )
            rows = [
                json.loads(line)
                for line in path.read_text(encoding="utf-8").splitlines()
            ]
        self.assertTrue(appended)
        self.assertEqual(rows[0]["status"], "interim_result")
        self.assertFalse(rows[0]["terminal"])
        self.assertEqual(rows[0]["actual_cost_usd"], 0.25)
        self.assertEqual(rows[1]["status"], "interim_result_fallback")
        self.assertTrue(rows[1]["terminal"])
        self.assertEqual(rows[1]["parsed_result"], parsed)


class ReconciliationArtifactTest(unittest.TestCase):
    RUNS = (
        "2026-07-26t071257z__gpt-5.6-sol__medium__"
        "tier-a-mixed-recovered-cascade-six-case-medium-schema-v2",
        "2026-07-26t084318z__gpt-5.6-sol__medium__"
        "tier-a-mixed-recovered-cascade-six-case-medium-schema-v3-preflight-v2",
        "2026-07-26t100925z__gpt-5.6-sol__medium__"
        "tier-a-mixed-recovered-two-case-output-cap-retry-v3-8192-v1",
    )

    def test_five_append_only_corrections_are_hash_linked(self) -> None:
        run_root = SKILL.parent / "results" / "tier-b" / "filter-runs"
        corrections: list[dict] = []
        for run_id in self.RUNS:
            run_dir = run_root / run_id
            artifact = json.loads(
                (
                    run_dir
                    / "reconciliation"
                    / "discarded-interim-results-v1.json"
                ).read_text(encoding="utf-8")
            )
            self.assertTrue(artifact["original_artifacts_unchanged"])
            self.assertEqual(artifact["run_id"], run_id)
            for filename, field in (
                ("manifest.jsonl", "original_manifest_sha256"),
                ("results.jsonl", "original_results_sha256"),
                (
                    "scoring/summary.json",
                    "original_scoring_summary_sha256",
                ),
            ):
                digest = hashlib.sha256(
                    (run_dir / filename).read_bytes()
                ).hexdigest()
                self.assertEqual(digest, artifact[field])
            corrections.extend(artifact["correction_records"])
        self.assertEqual(len(corrections), 5)
        self.assertTrue(
            all(
                row["semantic_status"] == "unresolved"
                and row["pipeline_disposition"] == "retain_and_escalate"
                and row["semantic_category_changed"] is False
                for row in corrections
            )
        )


if __name__ == "__main__":
    unittest.main()
