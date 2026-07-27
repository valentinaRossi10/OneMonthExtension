#!/usr/bin/env python3
"""Typed Responses stream observation and append-only ledger accounting."""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass
from typing import Any, Callable, Iterable


LEDGER_SCHEMA_VERSION = "tier-b-provider-call-ledger-v3"
STREAM_OUTCOMES = frozenset(
    {
        "completed",
        "completed_recovered",
        "incomplete_max_output_tokens",
        "incomplete_content_filter",
        "incomplete_other",
        "provider_failed",
        "provider_error_event",
        "stream_interrupted_after_created",
        "stream_ended_without_terminal",
        "stream_failed_before_created",
        "recovery_unresolved",
    }
)
RECOVERABLE_STREAM_OUTCOMES = frozenset(
    {
        "provider_failed",
        "provider_error_event",
        "stream_interrupted_after_created",
        "stream_ended_without_terminal",
    }
)
RETRIEVAL_DELAYS_SECONDS = (0, 2, 5, 10)


class LedgerPersistenceError(OSError):
    """The response ID could not be durably recorded."""


@dataclass
class StreamObservation:
    response: Any | None
    response_id: str | None
    provider_terminal_event_type: str | None
    provider_response_status: str | None
    provider_incomplete_reason: str | None
    stream_outcome: str
    stream_exception: dict[str, str] | None
    provider_error: dict[str, str | None] | None
    event_type_counts: dict[str, int]
    last_sequence_number: int | None
    partial_output_text: str
    partial_output_item_types: list[str]

    def ledger_fields(self) -> dict[str, Any]:
        return {
            "provider_response_id": self.response_id,
            "provider_terminal_event_type": self.provider_terminal_event_type,
            "provider_response_status": self.provider_response_status,
            "provider_incomplete_reason": self.provider_incomplete_reason,
            "stream_outcome": self.stream_outcome,
            "stream_exception": self.stream_exception,
            "provider_error": self.provider_error,
            "event_type_counts": self.event_type_counts,
            "last_sequence_number": self.last_sequence_number,
            "partial_output_text": self.partial_output_text,
            "partial_output_item_types": self.partial_output_item_types,
        }


def _attribute(value: Any, name: str, default: Any = None) -> Any:
    if isinstance(value, dict):
        return value.get(name, default)
    return getattr(value, name, default)


def _exception_record(exc: BaseException) -> dict[str, str]:
    return {"type": type(exc).__name__, "message": str(exc)}


def _provider_error(value: Any) -> dict[str, str | None] | None:
    if value is None:
        return None
    return {
        "type": _attribute(value, "type"),
        "code": _attribute(value, "code"),
        "message": _attribute(value, "message"),
        "param": _attribute(value, "param"),
    }


def _response_id(response: Any) -> str | None:
    value = _attribute(response, "id")
    return value if isinstance(value, str) and value else None


def _response_status(response: Any) -> str | None:
    value = _attribute(response, "status")
    return value if isinstance(value, str) else None


def _incomplete_reason(response: Any) -> str | None:
    details = _attribute(response, "incomplete_details")
    value = _attribute(details, "reason")
    return value if isinstance(value, str) else None


def _response_output_text(response: Any) -> str:
    direct = _attribute(response, "output_text")
    if isinstance(direct, str):
        return direct
    parts: list[str] = []
    for item in _attribute(response, "output", []) or []:
        for content in _attribute(item, "content", []) or []:
            text = _attribute(content, "text")
            if isinstance(text, str):
                parts.append(text)
    return "".join(parts)


def _response_output_item_types(response: Any) -> list[str]:
    result: list[str] = []
    for item in _attribute(response, "output", []) or []:
        item_type = _attribute(item, "type")
        result.append(item_type if isinstance(item_type, str) else "unknown")
    return result


def classify_response(
    response: Any,
    *,
    recovered: bool = False,
    terminal_event_type: str | None = None,
    event_type_counts: dict[str, int] | None = None,
    last_sequence_number: int | None = None,
) -> StreamObservation:
    status = _response_status(response)
    response_id = _response_id(response)
    reason = _incomplete_reason(response)
    provider_error = _provider_error(_attribute(response, "error"))
    if status == "completed":
        outcome = "completed_recovered" if recovered else "completed"
        terminal_event_type = terminal_event_type or "response.completed"
    elif status == "incomplete":
        terminal_event_type = terminal_event_type or "response.incomplete"
        if reason == "max_output_tokens":
            outcome = "incomplete_max_output_tokens"
        elif reason == "content_filter":
            outcome = "incomplete_content_filter"
        else:
            outcome = "incomplete_other"
    elif status in {"failed", "cancelled"}:
        outcome = "provider_failed"
        terminal_event_type = terminal_event_type or "response.failed"
    else:
        outcome = "recovery_unresolved" if recovered else "provider_failed"
    return StreamObservation(
        response=response,
        response_id=response_id,
        provider_terminal_event_type=terminal_event_type,
        provider_response_status=status,
        provider_incomplete_reason=reason,
        stream_outcome=outcome,
        stream_exception=None,
        provider_error=provider_error,
        event_type_counts=event_type_counts or {},
        last_sequence_number=last_sequence_number,
        partial_output_text=_response_output_text(response),
        partial_output_item_types=_response_output_item_types(response),
    )


def observe_response_stream(
    client: Any,
    request: dict[str, Any],
    on_created: Callable[[dict[str, Any]], None],
) -> StreamObservation:
    """Inspect a streaming response without relying on get_final_response()."""
    counts: Counter[str] = Counter()
    response_id: str | None = None
    last_sequence_number: int | None = None
    terminal_response: Any | None = None
    terminal_event_type: str | None = None
    typed_error: dict[str, str | None] | None = None
    streamed_text_parts: list[str] = []
    streamed_output_item_types: list[str] = []
    try:
        with client.responses.stream(**request) as stream:
            for event in stream:
                event_type = _attribute(event, "type")
                if not isinstance(event_type, str):
                    event_type = "unknown"
                counts[event_type] += 1
                sequence_number = _attribute(event, "sequence_number")
                if isinstance(sequence_number, int):
                    last_sequence_number = sequence_number
                if event_type == "response.created":
                    created_response = _attribute(event, "response")
                    created_id = _response_id(created_response)
                    if response_id is None and created_id is not None:
                        response_id = created_id
                        try:
                            on_created(
                                {
                                    "provider_response_id": response_id,
                                    "provider_event_type": event_type,
                                    "provider_response_status": _response_status(
                                        created_response
                                    ),
                                    "last_sequence_number": last_sequence_number,
                                }
                            )
                        except Exception as exc:
                            raise LedgerPersistenceError(
                                "Could not persist response.created"
                            ) from exc
                elif event_type == "response.output_text.delta":
                    delta = _attribute(event, "delta")
                    if isinstance(delta, str):
                        streamed_text_parts.append(delta)
                elif event_type == "response.output_item.added":
                    item = _attribute(event, "item")
                    item_type = _attribute(item, "type")
                    streamed_output_item_types.append(
                        item_type if isinstance(item_type, str) else "unknown"
                    )
                elif event_type in {
                    "response.completed",
                    "response.incomplete",
                    "response.failed",
                }:
                    terminal_response = _attribute(event, "response")
                    terminal_event_type = event_type
                    response_id = _response_id(terminal_response) or response_id
                elif event_type == "error":
                    terminal_event_type = "error"
                    typed_error = _provider_error(event)
    except LedgerPersistenceError:
        raise
    except Exception as exc:
        if terminal_response is not None:
            observed = classify_response(
                terminal_response,
                terminal_event_type=terminal_event_type,
                event_type_counts=dict(counts),
                last_sequence_number=last_sequence_number,
            )
            observed.stream_exception = _exception_record(exc)
            if not observed.partial_output_text:
                observed.partial_output_text = "".join(streamed_text_parts)
            if not observed.partial_output_item_types:
                observed.partial_output_item_types = streamed_output_item_types
            return observed
        outcome = (
            "stream_interrupted_after_created"
            if response_id is not None
            else "stream_failed_before_created"
        )
        return StreamObservation(
            response=None,
            response_id=response_id,
            provider_terminal_event_type=terminal_event_type,
            provider_response_status=None,
            provider_incomplete_reason=None,
            stream_outcome=outcome,
            stream_exception=_exception_record(exc),
            provider_error=typed_error,
            event_type_counts=dict(counts),
            last_sequence_number=last_sequence_number,
            partial_output_text="".join(streamed_text_parts),
            partial_output_item_types=streamed_output_item_types,
        )

    if terminal_response is not None:
        observed = classify_response(
            terminal_response,
            terminal_event_type=terminal_event_type,
            event_type_counts=dict(counts),
            last_sequence_number=last_sequence_number,
        )
        if not observed.partial_output_text:
            observed.partial_output_text = "".join(streamed_text_parts)
        if not observed.partial_output_item_types:
            observed.partial_output_item_types = streamed_output_item_types
        return observed
    if terminal_event_type == "error":
        return StreamObservation(
            response=None,
            response_id=response_id,
            provider_terminal_event_type="error",
            provider_response_status=None,
            provider_incomplete_reason=None,
            stream_outcome="provider_error_event",
            stream_exception=None,
            provider_error=typed_error,
            event_type_counts=dict(counts),
            last_sequence_number=last_sequence_number,
            partial_output_text="".join(streamed_text_parts),
            partial_output_item_types=streamed_output_item_types,
        )
    return StreamObservation(
        response=None,
        response_id=response_id,
        provider_terminal_event_type=None,
        provider_response_status=None,
        provider_incomplete_reason=None,
        stream_outcome=(
            "stream_ended_without_terminal"
            if response_id is not None
            else "stream_failed_before_created"
        ),
        stream_exception=(
            None
            if response_id is not None
            else {
                "type": "MissingResponseCreated",
                "message": "Stream ended before response.created",
            }
        ),
        provider_error=None,
        event_type_counts=dict(counts),
        last_sequence_number=last_sequence_number,
        partial_output_text="".join(streamed_text_parts),
        partial_output_item_types=streamed_output_item_types,
    )


def should_attempt_recovery(observation: StreamObservation) -> bool:
    return (
        observation.response_id is not None
        and observation.stream_outcome in RECOVERABLE_STREAM_OUTCOMES
    )


def recover_response(
    client: Any,
    response_id: str,
    on_attempt: Callable[[dict[str, Any]], None],
    *,
    delays: Iterable[int] = RETRIEVAL_DELAYS_SECONDS,
    sleep: Callable[[float], None] = time.sleep,
) -> StreamObservation:
    """Retrieve one existing response; this function never generates a response."""
    last_status: str | None = None
    for attempt_index, delay_seconds in enumerate(delays, 1):
        if delay_seconds:
            sleep(delay_seconds)
        try:
            response = client.responses.retrieve(response_id)
        except Exception as exc:
            on_attempt(
                {
                    "retrieval_attempt_index": attempt_index,
                    "retrieval_delay_seconds": delay_seconds,
                    "retrieval_outcome": "retrieval_error",
                    "provider_response_status": last_status,
                    "retrieval_error": _exception_record(exc),
                }
            )
            return StreamObservation(
                response=None,
                response_id=response_id,
                provider_terminal_event_type=None,
                provider_response_status=last_status,
                provider_incomplete_reason=None,
                stream_outcome="recovery_unresolved",
                stream_exception=_exception_record(exc),
                provider_error=None,
                event_type_counts={},
                last_sequence_number=None,
                partial_output_text="",
                partial_output_item_types=[],
            )
        status = _response_status(response)
        last_status = status
        on_attempt(
            {
                "retrieval_attempt_index": attempt_index,
                "retrieval_delay_seconds": delay_seconds,
                "retrieval_outcome": status or "unknown",
                "provider_response_status": status,
                "retrieval_error": None,
            }
        )
        if status not in {"queued", "in_progress"}:
            return classify_response(response, recovered=True)
    return StreamObservation(
        response=None,
        response_id=response_id,
        provider_terminal_event_type=None,
        provider_response_status=last_status,
        provider_incomplete_reason=None,
        stream_outcome="recovery_unresolved",
        stream_exception=None,
        provider_error=None,
        event_type_counts={},
        last_sequence_number=None,
        partial_output_text="",
        partial_output_item_types=[],
    )


def orphaned_provider_calls(
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    created: dict[str, dict[str, Any]] = {}
    outcomes: set[str] = set()
    for row in records:
        call_attempt_id = row.get("call_attempt_id")
        if not isinstance(call_attempt_id, str):
            continue
        if row.get("record_kind") == "provider_response_created":
            created[call_attempt_id] = row
        elif row.get("record_kind") == "model_call_outcome":
            outcomes.add(call_attempt_id)
    return [
        row
        for call_attempt_id, row in created.items()
        if call_attempt_id not in outcomes
    ]


def accounted_spend(records: list[dict[str, Any]]) -> float:
    """Count versioned call attempts once and retain legacy row accounting."""
    legacy_total = 0.0
    grouped: dict[str, dict[str, list[float]]] = {}
    for row in records:
        if not row.get("provider_call_made"):
            continue
        call_attempt_id = row.get("call_attempt_id")
        if not isinstance(call_attempt_id, str):
            cost = row.get("actual_cost_usd")
            if isinstance(cost, (int, float)):
                legacy_total += float(cost)
            else:
                reserved = row.get("reserved_cost_usd")
                if isinstance(reserved, (int, float)):
                    legacy_total += float(reserved)
            continue
        bucket = grouped.setdefault(
            call_attempt_id, {"actual": [], "reserved": []}
        )
        actual = row.get("actual_cost_usd")
        reserved = row.get("reserved_cost_usd")
        if isinstance(actual, (int, float)):
            bucket["actual"].append(float(actual))
        if isinstance(reserved, (int, float)):
            bucket["reserved"].append(float(reserved))
    total = legacy_total
    for bucket in grouped.values():
        if bucket["actual"]:
            total += bucket["actual"][-1]
        elif bucket["reserved"]:
            total += max(bucket["reserved"])
    return total


def provider_generation_call_count(records: list[dict[str, Any]]) -> int:
    legacy = 0
    versioned: set[str] = set()
    for row in records:
        if not row.get("provider_call_made"):
            continue
        call_attempt_id = row.get("call_attempt_id")
        if isinstance(call_attempt_id, str):
            versioned.add(call_attempt_id)
        else:
            legacy += 1
    return legacy + len(versioned)


def provider_retrieval_call_count(records: list[dict[str, Any]]) -> int:
    return sum(
        row.get("record_kind") == "provider_retrieval_attempt"
        for row in records
    )
