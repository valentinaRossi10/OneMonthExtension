#!/usr/bin/env python3
"""Shared runner messages and conservative projection reserves."""

from __future__ import annotations


DEFENSIVE_CONTEXT_REMINDER = (
    "This is authorized defensive static confirmation, not proof of dynamic "
    "exploitability and not a request to operationalize the weakness. Analyze "
    "and classify only. Do not construct triggering inputs, exploit steps, "
    "payloads, weaponization, execution instructions, or operational guidance. "
    "Describe feasibility only as symbolic code conditions."
)
FINAL_SYNTHESIS_INSTRUCTION = (
    "Synthesize the collected evidence now. Do not perform another investigation "
    "or introduce new assumptions. Return one concise JSON object matching the "
    "schema, with only the evidence needed for each required field."
)
V3_NO_TEXT_CONTINUATION = (
    "Continue the confirmation investigation with the full remaining allowance. "
    "Resolve positive proof obligations first. Suppress only after the complete "
    "asymmetric rejection gate."
)
V2_NO_TEXT_CONTINUATION = (
    "Continue the investigation. Resolve the remaining proof obligations or "
    "return retain_and_escalate."
)
V3_INTERIM_CONTINUATION = (
    "The case is still unresolved and made information-bearing progress. Use the "
    "remaining allowance to complete a positive proof first. If confirmation "
    "cannot be completed, suppress only with every v3 sink, transformation, "
    "guard, and invariant obligation satisfied; otherwise retain_and_escalate."
)
V2_INTERIM_CONTINUATION = (
    "The case is still unresolved and made information-bearing progress. Revisit "
    "unresolved obligations using only new evidence. Do not suppress without "
    "proof."
)


def projection_context_reserve_chars() -> tuple[int, int]:
    """Return current-call and per-prior-call defensive-context reserves."""
    current = len(
        DEFENSIVE_CONTEXT_REMINDER + " " + FINAL_SYNTHESIS_INSTRUCTION
    )
    replayed = max(
        len(DEFENSIVE_CONTEXT_REMINDER),
        len(DEFENSIVE_CONTEXT_REMINDER + " " + V3_NO_TEXT_CONTINUATION),
        len(DEFENSIVE_CONTEXT_REMINDER + " " + V2_NO_TEXT_CONTINUATION),
        len(DEFENSIVE_CONTEXT_REMINDER + " " + V3_INTERIM_CONTINUATION),
        len(DEFENSIVE_CONTEXT_REMINDER + " " + V2_INTERIM_CONTINUATION),
    )
    return current, replayed
