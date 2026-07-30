#!/usr/bin/env python3
"""Bounded, agent-directed queries over angr's existing analyses."""

from __future__ import annotations

import importlib.util
import time
from typing import Any


def available() -> tuple[bool, str | None]:
    if importlib.util.find_spec("angr") is None:
        return False, "angr is not installed in this Python environment"
    return True, None


def _address(value: str) -> int:
    raw = value.strip().lower()
    base = 16 if raw.startswith("0x") or any(c in "abcdef" for c in raw) else 16
    return int(raw.removeprefix("0x"), base)


def _translate(project: Any, ghidra_address: int, ghidra_image_base: int) -> int:
    return int(project.loader.main_object.mapped_base) + (
        ghidra_address - ghidra_image_base
    )


def _comparison(expression: Any, operation: str, value: int) -> Any:
    if operation == "eq":
        return expression == value
    if operation == "ne":
        return expression != value
    if operation == "lt":
        return expression < value
    if operation == "le":
        return expression <= value
    if operation == "gt":
        return expression > value
    if operation == "ge":
        return expression >= value
    raise ValueError("value_constraint requires a comparison other than none")


def query(
    *,
    artifact_path: str,
    analysis_image_base: str,
    query_kind: str,
    start_address: str,
    target_address: str,
    avoid_addresses: list[str],
    register: str,
    comparison: str,
    value: str,
    max_steps: int,
    timeout_seconds: int,
    max_active_states: int,
) -> dict[str, Any]:
    present, reason = available()
    if not present:
        return {
            "backend": "angr",
            "backend_status": "unavailable",
            "resolved": False,
            "limitation": reason,
        }
    import angr

    started = time.monotonic()
    project = angr.Project(artifact_path, auto_load_libs=False)
    image_base = _address(analysis_image_base)
    start_raw = _address(start_address)
    target_raw = _address(target_address)
    start = _translate(project, start_raw, image_base)
    target = _translate(project, target_raw, image_base)
    avoid = {
        _translate(project, _address(item), image_base)
        for item in avoid_addresses
    }
    state = project.factory.blank_state(addr=start)
    manager = project.factory.simulation_manager(state)
    found: Any | None = None
    steps = 0
    pruned_for_state_limit = 0
    while manager.active and steps < max_steps:
        if time.monotonic() - started >= timeout_seconds:
            return {
                "backend": "angr",
                "backend_version": angr.__version__,
                "backend_status": "timeout",
                "resolved": False,
                "steps": steps,
                "active_states": len(manager.active),
                "limitation": "The bounded query reached its wall-clock timeout.",
            }
        retained = []
        for candidate in manager.active:
            if candidate.addr == target:
                found = candidate
                break
            if candidate.addr not in avoid:
                retained.append(candidate)
        if found is not None:
            break
        if len(retained) > max_active_states:
            pruned_for_state_limit += len(retained) - max_active_states
            retained = retained[:max_active_states]
        manager.active = retained
        if not manager.active:
            break
        manager.step()
        steps += 1

    common = {
        "backend": "angr",
        "backend_version": angr.__version__,
        "backend_status": "completed",
        "query_kind": query_kind,
        "start_address": f"{start_raw:x}",
        "target_address": f"{target_raw:x}",
        "steps": steps,
        "active_states": len(manager.active),
        "pruned_for_state_limit": pruned_for_state_limit,
        "elapsed_seconds": round(time.monotonic() - started, 6),
        "bounds": {
            "max_steps": max_steps,
            "timeout_seconds": timeout_seconds,
            "max_active_states": max_active_states,
        },
    }
    if found is None:
        return {
            **common,
            "resolved": False,
            "reachable": False,
            "limitation": (
                "Target was not reached within the configured bounds; this "
                "does not prove unreachability."
            ),
        }
    history = [
        f"{int(address) - int(project.loader.main_object.mapped_base) + image_base:x}"
        for address in found.history.bbl_addrs.hardcopy[-64:]
    ]
    if query_kind in {"reachability", "targeted_symbolic_execution"}:
        return {
            **common,
            "resolved": True,
            "reachable": True,
            "basic_block_trace": history,
            "path_constraint_count": len(found.solver.constraints),
        }
    if query_kind == "value_constraint":
        if not register:
            raise ValueError("value_constraint requires a register")
        if not hasattr(found.regs, register):
            raise ValueError(f"Unknown angr register: {register}")
        expression = getattr(found.regs, register)
        constrained = found.copy()
        constrained.solver.add(
            _comparison(expression, comparison, _address(value))
        )
        satisfiable = constrained.solver.satisfiable()
        result = {
            **common,
            "resolved": True,
            "reachable": True,
            "register": register,
            "comparison": comparison,
            "value": value,
            "constraint_satisfiable": satisfiable,
            "basic_block_trace": history,
        }
        if satisfiable:
            result["register_min_unsigned"] = int(
                constrained.solver.min(getattr(constrained.regs, register))
            )
            result["register_max_unsigned"] = int(
                constrained.solver.max(getattr(constrained.regs, register))
            )
        return result
    if query_kind == "indirect_call_targets":
        successors = project.factory.successors(found)
        targets = sorted(
            {
                int(successor.addr)
                - int(project.loader.main_object.mapped_base)
                + image_base
                for successor in successors.flat_successors
            }
        )
        return {
            **common,
            "resolved": bool(targets),
            "reachable": True,
            "candidate_target_addresses": [f"{item:x}" for item in targets],
            "unconstrained_successor_count": len(successors.unconstrained_successors),
            "basic_block_trace": history,
            "limitation": (
                None
                if targets
                else "angr produced no concrete successor target within the query."
            ),
        }
    raise ValueError(f"Unsupported angr query kind: {query_kind}")
