#!/usr/bin/env python3
"""Bounded agent-directed glue over exported Ghidra facts."""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Any


def api_tools(policy: dict[str, Any]) -> list[dict[str, Any]]:
    max_nodes = policy["limits"].get("max_static_slice_nodes", 200)
    max_depth = policy["limits"].get("max_call_graph_depth", 8)
    return [
        {
            "type": "function",
            "name": "get_references",
            "description": (
                "Get Ghidra instruction references and resolved target functions "
                "for one function UID."
            ),
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
            "name": "get_pcode",
            "description": (
                "Read bounded raw Ghidra p-code operations for one function."
            ),
            "strict": True,
            "parameters": {
                "type": "object",
                "additionalProperties": False,
                "required": ["function_uid", "start_seq", "end_seq"],
                "properties": {
                    "function_uid": {"type": "string"},
                    "start_seq": {"type": "integer", "minimum": 0},
                    "end_seq": {"type": "integer", "minimum": 0},
                },
            },
        },
        {
            "type": "function",
            "name": "get_reaching_definitions",
            "description": (
                "Trace CFG-sensitive Ghidra p-code definitions reaching one "
                "input of one p-code operation."
            ),
            "strict": True,
            "parameters": {
                "type": "object",
                "additionalProperties": False,
                "required": ["function_uid", "use_seq", "input_index"],
                "properties": {
                    "function_uid": {"type": "string"},
                    "use_seq": {"type": "integer", "minimum": 0},
                    "input_index": {"type": "integer", "minimum": 0},
                },
            },
        },
        {
            "type": "function",
            "name": "slice_pcode",
            "description": (
                "Compute a bounded backward or forward p-code def-use slice "
                "from one operation."
            ),
            "strict": True,
            "parameters": {
                "type": "object",
                "additionalProperties": False,
                "required": ["function_uid", "direction", "seed_seq", "max_nodes"],
                "properties": {
                    "function_uid": {"type": "string"},
                    "direction": {
                        "type": "string",
                        "enum": ["backward", "forward"],
                    },
                    "seed_seq": {"type": "integer", "minimum": 0},
                    "max_nodes": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": max_nodes,
                    },
                },
            },
        },
        {
            "type": "function",
            "name": "get_dominance",
            "description": (
                "Get dominators, post-dominators, and the dominance frontier "
                "for one Ghidra basic block."
            ),
            "strict": True,
            "parameters": {
                "type": "object",
                "additionalProperties": False,
                "required": ["function_uid", "block_start"],
                "properties": {
                    "function_uid": {"type": "string"},
                    "block_start": {"type": "string"},
                },
            },
        },
        {
            "type": "function",
            "name": "resolve_indirect_call",
            "description": (
                "Resolve one indirect call site with a bounded backward p-code "
                "slice and in-package constant function targets."
            ),
            "strict": True,
            "parameters": {
                "type": "object",
                "additionalProperties": False,
                "required": ["function_uid", "site_address"],
                "properties": {
                    "function_uid": {"type": "string"},
                    "site_address": {"type": "string"},
                },
            },
        },
        {
            "type": "function",
            "name": "find_call_paths",
            "description": (
                "Find bounded analyzed call-graph paths between two function UIDs."
            ),
            "strict": True,
            "parameters": {
                "type": "object",
                "additionalProperties": False,
                "required": ["source_uid", "target_uid", "max_depth"],
                "properties": {
                    "source_uid": {"type": "string"},
                    "target_uid": {"type": "string"},
                    "max_depth": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": max_depth,
                    },
                },
            },
        },
        {
            "type": "function",
            "name": "query_angr",
            "description": (
                "Run one bounded targeted angr reachability, symbolic sink, "
                "value-constraint, or indirect-call query after Ghidra-first "
                "analysis is insufficient."
            ),
            "strict": True,
            "parameters": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "query_kind",
                    "start_address",
                    "target_address",
                    "avoid_addresses",
                    "register",
                    "comparison",
                    "value",
                    "max_steps",
                    "timeout_seconds",
                ],
                "properties": {
                    "query_kind": {
                        "type": "string",
                        "enum": [
                            "reachability",
                            "targeted_symbolic_execution",
                            "value_constraint",
                            "indirect_call_targets",
                        ],
                    },
                    "start_address": {"type": "string"},
                    "target_address": {"type": "string"},
                    "avoid_addresses": {
                        "type": "array",
                        "items": {"type": "string"},
                        "maxItems": 32,
                    },
                    "register": {"type": "string"},
                    "comparison": {
                        "type": "string",
                        "enum": ["none", "eq", "ne", "lt", "le", "gt", "ge"],
                    },
                    "value": {"type": "string"},
                    "max_steps": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 5000,
                    },
                    "timeout_seconds": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 60,
                    },
                },
            },
        },
    ]


class PcodeAnalysis:
    def __init__(self, package: Any, function_uid: str):
        self.package = package
        self.uid = function_uid
        self.ops = package.pcode_by_function.get(function_uid, [])
        self.by_seq = {row["pcode_seq"]: row for row in self.ops}
        if not self.ops:
            raise ValueError("Function has no packaged p-code")
        self.blocks = package.blocks_by_function.get(function_uid, [])
        self.block_by_start = {row["block_start"]: row for row in self.blocks}
        self.op_seqs_by_block: dict[str, list[int]] = defaultdict(list)
        for row in self.ops:
            self.op_seqs_by_block[row["block_start"]].append(row["pcode_seq"])
        self.predecessors: dict[str, set[str]] = {
            start: set() for start in self.block_by_start
        }
        for row in self.blocks:
            for successor in row["successors"]:
                if successor in self.predecessors:
                    self.predecessors[successor].add(row["block_start"])
        self.definitions: dict[str, set[int]] = defaultdict(set)
        for row in self.ops:
            output = row.get("output")
            if isinstance(output, dict) and output.get("key"):
                self.definitions[str(output["key"])].add(row["pcode_seq"])
        self.block_gen: dict[str, dict[str, int]] = defaultdict(dict)
        for block, sequences in self.op_seqs_by_block.items():
            for sequence in sequences:
                output = self.by_seq[sequence].get("output")
                if isinstance(output, dict) and output.get("key"):
                    self.block_gen[block][str(output["key"])] = sequence
        self.in_defs, self.out_defs = self._reaching_fixpoint()

    def _reaching_fixpoint(
        self,
    ) -> tuple[dict[str, set[int]], dict[str, set[int]]]:
        incoming = {block: set() for block in self.block_by_start}
        outgoing = {
            block: set(generated.values())
            for block, generated in self.block_gen.items()
        }
        for block in self.block_by_start:
            outgoing.setdefault(block, set())
        changed = True
        while changed:
            changed = False
            for block in sorted(self.block_by_start):
                new_in = set().union(
                    *(outgoing[pred] for pred in self.predecessors[block])
                ) if self.predecessors[block] else set()
                killed_keys = set(self.block_gen.get(block, {}))
                survivors = {
                    sequence
                    for sequence in new_in
                    if self.output_key(sequence) not in killed_keys
                }
                new_out = survivors | set(self.block_gen.get(block, {}).values())
                if new_in != incoming[block] or new_out != outgoing[block]:
                    incoming[block] = new_in
                    outgoing[block] = new_out
                    changed = True
        return incoming, outgoing

    def output_key(self, sequence: int) -> str | None:
        output = self.by_seq[sequence].get("output")
        return str(output["key"]) if isinstance(output, dict) and output.get("key") else None

    def reaching(self, use_seq: int, key: str) -> set[int]:
        use = self.by_seq.get(use_seq)
        if use is None:
            raise ValueError("Unknown p-code sequence")
        block = use["block_start"]
        state = {
            sequence
            for sequence in self.in_defs.get(block, set())
            if self.output_key(sequence) == key
        }
        for sequence in self.op_seqs_by_block.get(block, []):
            if sequence >= use_seq:
                break
            if self.output_key(sequence) == key:
                state = {sequence}
        return state

    def use_map(self) -> dict[int, set[int]]:
        result: dict[int, set[int]] = defaultdict(set)
        for row in self.ops:
            for item in row.get("inputs", []):
                if not isinstance(item, dict) or not item.get("key"):
                    continue
                for definition in self.reaching(
                    row["pcode_seq"], str(item["key"])
                ):
                    result[definition].add(row["pcode_seq"])
        return result


def _dominators(
    nodes: set[str],
    predecessors: dict[str, set[str]],
    entries: set[str],
) -> dict[str, set[str]]:
    result = {
        node: ({node} if node in entries else set(nodes))
        for node in nodes
    }
    changed = True
    while changed:
        changed = False
        for node in sorted(nodes - entries):
            preds = predecessors.get(node, set())
            common = set.intersection(*(result[pred] for pred in preds)) if preds else set()
            updated = {node} | common
            if updated != result[node]:
                result[node] = updated
                changed = True
    return result


def dominance(package: Any, uid: str, block_start: str) -> dict[str, Any]:
    blocks = package.blocks_by_function.get(uid, [])
    by_start = {row["block_start"]: row for row in blocks}
    if block_start not in by_start:
        raise ValueError("Unknown basic block")
    nodes = set(by_start)
    predecessors = {node: set() for node in nodes}
    successors = {node: set() for node in nodes}
    for row in blocks:
        successors[row["block_start"]] = set(row["successors"]) & nodes
        for successor in successors[row["block_start"]]:
            predecessors[successor].add(row["block_start"])
    entry_address = str(package.functions[uid]["address"])
    entries = {
        row["block_start"]
        for row in blocks
        if int(row["block_start"], 16)
        <= int(entry_address, 16)
        <= int(row["block_end"], 16)
    }
    if not entries:
        entries = {min(nodes, key=lambda value: int(value, 16))}
    dom = _dominators(nodes, predecessors, entries)
    exits = {node for node in nodes if not successors[node]} or set(entries)
    postdom = _dominators(nodes, successors, exits)
    frontier = {
        node
        for node in nodes
        if any(block_start in dom[pred] for pred in predecessors[node])
        and not (block_start in dom[node] and block_start != node)
    }
    return {
        "function_uid": uid,
        "block_start": block_start,
        "dominated_by": sorted(dom[block_start], key=lambda value: int(value, 16)),
        "dominates": sorted(
            (node for node in nodes if block_start in dom[node]),
            key=lambda value: int(value, 16),
        ),
        "post_dominated_by": sorted(
            postdom[block_start], key=lambda value: int(value, 16)
        ),
        "post_dominates": sorted(
            (node for node in nodes if block_start in postdom[node]),
            key=lambda value: int(value, 16),
        ),
        "dominance_frontier": sorted(frontier, key=lambda value: int(value, 16)),
        "entry_blocks": sorted(entries, key=lambda value: int(value, 16)),
        "exit_blocks": sorted(exits, key=lambda value: int(value, 16)),
    }


def call_paths(
    package: Any, source_uid: str, target_uid: str, max_depth: int
) -> dict[str, Any]:
    if source_uid not in package.functions or target_uid not in package.functions:
        raise ValueError("Unknown source or target function UID")
    adjacency: dict[str, set[str]] = defaultdict(set)
    for row in package.callsite_rows:
        target = row.get("target_uid")
        if isinstance(target, str):
            adjacency[row["caller_uid"]].add(target)
        elif row.get("call_kind") == "indirect":
            resolved = indirect_targets(
                package, row["caller_uid"], row["site_address"]
            )
            if resolved["resolution_status"] == "resolved_pcode":
                adjacency[row["caller_uid"]].add(
                    resolved["candidate_target_uids"][0]
                )
    queue = deque([[source_uid]])
    paths: list[list[str]] = []
    while queue and len(paths) < 20:
        path = queue.popleft()
        if path[-1] == target_uid:
            paths.append(path)
            continue
        if len(path) - 1 >= max_depth:
            continue
        for successor in sorted(adjacency.get(path[-1], set())):
            if successor not in path:
                queue.append(path + [successor])
    return {
        "source_uid": source_uid,
        "target_uid": target_uid,
        "max_depth": max_depth,
        "paths": paths,
        "path_count": len(paths),
        "truncated": len(paths) >= 20,
        "edge_scope": "Ghidra direct and reference-resolved indirect calls",
    }


def indirect_targets(
    package: Any, function_uid: str, site_address: str
) -> dict[str, Any]:
    normalized_site = site_address.lower().removeprefix("0x").lstrip("0") or "0"
    analysis = PcodeAnalysis(package, function_uid)
    calls = [
        row
        for row in analysis.ops
        if row["instruction_address"] == normalized_site
        and row["opcode"] == "CALLIND"
    ]
    if len(calls) != 1:
        raise ValueError(
            f"Indirect call site resolved to {len(calls)} CALLIND operations"
        )
    seed = calls[0]["pcode_seq"]
    visited: set[int] = set()
    pending = deque([seed])
    while pending and len(visited) < 200:
        current = pending.popleft()
        if current in visited:
            continue
        visited.add(current)
        for item in analysis.by_seq[current].get("inputs", []):
            if isinstance(item, dict) and item.get("key"):
                pending.extend(
                    analysis.reaching(current, str(item["key"])) - visited
                )
    by_address = {
        str(row["address"]): row["function_uid"]
        for row in package.function_rows
    }
    candidate_addresses: set[str] = set()
    for sequence in visited:
        for item in analysis.by_seq[sequence].get("inputs", []):
            if not isinstance(item, dict) or item.get("kind") != "constant":
                continue
            address = str(item.get("offset_unsigned_hex", "")).lstrip("0") or "0"
            if address in by_address:
                candidate_addresses.add(address)
    candidates = sorted(candidate_addresses, key=lambda value: int(value, 16))
    status = (
        "resolved_pcode"
        if len(candidates) == 1
        else "ambiguous_pcode"
        if candidates
        else "unresolved"
    )
    return {
        "function_uid": function_uid,
        "site_address": normalized_site,
        "call_pcode_seq": seed,
        "resolution_status": status,
        "candidate_target_addresses": candidates,
        "candidate_target_uids": [by_address[value] for value in candidates],
        "slice_pcode_sequences": sorted(visited),
        "slice_truncated": bool(pending),
        "analysis_scope": (
            "intraprocedural raw p-code backward slice; only constants bound "
            "to packaged function starts are accepted as targets"
        ),
    }


def execute(package: Any, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    if name == "get_references":
        uid = str(arguments["function_uid"])
        if uid not in package.functions:
            raise ValueError("Unknown function UID")
        rows = package.references_by_function.get(uid, [])
        limit = package.policy["limits"]["max_search_hits"]
        return {
            "function_uid": uid,
            "references": rows[:limit],
            "truncated": len(rows) > limit,
        }
    if name == "get_pcode":
        uid = str(arguments["function_uid"])
        start = int(arguments["start_seq"])
        end = int(arguments["end_seq"])
        if end < start or end - start > 400:
            raise ValueError("Invalid p-code range")
        rows = [
            row
            for row in package.pcode_by_function.get(uid, [])
            if start <= row["pcode_seq"] <= end
        ]
        return {
            "function_uid": uid,
            "start_seq": start,
            "end_seq": end,
            "operations": rows,
        }
    if name == "get_reaching_definitions":
        uid = str(arguments["function_uid"])
        sequence = int(arguments["use_seq"])
        input_index = int(arguments["input_index"])
        analysis = PcodeAnalysis(package, uid)
        use = analysis.by_seq.get(sequence)
        if use is None:
            raise ValueError("Unknown p-code sequence")
        inputs = use.get("inputs", [])
        if input_index >= len(inputs):
            raise ValueError("Input index is outside the p-code operation")
        item = inputs[input_index]
        key = item.get("key") if isinstance(item, dict) else None
        if not key:
            raise ValueError("Selected input has no varnode key")
        definitions = sorted(analysis.reaching(sequence, str(key)))
        return {
            "function_uid": uid,
            "use_seq": sequence,
            "input_index": input_index,
            "varnode": item,
            "definitions": [analysis.by_seq[value] for value in definitions],
            "definition_count": len(definitions),
            "analysis_scope": (
                "intraprocedural raw p-code reaching definitions; memory "
                "aliasing and callee side effects are not resolved"
            ),
        }
    if name == "slice_pcode":
        uid = str(arguments["function_uid"])
        direction = str(arguments["direction"])
        seed = int(arguments["seed_seq"])
        max_nodes = int(arguments["max_nodes"])
        analysis = PcodeAnalysis(package, uid)
        if seed not in analysis.by_seq:
            raise ValueError("Unknown seed p-code sequence")
        use_map = analysis.use_map() if direction == "forward" else {}
        visited: set[int] = set()
        pending = deque([seed])
        edges: list[dict[str, int]] = []
        while pending and len(visited) < max_nodes:
            current = pending.popleft()
            if current in visited:
                continue
            visited.add(current)
            neighbors: set[int] = set()
            if direction == "backward":
                for item in analysis.by_seq[current].get("inputs", []):
                    if isinstance(item, dict) and item.get("key"):
                        neighbors.update(
                            analysis.reaching(current, str(item["key"]))
                        )
            else:
                neighbors.update(use_map.get(current, set()))
            for neighbor in sorted(neighbors):
                edges.append(
                    {
                        "from_seq": neighbor if direction == "backward" else current,
                        "to_seq": current if direction == "backward" else neighbor,
                    }
                )
                if neighbor not in visited:
                    pending.append(neighbor)
        return {
            "function_uid": uid,
            "direction": direction,
            "seed_seq": seed,
            "nodes": [analysis.by_seq[value] for value in sorted(visited)],
            "edges": edges,
            "truncated": bool(pending),
            "analysis_scope": (
                "intraprocedural raw p-code data dependencies; memory aliasing, "
                "implicit flows, and callee side effects are not resolved"
            ),
        }
    if name == "get_dominance":
        return dominance(
            package,
            str(arguments["function_uid"]),
            str(arguments["block_start"]).lower().removeprefix("0x").lstrip("0") or "0",
        )
    if name == "resolve_indirect_call":
        return indirect_targets(
            package,
            str(arguments["function_uid"]),
            str(arguments["site_address"]),
        )
    if name == "find_call_paths":
        return call_paths(
            package,
            str(arguments["source_uid"]),
            str(arguments["target_uid"]),
            int(arguments["max_depth"]),
        )
    raise ValueError(f"Unknown static-analysis tool: {name}")
