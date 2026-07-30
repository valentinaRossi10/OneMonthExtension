# Agent-directed static-analysis tools

## Selection order

Use the packaged pseudo-C, call sites, instruction references, and function
identity first. Before declaring an indirect call unresolved, reconcile its
site with `get_references`, `resolve_indirect_call`, and `find_call_paths`.
One unique Ghidra target reference attached directly to that instruction may
resolve the edge. A function-wide reference is only a candidate; resolving it
requires the site-local p-code slice. Multiple candidates remain ambiguous.

Use `get_pcode` to locate the relevant raw operation and varnodes. Then select
the narrowest classical query:

- `get_reaching_definitions` for definitions reaching one operation input;
- `slice_pcode` for a bounded intraprocedural backward or forward data slice;
- `get_dominance` for dominators, post-dominators, or a dominance frontier;
- `find_call_paths` for bounded direct and reference-resolved call paths.

These tools are glue over Ghidra's exported raw p-code and basic-block graph.
They do not resolve memory aliasing, implicit flows, callee side effects,
interprocedural value ranges, or loop invariants automatically. State those
limits in any claim that relies on their output.

For the reviewed three-case required-tools rerun, all four of
`get_reaching_definitions`, `slice_pcode`, `get_dominance`, and `query_angr`
are material to each case and are frozen into its manifest. Use reaching
definitions and slicing for the loop-carried range or abstract lifetime value,
dominance for the exact guard/release/reset-to-sink relation, and angr for one
remaining bounded reachability, value-constraint, sink, or indirect-target
question. A completed retention is machine-blocked until this coverage is
recorded.

The reviewed round-3 subset contains only the prior OOB infrastructure failure
and integer-overflow resource exhaustion. All four tools remain required for
both. Begin `slice_pcode` with a bounded node count; if a required slice is
still oversized, narrow the source or node bound. That exact oversized result
unlocks the already-frozen adaptive stage so dominance and angr retain real
call opportunities.

## Targeted angr query

The execution dependencies are frozen in `../requirements-angr.txt`.
Install them in an isolated environment and invoke preparation/execution with
that environment's Python. If angr is absent, `query_angr` reports
`backend_status: unavailable`; the case remains unresolved rather than being
treated as safe.

Call `query_angr` only after recording the exact question that the packaged
Ghidra facts cannot answer. Choose one query kind:

- `reachability`: can the bounded symbolic exploration reach one address?
- `targeted_symbolic_execution`: return a bounded basic-block trace to a sink;
- `value_constraint`: at a reached sink, is one register relation satisfiable?
- `indirect_call_targets`: at a reached call site, enumerate concrete
  successors produced by angr.

Supply Ghidra-space hexadecimal addresses. The backend translates them with
the package's frozen Ghidra image base and angr's mapped base. Each query is
bounded by steps, wall-clock time, active states, and per-case query count.

`timeout`, state pruning, no target within bounds, unsupported lifting,
unconstrained successors, and backend unavailability are limitations, not
proof of unreachability or safety. Do not request or report concrete triggering
inputs. Cite the query hash and artifact SHA-256 in every material claim.

## Evidence discipline

Package indexes and query arguments are hash-bound. A static-tool result is
evidence only for the facts it directly reports. Never convert:

- a missing slice edge into proof of independence;
- absence within a bounded call-path search into proof of unreachability;
- one satisfying symbolic state into a universal range invariant;
- one infeasible constrained state into global safety; or
- an angr failure into a semantic negative.
