# Hypotheses and proof obligations

Enumerate relevant hypotheses before selecting one. Mark every obligation
`satisfied`, `contradicted`, or `unresolved`, with package evidence.

## Class hypotheses

- **Heap buffer overflow:** allocation site and extent; feasible write length
  or index; exact write; dominating guards; contextual path.
- **Integer overflow:** exact operation, width, and signedness; feasible
  operands; overflow or wrap; security-relevant consequence; ordering of
  effective checks.
- **NULL pointer dereference:** each dereferenced pointer; producer and
  pointer/index advances; shortest feasible non-null prefix; missing-next-item
  shapes; upstream minimum-argument validation; dominating non-null guards.
- **Out-of-bounds read:** object/readable extent; index transformations;
  feasible violating range; exact read; effective guards.
- **Use after free:** physical or logical lifetime end; surviving alias;
  release/reuse/reinitialization; later dereference; contextual path.
- **Command injection:** external influence; command construction; execution
  sink; complete or incomplete neutralization; contextual path.

## Confirmation gate

Require an identified operation, feasible value/input constraints, evidenced
contextual path, and satisfied class obligations. Challenge the proposed
confirmation once before finalizing it.

## Suppression gate

Permit suppression only when one of these is proven:

1. The candidate is absent under an audited artifact binding.
2. The candidate is unreachable from all in-scope roots and no relevant
   unresolved indirect-call site remains.
3. Every relevant hypothesis is contradicted by concrete, effective controls.

Reject suppression when identity is ambiguous, a relevant obligation is
unresolved, a guard lacks path/dominance evidence, or reachability depends on
an unresolved indirect call. Confidence alone is never proof.

## Adaptive progress

Qualifying progress is a new candidate/guard fact, call edge, input/value
constraint, resolved hypothesis, or narrowed unresolved obligation. Repeating
an equivalent query is not progress. Grant the extension stage only after
qualifying progress and retain a machine-readable progress record.
