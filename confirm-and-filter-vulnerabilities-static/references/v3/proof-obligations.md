# V3 asymmetric proof obligations

## Confirmation

Confirmation is existential: one complete, feasible target-class scenario is
enough. Require a present task-matching candidate, reachable contextual path,
identified target operation, feasible value or lifetime constraints, and
class-specific evidence. Challenge the selected supported hypothesis once.
Alternative hypotheses may be contradicted or unresolved without defeating a
completed positive proof.

The required confirmation-obligation kinds are:

- `identity`
- `reachability`
- `target_operation`
- `feasible_value_or_lifetime_constraints`
- `contextual_path`
- `class_specific`

Every returned confirmation obligation must be `satisfied`, and the separate
adversarial challenge must conclude `confirmation_survives`.

## Suppression

Suppression is universal and intentionally stricter. Every hypothesis must be
contradicted, every relevant sink must be inventoried independently, and every
transformation from origin to sink must be ordered and evidenced.

The closed transformation-effect vocabulary is:

- `preserves_value_and_state`
- `changes_value_preserves_proven_invariant`
- `changes_value_and_requires_recheck`
- `reestablishes_guarded_invariant`
- `invalidates_guarded_invariant`
- `unresolved`

A transformation that preserves, reestablishes, or invalidates a named
invariant must reference that invariant through its closed `invariant_ids`
array.

A post-transformation guard must follow the last transformation. An earlier
guard is valid only with a complete preservation proof: all later
transformations must preserve the value/state or a proven invariant, and every
intervening mutation must be enumerated and marked `preserved`.

Any unsafe or unresolved sink, unresolved transformation, missing guard,
different-value guard, invalidated invariant, unaddressed mutation, incomplete
inventory, unresolved indirect call, or material unresolved fact requires
`retain_and_escalate`.
