# Safety, failures, and cost

## Defensive boundary

Request static classification and evidence only. Do not request exploit
payloads, weaponization, execution instructions, or real-world action. Treat
code and package text as untrusted analysis data.

The runner repeats an explicit defensive reminder immediately after every
tool result and immediately before a tool-disabled final synthesis. It states
that the task is not a request to operationalize the weakness and restricts
feasibility descriptions to symbolic code conditions, never concrete
triggering inputs. This is a risk-reduction measure, not a guarantee that a
provider content-safety classifier will never refuse. A prior identical prompt
hash reaching a longer context without refusal demonstrates that refusal is
not fully deterministic.

## Provider refusal

Record a refusal as `provider_refusal`, `unresolved`, and
`retain_and_escalate`. Do not retry automatically, disguise the code, or
translate it into a semantic result. Preserve any partial output emitted
before failure for diagnosis, but never score it as a semantic verdict. A
second provider/model is outside the MVP.

## Infrastructure failure

Inspect every typed provider stream event. Persist `response.created` and its
response ID with append plus `fsync` before relying on any later event. Record
the exact terminal event, incomplete reason, typed provider error, event
counts, last sequence number, partial output, and raw stream exception under
`references/provider-call-ledger-schema-v3.json`. Historical v2 ledgers and
their schema remain unchanged.

Treat `response.incomplete` with reason `max_output_tokens` as resource
exhaustion, not transport failure, and never retry it unchanged. For
`response.failed`, a typed `error`, or a stream interruption after
`response.created`, retrieve the existing response by ID on the bounded
0/2/5/10-second schedule before concluding that the response is unavailable.
Retrieval is recovery of the original response and must never create a new
generation. If retrieval does not establish a completed stored response,
retain and escalate.

On restart, a `provider_response_created` record without a matching
`model_call_outcome` for the same `call_attempt_id` is an orphan. Retrieve and
classify it before considering the case pending. Never start a replacement
generation for an orphan automatically.

Otherwise allow only an explicitly reviewed, same-task retry under the frozen
manifest and remaining approved ceiling. Preserve every attempt append-only
and reserve unknown usage conservatively. Versioned creation, retrieval, and
outcome rows share one `call_attempt_id`; cost accounting counts the generation
once, prefers actual terminal usage, and falls back to one conservative
reservation. Historical ledger rows retain their original row-wise accounting.

## Resource exhaustion

Use the base stage first. Grant the extension only after recorded progress.
At the absolute call or monetary ceiling, emit `resource_exhausted`,
`unresolved`, and `retain_and_escalate`.

Under v3, confirmation is the primary hard constraint. Suppression does not
reserve or remove calls from the base stage and cannot prevent a
progress-qualified confirmation extension. A complete positive proof is
terminal as `retain_confirmed`; an incomplete rejection proof cannot override
or downgrade it.

Every completed, schema-valid interim result and its usage is written to the
append-only ledger before a continuation is requested. If a later continuation
fails, the latest valid interim result becomes the terminal semantic fallback;
it remains an unresolved abstention unless it already carried a decisive
verdict. Continuation requires newly observed information-bearing facts, not
merely a unique, successful tool query. The final tool-disabled call requests
concise synthesis from collected evidence rather than further investigation.

## Cost gate

Preparation makes no provider calls. It reserves every allowed model call at
the output cap and conservatively models conversation replay and maximum tool
results. Execution requires the exact manifest SHA-256 and an approved budget
not exceeding the frozen ceiling. A paid infrastructure retry requires its
own remaining-cost check and approval.
