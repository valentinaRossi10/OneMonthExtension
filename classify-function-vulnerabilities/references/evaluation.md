# Tier A evaluation rules

## Labels

Generate one task for every indexed sample, both `vulnerable` and `patched` variants, and all six configured target classes.

Set `expected_positive` only when both conditions hold:

1. The variant is `vulnerable`.
2. The normalized target class equals the row's normalized `bug_class`.

Treat every other task as benchmark-negative. Do not expose this label, the CVE, the variant, the indexed class, or the CVE description in the model prompt.

## Categories

For `status=ok` and decisive verdicts:

| Expected | Verdict | Category |
|---|---|---|
| positive | vulnerable | true_positive |
| positive | not_vulnerable | false_negative |
| negative | vulnerable | false_positive |
| negative | not_vulnerable | true_negative |

Categorize `indeterminate` as `abstention`. Categorize refusal, invalid output, API error, guard skip, unavailable input, and missing output separately. Give none of these correctness credit and never turn them into true negatives.

## Metrics

Report total tasks, expected positives/negatives, TP/FN/TN/FP, abstentions, failure statuses, decision coverage, end-to-end recall, precision, end-to-end specificity, false-positive rate, F1, balanced accuracy, and per-class results. Prefer macro/per-class interpretation over raw accuracy because the six-class cross-product is heavily negative.

Report CVE-2021-42386's indexed use-after-free task separately. The supplied `nvalloc` function does not locally contain the full free/stale-alias/use sequence, so it is a known Tier A observability limitation rather than a clean function-local positive. Include both all-positive recall and observable-positive recall excluding this designated limitation.

## Interpretation cautions

- A Tier A positive means the isolated function contains a class-consistent local pattern. It does not establish reachability, attacker control, or exploitability.
- `index.csv` verifies one historical CVE class per sample; it does not prove the absence of every secondary weakness. Call mismatched-class results false positives relative to benchmark labels, and preserve their evidence for review.
- Do not compare vulnerable and patched representations inside the prompt. A paired transition is an evaluation result only.
- Stratify results by `ghidra_pseudo_c` and `llvm_ir` because the representation itself can affect performance.
