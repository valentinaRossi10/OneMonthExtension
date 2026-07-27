# BusyBox Tier B v5 targeted follow-up summary

Status: completed and scored  
Model/reasoning: `gpt-5.6-sol` / `high`

## Scope

This operational follow-up contains two new protocol-v5 experiments and one
unchanged append-only retry in its original protocol-v4 ledger:

- unchanged CVE-2017-15873 vulnerable API-error retry;
- CVE-2021-42373 vulnerable/patched prompt-v5 pair; and
- CVE-2021-42386 vulnerable package-v3/12-tool case.

It is not a complete oracle matrix. The unchanged v4 retry is reported
separately from the new v5 methodological results and is not treated as if it
used prompt v5 or package v3.

## Runs and accounting

| Action | Manifest SHA-256 | Conservative additional projection | Additional spend | Additional calls |
|---|---|---:|---:|---:|
| [CVE-2017-15873 unchanged retry](../runs/2026-07-23t043100z__gpt-5-6-sol__high__busybox-cve-2017-15873-remediation-v4/results.jsonl) | `f04894851645805537308994f3029871c4d70f676d9ca38d99fcf32b8d2f8aea` | $4.578475 | $1.016135 | 10 |
| [CVE-2021-42373 prompt-v5 pair](../runs/2026-07-23t074000z__gpt-5-6-sol__high__busybox-cve-2021-42373-targeted-v5/results.jsonl) | `84ee06f94bab123f65d0c11cb65f7c843e2b29110b46054e3fd4e407b4df1070` | $9.172020 | $1.352795 | 22 |
| [CVE-2021-42386 package-v3 case](../runs/2026-07-23t074000z__gpt-5-6-sol__high__busybox-cve-2021-42386-targeted-v5/results.jsonl) | `c51a9e25213a7e0ca7670505b88e67ce77203b7c4b2ac3e3fd050f747ed9fd9f` | $6.102850 | $0.853810 | 13 |
| **Additional total** | — | **$19.853345** | **$3.222740** | **45** |

The CVE-2017 ledger had already spent $1.162285. Its cumulative spend after
the retry is $2.178420. Current cumulative spend across the three ledgers is
$4.385025, under their three $10 ceilings.

## Outcomes

| Case | Verdict/status | Frozen score |
|---|---|---|
| CVE-2017-15873 vulnerable retry | `api_error` | Failure; no verdict |
| CVE-2021-42373 vulnerable | `confirmed` | True positive |
| CVE-2021-42373 patched | `confirmed` | False positive |
| CVE-2021-42386 vulnerable | `rejected` | False negative |

For the two new v5 runs alone, strict accuracy is 1/3 (33.3%), sensitivity is
1/2 (50%), patched specificity is 0/1 (0%), and precision is 1/2 (50%). There
were no abstentions. The only pair produced a
`confirmed`-to-`confirmed` transition.

Across all four operational actions, including the unchanged v4 retry, there
is one true positive, one false positive, one false negative, and one explicit
failure.

## Diagnostic findings

### CVE-2017-15873 unchanged retry

The original attempt ended without a `response.completed` event at model call
11. The explicitly reviewed retry again ended without that event, this time at
model call 10, after an otherwise normal progressing trace. The repeated
failure remains infrastructure/transport evidence and supplies no verdict.
Both attempts remain append-only in the same ledger and cumulative ceiling.
No further automatic retry is justified.

### CVE-2021-42373 prompt-v5 pair

Prompt v5 corrected the vulnerable-side reasoning. The model used the shortest
non-null prefix: one section argument, pointer advance to the missing next
argument, and the later `strchr` dereference. The vulnerable case was correctly
`confirmed`.

The patched case was also `confirmed`, but through a different claimed path:
zero positional arguments reaching the initial helper call before the
line-83 next-argument guard. Under the frozen oracle this is a false positive.
The response did not establish that the generic option parser returns for zero
operands rather than terminating through its minimum-argument control.
Consequently the alternate path lacks the required path-feasibility proof.

The prompt change improved sensitivity but did not restore specificity. Any
future revision must require positive evidence that upstream validation
returns for an alternate input shape; plausibility of a null argv sentinel is
not sufficient.

### CVE-2021-42386 package-v3 case

Package v3 contains the intended neutral fact:

`FUN_001150ce` result assigned to `uVar1` at caller line 7 and later passed to
`FUN_00113ece` at line 8.

The model never requested `call_result_alias_reuse` facts for that caller. It
used all 12 tool turns on the candidate, entry, cleanup routine, allocator, and
other callers, then returned `rejected`. Its conclusion again treated retained
arena blocks as excluding the requested class and did not analyze the exposed
caller-side result reuse.

The representation now contains the relation, so this outcome is no longer
explained solely by missing package data. It is an evidence-access/tool-
selection failure plus a lifetime-reasoning false negative. Raising the limit
from 10 to 12 did not resolve it because the additional turns were allocated
elsewhere.

## Preserved artifacts

Each run retains its immutable manifest, exact prompts, append-only ledger,
metadata, `scoring/scoring.csv`, and `scoring/summary.json`. The
CVE-2021-42373 run also retains `scoring/paired-transitions.csv`.

Related summaries:

- [v3 four-pair follow-on](2026-07-23__busybox-four-pair-follow-on__tier-b-v3.md)
- [v4 remediation subset](2026-07-23__busybox-remediation-subset__tier-b-v4.md)
- [`EXPERIMENT.md`](../../../EXPERIMENT.md)
