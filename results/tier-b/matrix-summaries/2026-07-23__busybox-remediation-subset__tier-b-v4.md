# BusyBox Tier B v4 remediation-subset summary

Status: completed and scored  
Model/reasoning: `gpt-5.6-sol` / `high`  
Protocol/policy/prompt/package: `experiment-protocol-v4` /
`tier-b-policy-v4` / `tier-b-prompt-v4` / `tier-b-package-v2`

## Scope

This separately controlled subset contains four cases: CVE-2017-15873
vulnerable, both CVE-2021-42373 controls, and CVE-2021-42386 vulnerable. It is
not a complete four-pair or five-pair matrix and must not be combined with the
v3 follow-on or the standalone CVE-2026-29004 pilot.

## Runs and accounting

| Scope | Manifest SHA-256 | Projection | Spend | Calls |
|---|---|---:|---:|---:|
| [CVE-2017-15873 vulnerable](../runs/2026-07-23t043100z__gpt-5-6-sol__high__busybox-cve-2017-15873-remediation-v4/results.jsonl) | `f04894851645805537308994f3029871c4d70f676d9ca38d99fcf32b8d2f8aea` | $4.578475 | $1.162285 | 11 |
| [CVE-2021-42373 pair](../runs/2026-07-23t043100z__gpt-5-6-sol__high__busybox-cve-2021-42373-remediation-v4/results.jsonl) | `728358bd47645554610826ad001b66cebe25116c82fa1fc2228d3270f9fb5ac4` | $9.157390 | $1.340925 | 22 |
| [CVE-2021-42386 vulnerable](../runs/2026-07-23t043100z__gpt-5-6-sol__high__busybox-cve-2021-42386-remediation-v4/results.jsonl) | `4d857ed337f2b366f40671efe91daa41b79678f895c5bcf2427ba9273bccfb18` | $4.578420 | $0.567735 | 11 |
| **Aggregate** | — | **$18.314285** | **$3.070945** | **44** |

The approved aggregate ceiling was $30.

## Results

| Case | Result | Score |
|---|---|---|
| CVE-2017-15873 vulnerable | `api_error` | Failure; no verdict |
| CVE-2021-42373 vulnerable | `indeterminate` | Abstention |
| CVE-2021-42373 patched | `indeterminate` | Abstention |
| CVE-2021-42386 vulnerable | `indeterminate` | Abstention |

The subset produced three abstentions, one failure, zero decisive verdicts, and
0% strict accuracy.

## Diagnostic findings

### CVE-2017-15873

The closer entry removed the earlier indirect-call obstacle. Ten on-track tool
turns completed, but model call 11 failed because the stream did not deliver a
`response.completed` event. No verdict can be inferred. A dry readiness check
shows an unchanged append-only retry would combine $1.162285 already accounted
with a $4.578475 conservative retry projection, remaining under the original
$10 run ceiling. It still requires separate explicit retry approval.

### CVE-2021-42373

Both cases inspected the candidate first but analyzed a zero-positional-
argument path and spent the remaining tools on generic parser configuration.
The relevant minimal path uses the shortest non-null argument prefix and then
the next pointer advance. The patched candidate's line 83
`plVar12[1] == 0` guard was visible in the first lookup but its effect was
missed. This is a reasoning/path-selection error, not a missing-code or oracle
gap.

### CVE-2021-42386

The result improved from v3's false negative to an abstention: it recognized
direct reachability and the logical arena rewind. It exhausted all 10 tools
after finding a caller that passed the returned value to `FUN_00113ece`, with
no turn left to inspect that final consumer. Package v2 also lacked an explicit
neutral call-result alias-reuse relation. This is a representation and
tool-fit limitation, not the earlier physical-`free()` reasoning error.

## Preserved artifacts

Each run retains its immutable manifest, prompts, append-only ledger, metadata,
`scoring/scoring.csv`, and `scoring/summary.json`. The CVE-2021-42373 run also
retains `scoring/paired-transitions.csv`.

Related documentation:

- [`EXPERIMENT.md`](../../../EXPERIMENT.md)
- [v3 four-pair summary](2026-07-23__busybox-four-pair-follow-on__tier-b-v3.md)
- [`diagnostics.md`](../../../confirm-vulnerability-reachability/references/diagnostics.md)
- [`oracle-audits.md`](../../../confirm-vulnerability-reachability/references/oracle-audits.md)
