# samples/

Source code samples with **known, documented CVEs**, used as ground truth to
verify whether the LLM analysis correctly detects real vulnerabilities.

## Contents

One subfolder per sample, e.g.:

```
samples/
├── CVE-2021-42373-busybox/
│   ├── vulnerable/         # source at the vulnerable commit
│   ├── patched/            # source at the fixing commit (for diffing)
│   └── info.md             # CVE id, file/function/line, bug class, description
└── ...
```

## Ground-truth log

Keep a running index of all samples in `samples/index.csv` with columns:
`cve_id, project, file, function, line, bug_class, description`

This is the scoring key used by the Tier A preparer and scorer. Each indexed
historical class supplies the expected positive only for that sample's
vulnerable variant and matching class; all variants are still tested against
the full six-class cross-product.

## How to add a sample

```bash
git clone <upstream-project-repo> /tmp/proj
cd /tmp/proj
git log --oneline -- <affected_file>     # find the fixing commit
git show <fixing_commit_hash>            # inspect the fix/diff
git checkout <commit_before_fix>         # get the vulnerable version
```
Copy the relevant file(s) into `samples/<name>/vulnerable/` (and the fixed
version into `patched/`), then fill in `info.md`.
