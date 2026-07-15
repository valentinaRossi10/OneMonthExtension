#!/usr/bin/env python3
"""
Runs the real-firmware discovery benchmark for a single CVE sample under
firmware/ (see PLAN.md Stage 7): unlike the BusyBox calibration benchmark
(run_benchmark.py), this does NOT hand the LLM one pre-isolated function.
It runs the command-injection prompt against every decompiled function
in the relevant binary, for both the vulnerable and patched variant, and
scores whether the model correctly picks out the one real vulnerable
function among hundreds — a genuine discovery task, not a
confirm-what-you're-told task.

Only the command-injection prompt is used here (not the full
memory-safety-prompt cross-product from run_benchmark.py) - this phase
is specifically testing command-injection discovery at a scale (~1900
functions) where the full cross-product would be prohibitively
expensive for a proof-of-concept.

Input: the bulk-decompiled function set from
scripts/ghidra/ExportAllFunctions.java, one .c file per function
(FUN_<address>.c), for the vulnerable and patched binary. This lives
OUTSIDE the git repo (see firmware/README.md's no-redistribution
policy is about the binaries themselves; the bulk decompiled set here
is just large, not committed to keep the repo size sane - regenerate
via the Ghidra script instead of expecting it to already exist).

Requires ANTHROPIC_API_KEY and/or OPENAI_API_KEY in the environment,
same as run_benchmark.py.

Usage:
    python3 run_benchmark_firmware.py <cve_id> <vulnerable_dir> <patched_dir>

Example:
    python3 run_benchmark_firmware.py CVE-2016-6277-netgear-r6400 \\
        /home/.../repo/firmware/netgear-r6400/decompiled/netgear_httpd \\
        /home/.../repo/firmware/netgear-r6400/decompiled/netgear_patched_httpd
"""
import csv
import sys
from pathlib import Path

from run_benchmark import build_prompt, call_model, load_models

REPO_ROOT = Path(__file__).resolve().parent.parent
FIRMWARE_DIR = REPO_ROOT / "firmware"
RESULTS_DIR = REPO_ROOT / "results" / "runs-firmware"

COMMAND_INJECTION_PROMPT = "command-injection.md"


def load_ground_truth(cve_dir: Path) -> dict:
    """Returns {variant: vulnerable_function_filename_or_None}."""
    gt_path = cve_dir / "ground_truth.csv"
    result = {}
    with open(gt_path, newline="") as f:
        for row in csv.DictReader(f):
            fn = row["vulnerable_function_file"].strip()
            result[row["variant"]] = fn if fn else None
    return result


def main():
    if len(sys.argv) != 4:
        print(
            "Usage: run_benchmark_firmware.py <cve_id> <vulnerable_dir> <patched_dir>",
            file=sys.stderr,
        )
        sys.exit(1)

    cve_id = sys.argv[1]
    variant_dirs = {"vulnerable": Path(sys.argv[2]), "patched": Path(sys.argv[3])}

    cve_dir = FIRMWARE_DIR / cve_id
    if not cve_dir.exists():
        print(f"No such firmware sample: {cve_dir}", file=sys.stderr)
        sys.exit(1)

    ground_truth = load_ground_truth(cve_dir)
    models = load_models()
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    for variant, code_dir in variant_dirs.items():
        if not code_dir.is_dir():
            print(f"SKIP {variant}: {code_dir} not found", file=sys.stderr)
            continue

        c_files = sorted(code_dir.glob("*.c"))
        print(f"{variant}: {len(c_files)} functions found in {code_dir}")

        for code_path in c_files:
            code = code_path.read_text()
            prompt = build_prompt(COMMAND_INJECTION_PROMPT, code, "pseudo-code")
            func_name = code_path.stem  # e.g. "FUN_00033e0c"

            for model_cfg in models:
                provider = model_cfg["provider"]
                model = model_cfg["model"]
                if model.startswith("REPLACE_ME"):
                    continue

                out_file = RESULTS_DIR / f"{cve_id}__{variant}__{model}__{func_name}.md"
                if out_file.exists():
                    continue  # resumable: skip work already done in a prior run

                print(f"Running {cve_id} ({variant}) x {model} x {func_name} ...")
                try:
                    response = call_model(provider, model, prompt)
                except Exception as e:
                    response = f"[ERROR calling {provider}/{model}: {e}]"
                    print(f"  ERROR: {e}", file=sys.stderr)

                out_file.write_text(response)


if __name__ == "__main__":
    main()
