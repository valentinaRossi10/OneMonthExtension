#!/usr/bin/env python3
"""
Runs the vulnerability-detection benchmark: for each CVE sample (vulnerable
and patched), for each configured model, asks the model to analyze the
sample's code using the prompt template matching the sample's bug class.

Input code representation, in priority order per sample:
  1. pseudo-code/<sample>/{vulnerable,patched}.c   (primary, per mentor's decision)
  2. ir/<sample>/{vulnerable,patched}.ll            (fallback, if pseudo-code missing)

Requires ANTHROPIC_API_KEY and/or OPENAI_API_KEY in the environment,
depending on which providers are listed in models.yaml.

Usage:
    python3 run_benchmark.py
"""
import csv
import os
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLES_INDEX = REPO_ROOT / "samples" / "index.csv"
PSEUDOCODE_DIR = REPO_ROOT / "pseudo-code"
IR_DIR = REPO_ROOT / "ir"
PROMPTS_DIR = REPO_ROOT / "prompts"
RESULTS_DIR = REPO_ROOT / "results" / "runs"
MODELS_CONFIG = Path(__file__).resolve().parent / "models.yaml"

BUG_CLASS_TO_PROMPT = {
    "heap-buffer-overflow": "memory-buffer-overflow.md",
    "buffer-overflow": "memory-buffer-overflow.md",
    "use-after-free": "memory-use-after-free.md",
    "integer-overflow": "memory-integer-overflow.md",
    "null-pointer-dereference": "memory-null-pointer-dereference.md",
    "out-of-bounds-read": "memory-out-of-bounds-read.md",
}


def load_models():
    with open(MODELS_CONFIG) as f:
        config = yaml.safe_load(f)
    return config["models"]


def load_samples():
    with open(SAMPLES_INDEX, newline="") as f:
        return list(csv.DictReader(f))


def find_code_file(sample_dir_name: str, variant: str) -> tuple[Path, str]:
    """Returns (path, representation) for a sample variant, preferring
    pseudo-code, falling back to LLVM IR."""
    pseudo = PSEUDOCODE_DIR / sample_dir_name / f"{variant}.c"
    if pseudo.exists():
        return pseudo, "pseudo-code"
    ir = IR_DIR / sample_dir_name / f"{variant}.ll"
    if ir.exists():
        return ir, "llvm-ir"
    return None, None


def build_prompt(bug_class: str, code: str, representation: str) -> str:
    template_name = BUG_CLASS_TO_PROMPT.get(bug_class)
    if template_name is None:
        raise ValueError(f"No prompt template mapped for bug_class={bug_class!r}")
    template = (PROMPTS_DIR / template_name).read_text()
    note = ""
    if representation == "llvm-ir":
        note = (
            "\nNote: this is LLVM IR, not pseudo-C (fallback representation "
            "for this sample — see samples' info.md for why).\n"
        )
    return template.replace("<<<CODE>>>", note + code)


def call_anthropic(model: str, prompt: str) -> str:
    import anthropic

    client = anthropic.Anthropic()
    resp = client.messages.create(
        model=model,
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}],
    )
    return "".join(block.text for block in resp.content if block.type == "text")


def call_openai(model: str, prompt: str) -> str:
    import openai

    client = openai.OpenAI()
    resp = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
    )
    return resp.choices[0].message.content


def call_model(provider: str, model: str, prompt: str) -> str:
    if provider == "anthropic":
        return call_anthropic(model, prompt)
    if provider == "openai":
        return call_openai(model, prompt)
    raise ValueError(f"Unknown provider: {provider!r}")


def main():
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    models = load_models()
    samples = load_samples()

    for sample in samples:
        cve_id = sample["cve_id"]
        project = sample["project"]
        bug_class = sample["bug_class"]
        sample_dir_name = f"{cve_id}-{project}"

        for variant in ("vulnerable", "patched"):
            code_path, representation = find_code_file(sample_dir_name, variant)
            if code_path is None:
                print(
                    f"SKIP {cve_id} ({variant}): no pseudo-code or IR file found "
                    f"in pseudo-code/{sample_dir_name}/ or ir/{sample_dir_name}/",
                    file=sys.stderr,
                )
                continue

            code = code_path.read_text()
            prompt = build_prompt(bug_class, code, representation)

            for model_cfg in models:
                provider = model_cfg["provider"]
                model = model_cfg["model"]
                if model.startswith("REPLACE_ME"):
                    print(f"SKIP model {model!r}: placeholder, not configured", file=sys.stderr)
                    continue

                out_file = RESULTS_DIR / f"{cve_id}__{variant}__{model}.md"
                print(f"Running {cve_id} ({variant}, {representation}) x {model} ...")
                try:
                    response = call_model(provider, model, prompt)
                except Exception as e:
                    response = f"[ERROR calling {provider}/{model}: {e}]"
                    print(f"  ERROR: {e}", file=sys.stderr)

                out_file.write_text(response)


if __name__ == "__main__":
    main()
