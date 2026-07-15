#!/usr/bin/env python3
"""
Runs the vulnerability-detection benchmark as a full cross-product: for
each CVE sample (vulnerable and patched), for every prompt template (not
just the one matching the sample's own bug class), for each configured
model. Running every prompt against every sample — not just matched
pairs — is what lets score.py distinguish "the specialized prompt found
the real bug" from "an unrelated prompt hallucinated a false positive."

Input code representation, in priority order per sample:
  1. pseudo-code/<sample>/{vulnerable,patched}.c   (primary, per mentor's decision)
  2. ir/<sample>/{vulnerable,patched}.ll            (fallback, if pseudo-code missing)

Requires ANTHROPIC_API_KEY and/or OPENAI_API_KEY in the environment,
depending on which providers are listed in models.yaml.

Usage:
    python3 run_benchmark.py
"""
import csv
import sys
from pathlib import Path

import yaml

from bug_classes import ALL_PROMPT_FILES

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLES_INDEX = REPO_ROOT / "samples" / "index.csv"
PSEUDOCODE_DIR = REPO_ROOT / "pseudo-code"
IR_DIR = REPO_ROOT / "ir"
PROMPTS_DIR = REPO_ROOT / "prompts"
RESULTS_DIR = REPO_ROOT / "results" / "runs"
MODELS_CONFIG = Path(__file__).resolve().parent / "models.yaml"

# Real pseudo-code files for these samples top out around 12KB. The one
# LLVM IR fallback in use (CVE-2021-42386's patched variant, which has no
# pseudo-C because the fix removes the function entirely) turned out to be
# over 1MB - sent as-is, once per prompt template per model, it dominated
# an entire benchmark run's token spend. This guard catches any input of
# that scale before it reaches the API, instead of silently paying for it.
MAX_CODE_CHARS = 50_000


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


def build_prompt(template_name: str, code: str, representation: str) -> str:
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
        max_tokens=4096,
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
            if len(code) > MAX_CODE_CHARS:
                print(
                    f"SKIP {cve_id} ({variant}, {representation}): {code_path} is "
                    f"{len(code):,} chars, over the {MAX_CODE_CHARS:,}-char guard "
                    f"(see MAX_CODE_CHARS comment) - would blow up token spend",
                    file=sys.stderr,
                )
                continue

            for prompt_file in ALL_PROMPT_FILES:
                prompt_slug = Path(prompt_file).stem
                prompt = build_prompt(prompt_file, code, representation)

                for model_cfg in models:
                    provider = model_cfg["provider"]
                    model = model_cfg["model"]
                    if model.startswith("REPLACE_ME"):
                        print(f"SKIP model {model!r}: placeholder, not configured", file=sys.stderr)
                        continue

                    out_file = RESULTS_DIR / f"{cve_id}__{variant}__{model}__{prompt_slug}.md"
                    print(f"Running {cve_id} ({variant}, {representation}) x {model} x {prompt_slug} ...")
                    try:
                        response = call_model(provider, model, prompt)
                    except Exception as e:
                        response = f"[ERROR calling {provider}/{model}: {e}]"
                        print(f"  ERROR: {e}", file=sys.stderr)

                    out_file.write_text(response)


if __name__ == "__main__":
    main()
