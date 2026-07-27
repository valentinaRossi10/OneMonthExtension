#!/usr/bin/env python3
"""Audit a result schema offline for OpenAI Structured Outputs compatibility."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from filter_common import audit_strict_json_schema, load_json


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("schema", type=Path)
    value.add_argument(
        "--fine-tuned-model",
        action="store_true",
        help="Also enforce the additional documented fine-tuned-model limits.",
    )
    return value


def main() -> int:
    args = parser().parse_args()
    schema_path = args.schema.resolve()
    report = audit_strict_json_schema(
        load_json(schema_path),
        fine_tuned_model=args.fine_tuned_model,
    )
    output = {
        "schema_path": str(schema_path),
        "compatible": not report["errors"],
        **report,
        "provider_api_calls_made": 0,
    }
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0 if output["compatible"] else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)
