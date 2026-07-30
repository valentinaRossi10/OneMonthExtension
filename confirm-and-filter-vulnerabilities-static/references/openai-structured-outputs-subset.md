# OpenAI Structured Outputs schema preflight

Source checked: OpenAI's official “Structured model outputs” guide on
2026-07-26:
<https://developers.openai.com/api/docs/guides/structured-outputs#supported-schemas>

The offline preflight in `scripts/filter_common.py` implements the documented
base-model subset used by this harness:

- root must be an object and must not use `anyOf`;
- supported JSON types are string, number, boolean, integer, object, array,
  enum, and nested `anyOf`; `null` is accepted as a union member for an
  otherwise required field;
- every object property is required and every object sets
  `additionalProperties: false`;
- arrays have one `items` schema;
- supported base-model constraints are string `minLength`, `maxLength`,
  `pattern`, and the documented `format` values; numeric `minimum`, `maximum`,
  `exclusiveMinimum`, `exclusiveMaximum`, and `multipleOf`; and array
  `minItems` and `maxItems`;
- `allOf`, `not`, `dependentRequired`, `dependentSchemas`, `if`, `then`, and
  `else` are rejected;
- `uniqueItems` is rejected. It is absent from the documented supported-array
  keyword list and the Responses API explicitly rejected it in the preserved
  2026-07-26 v3 run;
- schemas are limited to 5,000 total object properties, 10 object nesting
  levels, 120,000 characters across property names, definition names, enum
  string values, and string const values, and 1,000 total enum values;
- a string enum with more than 250 values is limited to 15,000 characters
  across that enum's string values;
- local definitions and references are accepted; external references are not;
- each `const` or `enum` node must declare its type explicitly. This additional
  harness check preserves the earlier API-validated fix for the missing-type
  failures in this repository.

The optional `--fine-tuned-model` mode also rejects the extra type-specific
keywords that the official guide says fine-tuned Structured Outputs do not
support.

Run the preflight without making an API call:

```sh
python3 confirm-and-filter-vulnerabilities/scripts/validate_result_schema.py \
  confirm-and-filter-vulnerabilities/references/v3/result-schema.json
```

Run preparation and execution both call the same validator before provider
access, so this CLI is not a separate or weaker implementation.
