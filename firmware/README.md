# firmware/

Raw and extracted firmware images provided by the mentor. Empty until
received.

```
firmware/
├── raw/            # original downloaded firmware image(s), as-is
└── extracted/       # output of binwalk extraction
```

**Do not commit large firmware binaries to git** — add them to `.gitignore`
and note the source/download link + checksum in this README instead once
firmware arrives.

## Case A — source code available

If the firmware component comes with source, treat it like `samples/` and
generate IR directly with `clang` (see `ir/README.md`).

## Case B — binary-only firmware

1. **Extract** the filesystem/binaries:
   ```bash
   binwalk -e firmware.bin
   ```
2. **Identify architecture** of extracted ELF binaries:
   ```bash
   file extracted_binary
   ```
3. **Lift to LLVM IR** with RetDec (start here — easiest to run solo):
   ```bash
   # via Docker, e.g.:
   docker run --rm -v $(pwd):/data avast/retdec:latest \
     retdec-decompiler /data/extracted_binary
   ```
   Fallback if RetDec is insufficient: McSema or Remill (harder to build,
   more accurate).

Binary lifting is the hardest part of this pipeline — deprioritize it until
the source-based benchmark (`samples/`, `ir/`, `prompts/`, `results/`) is
working end to end.
