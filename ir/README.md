# ir/

Generated LLVM IR files, mirroring the structure of `samples/` (and later
`firmware/` once binary lifting is in use).

```
ir/
├── busybox-CVE-2022-xxxx/
│   ├── vulnerable.ll
│   └── patched.ll
└── ...
```

## Generating IR from source (samples/)

```bash
clang -S -emit-llvm -g -O0 <file.c> -o <file.ll>
```
- `-g` keeps debug info (line numbers) to map IR back to source.
- `-O0` avoids optimizing away the vulnerable pattern.

If a sample needs its original build system (multiple files/dependencies),
use `Bear` or `WLLVM` to capture the full build:
```bash
bear -- make          # produces compile_commands.json
# or
CC=wllvm make && extract-bc <binary_output>
```

## Generating IR from firmware binaries (firmware/, once lifting is set up)

Use RetDec (or McSema/Remill as a fallback) — see `firmware/README.md`.
