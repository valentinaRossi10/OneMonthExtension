# ir/

Generated LLVM IR files mirroring the BusyBox samples. LLVM IR is the Tier A
fallback when a target function has no usable Ghidra pseudo-C variant.

```
ir/
├── CVE-2021-42373-busybox/
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

The Tier A preparer extracts only the indexed target function before a prompt
is built; whole LLVM modules are never submitted to the API. The planned
Tier B representation has not yet been selected.
