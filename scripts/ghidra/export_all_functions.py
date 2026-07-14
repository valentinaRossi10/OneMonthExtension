# Ghidra headless post-script: decompiles every function in the current
# program above a minimum size (to skip obvious libc/thunk noise) and
# writes each to its own .c file, named by entry-point address (no
# symbol names survive stripping, so address is the only stable label).
#
# Run via analyzeHeadless with:
#   -postScript export_all_functions.py <output_dir> <min_size_bytes>
#
# Jython-compatible (Ghidra's classic scripting API) - avoid Python3-only
# syntax.
#
# @category IRSS

import os
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

args = getScriptArgs()
if len(args) < 2:
    print("Usage: export_all_functions.py <output_dir> <min_size_bytes>")
    exit(1)

out_dir = args[0]
min_size = int(args[1])

if not os.path.exists(out_dir):
    os.makedirs(out_dir)

monitor = ConsoleTaskMonitor()
decomp = DecompInterface()
decomp.openProgram(currentProgram)

fm = currentProgram.getFunctionManager()
functions = fm.getFunctions(True)  # True = forward order

total = 0
exported = 0
skipped_thunk = 0
skipped_external = 0
skipped_small = 0
skipped_failed = 0

for func in functions:
    total += 1

    if func.isThunk():
        skipped_thunk += 1
        continue
    if func.isExternal():
        skipped_external += 1
        continue

    body_size = func.getBody().getNumAddresses()
    if body_size < min_size:
        skipped_small += 1
        continue

    result = decomp.decompileFunction(func, 60, monitor)
    if not result.decompileCompleted():
        skipped_failed += 1
        print("FAILED to decompile %s: %s" % (func.getEntryPoint(), result.getErrorMessage()))
        continue

    code = result.getDecompiledFunction().getC()
    addr_str = str(func.getEntryPoint())
    out_path = os.path.join(out_dir, "FUN_%s.c" % addr_str)
    f = open(out_path, "w")
    f.write(code)
    f.close()
    exported += 1

print("=== export_all_functions summary ===")
print("Total functions seen:   %d" % total)
print("Exported:               %d" % exported)
print("Skipped (thunk):        %d" % skipped_thunk)
print("Skipped (external):     %d" % skipped_external)
print("Skipped (< min_size):   %d" % skipped_small)
print("Skipped (decomp fail):  %d" % skipped_failed)
print("Output dir: %s" % out_dir)
