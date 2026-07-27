// Headless post-script: given a comma-separated list of raw (unstripped-nm)
// hex offsets, resolves each to Ghidra's actual containing function entry
// point in the current (possibly fully stripped) program, using the
// program's own image base rather than an assumed constant. If Ghidra's
// own function-boundary analysis missed a function at that exact address
// (observed for some fully-stripped, externally-visible entry points),
// forces disassembly + function creation there and decompiles the result
// as a sanity check.
//
// Run via analyzeHeadless with:
//   -postScript ResolveOffsets.java <comma_separated_hex_offsets>
//
// @category IRSS

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class ResolveOffsets extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("Usage: ResolveOffsets.java <comma_separated_hex_offsets>");
            return;
        }
        Address base = currentProgram.getImageBase();
        println("=== ResolveOffsets for " + currentProgram.getDomainFile().getPathname()
                + " (image base " + base + ") ===");

        DecompInterface decomp = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        options.grabFromProgram(currentProgram);
        decomp.setOptions(options);
        decomp.setSimplificationStyle("decompile");
        decomp.openProgram(currentProgram);

        for (String rawOffset : args[0].split(",")) {
            long off = Long.parseLong(rawOffset.trim(), 16);
            Address target = base.add(off);
            Function fn = getFunctionContaining(target);
            if (fn != null) {
                println("offset " + rawOffset + " -> address " + target
                        + " -> function entry " + fn.getEntryPoint()
                        + " (name=" + fn.getName() + ", thunk=" + fn.isThunk() + ")");
                continue;
            }
            println("offset " + rawOffset + " -> address " + target
                    + " -> NO CONTAINING FUNCTION, attempting forced disassembly+createFunction");
            boolean disOk = disassemble(target);
            Function created = createFunction(target, null);
            if (created == null) {
                println("offset " + rawOffset + " -> FORCE FAILED (disassemble=" + disOk + ", createFunction=null)");
                continue;
            }
            println("offset " + rawOffset + " -> FORCED function entry " + created.getEntryPoint()
                    + " (name=" + created.getName() + ")");
            DecompileResults results = decomp.decompileFunction(created, 60, monitor);
            if (results.decompileCompleted()) {
                String code = results.getDecompiledFunction().getC();
                int lines = code.split("\n").length;
                println("offset " + rawOffset + " -> forced function decompiled OK, " + lines + " lines");
                println("----- first 20 lines -----");
                String[] codeLines = code.split("\n");
                for (int i = 0; i < Math.min(20, codeLines.length); i++) {
                    println(codeLines[i]);
                }
                println("----- end -----");
            } else {
                println("offset " + rawOffset + " -> forced function FAILED to decompile: " + results.getErrorMessage());
            }
        }
    }
}
