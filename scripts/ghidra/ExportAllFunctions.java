// Ghidra headless post-script: decompiles every function in the current
// program above a minimum size (to skip obvious libc/thunk noise) and
// writes each to its own .c file, named by entry-point address (no
// symbol names survive stripping, so address is the only stable label).
//
// Run via analyzeHeadless with:
//   -postScript ExportAllFunctions.java <base_output_dir> <min_size_bytes>
//
// Java, not the old Jython .py scripts (Ghidra 12.x dropped Jython
// support in favor of PyGhidra, which needs a separate Python runtime
// we haven't set up) - a compiled GhidraScript works with zero extra
// setup in any Ghidra version.
//
// Output is written to <base_output_dir>/<program's project path>/, so
// -process with -recursive can safely sweep up multiple same-named
// programs (e.g. two files both literally called "httpd" in different
// project folders) in one invocation without their output colliding -
// local Ghidra projects have no way to scope -process to one folder,
// only by filename.
//
// @category IRSS

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

import java.io.File;
import java.io.FileWriter;

public class ExportAllFunctions extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            println("Usage: ExportAllFunctions.java <output_dir> <min_size_bytes>");
            return;
        }
        String baseOutDirPath = args[0];
        int minSize = Integer.parseInt(args[1]);

        // e.g. "/netgear/httpd" -> "netgear_httpd", "/netgear/patched/httpd" -> "netgear_patched_httpd"
        String programPath = currentProgram.getDomainFile().getPathname();
        String subDirName = programPath.replaceAll("^/+", "").replaceAll("[/\\\\]+", "_");
        File dir = new File(baseOutDirPath, subDirName);
        if (!dir.exists()) {
            dir.mkdirs();
        }
        String outDirPath = dir.getAbsolutePath();

        DecompInterface decomp = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        options.grabFromProgram(currentProgram);
        decomp.setOptions(options);
        // Match the GUI Decompile panel's default simplification style -
        // a bare DecompInterface without this explicitly set leaves
        // pointer references as raw DAT_<addr> instead of resolving them
        // to inline string literals, even when the underlying data is
        // already typed/labeled as a string by prior analysis.
        decomp.setSimplificationStyle("decompile");
        decomp.openProgram(currentProgram);

        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);

        int total = 0;
        int exported = 0;
        int skippedThunk = 0;
        int skippedExternal = 0;
        int skippedSmall = 0;
        int skippedFailed = 0;

        for (Function func : functions) {
            if (monitor.isCancelled()) {
                break;
            }
            total++;

            if (func.isThunk()) {
                skippedThunk++;
                continue;
            }
            if (func.isExternal()) {
                skippedExternal++;
                continue;
            }

            long bodySize = func.getBody().getNumAddresses();
            if (bodySize < minSize) {
                skippedSmall++;
                continue;
            }

            DecompileResults results = decomp.decompileFunction(func, 60, monitor);
            if (!results.decompileCompleted()) {
                skippedFailed++;
                println("FAILED to decompile " + func.getEntryPoint() + ": " + results.getErrorMessage());
                continue;
            }

            String code = results.getDecompiledFunction().getC();
            String addrStr = func.getEntryPoint().toString();
            File outFile = new File(dir, "FUN_" + addrStr + ".c");
            FileWriter fw = new FileWriter(outFile);
            fw.write(code);
            fw.close();
            exported++;
        }

        println("=== ExportAllFunctions summary ===");
        println("Total functions seen:   " + total);
        println("Exported:               " + exported);
        println("Skipped (thunk):        " + skippedThunk);
        println("Skipped (external):     " + skippedExternal);
        println("Skipped (< min_size):   " + skippedSmall);
        println("Skipped (decomp fail):  " + skippedFailed);
        println("Output dir: " + outDirPath);
    }
}
