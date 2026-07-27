// Headless post-script: given a comma-separated list of raw (nm-derived)
// hex offsets that Ghidra's automatic function-boundary analysis failed to
// recognize as functions (observed for some BusyBox applet _main entry
// points, likely reached only via an indirect applet-dispatch table rather
// than a direct call instruction), force disassembly + function creation at
// each address, decompile, and write FUN_<addr>.c into the same
// per-program subfolder layout ExportAllFunctions.java uses, so the file
// lands alongside the rest of that program's exported corpus.
//
// Run via analyzeHeadless with:
//   -postScript ExportForcedFunctions.java <base_output_dir> <comma_separated_hex_offsets>
//
// @category IRSS

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

import java.io.File;
import java.io.FileWriter;

public class ExportForcedFunctions extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            println("Usage: ExportForcedFunctions.java <output_dir> <comma_separated_hex_offsets>");
            return;
        }
        String baseOutDirPath = args[0];
        String[] offsets = args[1].split(",");

        String programPath = currentProgram.getDomainFile().getPathname();
        String subDirName = programPath.replaceAll("^/+", "").replaceAll("[/\\\\]+", "_");
        File dir = new File(baseOutDirPath, subDirName);
        if (!dir.exists()) {
            dir.mkdirs();
        }

        DecompInterface decomp = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        options.grabFromProgram(currentProgram);
        decomp.setOptions(options);
        decomp.setSimplificationStyle("decompile");
        decomp.openProgram(currentProgram);

        Address base = currentProgram.getImageBase();
        int forcedOk = 0;
        int forcedFail = 0;
        int alreadyPresent = 0;

        for (String rawOffset : offsets) {
            long off = Long.parseLong(rawOffset.trim(), 16);
            Address target = base.add(off);

            Function fn = getFunctionContaining(target);
            if (fn != null && fn.getEntryPoint().equals(target)) {
                println("offset " + rawOffset + " already has a real function at " + target
                        + " (name=" + fn.getName() + "); skipping force");
                alreadyPresent++;
                continue;
            }

            disassemble(target);
            Function created = createFunction(target, null);
            if (created == null) {
                println("offset " + rawOffset + " -> FORCE FAILED (createFunction returned null)");
                forcedFail++;
                continue;
            }

            DecompileResults results = decomp.decompileFunction(created, 60, monitor);
            if (!results.decompileCompleted()) {
                println("offset " + rawOffset + " -> forced function FAILED to decompile: "
                        + results.getErrorMessage());
                forcedFail++;
                continue;
            }

            String code = results.getDecompiledFunction().getC();
            String addrStr = created.getEntryPoint().toString();
            File outFile = new File(dir, "FUN_" + addrStr + ".c");
            FileWriter fw = new FileWriter(outFile);
            fw.write(code);
            fw.close();
            println("offset " + rawOffset + " -> wrote " + outFile.getAbsolutePath());
            forcedOk++;
        }

        println("=== ExportForcedFunctions summary ===");
        println("Already present (skipped): " + alreadyPresent);
        println("Forced and exported:       " + forcedOk);
        println("Forced but failed:         " + forcedFail);
    }
}
