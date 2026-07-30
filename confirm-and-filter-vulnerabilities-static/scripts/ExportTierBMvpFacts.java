// Export minimal Tier B facts from Ghidra's program model.
//
// Run with:
//   -postScript ExportTierBMvpFacts.java <output_jsonl_or_directory>
//
// A directory argument writes one <executable_md5>.jsonl file per processed
// program, which permits a read-only recursive export from an existing Ghidra
// project without collisions between identically named programs.
//
// The export records analyzed functions, content fingerprints, direct calls
// from Ghidra references, and explicit unresolved indirect-call sites. It
// intentionally does not claim SSA, slicing, or indirect-target resolution.
//
// @category IRSS

import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.Reference;

import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class ExportTierBMvpFacts extends GhidraScript {

    private static String json(String value) {
        if (value == null) {
            return "null";
        }
        String escaped = value
            .replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t");
        return "\"" + escaped + "\"";
    }

    private static String stringArray(List<String> values) {
        List<String> encoded = new ArrayList<>();
        for (String value : values) {
            encoded.add(json(value));
        }
        return "[" + String.join(",", encoded) + "]";
    }

    private static String sha256(byte[] value) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(value);
        StringBuilder output = new StringBuilder();
        for (byte item : digest) {
            output.append(String.format("%02x", item & 0xff));
        }
        return output.toString();
    }

    private byte[] functionBytes(Function function) throws Exception {
        Memory memory = currentProgram.getMemory();
        ByteArrayOutputStream collected = new ByteArrayOutputStream();
        AddressRangeIterator ranges = function.getBody().getAddressRanges();
        while (ranges.hasNext()) {
            AddressRange range = ranges.next();
            long length = range.getLength();
            if (length > Integer.MAX_VALUE) {
                throw new IllegalStateException("Function range is too large");
            }
            Address address = range.getMinAddress();
            while (address.compareTo(range.getMaxAddress()) <= 0) {
                try {
                    // The presence marker distinguishes an unreadable gap from
                    // an initialized byte whose value happens to be zero.
                    collected.write(1);
                    collected.write(memory.getByte(address));
                }
                catch (MemoryAccessException error) {
                    collected.write(0);
                }
                address = address.next();
            }
        }
        return collected.toByteArray();
    }

    private String normalizedInstructionText(Function function) {
        StringBuilder output = new StringBuilder();
        InstructionIterator instructions =
            currentProgram.getListing().getInstructions(function.getBody(), true);
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            output.append(instruction.getMnemonicString().toLowerCase());
            output.append('(');
            for (int index = 0; index < instruction.getNumOperands(); index++) {
                if (index > 0) {
                    output.append(',');
                }
                output.append(instruction.getOperandType(index));
            }
            output.append(")\n");
        }
        return output.toString();
    }

    private List<String> bodyRanges(Function function) {
        List<String> result = new ArrayList<>();
        AddressRangeIterator ranges = function.getBody().getAddressRanges();
        while (ranges.hasNext()) {
            AddressRange range = ranges.next();
            result.add(range.getMinAddress() + "-" + range.getMaxAddress());
        }
        return result;
    }

    private int blockCount(Function function) throws Exception {
        BasicBlockModel model = new BasicBlockModel(currentProgram);
        CodeBlockIterator blocks =
            model.getCodeBlocksContaining(function.getBody(), monitor);
        int count = 0;
        while (blocks.hasNext()) {
            blocks.next();
            count++;
        }
        return count;
    }

    private boolean hasCallInd(Instruction instruction) {
        for (PcodeOp operation : instruction.getPcode()) {
            if (operation.getOpcode() == PcodeOp.CALLIND) {
                return true;
            }
        }
        return false;
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            println("Usage: ExportTierBMvpFacts.java <output_jsonl_or_directory>");
            return;
        }
        File outputFile = new File(args[0]).getAbsoluteFile();
        if (outputFile.isDirectory()) {
            outputFile = new File(
                outputFile,
                currentProgram.getExecutableMD5() + ".jsonl"
            );
        }
        File parent = outputFile.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            throw new IllegalStateException("Could not create output directory");
        }

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputFile))) {
            writer.write(
                "{\"record_type\":\"metadata\",\"analysis_source\":"
                + "\"ghidra-program-model\",\"analysis_tool\":\"Ghidra\","
                + "\"analysis_version\":" + json(Application.getApplicationVersion()) + ","
                + "\"executable_md5\":" + json(currentProgram.getExecutableMD5()) + ","
                + "\"program_name\":" + json(currentProgram.getName()) + "}\n"
            );

            FunctionIterator functions =
                currentProgram.getFunctionManager().getFunctions(true);
            int functionCount = 0;
            int callsiteCount = 0;
            while (functions.hasNext() && !monitor.isCancelled()) {
                Function function = functions.next();
                if (function.isExternal()) {
                    continue;
                }
                functionCount++;
                String address = function.getEntryPoint().toString();
                String byteHash = sha256(functionBytes(function));
                String instructionHash = sha256(
                    normalizedInstructionText(function).getBytes(StandardCharsets.UTF_8)
                );
                List<String> ranges = bodyRanges(function);
                Set<String> strings = new HashSet<>();
                Set<String> dataReferences = new HashSet<>();

                InstructionIterator instructions =
                    currentProgram.getListing().getInstructions(function.getBody(), true);
                while (instructions.hasNext()) {
                    Instruction instruction = instructions.next();
                    Reference[] references = instruction.getReferencesFrom();
                    boolean emittedDirect = false;
                    for (Reference reference : references) {
                        Address target = reference.getToAddress();
                        if (reference.getReferenceType().isData()) {
                            dataReferences.add(target.toString());
                            Data data = currentProgram.getListing().getDataAt(target);
                            if (data != null && data.getValue() instanceof String) {
                                strings.add((String) data.getValue());
                            }
                        }
                        if (reference.getReferenceType().isCall()) {
                            Function targetFunction =
                                currentProgram.getFunctionManager().getFunctionAt(target);
                            String targetAddress =
                                targetFunction == null ? target.toString()
                                                       : targetFunction.getEntryPoint().toString();
                            writer.write(
                                "{\"record_type\":\"callsite\",\"caller_address\":"
                                + json(address) + ",\"site_address\":"
                                + json(instruction.getAddress().toString())
                                + ",\"call_kind\":\"direct\",\"target_address\":"
                                + json(targetAddress) + ",\"evidence\":"
                                + json(reference.getReferenceType().toString()) + "}\n"
                            );
                            emittedDirect = true;
                            callsiteCount++;
                        }
                    }
                    if (hasCallInd(instruction)
                        || (instruction.getFlowType().isCall() && !emittedDirect
                            && instruction.getFlows().length == 0)) {
                        writer.write(
                            "{\"record_type\":\"callsite\",\"caller_address\":"
                            + json(address) + ",\"site_address\":"
                            + json(instruction.getAddress().toString())
                            + ",\"call_kind\":\"indirect\",\"target_address\":null,"
                            + "\"evidence\":" + json(instruction.toString()) + "}\n"
                        );
                        callsiteCount++;
                    }
                }

                List<String> sortedStrings = new ArrayList<>(strings);
                List<String> sortedReferences = new ArrayList<>(dataReferences);
                Collections.sort(sortedStrings);
                Collections.sort(sortedReferences);
                writer.write(
                    "{\"record_type\":\"function\",\"address\":" + json(address)
                    + ",\"byte_sha256\":" + json(byteHash)
                    + ",\"normalized_instruction_sha256\":" + json(instructionHash)
                    + ",\"body_ranges\":" + stringArray(ranges)
                    + ",\"size_bytes\":" + function.getBody().getNumAddresses()
                    + ",\"block_count\":" + blockCount(function)
                    + ",\"strings\":" + stringArray(sortedStrings)
                    + ",\"data_references\":" + stringArray(sortedReferences)
                    + "}\n"
                );
            }
            println("Exported functions: " + functionCount);
            println("Exported call sites: " + callsiteCount);
        }
        println("Tier B MVP analysis export: " + outputFile.getAbsolutePath());
    }
}
