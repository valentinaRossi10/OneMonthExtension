// Export agent-queryable Tier B facts from Ghidra's analyzed program model.
//
// Run with:
//   -postScript ExportTierBStaticFacts.java <output_jsonl_or_directory>
//
// The export is intentionally mechanical: functions, raw p-code, references,
// basic-block edges, analyzed calls, and reference-derived candidates for
// indirect calls.  Dominance, def-use, and slicing are computed later as
// bounded glue over these records; the exporter makes no vulnerability claim.
//
// @category IRSS

import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
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

public class ExportTierBStaticFacts extends GhidraScript {

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
            Address address = range.getMinAddress();
            while (address.compareTo(range.getMaxAddress()) <= 0) {
                try {
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

    private boolean hasCallInd(Instruction instruction) {
        for (PcodeOp operation : instruction.getPcode()) {
            if (operation.getOpcode() == PcodeOp.CALLIND) {
                return true;
            }
        }
        return false;
    }

    private int blockCount(Function function, BasicBlockModel model) throws Exception {
        CodeBlockIterator blocks =
            model.getCodeBlocksContaining(function.getBody(), monitor);
        int count = 0;
        while (blocks.hasNext()) {
            blocks.next();
            count++;
        }
        return count;
    }

    private String varnode(Varnode node) {
        if (node == null) {
            return "null";
        }
        String kind = "other";
        if (node.isConstant()) {
            kind = "constant";
        }
        else if (node.isRegister()) {
            kind = "register";
        }
        else if (node.isUnique()) {
            kind = "unique";
        }
        else if (node.isAddress()) {
            kind = "address";
        }
        String address = node.getAddress().toString();
        String key = node.getAddress().getAddressSpace().getName()
            + ":" + Long.toUnsignedString(node.getOffset(), 16)
            + ":" + node.getSize();
        return "{\"key\":" + json(key)
            + ",\"kind\":" + json(kind)
            + ",\"address\":" + json(address)
            + ",\"offset_unsigned_hex\":"
            + json(Long.toUnsignedString(node.getOffset(), 16))
            + ",\"size\":" + node.getSize() + "}";
    }

    private String varnodes(Varnode[] nodes) {
        List<String> encoded = new ArrayList<>();
        for (Varnode node : nodes) {
            encoded.add(varnode(node));
        }
        return "[" + String.join(",", encoded) + "]";
    }

    private String blockStart(BasicBlockModel model, Address address)
            throws Exception {
        CodeBlock block = model.getFirstCodeBlockContaining(address, monitor);
        return block == null ? null : block.getFirstStartAddress().toString();
    }

    private Set<String> indirectCandidates(Instruction instruction) {
        Set<String> result = new HashSet<>();
        for (Reference reference : instruction.getReferencesFrom()) {
            Function target = currentProgram.getFunctionManager().getFunctionAt(
                reference.getToAddress()
            );
            if (target != null && !target.isExternal()) {
                result.add(target.getEntryPoint().toString());
            }
        }
        for (PcodeOp operation : instruction.getPcode()) {
            for (Varnode input : operation.getInputs()) {
                if (!(input.isAddress() || input.isConstant())) {
                    continue;
                }
                Address candidate;
                try {
                    candidate = currentProgram.getAddressFactory()
                        .getDefaultAddressSpace().getAddress(input.getOffset());
                }
                catch (Exception ignored) {
                    continue;
                }
                Function target =
                    currentProgram.getFunctionManager().getFunctionAt(candidate);
                if (target != null && !target.isExternal()) {
                    result.add(target.getEntryPoint().toString());
                }
            }
        }
        return result;
    }

    private void emitBlocks(
            BufferedWriter writer,
            Function function,
            BasicBlockModel model
    ) throws Exception {
        CodeBlockIterator blocks =
            model.getCodeBlocksContaining(function.getBody(), monitor);
        while (blocks.hasNext()) {
            CodeBlock block = blocks.next();
            List<String> successors = new ArrayList<>();
            CodeBlockReferenceIterator destinations =
                block.getDestinations(monitor);
            while (destinations.hasNext()) {
                CodeBlockReference edge = destinations.next();
                Address destination = edge.getDestinationAddress();
                if (destination != null && function.getBody().contains(destination)) {
                    successors.add(destination.toString());
                }
            }
            Collections.sort(successors);
            writer.write(
                "{\"record_type\":\"basic_block\",\"function_address\":"
                + json(function.getEntryPoint().toString())
                + ",\"block_start\":"
                + json(block.getFirstStartAddress().toString())
                + ",\"block_end\":"
                + json(block.getMaxAddress().toString())
                + ",\"successors\":" + stringArray(successors) + "}\n"
            );
        }
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            println("Usage: ExportTierBStaticFacts.java <output_jsonl_or_directory>");
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

        BasicBlockModel blockModel = new BasicBlockModel(currentProgram);
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputFile))) {
            writer.write(
                "{\"record_type\":\"metadata\",\"analysis_source\":"
                + "\"ghidra-program-model-static-v2\",\"analysis_tool\":\"Ghidra\","
                + "\"analysis_version\":" + json(Application.getApplicationVersion()) + ","
                + "\"executable_md5\":" + json(currentProgram.getExecutableMD5()) + ","
                + "\"image_base\":" + json(currentProgram.getImageBase().toString()) + ","
                + "\"program_name\":" + json(currentProgram.getName()) + "}\n"
            );

            FunctionIterator functions =
                currentProgram.getFunctionManager().getFunctions(true);
            int functionCount = 0;
            int callsiteCount = 0;
            int pcodeCount = 0;
            int referenceCount = 0;
            while (functions.hasNext() && !monitor.isCancelled()) {
                Function function = functions.next();
                if (function.isExternal()) {
                    continue;
                }
                functionCount++;
                String functionAddress = function.getEntryPoint().toString();
                String byteHash = sha256(functionBytes(function));
                String instructionHash = sha256(
                    normalizedInstructionText(function).getBytes(StandardCharsets.UTF_8)
                );
                List<String> ranges = bodyRanges(function);
                Set<String> strings = new HashSet<>();
                Set<String> dataReferences = new HashSet<>();
                emitBlocks(writer, function, blockModel);

                int pcodeSequence = 0;
                InstructionIterator instructions =
                    currentProgram.getListing().getInstructions(function.getBody(), true);
                while (instructions.hasNext()) {
                    Instruction instruction = instructions.next();
                    String instructionAddress = instruction.getAddress().toString();
                    String block = blockStart(blockModel, instruction.getAddress());
                    Reference[] references = instruction.getReferencesFrom();
                    List<String> directTargets = new ArrayList<>();
                    for (Reference reference : references) {
                        Address target = reference.getToAddress();
                        Function targetFunction =
                            currentProgram.getFunctionManager().getFunctionAt(target);
                        if (reference.getReferenceType().isData()) {
                            dataReferences.add(target.toString());
                            Data data = currentProgram.getListing().getDataAt(target);
                            if (data != null && data.getValue() instanceof String) {
                                strings.add((String) data.getValue());
                            }
                        }
                        if (reference.getReferenceType().isCall()) {
                            directTargets.add(
                                targetFunction == null
                                    ? target.toString()
                                    : targetFunction.getEntryPoint().toString()
                            );
                        }
                        writer.write(
                            "{\"record_type\":\"reference\",\"function_address\":"
                            + json(functionAddress)
                            + ",\"site_address\":" + json(instructionAddress)
                            + ",\"reference_type\":"
                            + json(reference.getReferenceType().toString())
                            + ",\"target_address\":" + json(target.toString())
                            + ",\"target_function_address\":"
                            + json(
                                targetFunction == null
                                    ? null
                                    : targetFunction.getEntryPoint().toString()
                            )
                            + "}\n"
                        );
                        referenceCount++;
                    }

                    for (PcodeOp operation : instruction.getPcode()) {
                        writer.write(
                            "{\"record_type\":\"pcode\",\"function_address\":"
                            + json(functionAddress)
                            + ",\"pcode_seq\":" + pcodeSequence
                            + ",\"instruction_address\":" + json(instructionAddress)
                            + ",\"block_start\":" + json(block)
                            + ",\"opcode\":" + json(operation.getMnemonic())
                            + ",\"output\":" + varnode(operation.getOutput())
                            + ",\"inputs\":" + varnodes(operation.getInputs())
                            + "}\n"
                        );
                        pcodeSequence++;
                        pcodeCount++;
                    }

                    if (hasCallInd(instruction)) {
                        List<String> candidates =
                            new ArrayList<>(indirectCandidates(instruction));
                        Collections.sort(candidates);
                        String resolution = "unresolved";
                        String target = null;
                        if (candidates.size() == 1) {
                            resolution = "resolved_reference";
                            target = candidates.get(0);
                        }
                        else if (candidates.size() > 1) {
                            resolution = "ambiguous_reference";
                        }
                        writer.write(
                            "{\"record_type\":\"callsite\",\"caller_address\":"
                            + json(functionAddress)
                            + ",\"site_address\":" + json(instructionAddress)
                            + ",\"call_kind\":\"indirect\",\"target_address\":"
                            + json(target)
                            + ",\"candidate_target_addresses\":"
                            + stringArray(candidates)
                            + ",\"resolution_status_hint\":" + json(resolution)
                            + ",\"evidence\":" + json(instruction.toString()) + "}\n"
                        );
                        callsiteCount++;
                    }
                    else {
                        Collections.sort(directTargets);
                        for (String target : directTargets) {
                            writer.write(
                                "{\"record_type\":\"callsite\",\"caller_address\":"
                                + json(functionAddress)
                                + ",\"site_address\":" + json(instructionAddress)
                                + ",\"call_kind\":\"direct\",\"target_address\":"
                                + json(target)
                                + ",\"candidate_target_addresses\":[]"
                                + ",\"resolution_status_hint\":\"resolved\""
                                + ",\"evidence\":\"Ghidra call reference\"}\n"
                            );
                            callsiteCount++;
                        }
                        if (
                            instruction.getFlowType().isCall()
                            && directTargets.isEmpty()
                            && instruction.getFlows().length == 0
                        ) {
                            writer.write(
                                "{\"record_type\":\"callsite\",\"caller_address\":"
                                + json(functionAddress)
                                + ",\"site_address\":" + json(instructionAddress)
                                + ",\"call_kind\":\"indirect\",\"target_address\":null"
                                + ",\"candidate_target_addresses\":[]"
                                + ",\"resolution_status_hint\":\"unresolved\""
                                + ",\"evidence\":" + json(instruction.toString()) + "}\n"
                            );
                            callsiteCount++;
                        }
                    }
                }

                List<String> sortedStrings = new ArrayList<>(strings);
                List<String> sortedReferences = new ArrayList<>(dataReferences);
                Collections.sort(sortedStrings);
                Collections.sort(sortedReferences);
                writer.write(
                    "{\"record_type\":\"function\",\"address\":" + json(functionAddress)
                    + ",\"byte_sha256\":" + json(byteHash)
                    + ",\"normalized_instruction_sha256\":" + json(instructionHash)
                    + ",\"body_ranges\":" + stringArray(ranges)
                    + ",\"size_bytes\":" + function.getBody().getNumAddresses()
                    + ",\"block_count\":" + blockCount(function, blockModel)
                    + ",\"strings\":" + stringArray(sortedStrings)
                    + ",\"data_references\":" + stringArray(sortedReferences)
                    + "}\n"
                );
            }
            println("Exported functions: " + functionCount);
            println("Exported call sites: " + callsiteCount);
            println("Exported p-code operations: " + pcodeCount);
            println("Exported references: " + referenceCount);
        }
        println("Tier B static analysis export: " + outputFile.getAbsolutePath());
    }
}
