// Reapply a frozen Tier B package's exact function layout before analysis.
//
// Run as a pre-script:
//   -preScript ApplyTierBFunctionLayout.java <functions.jsonl>
//
// This preserves the evaluator-reviewed corpus/package identity when a fresh
// Ghidra import would otherwise choose different overlapping function starts.
//
// @category IRSS

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ApplyTierBFunctionLayout extends GhidraScript {

    private static final Pattern ADDRESS =
        Pattern.compile("\"address\":\"([0-9a-fA-F]+)\"");
    private static final Pattern RANGES =
        Pattern.compile("\"body_ranges\":\\[(.*?)\\]");
    private static final Pattern RANGE =
        Pattern.compile("\"([0-9a-fA-F]+)-([0-9a-fA-F]+)\"");

    private static class Layout {
        String address;
        List<String[]> ranges = new ArrayList<>();
    }

    private Layout parse(String line, int lineNumber) {
        Matcher addressMatch = ADDRESS.matcher(line);
        Matcher rangesMatch = RANGES.matcher(line);
        if (!addressMatch.find() || !rangesMatch.find()) {
            throw new IllegalArgumentException(
                "Invalid functions.jsonl row at line " + lineNumber
            );
        }
        Layout layout = new Layout();
        layout.address = addressMatch.group(1);
        Matcher rangeMatch = RANGE.matcher(rangesMatch.group(1));
        while (rangeMatch.find()) {
            layout.ranges.add(
                new String[] {rangeMatch.group(1), rangeMatch.group(2)}
            );
        }
        if (layout.ranges.isEmpty()) {
            throw new IllegalArgumentException(
                "Function has no body ranges at line " + lineNumber
            );
        }
        return layout;
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            println("Usage: ApplyTierBFunctionLayout.java <functions.jsonl>");
            return;
        }
        File input = new File(args[0]).getAbsoluteFile();
        if (!input.isFile()) {
            throw new IllegalArgumentException("Missing functions index: " + input);
        }
        List<Layout> layouts = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(input))) {
            String line;
            int lineNumber = 0;
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                if (!line.trim().isEmpty()) {
                    layouts.add(parse(line, lineNumber));
                }
            }
        }
        if (layouts.isEmpty()) {
            throw new IllegalArgumentException("Functions index is empty");
        }

        FunctionManager manager = currentProgram.getFunctionManager();
        List<Address> existingEntries = new ArrayList<>();
        FunctionIterator existing = manager.getFunctions(true);
        while (existing.hasNext()) {
            Function function = existing.next();
            if (!function.isExternal()) {
                existingEntries.add(function.getEntryPoint());
            }
        }
        for (Address entry : existingEntries) {
            manager.removeFunction(entry);
        }

        int created = 0;
        for (Layout layout : layouts) {
            Address entry = toAddr(layout.address);
            AddressSet body = new AddressSet();
            for (String[] range : layout.ranges) {
                body.addRange(toAddr(range[0]), toAddr(range[1]));
            }
            Function function = manager.createFunction(
                "FUN_" + entry.toString(),
                entry,
                body,
                SourceType.USER_DEFINED
            );
            if (function == null) {
                throw new IllegalStateException(
                    "Could not create frozen function at " + entry
                );
            }
            created++;
        }
        println("Applied frozen Tier B function layout: " + created);
    }
}
