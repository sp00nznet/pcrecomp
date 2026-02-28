// Ghidra script to export all function information
// @category Analysis
// @keybinding
// @menupath
// @toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;

import java.io.*;
import java.util.*;

public class ExportFunctions extends GhidraScript {

    @Override
    public void run() throws Exception {
        String outputDir = "D:/recomp/pc/gunman/disasm";
        String progName = currentProgram.getName().replace(".dll", "").replace(".exe", "");
        String outputPath = outputDir + "/" + progName + "_functions.txt";

        new File(outputDir).mkdirs();

        FunctionManager funcManager = currentProgram.getFunctionManager();
        SymbolTable symbolTable = currentProgram.getSymbolTable();
        ReferenceManager refManager = currentProgram.getReferenceManager();

        int totalFunctions = 0;
        int namedCount = 0;
        int autoCount = 0;
        int thunkCount = 0;
        int externalCount = 0;

        List<String> lines = new ArrayList<>();

        FunctionIterator funcIter = funcManager.getFunctions(true);
        while (funcIter.hasNext()) {
            Function func = funcIter.next();
            Address entry = func.getEntryPoint();
            long size = func.getBody().getNumAddresses();
            String name = func.getName();
            boolean isThunk = func.isThunk();
            boolean isExternal = func.isExternal();
            String callingConv = func.getCallingConventionName();
            if (callingConv == null) callingConv = "unknown";

            // Count references
            int refCount = 0;
            ReferenceIterator refs = refManager.getReferencesTo(entry);
            while (refs.hasNext()) {
                refs.next();
                refCount++;
            }

            // Build flags
            StringBuilder flags = new StringBuilder();
            if (isThunk) { flags.append("THUNK,"); thunkCount++; }
            if (isExternal) { flags.append("EXT,"); externalCount++; }
            String flagStr = flags.length() > 0 ? flags.substring(0, flags.length()-1) : "-";

            if (name.startsWith("FUN_")) {
                autoCount++;
            } else {
                namedCount++;
            }

            lines.add(String.format("%s | %6d | %4d | %-12s | %-10s | %s",
                entry.toString(), size, refCount, callingConv, flagStr, name));

            totalFunctions++;
        }

        // Write output
        PrintWriter out = new PrintWriter(new FileWriter(outputPath));
        out.println("# Ghidra Function Export: " + currentProgram.getName());
        out.println("# Total functions: " + totalFunctions);
        out.println("# Named (non-FUN_): " + namedCount);
        out.println("# Auto-named (FUN_): " + autoCount);
        out.println("# Thunks: " + thunkCount);
        out.println("# External: " + externalCount);
        out.println("# Format: address | size | refs | calling_conv | flags | name");
        out.println("#" + "=".repeat(100));

        for (String line : lines) {
            out.println(line);
        }

        out.close();
        println("Exported " + totalFunctions + " functions to " + outputPath);
    }
}
