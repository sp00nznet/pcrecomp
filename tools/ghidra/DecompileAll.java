// Ghidra script to decompile all functions and export C pseudocode
// @category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

import java.io.*;

public class DecompileAll extends GhidraScript {

    @Override
    public void run() throws Exception {
        String outputDir = "D:/recomp/pc/gunman/disasm";
        String progName = currentProgram.getName().replace(".dll", "").replace(".exe", "");
        String outputPath = outputDir + "/" + progName + "_decompiled.c";

        new File(outputDir).mkdirs();

        DecompInterface decomp = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        decomp.setOptions(options);

        if (!decomp.openProgram(currentProgram)) {
            println("ERROR: Failed to open program in decompiler");
            return;
        }

        FunctionManager funcManager = currentProgram.getFunctionManager();
        int totalFunctions = 0;
        int decompiled = 0;
        int failed = 0;

        FunctionIterator countIter = funcManager.getFunctions(true);
        while (countIter.hasNext()) {
            countIter.next();
            totalFunctions++;
        }

        println("Decompiling " + totalFunctions + " functions...");

        PrintWriter out = new PrintWriter(new FileWriter(outputPath));
        out.println("/*");
        out.println(" * Ghidra Decompilation: " + currentProgram.getName());
        out.println(" * Total functions: " + totalFunctions);
        out.println(" */");
        out.println();

        FunctionIterator funcIter = funcManager.getFunctions(true);
        while (funcIter.hasNext()) {
            Function func = funcIter.next();
            if (func.isExternal()) continue;

            String name = func.getName();
            Address entry = func.getEntryPoint();
            long size = func.getBody().getNumAddresses();

            try {
                DecompileResults results = decomp.decompileFunction(func, 30, monitor);

                if (results != null) {
                    ClangTokenGroup markup = results.getCCodeMarkup();
                    if (markup != null) {
                        String code = markup.toString();
                        if (code != null && code.length() > 0) {
                            out.println("/* ========================================");
                            out.println(" * Function: " + name);
                            out.println(" * Address:  " + entry.toString());
                            out.println(" * Size:     " + size + " bytes");
                            out.println(" * ======================================== */");
                            out.println(code);
                            out.println();
                            decompiled++;
                        } else {
                            failed++;
                        }
                    } else {
                        failed++;
                    }
                } else {
                    failed++;
                }
            } catch (Exception e) {
                failed++;
            }

            if ((decompiled + failed) % 200 == 0) {
                println("Progress: " + (decompiled + failed) + "/" + totalFunctions +
                        " (" + decompiled + " ok, " + failed + " fail)");
            }
        }

        out.println("/* === DECOMPILATION SUMMARY ===");
        out.println(" * Decompiled: " + decompiled);
        out.println(" * Failed: " + failed);
        out.println(" * Total: " + totalFunctions);
        out.println(" */");
        out.close();

        decomp.dispose();
        println("Done! Decompiled: " + decompiled + "/" + totalFunctions + " -> " + outputPath);
    }
}
