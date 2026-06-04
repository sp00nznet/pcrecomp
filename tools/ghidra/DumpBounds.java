// Export every function's [start, end) bounds to a CSV (one "start,end" row
// per function, hex, end exclusive). A minimal companion to ExportFunctions.java
// for tools that only need address ranges (e.g. to drive a lifter's function
// table or to diff function boundaries between two analyses).
//
// Usage (headless):
//   analyzeHeadless <proj> <name> -process <bin> \
//     -postScript DumpBounds.java [out.csv]
//
// If out.csv is omitted, writes "<program>_bounds.csv" next to the analyzed
// binary.
// @category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import java.io.File;
import java.io.FileWriter;

public class DumpBounds extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outPath;
        if (args.length >= 1 && !args[0].isEmpty()) {
            outPath = args[0];
        } else {
            String exe = currentProgram.getExecutablePath();
            File dir = (exe != null) ? new File(exe).getParentFile() : new File(".");
            outPath = new File(dir, currentProgram.getName() + "_bounds.csv").getPath();
        }

        FunctionManager fm = currentProgram.getFunctionManager();
        FunctionIterator it = fm.getFunctions(true);
        StringBuilder sb = new StringBuilder();
        int n = 0;
        while (it.hasNext()) {
            Function f = it.next();
            long s = f.getEntryPoint().getOffset();
            long e = f.getBody().getMaxAddress().getOffset();
            sb.append(Long.toHexString(s)).append(",").append(Long.toHexString(e + 1)).append("\n");
            n++;
        }

        try (FileWriter w = new FileWriter(outPath)) {
            w.write(sb.toString());
        }
        println("wrote bounds for " + n + " functions -> " + outPath);
    }
}
