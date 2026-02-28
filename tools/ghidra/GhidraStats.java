// Ghidra headless script to extract analysis stats
// @category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class GhidraStats extends GhidraScript {
    @Override
    public void run() throws Exception {
        FunctionManager fm = currentProgram.getFunctionManager();
        SymbolTable st = currentProgram.getSymbolTable();

        int funcCount = fm.getFunctionCount();
        println("=== Black & White Analysis Stats ===");
        println("Total functions found: " + funcCount);

        int named = 0;
        int unnamed = 0;
        int thunks = 0;
        int external = 0;
        FunctionIterator iter = fm.getFunctions(true);
        while (iter.hasNext()) {
            Function f = iter.next();
            if (f.isThunk()) thunks++;
            else if (f.isExternal()) external++;
            else if (f.getName().startsWith("FUN_")) unnamed++;
            else named++;
        }
        println("Named functions: " + named);
        println("Unnamed functions (FUN_): " + unnamed);
        println("Thunk functions: " + thunks);
        println("External functions: " + external);

        // Count C++ classes from RTTI
        java.util.HashSet<String> classNames = new java.util.HashSet<>();
        SymbolIterator si = st.getSymbolIterator();
        while (si.hasNext()) {
            Symbol s = si.next();
            Namespace ns = s.getParentNamespace();
            if (ns != null && !ns.isGlobal() && ns.getSymbol().getSymbolType() == SymbolType.CLASS) {
                classNames.add(ns.getName());
            }
        }
        println("C++ classes identified: " + classNames.size());

        java.util.ArrayList<String> sorted = new java.util.ArrayList<>(classNames);
        java.util.Collections.sort(sorted);
        int count = 0;
        for (String name : sorted) {
            if (count >= 50) {
                println("  ... and " + (classNames.size() - 50) + " more");
                break;
            }
            println("  " + name);
            count++;
        }

        println("=== End Stats ===");
    }
}
