// Find all references TO one or more addresses, reporting the containing
// function for each reference site. Generic replacement for project-specific
// "who writes/calls this address" scripts.
//
// Usage (headless):
//   analyzeHeadless <proj> <name> -process <bin> \
//     -postScript FindRefs.java 0x530D40 0x52B3A0
//   ... add  --writes  to list only write references (find who clobbers a var)
//   ... add  --calls   to list only call references
//
// Addresses may be given as 0x-prefixed or bare hex.
// @category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import java.util.*;

public class FindRefs extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        boolean writesOnly = false;
        boolean callsOnly = false;
        List<Long> targets = new ArrayList<>();
        for (String a : args) {
            if (a.equalsIgnoreCase("--writes")) { writesOnly = true; continue; }
            if (a.equalsIgnoreCase("--calls")) { callsOnly = true; continue; }
            targets.add(parseAddr(a));
        }
        if (targets.isEmpty()) {
            println("FindRefs: no target addresses given. " +
                    "Usage: FindRefs.java <addr...> [--writes|--calls]");
            return;
        }
        for (long t : targets) {
            dump(t, writesOnly, callsOnly);
        }
    }

    private void dump(long t, boolean writesOnly, boolean callsOnly) {
        ReferenceManager rm = currentProgram.getReferenceManager();
        FunctionManager fm = currentProgram.getFunctionManager();
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        Address target = sp.getAddress(t);

        Symbol sym = getSymbolAt(target);
        String label = sym != null ? sym.getName() : "<unnamed>";
        println("===== refs to 0x" + Long.toHexString(t) + " (" + label + ") =====");

        ReferenceIterator it = rm.getReferencesTo(target);
        // Deduplicate by (function, refType) so a tight loop doesn't spam output.
        Set<String> seen = new LinkedHashSet<>();
        int total = 0;
        while (it.hasNext()) {
            Reference r = it.next();
            RefType rt = r.getReferenceType();
            if (writesOnly && !rt.isWrite()) continue;
            if (callsOnly && !rt.isCall()) continue;
            Function fn = fm.getFunctionContaining(r.getFromAddress());
            String fname = fn != null ? fn.getName() : "<none>";
            String line = "  " + rt + " in " + fname + " @0x" + r.getFromAddress();
            if (seen.add(line)) {
                println(line);
                total++;
            }
        }
        println("  (" + total + " unique reference site(s))");
    }

    private long parseAddr(String s) {
        s = s.trim();
        if (s.startsWith("0x") || s.startsWith("0X")) s = s.substring(2);
        return Long.parseLong(s, 16);
    }
}
