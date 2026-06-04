// Decompile a specific list of functions by address and print their C. Use
// when you want pseudocode for a handful of functions of interest rather than
// the whole program (see DecompileAll.java for the batch case).
//
// Usage (headless):
//   analyzeHeadless <proj> <name> -process <bin> \
//     -postScript DecompAddrs.java 0x404290 0x4EBEE0 0x4EBA20
//   ... or read addresses (one per line, '#' comments allowed) from a file:
//   -postScript DecompAddrs.java @addrs.txt
//
// Addresses may be 0x-prefixed or bare hex; an address inside a function
// decompiles that whole function.
// @category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import java.io.*;
import java.util.*;

public class DecompAddrs extends GhidraScript {

    @Override
    public void run() throws Exception {
        List<Long> addrs = collectAddrs(getScriptArgs());
        if (addrs.isEmpty()) {
            println("DecompAddrs: no addresses given. " +
                    "Usage: DecompAddrs.java <addr...> | @file");
            return;
        }

        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        FunctionManager fm = currentProgram.getFunctionManager();
        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();

        for (long a : addrs) {
            Function fn = fm.getFunctionContaining(sp.getAddress(a));
            if (fn == null) {
                println("##### 0x" + Long.toHexString(a) + ": NO FUNCTION #####");
                continue;
            }
            println("##### FUNC 0x" + Long.toHexString(a) + " " + fn.getName() + " #####");
            DecompileResults res = di.decompileFunction(fn, 90, monitor);
            println(res != null && res.decompileCompleted()
                    ? res.getDecompiledFunction().getC() : "FAILED");
            println("##### end #####");
        }
    }

    private List<Long> collectAddrs(String[] args) throws IOException {
        List<Long> out = new ArrayList<>();
        for (String a : args) {
            if (a.startsWith("@")) {
                try (BufferedReader br = new BufferedReader(new FileReader(a.substring(1)))) {
                    String line;
                    while ((line = br.readLine()) != null) {
                        int hash = line.indexOf('#');
                        if (hash >= 0) line = line.substring(0, hash);
                        line = line.trim();
                        if (!line.isEmpty()) out.add(parseAddr(line));
                    }
                }
            } else {
                out.add(parseAddr(a));
            }
        }
        return out;
    }

    private long parseAddr(String s) {
        s = s.trim();
        if (s.startsWith("0x") || s.startsWith("0X")) s = s.substring(2);
        return Long.parseLong(s, 16);
    }
}
