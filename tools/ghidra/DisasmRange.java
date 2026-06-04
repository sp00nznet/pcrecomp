// Print the disassembly listing for an arbitrary address range, and report the
// function (if any) containing the start address with its bounds. Useful for
// inspecting jump tables, switch dispatch, or a suspect byte range without
// decompiling a whole function.
//
// Usage (headless):
//   analyzeHeadless <proj> <name> -process <bin> \
//     -postScript DisasmRange.java 0x59ee70 0x59eeb0
//
// Addresses may be 0x-prefixed or bare hex. End is exclusive.
// @category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

public class DisasmRange extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            println("DisasmRange: need start and end. " +
                    "Usage: DisasmRange.java <start> <end>");
            return;
        }
        long startOff = parseAddr(args[0]);
        long endOff = parseAddr(args[1]);

        AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
        Listing l = currentProgram.getListing();
        Address start = sp.getAddress(startOff);

        println("===== disasm 0x" + Long.toHexString(startOff) +
                " - 0x" + Long.toHexString(endOff) + " =====");
        InstructionIterator it = l.getInstructions(start, true);
        while (it.hasNext()) {
            Instruction in = it.next();
            if (in.getAddress().getOffset() >= endOff) break;
            println("0x" + in.getAddress() + "  " + in.toString());
        }

        Function fn = currentProgram.getFunctionManager()
                .getFunctionContaining(start);
        if (fn != null) {
            println("containing function: " + fn.getName() +
                    " 0x" + Long.toHexString(fn.getEntryPoint().getOffset()) +
                    "-0x" + Long.toHexString(fn.getBody().getMaxAddress().getOffset()));
        } else {
            println("containing function: <none>");
        }
    }

    private long parseAddr(String s) {
        s = s.trim();
        if (s.startsWith("0x") || s.startsWith("0X")) s = s.substring(2);
        return Long.parseLong(s, 16);
    }
}
