"""
ida_xrefs.py - Export a call graph + import-usage + FPU-density map from IDA.

This is the data you need to *classify* a recovered binary: who calls whom, which
functions touch which OS APIs, and where the floating-point math lives. From it you
can sort functions into subsystems (render / audio / input / I/O / math) and find
the hot path by reachability and fan-in.

For every function it records:
  - callees:     function EAs this function calls directly (deduped)
  - imports:     names of imported APIs this function reaches (direct or via thunk)
  - fpu_ops:     count of x87 FPU instructions (fld/fmul/fadd/...) — 3D math marker
  - n_insns:     instruction count

Plus global rollups: fan-in (callers) per function, and an import -> [callers] index.

Run inside IDA's Python (idalib/idapro), Python 3.11:

    py -3.11 tools/ida/ida_xrefs.py <binary> <out.json>

Part of the pcrecomp toolbox.
"""
import sys
import json
import idapro
import ida_auto
import ida_funcs
import ida_name
import ida_nalt
import ida_ua
import idautils
import idc


def _collect_imports():
    """Return {ea: api_name} for every imported function slot/thunk IDA knows."""
    imp = {}
    n = ida_nalt.get_import_module_qty()
    for i in range(n):
        def cb(ea, name, ordinal, _name=None):
            if name:
                imp[ea] = name
            return True
        ida_nalt.enum_import_names(i, cb)
    return imp


def _fpu_count_and_callees(func, func_starts, imp_names):
    """Walk a function's instructions: count FPU ops, collect call/jump callees."""
    callees = set()
    imports = set()
    fpu = 0
    n = 0
    for head in idautils.FuncItems(func.start_ea):
        n += 1
        mnem = idc.print_insn_mnem(head).lower()
        if mnem and mnem[0] == "f" and mnem not in ("fs", "fxch_disabled"):
            # x87 ops: fld fst fmul fadd fsub fdiv fcom fild fist fldz fld1 fsqrt ...
            if mnem.startswith(("fld", "fst", "fmul", "fadd", "fsub", "fdiv",
                                "fil", "fis", "fcom", "fco", "fch", "fsq", "fab",
                                "fpr", "fsc", "fpt", "fra", "frn", "fnc", "fwa",
                                "fxa", "fxt", "fyl", "f2x", "fpa", "fde", "fin",
                                "fic", "fsi", "fco", "ftst", "fucom", "fnstsw",
                                "fnstcw", "fldcw", "fldenv", "fnsave", "frstor")):
                fpu += 1
        # call/jump edges
        for ref in idautils.CodeRefsFrom(head, False):  # False = only far/call/jmp, not flow
            if ref in func_starts:
                callees.add(ref)
            if ref in imp_names:
                imports.add(imp_names[ref])
        # also catch call [import] via operand value
        for ref in idautils.DataRefsFrom(head):
            if ref in imp_names:
                imports.add(imp_names[ref])
    return fpu, n, callees, imports


def main(argv):
    if len(argv) < 2:
        print("usage: ida_xrefs.py <binary> <out.json>", file=sys.stderr)
        return 2
    binary, out = argv[0], argv[1]

    if idapro.open_database(binary, True) != 0:
        print(f"failed to open {binary}", file=sys.stderr)
        return 1
    ida_auto.auto_wait()

    imp_names = _collect_imports()

    funcs = {}
    func_starts = set(idautils.Functions())
    # thunk targets: if a function is a thunk to an import, treat callers as using it
    thunk_to_import = {}
    for ea in func_starts:
        f = ida_funcs.get_func(ea)
        if f and (f.flags & ida_funcs.FUNC_THUNK):
            tgt, _ = ida_funcs.calc_thunk_func_target(f)
            if tgt in imp_names:
                thunk_to_import[ea] = imp_names[tgt]
            else:
                nm = ida_name.get_name(ea)
                # thunk named after an import (jmp ds:__imp_X)
                if nm:
                    thunk_to_import[ea] = nm

    nodes = {}
    for ea in func_starts:
        f = ida_funcs.get_func(ea)
        if not f:
            continue
        fpu, n, callees, imports = _fpu_count_and_callees(f, func_starts, imp_names)
        # resolve callees that are import-thunks into import names
        for c in list(callees):
            if c in thunk_to_import:
                imports.add(thunk_to_import[c])
        nodes[ea] = {
            "ea": ea,
            "name": ida_name.get_name(ea) or f"sub_{ea:X}",
            "size": f.end_ea - f.start_ea,
            "n_insns": n,
            "fpu_ops": fpu,
            "callees": sorted(callees),
            "imports": sorted(imports),
        }

    # fan-in
    fanin = {ea: 0 for ea in nodes}
    callers = {ea: [] for ea in nodes}
    for ea, nd in nodes.items():
        for c in nd["callees"]:
            if c in fanin:
                fanin[c] += 1
                callers[c].append(ea)
    for ea in nodes:
        nodes[ea]["fan_in"] = fanin[ea]

    # import -> callers index
    import_index = {}
    for ea, nd in nodes.items():
        for api in nd["imports"]:
            import_index.setdefault(api, []).append(ea)

    result = {
        "binary": binary.replace("\\", "/").split("/")[-1],
        "entry": idc.get_inf_attr(idc.INF_START_EA),
        "n_functions": len(nodes),
        "n_imports": len(import_index),
        "import_index": {k: sorted(v) for k, v in sorted(import_index.items())},
        "functions": [nodes[ea] for ea in sorted(nodes)],
    }
    with open(out, "w") as fh:
        json.dump(result, fh, indent=1)
    print(f"Wrote {out}: {len(nodes)} functions, {len(import_index)} imports referenced, "
          f"entry=0x{result['entry']:X}")
    idapro.close_database(False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
