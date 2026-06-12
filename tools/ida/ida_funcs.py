"""
ida_funcs.py - Export a function catalog from IDA for recompilation planning.

Where ida_export.py gives instruction-head / code-range truth for the lifters,
this gives the *function-level* picture you need to plan and triage a lift:
every function's name, bounds, size, and IDA's classification flags (library
code recognised by FLIRT, thunks, no-return, etc.). FLIRT-identified library
functions are the CRT/runtime routines you usually want to *shim* rather than
lift, so separating them out up front saves a lot of wasted effort.

Output JSON:
  {
    "binary": "GAME.EXE",
    "image_base": 0x400000,
    "count": 1932,
    "stats": { "library": 412, "thunks": 88, "user_named": 0, "noret": 7 },
    "functions": [
      {"ea": 0x401000, "end": 0x401040, "size": 64, "name": "sub_401000",
       "library": false, "thunk": false, "noret": false, "named": false},
      ...
    ]
  }

Run inside IDA's Python (idalib/idapro), Python 3.11:

    py -3.11 tools/ida/ida_funcs.py <binary> <out.json> [--min-size N]

Part of the pcrecomp toolbox.
"""
import sys
import json
import idapro
import ida_funcs
import ida_name
import idautils
import ida_nalt


def main(argv):
    if len(argv) < 2:
        print("usage: ida_funcs.py <binary> <out.json> [--min-size N]", file=sys.stderr)
        return 2
    binary, out = argv[0], argv[1]
    min_size = 0
    if "--min-size" in argv:
        min_size = int(argv[argv.index("--min-size") + 1])

    if idapro.open_database(binary, True) != 0:
        print(f"failed to open {binary}", file=sys.stderr)
        return 1
    import ida_auto
    ida_auto.auto_wait()

    image_base = ida_nalt.get_imagebase()
    funcs = []
    stats = {"library": 0, "thunks": 0, "user_named": 0, "noret": 0}

    for ea in idautils.Functions():
        f = ida_funcs.get_func(ea)
        if not f:
            continue
        size = f.end_ea - f.start_ea
        if size < min_size:
            continue
        flags = f.flags
        is_lib = bool(flags & ida_funcs.FUNC_LIB)
        is_thunk = bool(flags & ida_funcs.FUNC_THUNK)
        is_noret = bool(flags & ida_funcs.FUNC_NORET)
        name = ida_name.get_name(ea) or f"sub_{ea:X}"
        # "named" = a real name, not IDA's auto sub_/loc_ placeholder
        named = not (name.startswith("sub_") or name.startswith("loc_")
                     or name.startswith("nullsub_") or name.startswith("unknown_"))
        if is_lib:
            stats["library"] += 1
        if is_thunk:
            stats["thunks"] += 1
        if is_noret:
            stats["noret"] += 1
        if named and not is_lib:
            stats["user_named"] += 1
        funcs.append({
            "ea": f.start_ea, "end": f.end_ea, "size": size, "name": name,
            "library": is_lib, "thunk": is_thunk, "noret": is_noret, "named": named,
        })

    funcs.sort(key=lambda x: x["ea"])
    result = {
        "binary": binary.replace("\\", "/").split("/")[-1],
        "image_base": image_base,
        "count": len(funcs),
        "stats": stats,
        "functions": funcs,
    }
    with open(out, "w") as fh:
        json.dump(result, fh, indent=1)
    print(f"Wrote {out}: {len(funcs)} functions "
          f"(library={stats['library']}, thunks={stats['thunks']}, "
          f"user_named={stats['user_named']}, noret={stats['noret']})")
    idapro.close_database(False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
