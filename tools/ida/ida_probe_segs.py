"""
ida_probe_segs.py - Dump IDA's segment layout.

Diagnostic: shows how IDA parsed a binary into segments so you can map IDA
segment indices to the format's own numbering (e.g. NE segment number ==
IDA index + 1) before running ida_export.py. Prints name, class, address
range, selector, bitness, size, and function count per segment.

Run inside IDA's Python (idalib/idapro):
    py -3 tools/ida/ida_probe_segs.py <binary> [--code-only]
"""
import sys
import idapro
import ida_auto, ida_segment, idautils


def main():
    argv = sys.argv[1:]
    code_only = "--code-only" in argv
    argv = [a for a in argv if a != "--code-only"]
    if not argv:
        raise SystemExit("usage: ida_probe_segs.py <binary> [--code-only]")
    binary = argv[0]

    if idapro.open_database(binary, run_auto_analysis=True):
        raise SystemExit("open failed")
    ida_auto.auto_wait()

    try:
        print("=== SEGMENTS ===")
        n = ida_segment.get_segm_qty()
        for i in range(n):
            s = ida_segment.getnseg(i)
            name = ida_segment.get_segm_name(s) or "?"
            cls = ida_segment.get_segm_class(s) or "?"
            size = s.end_ea - s.start_ea
            fcount = sum(1 for _ in idautils.Functions(s.start_ea, s.end_ea))
            if code_only and cls != "CODE":
                continue
            print(f"idx={i:3d} NE={i+1:3d} name={name:12s} class={cls:6s} "
                  f"start={s.start_ea:08X} end={s.end_ea:08X} sel={s.sel:5d} "
                  f"bitness={s.bitness} size={size:6d} funcs={fcount}")
        print(f"total segments: {n}")
        print(f"total functions: {len(list(idautils.Functions()))}")
    finally:
        idapro.close_database(save=False)


if __name__ == "__main__":
    main()
