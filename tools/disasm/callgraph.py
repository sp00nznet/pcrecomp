#!/usr/bin/env python3
"""
callgraph.py - Direct call-graph scanner for 32-bit PE binaries.

A dependency-free way to answer "who calls this?" and "what does this call?"
without loading the binary into Ghidra/IDA. It scans the executable sections
for direct near CALL/JMP (E8/E9 rel32), computes each target VA, and keeps the
edges whose target lands inside an executable section.

On its own it gives you:
  - direct callers of an address          (--callers 0xADDR)
  - the most-referenced targets ("hot")   (--hot [N])

Give it a function-bounds CSV (the output of ghidra/DumpBounds.java -- one
"start,end" hex row per function) and it becomes a function-level call graph:
  - callees of a function                 (--bounds f.csv --callees 0xADDR)
  - leaf functions (call nothing local)   (--bounds f.csv --leaves)
  - summary: functions, edges, leaves     (--bounds f.csv)

Leaf/pure-function detection is handy for differential testing a
recompilation: a leaf that calls nothing and touches no imports is bounded
straight-line compute you can fuzz against the original in isolation.

Note: a raw opcode scan finds real E8/E9 bytes that may also occur inside data
or as operand bytes. Restricting targets to executable sections (and, with
--bounds, to known function starts) removes almost all of that noise, but treat
the raw counts as a strong signal rather than ground truth.

Usage:
    python callgraph.py <file.exe> [--callers 0xADDR] [--hot [N]]
                        [--bounds bounds.csv] [--callees 0xADDR] [--leaves]
"""
import struct
import sys


def parse_pe(data):
    """Return (image_base, entry_va, [exec sections as (va, size, file_off)])."""
    pe = struct.unpack_from('<I', data, 0x3C)[0]
    if data[pe:pe + 4] != b'PE\x00\x00':
        raise ValueError("No PE signature")
    num_sections = struct.unpack_from('<H', data, pe + 6)[0]
    opt_size = struct.unpack_from('<H', data, pe + 20)[0]
    opt = pe + 24
    opt_magic = struct.unpack_from('<H', data, opt)[0]
    base = struct.unpack_from('<Q' if opt_magic == 0x20b else '<I', data,
                              opt + (24 if opt_magic == 0x20b else 28))[0]
    entry = struct.unpack_from('<I', data, opt + 16)[0]

    sec_start = opt + opt_size
    exec_secs = []
    for i in range(num_sections):
        o = sec_start + i * 40
        vsize, va, raw_size, raw_off = struct.unpack_from('<IIII', data, o + 8)
        chars = struct.unpack_from('<I', data, o + 36)[0]
        if chars & (0x20000000 | 0x20):  # MEM_EXECUTE | CNT_CODE
            exec_secs.append((base + va, max(vsize, raw_size), raw_off, raw_size))
    return base, base + entry, exec_secs


def in_exec(va, exec_secs):
    return any(s_va <= va < s_va + s_size for s_va, s_size, _, _ in exec_secs)


def scan_edges(data, exec_secs):
    """Scan executable sections for E8/E9 rel32; return list of (site, target, op)."""
    edges = []
    for s_va, s_size, raw_off, raw_size in exec_secs:
        seg = data[raw_off:raw_off + raw_size]
        for j in range(len(seg) - 4):
            op = seg[j]
            if op in (0xE8, 0xE9):
                rel = struct.unpack_from('<i', seg, j + 1)[0]
                site = s_va + j
                target = (site + 5 + rel) & 0xFFFFFFFF
                if in_exec(target, exec_secs):
                    edges.append((site, target, 'call' if op == 0xE8 else 'jmp'))
    return edges


def load_bounds(path):
    """Load 'start,end' hex rows (ghidra/DumpBounds.java). Return sorted [(start,end)]."""
    funcs = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or ',' not in line:
                continue
            a, b = line.split(',')[:2]
            funcs.append((int(a, 16), int(b, 16)))
    funcs.sort()
    return funcs


def containing_func(va, funcs):
    """Binary-search the function whose [start,end) contains va."""
    lo, hi = 0, len(funcs)
    while lo < hi:
        mid = (lo + hi) // 2
        if funcs[mid][0] <= va:
            lo = mid + 1
        else:
            hi = mid
    i = lo - 1
    if 0 <= i < len(funcs) and funcs[i][0] <= va < funcs[i][1]:
        return funcs[i][0]
    return None


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    path = sys.argv[1]
    argv = sys.argv[2:]

    def opt_val(flag):
        return argv[argv.index(flag) + 1] if flag in argv and argv.index(flag) + 1 < len(argv) else None

    with open(path, 'rb') as f:
        data = f.read()
    base, entry, exec_secs = parse_pe(data)
    edges = scan_edges(data, exec_secs)
    print(f"image base 0x{base:X}, entry 0x{entry:X}, "
          f"{len(exec_secs)} exec section(s), {len(edges)} direct call/jmp edges")

    if '--callers' in argv:
        target = int(opt_val('--callers'), 0)
        callers = [(site, op) for site, t, op in edges if t == target]
        print(f"\ndirect callers of 0x{target:X}: {len(callers)}")
        for site, op in sorted(callers):
            print(f"  {op} from 0x{site:X}")
        return

    if '--hot' in argv:
        idx = argv.index('--hot')
        n = int(argv[idx + 1]) if idx + 1 < len(argv) and argv[idx + 1].isdigit() else 25
        counts = {}
        for _site, t, _op in edges:
            counts[t] = counts.get(t, 0) + 1
        print(f"\ntop {n} most-referenced targets:")
        for t, c in sorted(counts.items(), key=lambda kv: -kv[1])[:n]:
            print(f"  0x{t:X}  {c} refs")
        return

    bounds_path = opt_val('--bounds')
    if not bounds_path:
        print("\n(supply --bounds <csv> for function-level analysis, "
              "or use --callers/--hot)")
        return

    funcs = load_bounds(bounds_path)
    starts = {s for s, _e in funcs}
    # Function-level edges: caller-func -> callee-func (callee must be a known start).
    fedges = set()
    callees_of = {}
    callers_of = {}
    for site, t, _op in edges:
        cf = containing_func(site, funcs)
        if cf is None or t not in starts or t == cf:
            continue
        fedges.add((cf, t))
        callees_of.setdefault(cf, set()).add(t)
        callers_of.setdefault(t, set()).add(cf)

    if '--callees' in argv:
        a = int(opt_val('--callees'), 0)
        cf = containing_func(a, funcs) or a
        cs = sorted(callees_of.get(cf, ()))
        print(f"\nfunction 0x{cf:X} calls {len(cs)} local function(s):")
        for c in cs:
            print(f"  0x{c:X}")
        return

    if '--leaves' in argv:
        leaves = sorted(s for s, _e in funcs if not callees_of.get(s))
        print(f"\nleaf functions (call no other local function): "
              f"{len(leaves)} of {len(funcs)}")
        for s in leaves:
            print(f"  0x{s:X}  ({len(callers_of.get(s, ()))} callers)")
        return

    leaves = [s for s, _e in funcs if not callees_of.get(s)]
    print(f"\nfunctions: {len(funcs)}")
    print(f"function-level edges: {len(fedges)}")
    print(f"leaf functions: {len(leaves)}")
    top = sorted(callers_of.items(), key=lambda kv: -len(kv[1]))[:10]
    print("most-called functions:")
    for t, callers in top:
        print(f"  0x{t:X}  {len(callers)} callers")


if __name__ == '__main__':
    main()
