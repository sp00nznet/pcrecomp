#!/usr/bin/env python3
"""Give every module a program runs its own fixed VA, before disassembly.

DLLs are often all linked at the same base (MSVC's default is 0x10000000).
The Windows loader relocates every module after the first at run time; a static
recompilation cannot, because the lifted C has every absolute address baked in.
So each module that has to move is relocated here, once, on the file, and the
host maps each copy at exactly that base. The lift then works on the rebased
copies, and every sub_XXXXXXXX is unique across modules.

    python tools/pe/rebase.py SRC_DIR OUT_DIR a.exe b.dll=0x10400000 c.dll ...

A module given without a base keeps its linked one if it is free, and is
otherwise put at the next free 1 MB-aligned address above every module placed
so far. The layout is printed (and written with --json), so the host can hold
the same table. Overlaps are an error.

Extracted from gunman's and ut99's tools/rebase.py; Sambar Server was the
third user.
"""
import argparse
import json
import os
import sys

import pefile

ALIGN = 0x100000


def rebase(path, base):
    """(bytes, SizeOfImage, linked base) for the file relocated to `base`.

    Each HIGHLOW fixup is applied by hand rather than with pefile's
    relocate_image(), which also rewrites the import thunks it parsed (the
    names would then point nowhere in the file).
    """
    raw = open(path, 'rb').read()
    pe = pefile.PE(data=raw)
    data = bytearray(raw)
    linked = pe.OPTIONAL_HEADER.ImageBase
    delta = (base - linked) & 0xFFFFFFFF
    if delta:
        if not pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size:
            raise ValueError('%s has no relocations: it can only load at 0x%08X' % (path, linked))
        for block in getattr(pe, 'DIRECTORY_ENTRY_BASERELOC', ()):
            for e in block.entries:
                if e.type == 3:                      # IMAGE_REL_BASED_HIGHLOW
                    off = pe.get_offset_from_rva(e.rva)
                    v = int.from_bytes(data[off:off + 4], 'little')
                    data[off:off + 4] = ((v + delta) & 0xFFFFFFFF).to_bytes(4, 'little')
                elif e.type != 0:                    # ABSOLUTE is padding
                    raise ValueError('%s: relocation type %d' % (path, e.type))
        off = pe.OPTIONAL_HEADER.get_file_offset() + 28   # ImageBase
        data[off:off + 4] = base.to_bytes(4, 'little')
    return bytes(data), pe.OPTIONAL_HEADER.SizeOfImage, linked


def layout(specs, sizes):
    """{name: base} for [(name, base or None)], sizes {name: (SizeOfImage, linked)}."""
    placed = {}

    def free(b, n):
        return all(b + sizes[n][0] <= p or b >= p + sizes[m][0] for m, p in placed.items())

    for name, base in specs:                       # pinned first
        if base is not None:
            placed[name] = base
    for name, base in specs:
        if base is None:
            b = sizes[name][1]
            while not free(b, name):                # past the module in the way
                b = max(p + sizes[m][0] for m, p in placed.items() if p <= b + sizes[name][0] - 1
                        and b < p + sizes[m][0])
                b = (b + ALIGN - 1) & ~(ALIGN - 1)
            placed[name] = b
    spans = sorted((b, b + sizes[n][0], n) for n, b in placed.items())
    for (_, a1, n), (b0, _, m) in zip(spans, spans[1:]):
        if a1 > b0:
            raise ValueError('%s overlaps %s' % (n, m))
    return placed


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('src')
    ap.add_argument('out')
    ap.add_argument('modules', nargs='+', help='file[=base]')
    ap.add_argument('--json', help='write {file: base} here')
    a = ap.parse_args()
    specs = [(m.split('=')[0], int(m.split('=')[1], 0) if '=' in m else None) for m in a.modules]
    files, sizes = {}, {}
    for n, _ in specs:
        pe = pefile.PE(os.path.join(a.src, n), fast_load=True)
        sizes[n] = (pe.OPTIONAL_HEADER.SizeOfImage, pe.OPTIONAL_HEADER.ImageBase)
        pe.close()
    bases = layout(specs, sizes)
    os.makedirs(a.out, exist_ok=True)
    for n, b in bases.items():
        data, size, linked = rebase(os.path.join(a.src, n), b)
        with open(os.path.join(a.out, n), 'wb') as f:
            f.write(data)
        print('%-20s 0x%08X-0x%08X%s' % (n, b, b + size, '' if b == linked else '  (linked 0x%08X)' % linked))
    if a.json:
        json.dump({n: '0x%08X' % b for n, b in bases.items()}, open(a.json, 'w'), indent=1)


def _selftest():
    s = {'a.exe': (0x10000, 0x400000), 'b.dll': (0x314000, 0x10000000),
         'c.dll': (0x102000, 0x10000000), 'd.dll': (0x39000, 0x10000000)}
    p = layout([('a.exe', None), ('b.dll', None), ('c.dll', None), ('d.dll', 0x20000000)], s)
    assert p == {'a.exe': 0x400000, 'b.dll': 0x10000000, 'c.dll': 0x10400000, 'd.dll': 0x20000000}, p
    try:
        layout([('b.dll', 0x10000000), ('c.dll', 0x10100000)], s)
        raise AssertionError('overlap not caught')
    except ValueError:
        pass
    print('rebase selftest: ok')


if __name__ == '__main__':
    if sys.argv[1:] == ['--selftest']:
        _selftest()
    else:
        main()
