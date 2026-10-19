"""Read a MAPSYM .SYM file: the symbol table Microsoft's MAPSYM built from a
linker map, which some Win16 programs shipped beside the EXE (for the
debugger, SYMDEB / CodeView / WDEB386).

  py -3 tools/ne/mapsym.py GAME.SYM                 # seg:off name, one per line
  py -3 tools/ne/mapsym.py GAME.SYM --funcs out.txt # same, as a function list

Layout (all offsets little-endian; "pp" fields are paragraph pointers, x16):
  MAPDEF  ppNextMap u16, bFlags u8, res u8, pSegEntry u16, cConsts u16,
          pConstDef u16, cSegs u16, ppSegDef u16, cbMaxSym u8, name (len u8 + bytes)
  SEGDEF  ppNextSeg u16, cSymbols u16, pSymDef u16, res u16 x4, bFlags u8,
          res u8, ppLineDef u16, res u8 x2, name (len u8 + bytes)
  pSymDef is a table of cSymbols u16 offsets, from the SEGDEF, to SYMDEFs:
  value (u16, or u32 when SEGDEF.bFlags & 1), name (len u8 + bytes).
  SEGDEFs are listed in NE segment order, starting at segment 1.
"""
import struct
import sys


def _name(b, at):
    n = b[at]
    return b[at + 1:at + 1 + n].decode('latin-1')


def read(path):
    """-> (module, [(seg, offset, name)]) with seg 1-based; constants as seg 0."""
    b = open(path, 'rb').read()
    _next, _fl, _r, _entry, cconsts, pconst, csegs, ppseg, _max = struct.unpack_from('<HBBHHHHHB', b, 0)
    module = _name(b, 0x0F)
    out = []
    for i in range(cconsts):
        p = struct.unpack_from('<H', b, pconst + 2 * i)[0]
        out.append((0, struct.unpack_from('<H', b, p)[0], _name(b, p + 2)))
    seg = ppseg * 16
    for n in range(1, csegs + 1):
        nxt, csyms, psym = struct.unpack_from('<HHH', b, seg)
        wide = b[seg + 0x0E] & 1
        for i in range(csyms):
            p = seg + struct.unpack_from('<H', b, seg + psym + 2 * i)[0]
            val = struct.unpack_from('<I' if wide else '<H', b, p)[0]
            out.append((n, val, _name(b, p + (4 if wide else 2))))
        seg = nxt * 16
        if not nxt:
            break
    return module, out


def _selftest():
    # one segment with two symbols, one constant
    name = b'\x04TEST'
    hdr = struct.pack('<HBBHHHHHB', 0, 0, 0, 0, 1, 0x20, 1, 0x3, 32) + name
    hdr = hdr.ljust(0x20, b'\0')
    const = struct.pack('<H', 0x24) + b'\0\0' + struct.pack('<H', 7) + b'\x01K'
    body = (hdr + const).ljust(0x30, b'\0')
    segdef = struct.pack('<HHH', 0, 2, 0x20) + b'\0' * 8 + b'\0\0' + b'\0\0' + b'\0\0' + b'\x05_TEXT'
    segdef = segdef.ljust(0x20, b'\0') + struct.pack('<HH', 0x24, 0x2A)
    segdef += struct.pack('<H', 0x10) + b'\x03FOO' + struct.pack('<H', 0x2A) + b'\x03BAR'
    import tempfile, os
    fd, p = tempfile.mkstemp(); os.write(fd, body + segdef); os.close(fd)
    try:
        mod, syms = read(p)
    finally:
        os.remove(p)
    assert mod == 'TEST', mod
    assert syms == [(0, 7, 'K'), (1, 0x10, 'FOO'), (1, 0x2A, 'BAR')], syms
    print('mapsym selftest ok')


if __name__ == '__main__':
    if sys.argv[1:] == ['--selftest']:
        _selftest()
        sys.exit()
    mod, syms = read(sys.argv[1])
    lines = [f'{s}:{o:04X} {n}' for s, o, n in syms]
    if '--funcs' in sys.argv:
        open(sys.argv[sys.argv.index('--funcs') + 1], 'w').write('\n'.join(lines) + '\n')
    else:
        print(f'; {mod}: {len(syms)} symbols')
        print('\n'.join(lines))
