#!/usr/bin/env python3
"""
pdb2_ref.py - a function catalog from a Visual C++ 5/6 PDB (format 2.00).

Some games shipped their release PDB on the disc (MechCommander 2's
MC2REL.PDB). Those PDBs predate the MSF 7.00 container that llvm-pdbutil and
pdb_ref.py read: page numbers are 16-bit, and symbol records are the `_ST`
family (length-prefixed names). This reads that format directly, with no
external tool, and writes the same JSON as pdb_ref.py, so score_recovery and
disasm32 --seed-functions take it as is.

Written from the public descriptions of the format: LLVM's MSF/CodeView docs
and Microsoft's microsoft-pdb headers (cvinfo.h, MIT).

The PDB and everything made from it are derived from a proprietary binary:
they stay in a gitignored work directory and are never committed.

Usage:
  python pdb2_ref.py <image.exe> <file.pdb> -o ref.json [--seeds seeds.json]
  python pdb2_ref.py --selftest
"""

import argparse
import json
import struct
import sys

MAGIC = b'Microsoft C/C++ program database 2.00\r\n\x1aJG\0\0'
S_PUB32_ST, S_LPROC32_ST, S_GPROC32_ST = 0x1009, 0x100A, 0x100B
CV_SIGNATURE_C11 = 2


def streams(pdb):
    """The MSF 2.00 container: header, root stream of (size, pages) per stream."""
    if not pdb.startswith(MAGIC):
        raise ValueError('not a PDB 2.00 file (an MSF 7.00 PDB goes to pdb_ref.py)')
    ps, = struct.unpack_from('<I', pdb, 0x2C)
    rsz, = struct.unpack_from('<I', pdb, 0x34)

    def read(pages, size):
        return b''.join(pdb[p * ps:(p + 1) * ps] for p in pages)[:size]

    root = read(struct.unpack_from('<%dH' % (-(-rsz // ps)), pdb, 0x3C), rsz)
    n, = struct.unpack_from('<H', root, 0)
    off, out = 4 + 8 * n, []
    for i in range(n):
        size, = struct.unpack_from('<I', root, 4 + 8 * i)
        size = 0 if size == 0xFFFFFFFF else size
        k = -(-size // ps)
        out.append(read(struct.unpack_from('<%dH' % k, root, off), size))
        off += 2 * k
    return out


def records(s, start):
    o = start
    while o + 4 <= len(s):
        ln, t = struct.unpack_from('<HH', s, o)
        if ln < 2:
            return
        yield t, s[o + 4:o + 2 + ln]
        o += 2 + ln


def pstr(b, at):
    return b[at + 1:at + 1 + b[at]].decode('latin-1')


def symbols(pdb):
    """(seg, off, size or None, name) for every procedure and public.

    Procedures (with sizes) are in the module streams, which start with the
    C11 signature; publics (no size, but they cover the libraries built
    without debug info) are in the symbol-record stream. Streams are told
    apart by content rather than through the DBI module table: every module
    stream starts with the signature, and nothing else in the file does.
    """
    out = []
    for s in streams(pdb):
        if len(s) >= 4 and struct.unpack_from('<I', s, 0)[0] == CV_SIGNATURE_C11:
            for t, b in records(s, 4):
                if t in (S_LPROC32_ST, S_GPROC32_ST) and len(b) >= 36:
                    size, = struct.unpack_from('<I', b, 12)
                    off, seg = struct.unpack_from('<IH', b, 28)
                    out.append((seg, off, size, pstr(b, 35)))
        else:
            for t, b in records(s, 0):
                if t == S_PUB32_ST and len(b) >= 11:
                    off, seg = struct.unpack_from('<IH', b, 4)
                    out.append((seg, off, None, pstr(b, 10)))
    return out


def pe_sections(img):
    """[(va, vsize, raw_off, executable)] in section order (seg 1 = first)."""
    pe, = struct.unpack_from('<I', img, 0x3C)
    nsec, = struct.unpack_from('<H', img, pe + 6)
    opt, = struct.unpack_from('<H', img, pe + 20)
    base, = struct.unpack_from('<I', img, pe + 24 + 28)
    t = pe + 24 + opt
    out = []
    for i in range(nsec):
        vs, va, _, raw = struct.unpack_from('<IIII', img, t + 40 * i + 8)
        ch, = struct.unpack_from('<I', img, t + 40 * i + 36)
        out.append((base + va, vs, raw, bool(ch & 0x20000000)))
    return out


def catalog(img, pdb):
    secs = pe_sections(img)
    funcs = {}
    # Procedures first, so their sizes win over a public at the same address.
    for seg, off, size, nm in sorted(symbols(pdb), key=lambda r: r[2] is None):
        if not 1 <= seg <= len(secs) or not secs[seg - 1][3]:
            continue                                   # data, or an absolute
        va, _, raw, _ = secs[seg - 1]
        va += off
        if size:                                       # trailing int3/nop padding is not code
            while size and img[raw + off + size - 1] in (0xCC, 0x90):
                size -= 1
        f = funcs.setdefault(va, {'address': va, 'end': None, 'name': nm})
        if size and f['end'] is None:
            f['end'] = va + size
    return sorted(funcs.values(), key=lambda f: f['address'])


def selftest():
    # A one-module PDB in a 512-byte-page MSF: one proc, one public, one data public.
    def rec(t, body):
        body += b'\0' * (-(len(body) + 4) % 4)
        return struct.pack('<HH', len(body) + 2, t) + body

    proc = struct.pack('<IIIIIIIIHB', 0, 0, 0, 5, 0, 0, 0, 0x10, 1, 0) + b'\x03foo'
    mod = struct.pack('<I', CV_SIGNATURE_C11) + rec(S_GPROC32_ST, proc)
    pubs = (rec(S_PUB32_ST, struct.pack('<IIH', 0, 0x20, 1) + b'\x03bar') +
            rec(S_PUB32_ST, struct.pack('<IIH', 0, 0x8, 2) + b'\x04data'))
    ps, body = 512, [mod, pubs]
    root = struct.pack('<HH', len(body), 0) + b''.join(struct.pack('<II', len(s), 0) for s in body)
    root += struct.pack('<HH', 2, 3)                    # module at page 2, publics at page 3
    hdr = MAGIC + struct.pack('<IHHII', ps, 0, 4, len(root), 0) + struct.pack('<H', 1)
    pdb = b''.join(x.ljust(ps, b'\0') for x in (hdr, root, mod, pubs))
    img = bytearray(0x400)
    struct.pack_into('<I', img, 0x3C, 0x80)
    struct.pack_into('<HH', img, 0x86, 2, 0)            # 2 sections
    struct.pack_into('<H', img, 0x94, 0xE0)
    struct.pack_into('<I', img, 0x98 + 28, 0x400000)
    for i, (va, ch) in enumerate(((0x1000, 0x60000020), (0x2000, 0xC0000040))):
        struct.pack_into('<IIII', img, 0x178 + 40 * i + 8, 0x100, va, 0x100, 0x200)
        struct.pack_into('<I', img, 0x178 + 40 * i + 36, ch)
    img[0x200 + 0x10 + 4] = 0xCC                       # foo's last byte is padding
    got = catalog(bytes(img), pdb)
    want = [{'address': 0x401010, 'end': 0x401014, 'name': 'foo'},
            {'address': 0x401020, 'end': None, 'name': 'bar'}]
    assert got == want, got
    print('PASS pdb2_ref selftest')


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[1])
    ap.add_argument('image', nargs='?')
    ap.add_argument('pdb', nargs='?')
    ap.add_argument('-o', '--output')
    ap.add_argument('--seeds', help='also write a disasm32 --seed-functions list')
    ap.add_argument('--selftest', action='store_true')
    a = ap.parse_args(argv)
    if a.selftest:
        return selftest()
    if not (a.image and a.pdb and a.output):
        ap.error('image, pdb and -o are required')
    img, pdb = open(a.image, 'rb').read(), open(a.pdb, 'rb').read()
    fl = catalog(img, pdb)
    with open(a.output, 'w') as f:
        json.dump({'pdb': a.pdb, 'functions': fl}, f, indent=0)
    if a.seeds:
        with open(a.seeds, 'w') as f:
            json.dump([x['address'] for x in fl], f)
    print('[*] %s: %d functions (%d with ranges) -> %s'
          % (a.pdb, len(fl), sum(x['end'] is not None for x in fl), a.output))


if __name__ == '__main__':
    sys.exit(main())
