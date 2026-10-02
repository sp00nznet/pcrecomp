#!/usr/bin/env python3
"""
test_unlzexe.py - unlzexe against a packed file built here, so the check needs
no game executable: a tiny LZ91 encoder writes literals, a short match, a long
match, a long match with an extended length, and the end mark, around a
loader segment holding the original CS:IP/SS:SP and a delta-coded relocation
table. Unpacking it must give back the module, the registers and the
relocations exactly.

    python tools/drm/test_unlzexe.py
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import unlzexe  # noqa: E402


class _Enc:
    """Mirror of unlzexe._Bits: 16-bit flag words, LSB first, and the next
    word is fetched the moment the last bit of the current one is used -- so
    its slot is reserved right then, before any byte that follows."""

    def __init__(self):
        self.out = bytearray(b'\0\0')
        self.slot, self.word, self.n = 0, 0, 0

    def bit(self, b):
        self.word |= (b & 1) << self.n
        self.n += 1
        if self.n == 16:
            struct.pack_into('<H', self.out, self.slot, self.word)
            self.slot, self.word, self.n = len(self.out), 0, 0
            self.out += b'\0\0'

    def byte(self, b):
        self.out.append(b)

    def literal(self, b):
        self.bit(1)
        self.byte(b)

    def short(self, span, n):            # n 2..5, span -1..-256
        self.bit(0); self.bit(0)
        self.bit((n - 2) >> 1); self.bit((n - 2) & 1)
        self.byte(span + 0x100)

    def long(self, span, n):             # span -1..-8192
        self.bit(0); self.bit(1)
        v = span & 0x1FFF
        lo, hi = v & 0xFF, (v >> 5) & 0xF8
        if 3 <= n <= 9:
            self.byte(lo); self.byte(hi | (n - 2))
        else:
            self.byte(lo); self.byte(hi); self.byte(n - 1)

    def end(self):
        self.bit(0); self.bit(1)
        self.byte(0); self.byte(0); self.byte(0)
        struct.pack_into('<H', self.out, self.slot, self.word)
        return bytes(self.out)


def build():
    module = bytearray(b'MZ-test ' * 4)            # 32 literal bytes ...
    e = _Enc()
    for b in module:
        e.literal(b)
    e.short(-8, 4); module += module[-8:-4]        # ... then copies of them
    e.long(-32, 7); module += module[-32:-25]
    e.long(-40, 20)                                 # extended length, overlapping
    for _ in range(20):
        module.append(module[-40])
    for b in b'\x90\x90\xcb':
        e.literal(b)
    module += b'\x90\x90\xcb'
    packed = e.end()

    relocs = [(0x0003, 0x0000), (0x0010, 0x0000), (0x0005, 0x0001)]  # (off, seg)
    rt = bytearray()
    prev = 0
    for off, seg in relocs:
        lin = seg * 16 + off
        rt.append(lin - prev)
        prev = lin
    rt += b'\0\x01\0'                              # 0, then word 1: end

    cparas = (len(packed) + 15) // 16
    packed = packed.ljust(cparas * 16, b'\0')
    loader = bytearray(0x158) + rt
    struct.pack_into('<8H', loader, 0,
                     0x1234, 0x0002, 0x0400, 0x0003,   # IP CS SP SS
                     cparas, 0x0010, len(loader), 0)
    hdr = bytearray(0x20)
    total = 0x20 + len(packed) + len(loader)
    struct.pack_into('<14H', hdr, 0, 0x5A4D, total & 0x1FF, (total + 0x1FF) >> 9, 0, 2,
                     0x0100, 0xFFFF, 0, 0x80, 0, 0x000E, cparas, 0x1C, 0)
    hdr[0x1C:0x20] = b'LZ91'
    return bytes(hdr) + packed + bytes(loader), bytes(module), relocs


def test():
    exe, module, relocs = build()
    out = unlzexe.unpack(exe)
    h = struct.unpack_from('<14H', out, 0)
    hlen = h[4] * 16
    assert out[:2] == b'MZ'
    assert out[hlen:] == module, 'load module differs'
    assert (h[10], h[11], h[8], h[7]) == (0x1234, 0x0002, 0x0400, 0x0003), 'registers'
    got = [struct.unpack_from('<HH', out, 0x1C + 4 * i) for i in range(h[3])]
    want = [(lin & 0xF, lin >> 4) for lin in
            (seg * 16 + off for off, seg in relocs)]
    assert got == want, (got, want)
    assert hlen % 512 == 0 and (h[2] - 1) * 512 + (h[1] or 512) == len(out)
    print(f'unlzexe: ok ({len(module)}-byte module, {len(got)} relocations)')


if __name__ == '__main__':
    test()
