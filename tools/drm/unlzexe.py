#!/usr/bin/env python3
"""
unlzexe.py - undo LZEXE 0.90/0.91 compression of a DOS MZ executable.

LZEXE (Fabrice Bellard, 1989-90) was the shareware-era EXE packer: id Software,
Apogee and JAM shipped their games through it. A packed file carries "LZ09" or
"LZ91" at offset 1Ch, a tiny header, the compressed load module, and a loader
segment that holds the original CS:IP/SS:SP and a compressed relocation table.
The disassembler sees only the loader, so every 16-bit target that ships packed
has to come through here first.

Pure Python and headless: the loader is never run, the format is decoded
directly (the same scheme as Kurizono's UNLZEXE). The output is a plain MZ with
a 512-byte-aligned header and the original relocation table, which is what
decode16/analyze expect.

    python unlzexe.py PACKED.EXE OUT.EXE
"""
import struct
import sys


class _Bits:
    """LZEXE's bit reader: 16-bit little-endian words, LSB first. The next
    word is fetched as soon as the last bit of the current one is taken, so
    byte reads interleave with it exactly as the loader's do."""

    def __init__(self, data, pos):
        self.d, self.p = data, pos
        self.buf = self._word()
        self.n = 16

    def _word(self):
        w = self.d[self.p] | (self.d[self.p + 1] << 8)
        self.p += 2
        return w

    def byte(self):
        b = self.d[self.p]
        self.p += 1
        return b

    def bit(self):
        b = self.buf & 1
        self.n -= 1
        if self.n == 0:
            self.buf, self.n = self._word(), 16
        else:
            self.buf >>= 1
        return b


def _relocs90(d, pos):
    """0.90: 16 groups (one per 64K frame), each a count then 16-bit offsets."""
    out = []
    for seg in range(16):
        n = struct.unpack_from('<H', d, pos)[0]; pos += 2
        for _ in range(n):
            out.append((struct.unpack_from('<H', d, pos)[0], seg * 0x1000)); pos += 2
    return out


def _relocs91(d, pos):
    """0.91: a delta stream. A byte is the span to the next fixup; a zero byte
    escapes to a word span, where 0 means 'advance 0FFF0h bytes' and 1 ends."""
    out, off, seg = [], 0, 0
    while True:
        span = d[pos]; pos += 1
        if span == 0:
            span = struct.unpack_from('<H', d, pos)[0]; pos += 2
            if span == 0:
                seg += 0x0FFF
                continue
            if span == 1:
                return out
        off += span
        seg += (off & ~0x0F) >> 4
        off &= 0x0F
        out.append((off, seg))


def unpack(data: bytes) -> bytes:
    h = list(struct.unpack_from('<14H', data, 0))
    sig = data[0x1C:0x20]
    if h[0] != 0x5A4D or sig not in (b'LZ09', b'LZ91'):
        raise ValueError('not an LZEXE 0.90/0.91 file')
    hdr = h[4] << 4
    ldr = hdr + (h[11] << 4)                       # loader segment = packed CS
    ip, cs, sp, ss, cparas, grow, ldrsize, _ = struct.unpack_from('<8H', data, ldr)

    rel = (_relocs90 if sig == b'LZ09' else _relocs91)(
        data, ldr + (0x19D if sig == b'LZ09' else 0x158))

    # The compressed module sits directly below the loader segment.
    bits = _Bits(data, hdr + ((h[11] - cparas) << 4))
    out = bytearray()
    while True:
        if bits.bit():
            out.append(bits.byte())
            continue
        if not bits.bit():
            n = ((bits.bit() << 1) | bits.bit()) + 2
            span = bits.byte() - 0x100              # -1 .. -256
        else:
            lo, hi = bits.byte(), bits.byte()
            span = (lo | ((hi & 0xF8) << 5) | 0xE000) - 0x10000
            n = (hi & 7) + 2
            if n == 2:
                n = bits.byte()
                if n == 0:
                    break                           # end of the load module
                if n == 1:
                    continue                        # segment boundary, no data
                n += 1
        for _ in range(n):                          # may overlap: byte by byte
            out.append(out[span])

    # Header: 1Ch fixed words, the relocation table, padded to 512 bytes.
    hlen = 0x1C + 4 * len(rel)
    hlen = (hlen + 0x1FF) & ~0x1FF
    total = hlen + len(out)
    minalloc = h[5]
    maxalloc = h[6]
    if maxalloc:
        # The packed file asked for room to decompress in; give back what the
        # loader itself needed and keep the BSS the original declared.
        minalloc = (h[5] - grow - ((ldrsize + 15) >> 4) - 9) & 0xFFFF
        if maxalloc != 0xFFFF:
            maxalloc = (maxalloc - (h[5] - minalloc)) & 0xFFFF
    hdrw = [0x5A4D, total & 0x1FF, (total + 0x1FF) >> 9, len(rel), hlen >> 4,
            minalloc, maxalloc, ss, sp, 0, ip, cs, 0x1C, 0]
    head = bytearray(struct.pack('<14H', *hdrw))
    for off, seg in rel:
        head += struct.pack('<HH', off, seg)
    head += bytes(hlen - len(head))
    return bytes(head) + bytes(out)


def main(argv):
    if len(argv) != 3:
        print(__doc__.strip().splitlines()[-1].strip())
        return 2
    src = open(argv[1], 'rb').read()
    out = unpack(src)
    open(argv[2], 'wb').write(out)
    nrel = struct.unpack_from('<H', out, 6)[0]
    print(f'{argv[1]}: {len(src)} -> {len(out)} bytes, {nrel} relocations, '
          f'entry {struct.unpack_from("<H", out, 0x16)[0]:04X}:'
          f'{struct.unpack_from("<H", out, 0x14)[0]:04X}')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
