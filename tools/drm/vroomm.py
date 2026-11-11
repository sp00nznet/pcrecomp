#!/usr/bin/env python3
"""
vroomm.py - make Borland VROOMM overlays resident, for a static lift.

A Borland C++ real-mode program linked with overlays carries an `FBOV` block
after its MZ load image. Each overlaid code segment leaves a *stub segment* in
the resident image:

  +00 CD 3F       int 3Fh          +04 dd  offset of its code in the FBOV block
  +08 dw  code size                +0A dw  fixup bytes (segment-word offsets, after the code)
  +0C dw  entries                  +20 entries, 5 bytes each: CD 3F <dw offset> 00

At run time the overlay manager loads the code into a buffer (or EMS) and
patches each entry into `jmp far buf:offset`. This does that once, ahead of
time: every overlay gets a fixed home in memory the program does not use, its
fixups become ordinary relocations, and its entries become far jumps. The
lifter then sees one resident program and INT 3Fh never fires.

    stubs = vroomm.place(img, relocs, raw, end, load_seg, regions)

  img      bytearray, the load image (grown as needed)
  relocs   list of (offset, segment) relocations, extended in place
  raw      the whole EXE; end = file offset where the load image stops
  regions  [(start, end)] runtime paragraphs free for overlay code, e.g.
           [(0xC000, 0xE000), (0xF100, 0xFFFF), (0xB000, 0xB800)]

Returns [(stub linear, image segment, size, entries)], biggest first.
Seen on Mario Is Missing! CD-ROM Deluxe (40 overlays) and Wing Commander
(40 overlays, 867 entries). The FBOV header: 'FBOV', dd size, dd file offset
of the segment table, dd its entries; a table entry is 8 bytes and starts with
the segment's paragraph. An overlay's fixup words hold *table offsets*
(entry * 8), not segments.

ponytail: no EMS/XMS swapping model; every overlay is resident at once.

    python tools/drm/vroomm.py      # self-check on a synthetic EXE
"""
import struct


def is_vroomm(raw, end):
    return raw[end:end + 4] == b'FBOV'


def find_stubs(img, fbov):
    stubs = []
    p = img.find(b'\xcd\x3f\x00\x00')
    while p >= 0:                             # not always paragraph-aligned
        fo, size, fix, n = struct.unpack_from('<IHHH', img, p + 4)
        if size and n and fo + size <= len(fbov) and \
                all(img[p + 0x20 + 5 * k:p + 0x22 + 5 * k] == b'\xcd\x3f' for k in range(n)):
            stubs.append((p, fo, size, fix, n))   # p: the header's linear address
        p = img.find(b'\xcd\x3f\x00\x00', p + 1)
    return stubs


def place(img, relocs, raw, end, load_seg, regions):
    _, tab, ntab = struct.unpack_from('<III', raw, end + 4)
    segtab = [struct.unpack_from('<H', raw, tab + 8 * k)[0] for k in range(ntab)]
    fbov = raw[end + 16:]
    regions = [list(r) for r in regions]
    placed = []
    for stub, fo, size, fix, n in sorted(find_stubs(img, fbov), key=lambda s: -s[2]):
        paras = (size + 15) // 16
        r = next((r for r in regions if r[1] - r[0] >= paras), None)
        if r is None:
            raise ValueError(f'overlays: no room for stub {stub:05X} ({size} bytes)')
        seg = r[0] - load_seg                     # image-relative, like every other segment
        r[0] += paras
        base = seg * 16
        if len(img) < base + paras * 16:
            img.extend(bytes(base + paras * 16 - len(img)))
        img[base:base + size] = fbov[fo:fo + size]
        for k in range(fix // 2):                 # segment words: table offset -> segment, then relocate
            off = struct.unpack_from('<H', fbov, fo + size + 2 * k)[0]
            v = struct.unpack_from('<H', img, base + off)[0]
            img[base + off:base + off + 2] = struct.pack('<H', segtab[v >> 3])
            relocs.append((off, seg))
        for k in range(n):                        # int 3Fh entry -> jmp far seg:off
            e = stub + 0x20 + 5 * k
            off = struct.unpack_from('<H', img, e + 2)[0]
            img[e:e + 5] = bytes([0xEA]) + struct.pack('<HH', off, seg)
            relocs.append(((e + 3) & 15, (e + 3) >> 4))
        placed.append((stub, seg, size, n))
    return placed


def _selftest():
    # image: one stub segment at 0x100 with 2 entries; FBOV: 0x20 bytes of
    # code whose word at +4 is a segment fixup naming table entry 1.
    img = bytearray(0x200)
    code = bytearray(b'\x90' * 0x20)
    struct.pack_into('<H', code, 4, 1 * 8)
    fbov = bytes(code) + struct.pack('<H', 4)
    struct.pack_into('<2sHIHHH', img, 0x100, b'\xcd\x3f', 0, 0, len(code), 2, 2)
    for k, off in enumerate((0x0000, 0x0010)):
        struct.pack_into('<2sHB', img, 0x120 + 5 * k, b'\xcd\x3f', off, 0)
    hdr = bytearray(0x20)
    tab_at = 0x20 + len(img) + 16 + len(fbov)
    raw = bytes(hdr) + bytes(img) + b'FBOV' + struct.pack('<III', len(fbov), tab_at, 2) + fbov \
        + struct.pack('<HHI', 0x0010, 0, 0) + struct.pack('<HHI', 0x0042, 0, 0)
    end = 0x20 + len(img)
    assert is_vroomm(raw, end)
    relocs = []
    placed = place(img, relocs, raw, end, 0x110, [(0xC000, 0xE000)])
    seg = 0xC000 - 0x110
    assert placed == [(0x100, seg, 0x20, 2)], placed
    assert img[seg * 16 + 4:seg * 16 + 6] == struct.pack('<H', 0x42)          # fixup -> table segment
    assert img[0x120:0x125] == b'\xea\x00\x00' + struct.pack('<H', seg)       # entry -> jmp far
    assert img[0x125:0x12A] == b'\xea\x10\x00' + struct.pack('<H', seg)
    assert (4, seg) in relocs and ((0x123 & 15), 0x123 >> 4) in relocs
    print('vroomm: ok')


if __name__ == '__main__':
    _selftest()
