#!/usr/bin/env python3
"""Clickteam Install Maker (2000s): the files out of setup.exe, without running it.

    python -I tools/assets/extract_clickteam.py setup.exe out_dir/

The stub is UPX-packed; the payload is appended after the PE as blocks
(u16 id, u16 flags, u32 size) behind the "wwgT)H" signature. Block 0x143A is
the file list (zlib), 0x7F7F the file data. Each list entry is u16 length,
u16 type (0 = file), then at +6 u32 offset/packed size/size and the name at
+0x36. Each file is u32 size, u8 method (1 zlib, 2 bzip2, else stored), data.
Retail Plus Lite (Tucows 341566) is the reference installer.
"""
import bz2
import os
import struct
import sys
import zlib


def extract(path, out):
    d = open(path, 'rb').read()
    p = d.index(b'wwgT)H') + 6
    blocks = {}
    while p < len(d) - 8:
        bid, _, sz = struct.unpack_from('<HHI', d, p)
        blocks[bid] = d[p + 8:p + 8 + sz]
        p += 8 + sz
    lst, data = zlib.decompress(blocks[0x143A][5:]), blocks[0x7F7F]
    os.makedirs(out, exist_ok=True)
    p, n = 4, 0
    while p < len(lst) - 4:
        ln, typ = struct.unpack_from('<HH', lst, p)
        if not ln:
            break
        if typ == 0:
            off, cs, us = struct.unpack_from('<III', lst, p + 6)
            name = os.path.basename(lst[p + 0x36:p + ln].split(b'\0')[0].decode('latin1').replace('\\', '/'))
            m, b = data[off + 4], data[off + 5:off + cs]
            b = zlib.decompressobj().decompress(b) if m == 1 else bz2.BZ2Decompressor().decompress(b) if m == 2 else b
            if len(b) != us:
                sys.exit('%s: %d bytes, list says %d' % (name, len(b), us))
            open(os.path.join(out, name), 'wb').write(b)
            n += 1
        p += ln
    return n


if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    print('%d files' % extract(sys.argv[1], sys.argv[2]))
