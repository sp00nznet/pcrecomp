"""
extract_nsis.py - Extract an early NSIS 2 installer, without running it.

7-Zip reads NSIS 2.x installers, but not the 2.0 betas of 2002-2006: it
lists them as `NSIS-2 BadCmd=...` with 0 files, because their install script
has 24-byte entries (an opcode and five parameters) where 2.x has 28, and
different opcode numbers. Those betas shipped a lot of freeware (Sambar Server
6.x is one). This tool reads the script far enough to place every file:

  - the first header (`0xDEADBEEF NullsoftInst`, 512-byte aligned) and the
    data blocks after it, each a 4-byte length, raw DEFLATE when its top bit
    is set (non-solid; solid and LZMA/bzip2 installers are reported, not read);
  - the entry table, found by the stride of the parameters that are data block
    offsets; ExtractFile entries name a string and a block, SetOutPath entries
    name the folder;
  - the string table, found as the offset at which the first ExtractFile names
    are all NUL-terminated strings.

A folder's leading variable ($INSTDIR, a one-byte code in these betas) is
dropped, so files land relative to the install folder. A block no entry names
(the uninstaller, plug-ins) stays as blk_<offset>.bin.

Usage:
    python extract_nsis.py <installer.exe> <out_dir>
    python extract_nsis.py --selftest
"""
import os
import struct
import sys
import zlib

# entry size in ints -> (SetOutPath, ExtractFile) opcodes. 6 is the 2.0 beta
# layout (verified on sambar64p.exe); 7 is 2.x final, which 7-Zip also reads.
OPCODES = {6: (14, 21), 7: (11, 20)}


def blocks(d):
    """(header bytes, {data offset: bytes}) of the installer image `d`."""
    off = -1
    while True:
        off = d.find(b'\xef\xbe\xad\xdeNullsoftInst', off + 1)
        if off < 0:
            raise ValueError('not an NSIS installer (no first header)')
        if (off - 4) % 512 == 0:
            break
    fh = off - 4
    flags, _, hlen, alen = struct.unpack_from('<II12xII', d, fh)

    def block(p):
        n, = struct.unpack_from('<I', d, p)
        raw = d[p + 4:p + 4 + (n & 0x7FFFFFFF)]
        if n & 0x80000000:
            raw = zlib.decompressobj(-15).decompress(raw)
        return raw, p + 4 + (n & 0x7FFFFFFF)

    try:
        hdr, p = block(fh + 28)
    except zlib.error:
        raise ValueError('header is not raw DEFLATE: a solid, LZMA or bzip2 installer')
    data0, out = p, {}
    while p < min(fh + alen, len(d)) - 4:
        try:
            raw, np_ = block(p)
        except zlib.error:
            raise ValueError('block at 0x%X is not raw DEFLATE' % p)
        out[p - data0] = raw
        p = np_
    return hdr, out


def entries(hdr, offsets):
    """[(op, parms...)] and the entry size, from the stride of data offsets."""
    ints = struct.unpack_from('<%dI' % (len(hdr) // 4), hdr)
    hits = [i for i, v in enumerate(ints) if v in offsets and v]
    if len(hits) < 2:
        raise ValueError('no entry table found')
    gaps = {}
    for a, b in zip(hits, hits[1:]):
        gaps[b - a] = gaps.get(b - a, 0) + 1
    size = min((g for g in gaps if g in OPCODES), key=lambda g: -gaps[g], default=None)
    if size is None:
        raise ValueError('entry size %s not known' % sorted(gaps, key=lambda g: -gaps[g])[:3])
    start = (hits[0] - 3) % size
    return [ints[k:k + size] for k in range(start, len(ints) - size + 1, size)], size


def extract(path, out):
    d = open(path, 'rb').read()
    hdr, data = blocks(d)
    ents, size = entries(hdr, set(data))
    set_out, extract_op = OPCODES[size]
    names = [e[2] for e in ents if e[0] == extract_op and e[3] in data][:10]
    soff = next((s for s in range(len(hdr)) if all(s + n < len(hdr) and (s + n == 0 or hdr[s + n - 1] == 0)
                                                    and hdr[s + n] for n in names)), None)
    if soff is None:
        raise ValueError('string table not found')

    def string(o):
        p, r = soff + o, bytearray()
        while p < len(hdr) and hdr[p]:
            r.append(hdr[p])
            p += 1
        return r

    def clean(b):                                   # drop variable codes, keep the path
        return ''.join(chr(c) for c in b if 0x20 <= c < 0x80).replace('\\', '/').strip('/')

    folder, placed = '', set()
    for e in ents:
        if e[0] == set_out and soff + e[1] < len(hdr):
            folder = clean(string(e[1]))
        elif e[0] == extract_op and e[3] in data and e[3] not in placed:
            rel = os.path.normpath(os.path.join(folder, clean(string(e[2]))))
            if rel.startswith('..') or os.path.isabs(rel):
                raise ValueError('entry escapes the output folder: %s' % rel)
            dst = os.path.join(out, rel)
            os.makedirs(os.path.dirname(dst) or out, exist_ok=True)
            open(dst, 'wb').write(data[e[3]])
            placed.add(e[3])
    for o, raw in data.items():
        if o not in placed:
            os.makedirs(out, exist_ok=True)
            open(os.path.join(out, 'blk_%06x.bin' % o), 'wb').write(raw)
    return len(placed), len(data) - len(placed), size


def _selftest():
    assert OPCODES[6] == (14, 21)
    # A 6-int table: SetOutPath "x" then two ExtractFiles of blocks 5 and 11.
    ints = [0, 0, 0] + [14, 0, 1, 0, 0, 0] + [21, 0, 2, 5, 0, 0] + [21, 0, 4, 11, 0, 0]
    hdr = struct.pack('<%dI' % len(ints), *ints)
    ents, size = entries(hdr, {5, 11})
    assert size == 6 and [e[0] for e in ents][:3] == [14, 21, 21], (size, ents)
    print('extract_nsis selftest: ok')


if __name__ == '__main__':
    if sys.argv[1:] == ['--selftest']:
        _selftest()
    elif len(sys.argv) == 3:
        n, left, size = extract(sys.argv[1], sys.argv[2])
        print('%d files placed, %d unnamed blocks, %d-int entries' % (n, left, size))
    else:
        sys.exit(__doc__)
