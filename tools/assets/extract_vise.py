"""
extract_vise.py - Extract a MindVision Installer VISE (Windows) installer, without running it.

7-Zip and Universal Extractor don't read VISE for Windows (Napster 2.0 betas,
2000-2001, and other Mac-first vendors' Windows installers). The format, as
read from the stub of napv2b10-3.exe:

  - the last 8 bytes are `ESIV` and the u32 file offset of the archive, which
    starts with `ESIVI`;
  - every stream is raw DEFLATE (Info-ZIP's inflate) read through 16-bit
    big-endian words: swap each byte pair, then inflate. A stream that starts
    on an odd offset is swapped from that offset;
  - the stub's own files (vise32ex.dll, the language file, the uninstaller)
    are records `[u8 len][name][u32 dos time][8][u32 csize][data]`;
  - the install files are named in a table of records
    `[u16 len][name][u32][u32 size][u32 csize][u32][u32 offset][u32 attr]`,
    the offset relative to the archive start. The table itself is plain.

Each record is accepted only when its stream inflates to exactly its stated
size, so a false match in compressed data is never written. Names are taken
as plain file names; a path separator or `..` is refused.

Usage:
    python extract_vise.py <installer.exe> <out_dir>
    python extract_vise.py --selftest
"""
import os
import re
import struct
import sys
import zlib


def inflate_words(d, off, csize):
    """Inflate `csize` bytes at `off`, read as big-endian 16-bit words."""
    s = d[off:off + csize + (csize & 1)]
    s = s[:len(s) // 2 * 2]
    sw = bytearray(len(s))
    sw[0::2], sw[1::2] = s[1::2], s[0::2]
    z = zlib.decompressobj(-15)
    out = z.decompress(bytes(sw))
    return out if z.eof else None


def archive_base(d):
    if d[-8:-4] != b'ESIV':
        raise ValueError('not a VISE installer (no ESIV trailer)')
    base, = struct.unpack('<I', d[-4:])
    if d[base:base + 5] != b'ESIVI':
        raise ValueError('ESIV trailer points at 0x%X, which is not ESIVI' % base)
    return base


def safe(name):
    n = name.decode('latin-1')
    if '/' in n or '\\' in n or n in ('.', '..') or ':' in n:
        raise ValueError('refusing file name %r' % n)
    return n


def files(d):
    """[(name, bytes)] of every record whose stream checks out, in file order."""
    base = archive_base(d)
    found = {}
    # stub records: u8 name length, data 16 bytes after the name
    for m in re.finditer(rb'([\x03-\x40])([\x20-\x7e]{3,64})', d[base:]):
        n = m.group(1)[0]
        name = m.group(2)[:n]
        if len(name) != n or b'.' not in name:
            continue
        p = base + m.start() + 1 + n
        if p + 16 > len(d):
            continue
        cs, = struct.unpack_from('<I', d, p + 12)
        if not 0 < cs <= len(d) - p - 16:
            continue
        try:
            out = inflate_words(d, p + 16, cs)
        except zlib.error:
            continue
        if out is not None:
            found[p + 16] = (name, out)
    # install file table: u16 name length, sizes and archive offset after it
    for m in re.finditer(rb'([\x03-\x40])\x00([\x20-\x7e]{3,64})', d[base:]):
        n = m.group(1)[0]
        name = m.group(2)[:n]
        if len(name) != n:
            continue
        p = base + m.start() + 2 + n
        if p + 20 > len(d):
            continue
        size, cs, _, off = struct.unpack_from("<IIII", d, p + 4)
        if not (0 < cs <= len(d) and 0 <= size < 1 << 30 and base + off + cs <= len(d)):
            continue
        try:
            out = inflate_words(d, base + off, cs)
        except zlib.error:
            continue
        if out is not None and len(out) == size:
            found[base + off] = (name, out)
    return [(safe(nm), data) for _, (nm, data) in sorted(found.items())]


def extract(path, out_dir):
    d = open(path, 'rb').read()
    os.makedirs(out_dir, exist_ok=True)
    got = files(d)
    seen = {}
    for name, data in got:
        k = name.lower()
        if k in seen:                       # same name twice: keep both
            seen[k] += 1
            name = '%s.%d' % (name, seen[k])
        else:
            seen[k] = 0
        with open(os.path.join(out_dir, name), 'wb') as f:
            f.write(data)
        print('%10d  %s' % (len(data), name))
    print('%d files' % len(got))
    return got


def selftest():
    def stream(raw):
        c = zlib.compressobj(9, zlib.DEFLATED, -15)
        z = c.compress(raw) + c.flush()
        if len(z) & 1:
            z += b'\0'
        sw = bytearray(len(z))
        sw[0::2], sw[1::2] = z[1::2], z[0::2]
        return bytes(sw)
    a, b = b'MZ stub file ' * 50, b'install file payload ' * 80
    sa, sb = stream(a), stream(b)
    base = 16
    arc = bytearray(b'ESIVI' + b'\0' * 11)
    arc += bytes([6]) + b'a1.dll' + b'\0' * 12 + struct.pack('<I', len(sa)) + sa
    off = len(arc)
    arc += sb
    arc += struct.pack('<H', 7) + b'app.exe' + b'\0' * 4 + struct.pack('<IIII', len(b), len(sb), 1, off) + b'\x20\0\0\0'
    img = b'\0' * base + bytes(arc) + b'ESIV' + struct.pack('<I', base)
    got = dict(files(img))
    assert got == {'a1.dll': a, 'app.exe': b}, got
    try:
        safe(b'..\\evil.dll')
        raise AssertionError('path accepted')
    except ValueError:
        pass
    print('extract_vise selftest: ok')


if __name__ == '__main__':
    if sys.argv[1:] == ['--selftest']:
        selftest()
    elif len(sys.argv) == 3:
        extract(sys.argv[1], sys.argv[2])
    else:
        sys.exit(__doc__)
