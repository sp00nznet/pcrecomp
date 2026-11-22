"""
msexpand.py - Unpack MS COMPRESS files (the FOO.EX_ files on DOS/Windows 3.x
setup disks): SZDD (COMPRESS.EXE / expand.exe, LZSS) and KWAJ (Windows 3.1x,
methods 0-3; method 3 is LZ77 + five canonical Huffman tables).

    python msexpand.py <in dir> <out dir>      every *_ file; names from the
                                                KWAJ header, else the last
                                                char from SZDD's, else kept
    python msexpand.py --selftest

Written from the file formats (KWAJ as documented by libmspack's kwaj.h /
the MS-KWAJ notes); no code copied.
"""
import os
import sys


def szdd(d):
    # 'SZDD' 88 F0 27 33, 'A', missing last char, u32 length, then LZSS
    n = int.from_bytes(d[10:14], 'little')
    win = bytearray(b' ' * 4096)
    pos, out, i = 4096 - 16, bytearray(), 14
    while i < len(d) and len(out) < n:
        ctl = d[i]; i += 1
        for b in range(8):
            if i >= len(d) or len(out) >= n:
                break
            if ctl >> b & 1:
                c = d[i]; i += 1
                out.append(c); win[pos] = c; pos = (pos + 1) & 4095
            else:
                if i + 1 >= len(d):
                    break
                m = d[i] | (d[i + 1] & 0xF0) << 4
                ln = (d[i + 1] & 15) + 3; i += 2
                for k in range(ln):
                    c = win[(m + k) & 4095]
                    out.append(c); win[pos] = c; pos = (pos + 1) & 4095
    return bytes(out)


class Bits:
    def __init__(self, d, i):
        self.d, self.i, self.buf, self.n = d, i, 0, 0

    def get(self, k):
        while self.n < k:
            c = self.d[self.i] if self.i < len(self.d) else 0
            self.i += 1
            self.buf = self.buf << 8 | c; self.n += 8
        self.n -= k
        return self.buf >> self.n & ((1 << k) - 1)

    def eof(self):
        return self.i > len(self.d) + 4


def lens(bits, typ, nsym):
    if typ == 0:
        return [{16: 4, 32: 5, 64: 6, 256: 8}[nsym]] * nsym
    if typ == 3:
        return [bits.get(4) for _ in range(nsym)]
    c = bits.get(4); out = [c]
    for _ in range(1, nsym):
        if typ == 1:
            if bits.get(1):
                if bits.get(1):
                    c = bits.get(4)
                else:
                    c += 1
        else:  # typ 2
            s = bits.get(2)
            c = bits.get(4) if s == 3 else c + s - 1
        out.append(c)
    return out


def huff(ln):
    # canonical: by length, then by symbol; {(len, code): sym}
    t, code = {}, 0
    for L in range(1, 17):
        for s, l in enumerate(ln):
            if l == L:
                t[(L, code)] = s; code += 1
        code <<= 1
    return t


def sym(bits, t):
    code = 0
    for L in range(1, 17):
        code = code << 1 | bits.get(1)
        s = t.get((L, code))
        if s is not None:
            return s
    raise ValueError('bad Huffman code')


def kwaj_lzh(d, i, n):
    b = Bits(d, i)
    types = [b.get(4) for _ in range(6)]   # six; the sixth is unused
    ml1, ml2, ll, off, lit = (huff(lens(b, types[k], s)) for k, s in enumerate((16, 16, 32, 64, 256)))
    win, pos, out, run = bytearray(b' ' * 4096), 0, bytearray(), False
    def put(c):
        nonlocal pos
        out.append(c); win[pos] = c; pos = (pos + 1) & 4095
    while len(out) < n and not b.eof():
        ln = sym(b, ml2 if run else ml1)
        if ln:
            ln += 2; run = False
            j = sym(b, off) << 6 | b.get(6)
            for _ in range(ln):
                put(win[(pos - j) & 4095])
        else:
            ln = sym(b, ll) + 1
            run = ln != 32
            for _ in range(ln):
                put(sym(b, lit))
    return bytes(out[:n])


def kwaj(d):
    method, data, flags = (int.from_bytes(d[k:k + 2], 'little') for k in (8, 10, 12))
    i, n, name = 14, None, b''
    if flags & 1:
        n = int.from_bytes(d[i:i + 4], 'little'); i += 4
    if flags & 2:
        i += 2
    if flags & 4:
        i += 2 + int.from_bytes(d[i:i + 2], 'little')
    if flags & 8:
        e = d.index(0, i); name = d[i:e]; i = e + 1
    if flags & 16:
        e = d.index(0, i); name += b'.' + d[i:e]; i = e + 1
    body = d[data:]
    if method == 0:
        out = body
    elif method == 1:
        out = bytes(c ^ 0xFF for c in body)
    elif method == 2:
        out = szdd(b'\0' * 10 + (n or 1 << 30).to_bytes(4, 'little') + body)
    elif method == 3:
        out = kwaj_lzh(d, data, n if n is not None else 1 << 30)
    else:
        raise ValueError('KWAJ method %d (MSZIP) not supported' % method)
    return out, name.decode('latin-1')


def expand(path):
    """-> (bytes, real name or None)"""
    d = open(path, 'rb').read()
    if d[:8] == b'SZDD\x88\xf0\x27\x33':
        nm = os.path.basename(path)
        if d[9:10] != b'\0' and nm.endswith('_'):
            nm = nm[:-1] + chr(d[9])
        return szdd(d), nm
    if d[:8] == b'KWAJ\x88\xf0\x27\xd1':
        out, nm = kwaj(d)
        return out, nm or None
    return None, None


def selftest():
    # SZDD: 'ABC' literal then a 3-byte match of 'ABC' (window 0xFF0), length 6
    s = b'SZDD\x88\xf0\x27\x33A\0' + (6).to_bytes(4, 'little') + bytes([0b111, 65, 66, 67, 0xF0, 0xF0])
    assert szdd(s) == b'ABCABC', szdd(s)
    # KWAJ method 1 (xor) with a stored name
    k = b'KWAJ\x88\xf0\x27\xd1' + (1).to_bytes(2, 'little') + (0x17).to_bytes(2, 'little') + (0x19).to_bytes(2, 'little')
    k += (2).to_bytes(4, 'little') + b'AB\0' + b'C\0'
    k += bytes(c ^ 0xFF for c in b'hi')
    assert kwaj(k) == (b'hi', 'AB.C'), kwaj(k)
    print('selftest ok')


def main(a):
    if a[:1] == ['--selftest']:
        return selftest()
    src, dst = a
    os.makedirs(dst, exist_ok=True)
    for f in sorted(os.listdir(src)):
        p = os.path.join(src, f)
        if not os.path.isfile(p):
            continue
        out, nm = expand(p) if f.endswith('_') else (None, None)
        if out is None:
            out, nm = open(p, 'rb').read(), f
        elif not nm:
            nm = f
        open(os.path.join(dst, nm.upper()), 'wb').write(out)


if __name__ == '__main__':
    main(sys.argv[1:])
