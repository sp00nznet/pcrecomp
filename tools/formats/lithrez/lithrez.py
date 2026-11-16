#!/usr/bin/env python3
"""LithTech REZ archives ("RezMgr Version 1"): list them, or pull files out.

The same format from LithTech 1.0 (Shogo, whose game DLLs ship inside the
.rez) through LithTech 2.x (KISS Psycho Circus, whose PSYCHO.REZ holds only
data). The engine copies DLLs it finds in a rez to temp files and
LoadLibrary's those.

    py -3 lithrez.py game/SHOGOP3.REZ              # list
    py -3 lithrez.py game/SHOGOP3.REZ out dll,lto  # extract by extension
    py -3 lithrez.py --selftest
"""
import os
import struct
import sys


def entries(path):
    """(name with extension, offset, size) for every resource, depth first."""
    with open(path, 'rb') as f:
        f.seek(0x7F)                                   # after the three text lines + ^Z
        _ver, pos, size = struct.unpack('<III', f.read(12))
        yield from _walk(f, pos, size, [])


def _walk(f, pos, size, path):
    f.seek(pos)
    d, i = f.read(size), 0
    while i < len(d):
        kind, p, sz, _t = struct.unpack_from('<IIII', d, i)
        i += 16
        if kind == 1:                                  # a directory
            j = d.index(b'\0', i)
            name, i = d[i:j].decode('latin1'), j + 1
            yield from _walk(f, p, sz, path + [name])
            f.seek(0)
            continue
        _id, typ, nkeys = struct.unpack_from('<III', d, i)
        i += 12
        j = d.index(b'\0', i)
        name, i = d[i:j].decode('latin1'), j + 1
        i = d.index(b'\0', i) + 1 + 4 * nkeys          # description, keys
        ext = struct.pack('<I', typ).rstrip(b'\0').decode('latin1')[::-1]
        yield '/'.join(path + [name + '.' + ext]), p, sz


def read(path, name):
    for n, p, sz in entries(path):
        if n.lower() == name.lower():
            with open(path, 'rb') as f:
                f.seek(p)
                return f.read(sz)
    raise KeyError('%s: no %s' % (path, name))


def _selftest():
    """A two-level archive built by hand, read back."""
    import tempfile
    blob = b'MZ-data'
    # a resource: kind 0, pos, size, time, id, type 'DLL', 0 keys, name, description
    res = struct.pack('<IIII', 0, 0x7F + 12, len(blob), 0) + struct.pack('<III', 7, 0x444C4C, 0) \
        + b'CSHELL\x00\x00'
    sub = 0x7F + 12 + len(blob)
    root = struct.pack('<IIII', 1, sub, len(res), 0) + b'Code\x00'     # a directory
    hdr = b'\r\nRezMgr Version 1'.ljust(0x7F, b' ')
    data = hdr + struct.pack('<III', 1, sub + len(res), len(root)) + blob + res + root
    with tempfile.NamedTemporaryFile(suffix='.rez', delete=False) as f:
        f.write(data)
    try:
        assert list(entries(f.name)) == [('Code/CSHELL.DLL', 0x7F + 12, len(blob))], list(entries(f.name))
        assert read(f.name, 'code/cshell.dll') == blob
    finally:
        os.remove(f.name)
    print('lithrez selftest ok')


def main():
    if sys.argv[1:] == ['--selftest']:
        return _selftest()
    want = sys.argv[3].lower().split(',') if len(sys.argv) > 3 else None
    for n, p, sz in entries(sys.argv[1]):
        if want and n.rsplit('.', 1)[-1].lower() not in want:
            continue
        print(n, sz)
        if len(sys.argv) > 2:
            out = os.path.join(sys.argv[2], n)
            os.makedirs(os.path.dirname(out) or '.', exist_ok=True)
            with open(sys.argv[1], 'rb') as f:
                f.seek(p)
                open(out, 'wb').write(f.read(sz))


if __name__ == '__main__':
    main()
