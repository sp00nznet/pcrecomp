"""le_parse on a hand-built LE: objects placed, fixups applied, PE wrap readable.

The image is the smallest thing that exercises the format's two traps: the
page map's 24-bit big-endian page number, and fixups stored per page with a
page-relative source. One code object with a function and a two-entry jump
table (fixups 4 bytes apart, so they seed functions), and one data object
with a pointer to the function.

Run: py -3 tools/le/test_le_parse.py
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from le_parse import LEImage, code_pointers, to_pe  # noqa: E402

PAGE = 0x1000


def build():
    # Object 1 (code, linked at 0x10000): ret at +0, ret at +0x10, then a
    # table at +0x20 holding obj1+0 and obj1+0x10. Object 2 (data, linked at
    # 0x20000): a pointer to obj1+0x10.
    code = bytearray(PAGE)
    code[0] = code[0x10] = 0xC3
    data = bytearray(PAGE)
    hdr, objtab = 0x40, 0xC4
    pagemap = objtab + 2 * 24
    fixpage = pagemap + 2 * 4
    fixrec = fixpage + 3 * 4

    def rec(src_off, obj, off):     # 32-bit offset, internal, 8-bit object, 16-bit offset
        return struct.pack("<BBhBH", 0x07, 0x00, src_off, obj, off)
    page1 = rec(0x20, 1, 0) + rec(0x24, 1, 0x10)
    page2 = rec(0x00, 1, 0x10)
    loader_end = fixrec + len(page1) + len(page2)
    data_pages = (hdr + loader_end + 0x1FF) & ~0x1FF

    le = bytearray(loader_end)
    le[0:2] = b"LE"
    u32 = lambda o, v: struct.pack_into("<I", le, o, v)
    u32(0x14, 2)                              # pages
    u32(0x18, 1); u32(0x1C, 0)                # eip = obj1:0
    u32(0x20, 2); u32(0x24, 0x100)            # esp = obj2:0x100
    u32(0x28, PAGE); u32(0x2C, PAGE)          # page size, last page size
    u32(0x40, objtab); u32(0x44, 2)
    u32(0x48, pagemap)
    u32(0x68, fixpage); u32(0x6C, fixrec)
    u32(0x80, data_pages)
    struct.pack_into("<6I", le, objtab, PAGE, 0x10000, 0x2005, 1, 1, 0)
    struct.pack_into("<6I", le, objtab + 24, PAGE, 0x20000, 0x2003, 2, 1, 0)
    le[pagemap:pagemap + 8] = bytes([0, 0, 1, 0, 0, 0, 2, 0])   # big-endian page numbers
    struct.pack_into("<3I", le, fixpage, 0, len(page1), len(page1) + len(page2))
    le[fixrec:fixrec + len(page1) + len(page2)] = page1 + page2

    mz = bytearray(hdr)
    mz[0:2] = b"MZ"
    struct.pack_into("<I", mz, 0x3C, hdr)
    out = mz + le
    out += b"\0" * (data_pages - len(out))
    return bytes(out + code + data)


def main():
    le = LEImage(build())
    bad = 0

    def check(what, ok):
        nonlocal bad
        if not ok:
            print("FAIL", what)
            bad += 1

    img, lo, objs, relocs = le.build(0x400000)
    r32 = lambda va: struct.unpack_from("<I", img, va - lo)[0]
    check("objects moved to the base", objs[0]["addr"] == 0x400000 and objs[1]["addr"] == 0x410000)
    check("entry follows the move", le.entry(objs) == 0x400000)
    check("table fixups applied", r32(0x400020) == 0x400000 and r32(0x400024) == 0x400010)
    check("data fixup applied", r32(0x410000) == 0x400010)
    check("code bytes kept", img[0] == 0xC3 and img[0x10] == 0xC3)
    check("table entries seed functions", code_pointers(objs, relocs, img, lo) == [0x400000, 0x400010])

    pe = to_pe(img, lo, objs, relocs, le.entry(objs))
    e = struct.unpack_from("<I", pe, 0x3C)[0]
    base, = struct.unpack_from("<I", pe, e + 0x18 + 28)
    ep, = struct.unpack_from("<I", pe, e + 0x18 + 16)
    check("PE signature", pe[e:e + 4] == b"PE\0\0")
    check("PE entry point", base + ep == 0x400000)

    linked, *_ = le.build(None)
    check("default keeps the linker's bases", struct.unpack_from("<I", linked, 0x20)[0] == 0x10000)

    print("%s: %d failed" % ("FAIL" if bad else "ok", bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
