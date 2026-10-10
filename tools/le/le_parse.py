"""
le_parse.py - LE (Linear Executable) parser and flat-image builder

LE is the 32-bit format that DOS extenders load: DOS/4GW, DOS/32A, PMODE/W,
CauseWay. Most Watcom-built DOS games of 1993-97 ship as an MZ stub plus an
LE image. This reads the object table, the page map and the fixup tables,
and lays the objects out as one flat little-endian image with every internal
fixup applied, so disasm32 and lift32 can treat it like any 32-bit image.

The format reference is IBM's "LX - Linear eXecutable Module Format
Description" (LE differs only in the page map entry and the last-page field).

Why we apply the fixups ourselves: a DOS extender loads the objects wherever
DPMI hands it memory and patches every absolute address. We pick the load
address instead (`--base`), so the lifted code and the runtime agree on one
layout and nothing is patched at run time. The default keeps the linker's
own object bases.

The fixup list is also the best function-discovery seed an LE image has: each
32-bit offset fixup whose target lands in an executable object is a stored
code address (a call table, a jump table, a callback), the LE equivalent of
the DIR64 relocation sweep in generate64.

Usage:
    python le_parse.py MAIN.EXE                      # summary
    python le_parse.py MAIN.EXE --image out.bin --json out.json [--base 0x400000]
"""

import argparse
import json
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "disasm"))
from disasm32 import NOT_COMPILED  # noqa: E402  instructions that mean "this is data"

# Fixup source types (low nibble of the source byte).
SRC_BYTE, SRC_SEL16, SRC_PTR1616, SRC_OFF16 = 0x00, 0x02, 0x03, 0x05
SRC_PTR1632, SRC_OFF32, SRC_REL32 = 0x06, 0x07, 0x08
SRC_SIZES = {SRC_BYTE: 1, SRC_SEL16: 2, SRC_PTR1616: 4, SRC_OFF16: 2,
             SRC_PTR1632: 6, SRC_OFF32: 4, SRC_REL32: 4}

OBJ_READ, OBJ_WRITE, OBJ_EXEC, OBJ_BIG = 0x1, 0x2, 0x4, 0x2000


class LEError(Exception):
    pass


class LEImage:
    def __init__(self, data):
        self.data = data
        if data[:2] != b"MZ":
            raise LEError("not an MZ executable")
        self.hdr = struct.unpack_from("<I", data, 0x3C)[0]
        sig = data[self.hdr:self.hdr + 2]
        if sig not in (b"LE", b"LX"):
            raise LEError("no LE/LX header at e_lfanew (found %r)" % sig)
        self.lx = sig == b"LX"
        u32 = lambda o: struct.unpack_from("<I", data, self.hdr + o)[0]
        self.npages = u32(0x14)
        self.eip_obj, self.eip = u32(0x18), u32(0x1C)
        self.esp_obj, self.esp = u32(0x20), u32(0x24)
        self.page_size = u32(0x28)
        # LE: size of the last page. LX: page offset shift.
        self.last_page = u32(0x2C)
        self.objtab, self.nobj = u32(0x40), u32(0x44)
        self.pagemap = u32(0x48)
        self.fixpage, self.fixrec = u32(0x68), u32(0x6C)
        self.nimports = u32(0x74)
        self.data_pages = u32(0x80)  # from the start of the file, not the header
        self.objects = []
        for i in range(self.nobj):
            vs, base, fl, pti, npe, _ = struct.unpack_from(
                "<6I", data, self.hdr + self.objtab + 24 * i)
            self.objects.append(dict(index=i + 1, vsize=vs, base=base,
                                     flags=fl, page_index=pti, npages=npe))

    def page_file_offset(self, page):
        """File offset and length of logical page `page` (1-based)."""
        e = self.data[self.hdr + self.pagemap + 4 * (page - 1):][:4]
        if self.lx:
            off, size, flags = struct.unpack("<IHH", self.data[
                self.hdr + self.pagemap + 8 * (page - 1):][:8])
            if flags not in (0, 3):  # 3 = zero-filled, 0 = legal physical
                raise LEError("LX page %d has unsupported flags %#x" % (page, flags))
            return (self.data_pages + (off << self.last_page), size)
        # LE: a 24-bit big-endian physical page number, then a flags byte.
        num = (e[0] << 16) | (e[1] << 8) | e[2]
        if e[3] not in (0,):
            raise LEError("LE page %d has unsupported flags %#x" % (page, e[3]))
        size = self.last_page if page == self.npages else self.page_size
        return (self.data_pages + (num - 1) * self.page_size, size)

    def object_bytes(self, obj):
        buf = bytearray(obj["vsize"])
        for k in range(obj["npages"]):
            off, size = self.page_file_offset(obj["page_index"] + k)
            chunk = self.data[off:off + size]
            dst = k * self.page_size
            n = max(0, min(len(chunk), len(buf) - dst))
            buf[dst:dst + n] = chunk[:n]
        return buf

    def fixups(self):
        """Yield (page, src_type, src_offsets, target) for every fixup record.

        target is ("internal", obj, offset, additive) or ("import", ...).
        src_offsets are page-relative and may be negative (a fixup that
        straddles the start of the page is repeated on both pages).
        """
        d, base = self.data, self.hdr + self.fixrec
        for page in range(1, self.npages + 1):
            lo, hi = struct.unpack_from("<II", d, self.hdr + self.fixpage + 4 * (page - 1))
            p, end = base + lo, base + hi
            while p < end:
                src, flags = d[p], d[p + 1]
                p += 2
                if src & 0x20:
                    count = d[p]
                    p += 1
                else:
                    srcoffs = [struct.unpack_from("<h", d, p)[0]]
                    p += 2
                kind = flags & 3
                if kind != 0:
                    raise LEError("page %d: import/entry fixups (type %d) are not "
                                  "supported; DOS extender images have none" % (page, kind))
                if flags & 0x40:
                    tobj = struct.unpack_from("<H", d, p)[0]; p += 2
                else:
                    tobj = d[p]; p += 1
                stype = src & 0x0F
                toff = 0
                if stype != SRC_SEL16:
                    if flags & 0x10:
                        toff = struct.unpack_from("<I", d, p)[0]; p += 4
                    else:
                        toff = struct.unpack_from("<H", d, p)[0]; p += 2
                add = 0
                if flags & 0x04:
                    if flags & 0x20:
                        add = struct.unpack_from("<I", d, p)[0]; p += 4
                    else:
                        add = struct.unpack_from("<H", d, p)[0]; p += 2
                if src & 0x20:
                    srcoffs = list(struct.unpack_from("<%dh" % count, d, p))
                    p += 2 * count
                yield page, src, srcoffs, ("internal", tobj, toff, add)

    def build(self, base=None):
        """Return (image, lo, objects, relocs) with fixups applied.

        base: where the lowest object goes; None keeps the linker's bases.
        relocs: list of dicts {at, type, target} in final linear addresses.
        """
        lo0 = min(o["base"] for o in self.objects)
        delta = 0 if base is None else base - lo0
        objs = [dict(o, addr=o["base"] + delta) for o in self.objects]
        lo = min(o["addr"] for o in objs)
        hi = max(o["addr"] + o["vsize"] for o in objs)
        img = bytearray(hi - lo)
        for o in objs:
            b = self.object_bytes(o)
            img[o["addr"] - lo:o["addr"] - lo + len(b)] = b
        # Which object owns each logical page: fixups are page-relative.
        page_obj = {}
        for o in objs:
            for k in range(o["npages"]):
                page_obj[o["page_index"] + k] = (o, k * self.page_size)
        relocs, seen = [], set()
        for page, src, srcoffs, (_, tobj, toff, add) in self.fixups():
            if page not in page_obj:
                continue
            o, pbase = page_obj[page]
            stype = src & 0x0F
            target = objs[tobj - 1]["addr"] + toff + add
            for so in srcoffs:
                off = pbase + so
                if off < 0 or off + SRC_SIZES.get(stype, 4) > o["vsize"]:
                    continue  # the other half of a page-straddling fixup
                at = o["addr"] + off
                if (at, stype) in seen:
                    continue
                seen.add((at, stype))
                i = at - lo
                if stype == SRC_OFF32:
                    struct.pack_into("<I", img, i, target & 0xFFFFFFFF)
                elif stype == SRC_REL32:
                    struct.pack_into("<I", img, i, (target - (at + 4)) & 0xFFFFFFFF)
                elif stype == SRC_PTR1632:
                    struct.pack_into("<I", img, i, target & 0xFFFFFFFF)
                    # selector half left as linked; flat-model code never loads it
                elif stype == SRC_OFF16:
                    struct.pack_into("<H", img, i, target & 0xFFFF)
                elif stype in (SRC_SEL16, SRC_PTR1616, SRC_BYTE):
                    pass  # selectors: meaningless in a flat image, the runtime owns them
                else:
                    raise LEError("unknown fixup source type %#x at %#x" % (src, at))
                relocs.append(dict(at=at, type=stype, target=target))
        relocs.sort(key=lambda r: r["at"])
        return img, lo, objs, relocs

    def entry(self, objs):
        return objs[self.eip_obj - 1]["addr"] + self.eip

    def stack(self, objs):
        return objs[self.esp_obj - 1]["addr"] + self.esp


def _is_mem_operand(img, lo, at):
    """True if the fixup at `at` is the disp32 of an absolute memory operand.

    Watcom keeps data in the code object (the startup's saved ds, switch
    tables), and an instruction that reads or writes it carries a fixup that
    points into code without being a code address. The byte before such a
    disp32 is a ModRM with mod=00 rm=101 ([disp32]), or a SIB with base=101
    after a ModRM with rm=100 ([disp32 + index*scale]). An immediate never
    follows either: push imm32 is 68, mov r32, imm32 is B8-BF.
    """
    i = at - lo
    if i < 2:
        return False
    b1, b2 = img[i - 1], img[i - 2]
    # Also the base of a switch table, `jmp/call [reg + disp32]` (FF /4, /2
    # with mod=10): Watcom keeps the table right after the jump, and seeding
    # its start splits the switch's function in two. mov r32, imm32 (B8-BF)
    # reads as /7 and is not caught.
    table = b2 == 0xFF and (b1 & 0xC0) == 0x80 and ((b1 >> 3) & 7) in (2, 4) and (b1 & 7) != 4
    return table or (b1 & 0xC7) == 0x05 or ((b1 & 0x07) == 0x05 and (b2 & 0xC7) == 0x04)


def _plausible_code(img, lo, target, window=4096):
    """Does `target` decode as compiled code, up to a ret or jmp?

    The last check on a seed: Watcom keeps strings and byte tables in its code
    object, and decoded as code they meet an instruction no compiler emits
    (a string is `arpl`, `bound`, BCD) or stop decoding before a terminator.
    """
    import capstone
    i = target - lo
    if img[i:i + 2] == b"\0\0":
        return False
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    for ins in md.disasm(bytes(img[i:i + window]), target):
        if ins.mnemonic in NOT_COMPILED:
            return False
        if ins.mnemonic in ("ret", "retf", "jmp", "iretd"):
            return True
    return False


def code_pointers(objs, relocs, img=None, lo=0):
    """32-bit offset fixups whose target is in an executable object.

    With the image, data kept in the code object is left out: targets named
    only by an instruction operand in code, and targets that do not decode as
    plausible code.
    """
    ex = [(o["addr"], o["addr"] + o["vsize"]) for o in objs if o["flags"] & OBJ_EXEC]
    in_ex = lambda v: any(a <= v < b for a, b in ex)
    # A fixup inside code is an instruction's operand or an entry of a table
    # kept in code (Watcom's switch tables). Only the tables name code for
    # certain; an operand may as well point at a string, and disasm32 probes
    # code immediates itself. A table entry has a neighbour 4 bytes away.
    at = {r["at"] for r in relocs if r["type"] == SRC_OFF32}
    def vouches(r):
        if not in_ex(r["at"]):
            return True
        if img is None:
            return True
        return (r["at"] - 4 in at or r["at"] + 4 in at) and not _is_mem_operand(img, lo, r["at"])
    out = {r["target"] for r in relocs if r["type"] == SRC_OFF32 and in_ex(r["target"]) and vouches(r)}
    if img is not None:
        out = {t for t in out if _plausible_code(img, lo, t)}
    return sorted(out)


def to_pe(img, lo, objs, relocs, entry):
    """Wrap the flat image as a minimal PE32, so the PE pipeline runs unchanged.

    disasm32, lift32 and generate all read PE. Rather than teach each of them
    a second container, the LE image is re-wrapped: one section per object at
    its final address, the fixups as a .reloc directory (HIGHLOW), no imports.
    The result is an analysis input, never something to run.
    """
    FA, SA = 0x200, 0x1000
    align = lambda v, a: (v + a - 1) & ~(a - 1)
    image_base = (lo - SA) & ~0xFFFF
    # .reloc: one block per 4 KB page with HIGHLOW entries. disasm32 seeds
    # functions from relocations into code, so those go through the same
    # filter as code_pointers: a fixup to data kept in code is left out.
    cps = set(code_pointers(objs, relocs, img, lo))
    ex = [(o["addr"], o["addr"] + o["vsize"]) for o in objs if o["flags"] & OBJ_EXEC]
    pages = {}
    for r in relocs:
        if r["type"] == SRC_OFF32 and (r["target"] in cps or
                                       not any(a <= r["target"] < b for a, b in ex)):
            pages.setdefault((r["at"] - image_base) & ~0xFFF, []).append((r["at"] - image_base) & 0xFFF)
    reloc = bytearray()
    for prva in sorted(pages):
        ents = [(3 << 12) | o for o in sorted(pages[prva])]
        if len(ents) % 2:
            ents.append(0)
        reloc += struct.pack("<II", prva, 8 + 2 * len(ents)) + struct.pack("<%dH" % len(ents), *ents)
    end = max(o["addr"] + o["vsize"] for o in objs)
    secs = [(".obj%d" % o["index"], o["addr"] - image_base, o["vsize"],
             bytes(img[o["addr"] - lo:o["addr"] - lo + o["vsize"]]),
             0x60000020 if o["flags"] & OBJ_EXEC else 0xC0000040) for o in objs]
    secs.append((".reloc", align(end - image_base, SA), len(reloc), bytes(reloc), 0x42000040))
    hdr_size = align(0x40 + 4 + 20 + 0xE0 + 40 * len(secs), FA)
    size_of_image = align(secs[-1][1] + secs[-1][2], SA)
    out = bytearray(hdr_size)
    out[0:2] = b"MZ"
    struct.pack_into("<I", out, 0x3C, 0x40)
    out[0x40:0x44] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", out, 0x44, 0x14C, len(secs), 0, 0, 0, 0xE0, 0x0103)
    code = [s for s in secs if s[4] & 0x20]
    opt = struct.pack("<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
                      0x10B, 6, 0, sum(s[2] for s in code), 0, 0,
                      entry - image_base, code[0][1], secs[-1][1], image_base, SA, FA,
                      4, 0, 0, 0, 4, 0, 0, size_of_image, hdr_size, 0, 3, 0,
                      0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    dirs = [(0, 0)] * 16
    dirs[5] = (secs[-1][1], len(reloc))
    opt += b"".join(struct.pack("<II", *d) for d in dirs)
    out[0x58:0x58 + len(opt)] = opt
    p = 0x58 + 0xE0
    raw = hdr_size
    for name, rva, vs, data, ch in secs:
        rs = align(len(data), FA)
        struct.pack_into("<8sIIIIIIHHI", out, p, name.encode(), vs, rva, rs, raw, 0, 0, 0, 0, ch)
        p += 40
        raw += rs
    for _, _, _, data, _ in secs:
        out += data + b"\0" * (align(len(data), FA) - len(data))
    return bytes(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("exe")
    ap.add_argument("--base", type=lambda s: int(s, 0), default=None,
                    help="load the lowest object here (default: the linker's base)")
    ap.add_argument("--image", help="write the flat image here")
    ap.add_argument("--json", help="write objects, entry, stack and fixups here")
    ap.add_argument("--pe", help="write the image re-wrapped as a PE32 for disasm32/lift32")
    ap.add_argument("--seeds", help="write the code pointers as a disasm32 --seed-functions list")
    a = ap.parse_args(argv)
    le = LEImage(open(a.exe, "rb").read())
    img, lo, objs, relocs = le.build(a.base)
    cps = code_pointers(objs, relocs, img, lo)
    print("%s image, %d objects, %d pages of %#x, %d fixups applied"
          % ("LX" if le.lx else "LE", len(objs), le.npages, le.page_size, len(relocs)))
    for o in objs:
        fl = "".join(c for c, b in (("R", OBJ_READ), ("W", OBJ_WRITE), ("X", OBJ_EXEC),
                                     ("32", OBJ_BIG)) if o["flags"] & b)
        print("  obj %d  %#010x..%#010x  %-4s  (linked at %#x)"
              % (o["index"], o["addr"], o["addr"] + o["vsize"], fl, o["base"]))
    print("  entry %#x  stack %#x  code pointers in fixups: %d"
          % (le.entry(objs), le.stack(objs), len(cps)))
    if a.image:
        open(a.image, "wb").write(img)
    if a.pe:
        open(a.pe, "wb").write(to_pe(img, lo, objs, relocs, le.entry(objs)))
    if a.seeds:
        json.dump(["0x%x" % c for c in cps], open(a.seeds, "w"))
    if a.json:
        json.dump(dict(format="LX" if le.lx else "LE", image_base=lo, image_size=len(img),
                       entry=le.entry(objs), stack=le.stack(objs),
                       objects=[{k: o[k] for k in ("index", "addr", "vsize", "flags", "base")}
                                for o in objs],
                       code_pointers=cps, fixups=relocs),
                  open(a.json, "w"), indent=1)


if __name__ == "__main__":
    sys.exit(main())
