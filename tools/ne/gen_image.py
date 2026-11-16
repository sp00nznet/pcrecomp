"""
gen_image.py - Build a Win16 NE target's flat memory image + layout header.

The lifted C normalises every relocated selector to its NE segment index
(SEG_n == (uint16_t)n). This places each segment n at SEG_SEGMENT_BASE[n] in
one flat image, copies its bytes in, and applies every INTERNAL relocation so
selector fields hold the segment index and offset fields hold the target
offset.

Import relocations are deliberately NOT applied: the lifter emits a far call
to an import as MODULE_API(cpu), or a call into another lifted module as that
module's segNNN_XXXX, so there is nothing in the image to fix up.

    python gen_image.py GAME.DLL --image work/mem_image.bin \\
                                 --header work/runtime/mem_layout.h

Several modules (the DLLs a host imports, then the host) go into one image with
one segment numbering; pass them in that order, or use ne_link.py, which does
this as part of lifting them together:

    python gen_image.py ENGINE.DLL GAME.EXE --image ... --header ...

The header then also carries RECOMP_MODULES[], one row per module, which is
what a runtime needs to run each DLL's LibMain, route a window procedure to the
right DGROUP, and answer GetModuleHandle.

Both outputs are derived from the target binary, so both are generated build
artefacts -- they belong in a gitignored directory and are never committed.

Upstreamed from catz/tools/, where paths and the include guard were hardcoded.
"""
import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ne_parse import parse_ne

PARA = 16
MAX_SEL = 0x10000
# Identity mode (NE_IDENTITY_SEL=1, a 32-bit host sharing one LDT with lifted
# 32-bit code, Windows 9x): segment n's selector is LDT index n, (n << 3) | 7,
# a real selector MapSL can resolve; gen_segments_h emits SEG_n the same way.
IDENTITY = os.environ.get('NE_IDENTITY_SEL') == '1'


def sel_value(n):
    return (n << 3) | 7 if IDENTITY else n  # selector table covers any 16-bit value (raw selectors too)
NE_DLL = 0x8000    # NE header flag: library module


def roundup(n, a):
    return (n + a - 1) // a * a


def chain_offsets(seg, r):
    """All fixup offsets for a relocation: walk the NE chain through seg.data
    (word at each location -> next, until 0xFFFF). Additive = single site."""
    if r.additive or not seg.data:
        return [r.offset]
    offs = []
    off = r.offset
    seen = set()
    data = seg.data
    while off != 0xFFFF and off not in seen and 0 <= off + 1 < len(data):
        seen.add(off)
        offs.append(off)
        off = struct.unpack_from('<H', data, off)[0]
    return offs


def renumber_all(nes):
    """Give modules consecutive segment numbers in the order given."""
    base = 0
    for ne in nes:
        ne.renumber(base)
        base += len(ne.segments)
    return nes


def build(nes, stack=0):
    """Lay out every segment of every (already renumbered) module.

    Returns (image, base, info). A module's DGROUP is sized for its statics
    PLUS its local heap and stack: the NE header carries those separately and
    the segment's own size covers only the statics. Sized at the statics alone,
    the guest allocator hands out blocks that overlap static data (on Catz,
    entries of the ball-rotation sin table were overwritten mid-run)."""
    segs = [s for ne in nes for s in ne.segments]
    nseg = max(s.index for s in segs)
    extra = {ne.auto_data_seg: ne.heap_size + ne.stack_size
             for ne in nes if ne.auto_data_seg}
    base = [0] * MAX_SEL
    cursor = PARA  # leave a guard paragraph at offset 0 (null selector)
    for s in segs:
        sz = min(max(s.actual_size, s.alloc_size, 1) + extra.get(s.index, 0), 0x10000)
        base[s.index] = cursor
        cursor += roundup(sz, PARA)

    # Optional stack segment, one past the last real segment. Kept inside the
    # mapped range (not in the guard region) so a stray unmapped access cannot
    # quietly scribble on the stack. A DLL has no stack of its own (ss:sp 0:0).
    host = nes[-1]
    stack_seg, stack_sp = host.ss, host.sp
    if stack:
        nseg += 1
        stack_seg = nseg
        base[stack_seg] = cursor
        cursor += roundup(stack, PARA)
        stack_sp = (stack - 2) & 0xFFFE

    # Guard region for unmapped/raw selectors (e.g. 0xF6) -> isolated 64K.
    guard_base = cursor
    cursor += 0x10000
    for sel in range(MAX_SEL):
        if base[sel] == 0:
            base[sel] = guard_base
    base[0] = guard_base

    image = bytearray(cursor)
    for s in segs:
        if s.data:
            image[base[s.index]:base[s.index] + len(s.data)] = s.data

    applied = skipped_move = 0
    for s in segs:
        for r in s.relocations:
            if (r.flags & 3) != 0:      # only internal references
                continue
            if r.target_seg == 0xFF:    # moveable entry point (entry table) - skip for now
                skipped_move += 1
                continue
            sel = r.target_seg          # normalized selector == segment index
            if not (1 <= sel <= nseg):
                continue
            for off in chain_offsets(s, r):
                addr = base[s.index] + off
                if addr + 1 >= len(image):
                    continue
                if r.src_type == 2:        # SELECTOR (2 bytes)
                    struct.pack_into('<H', image, addr, sel_value(sel))
                elif r.src_type == 5:      # OFFSET16 (2 bytes)
                    struct.pack_into('<H', image, addr, r.target_off & 0xFFFF)
                elif r.src_type == 3:      # FAR_PTR (off16 + sel16)
                    if addr + 3 < len(image):
                        struct.pack_into('<H', image, addr, r.target_off & 0xFFFF)
                        struct.pack_into('<H', image, addr + 2, sel_value(sel))
                elif r.src_type == 11:     # PTR48 (off32 + sel16)
                    if addr + 5 < len(image):
                        struct.pack_into('<I', image, addr, r.target_off & 0xFFFFFFFF)
                        struct.pack_into('<H', image, addr + 4, sel_value(sel))
                else:
                    continue
                applied += 1

    info = dict(nseg=nseg, guard_base=guard_base, stack_seg=stack_seg,
                stack_sp=stack_sp, applied=applied, skipped_move=skipped_move)
    return image, base, info


def header(nes, base, info, guard):
    host = nes[-1]
    h = ['/* mem_layout.h - Auto-generated by gen_image.py. Do not edit. */',
         f'#ifndef {guard}', f'#define {guard}', '#include <stdint.h>',
         f'#define RECOMP_IMAGE_SIZE {info["size"]}u',
         f'#define RECOMP_GUARD_BASE {info["guard_base"]}u',
         f'#define RECOMP_NUM_SEG {info["nseg"]}',
         f'#define RECOMP_ENTRY_SEG {host.cs}',
         f'#define RECOMP_ENTRY_IP 0x{host.ip:04X}u',
         f'#define RECOMP_STACK_SEG {info["stack_seg"]}',
         f'#define RECOMP_STACK_SP 0x{info["stack_sp"]:04X}u',
         f'#define RECOMP_AUTO_DATA_SEG {host.auto_data_seg}',
         '',
         '/* One row per module, in load order: DLLs first, the host last. */',
         'typedef struct {',
         '    const char *name;        /* module name (resident name ordinal 0) */',
         '    const char *file;        /* file it was lifted from */',
         '    uint16_t first_seg, last_seg;',
         '    uint16_t cs, ip;         /* entry: LibMain for a DLL, startup for an EXE; cs 0 = none */',
         '    uint16_t dgroup;         /* auto data segment, 0 = none */',
         '    uint16_t heap, stack;    /* local heap and stack sizes from the NE header */',
         '    uint8_t  is_dll;',
         '} RecompModule;',
         f'#define RECOMP_NUM_MODULES {len(nes)}',
         f'static const RecompModule RECOMP_MODULES[{len(nes)}] = {{']
    for ne in nes:
        first = ne.seg_base + 1
        last = ne.seg_base + len(ne.segments)
        h.append(f'    {{ "{ne.module_name}", "{os.path.basename(ne.filename)}", '
                 f'{first}, {last}, {ne.cs}, 0x{ne.ip:04X}, {ne.auto_data_seg}, '
                 f'0x{ne.heap_size:04X}, 0x{ne.stack_size:04X}, {1 if ne.flags & NE_DLL else 0} }},')
    h.append('};')
    # Compact base table for segment numbers 0..nseg; the runtime maps any
    # other selector to the guard base.
    h.append(f'static const uint32_t SEG_SEGMENT_BASE[{info["nseg"] + 1}] = {{')
    row = []
    for n in range(info['nseg'] + 1):
        row.append(str(base[n]))
        if len(row) == 12:
            h.append('    ' + ','.join(row) + ',')
            row = []
    if row:
        h.append('    ' + ','.join(row) + ',')
    h += ['};', f'#endif /* {guard} */']
    return '\n'.join(h) + '\n'


def write(nes, image_path, header_path, guard='RECOMP_WIN16_MEM_LAYOUT_H', stack=0):
    image, base, info = build(nes, stack)
    info['size'] = len(image)
    os.makedirs(os.path.dirname(os.path.abspath(image_path)), exist_ok=True)
    with open(image_path, 'wb') as f:
        f.write(image)
    os.makedirs(os.path.dirname(os.path.abspath(header_path)), exist_ok=True)
    with open(header_path, 'w', encoding='utf-8', newline='\n') as f:
        f.write(header(nes, base, info, guard))
    host = nes[-1]
    print(f'image: {len(image)} bytes ({len(image)/1048576:.2f} MB) -> {image_path}')
    print(f'guard_base=0x{info["guard_base"]:X}  segments={info["nseg"]}  '
          f'relocs applied={info["applied"]}  moveable skipped={info["skipped_move"]}')
    print(f'entry seg{host.cs}:0x{host.ip:04X}  stack seg{info["stack_seg"]}:0x{info["stack_sp"]:04X}')
    return info


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ne", nargs='+', help="the NE binaries, DLLs first and the host last")
    ap.add_argument("--image", required=True, help="flat memory image to write")
    ap.add_argument("--header", required=True, help="mem_layout.h to write")
    ap.add_argument("--guard", default="RECOMP_WIN16_MEM_LAYOUT_H")
    ap.add_argument("--stack", type=lambda v: int(v, 0), default=0,
                    help="append a stack segment of this many bytes; a DLL has "
                         "no stack of its own so its NE ss:sp is 0:0 and the "
                         "host has to map one")
    args = ap.parse_args()
    write(renumber_all([parse_ne(p) for p in args.ne]),
          args.image, args.header, args.guard, args.stack)


if __name__ == '__main__':
    main()
