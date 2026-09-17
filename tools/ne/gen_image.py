"""
gen_image.py - Build a Win16 NE target's flat memory image + layout header.

The lifted C normalises every relocated selector to its NE segment index
(SEG_n == (uint16_t)n). This places each segment n at SEG_SEGMENT_BASE[n] in
one flat image, copies its bytes in, and applies every INTERNAL relocation so
selector fields hold the segment index and offset fields hold the target
offset.

Import relocations are deliberately NOT applied: the lifter emits a far call
to an import as MODULE_API(cpu), so there is nothing in the image to fix up.

    python gen_image.py GAME.DLL --image work/mem_image.bin \\
                                 --header work/runtime/mem_layout.h

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
MAX_SEL = 0x10000  # selector table covers any 16-bit value (raw selectors too)


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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ne", help="the NE binary to build an image for")
    ap.add_argument("--image", required=True, help="flat memory image to write")
    ap.add_argument("--header", required=True, help="mem_layout.h to write")
    ap.add_argument("--guard", default="RECOMP_WIN16_MEM_LAYOUT_H")
    ap.add_argument("--stack", type=lambda v: int(v, 0), default=0,
                    help="append a stack segment of this many bytes; a DLL has "
                         "no stack of its own so its NE ss:sp is 0:0 and the "
                         "host has to map one")
    args = ap.parse_args()
    exe = args.ne
    ne = parse_ne(exe)

    nseg = len(ne.segments)
    region = [0] * (nseg + 1)      # region size per segment number
    base = [0] * (MAX_SEL)         # SEG_BASE[selector] -> flat offset

    # Layout: each segment gets max(actual,alloc) bytes, paragraph-aligned.
    cursor = PARA  # leave a guard paragraph at offset 0 (null selector)
    for s in ne.segments:
        sz = max(s.actual_size, s.alloc_size, 1)
        region[s.index] = roundup(sz, PARA)
        base[s.index] = cursor
        cursor += region[s.index]

    # Optional stack segment, one past the last real segment. Kept inside the
    # mapped range (not in the guard region) so a stray unmapped access cannot
    # quietly scribble on the stack.
    stack_seg, stack_sp = ne.ss, ne.sp
    if args.stack:
        stack_seg = nseg + 1
        region.append(roundup(args.stack, PARA))
        base[stack_seg] = cursor
        cursor += region[stack_seg]
        stack_sp = (args.stack - 2) & 0xFFFE
        nseg = stack_seg

    # Guard region for unmapped/raw selectors (e.g. 0xF6) -> isolated 64K.
    guard_base = cursor
    cursor += 0x10000
    image_size = cursor
    for sel in range(MAX_SEL):
        if base[sel] == 0:
            base[sel] = guard_base
    base[0] = guard_base  # null selector -> guard

    image = bytearray(image_size)

    # Copy segment data
    for s in ne.segments:
        if s.data:
            b = base[s.index]
            image[b:b + len(s.data)] = s.data

    # Apply INTERNAL relocations
    applied = 0
    skipped_move = 0
    for s in ne.segments:
        for r in s.relocations:
            if (r.flags & 3) != 0:      # only internal references
                continue
            if r.target_seg == 0xFF:    # moveable entry point (entry table) - skip for now
                skipped_move += 1
                continue
            tseg = r.target_seg
            if not (1 <= tseg <= nseg):
                continue
            sel = tseg                  # normalized selector == segment index
            for off in chain_offsets(s, r):
                addr = base[s.index] + off
                if addr + 1 >= image_size:
                    continue
                if r.src_type == 2:        # SELECTOR (2 bytes)
                    struct.pack_into('<H', image, addr, sel)
                elif r.src_type == 5:      # OFFSET16 (2 bytes)
                    struct.pack_into('<H', image, addr, r.target_off & 0xFFFF)
                elif r.src_type == 3:      # FAR_PTR (off16 + sel16)
                    if addr + 3 < image_size:
                        struct.pack_into('<H', image, addr, r.target_off & 0xFFFF)
                        struct.pack_into('<H', image, addr + 2, sel)
                elif r.src_type == 11:     # PTR48 (off32 + sel16)
                    if addr + 5 < image_size:
                        struct.pack_into('<I', image, addr, r.target_off & 0xFFFFFFFF)
                        struct.pack_into('<H', image, addr + 4, sel)
                else:
                    continue
                applied += 1

    # Write image
    img_path = args.image
    os.makedirs(os.path.dirname(os.path.abspath(img_path)), exist_ok=True)
    with open(img_path, 'wb') as f:
        f.write(image)

    # Write layout header
    hdr = []
    hdr.append('/* mem_layout.h - Auto-generated by gen_image.py. Do not edit. */')
    hdr.append(f'#ifndef {args.guard}')
    hdr.append(f'#define {args.guard}')
    hdr.append('#include <stdint.h>')
    hdr.append(f'#define RECOMP_IMAGE_SIZE {image_size}u')
    hdr.append(f'#define RECOMP_GUARD_BASE {guard_base}u')
    hdr.append(f'#define RECOMP_NUM_SEG {nseg}')
    hdr.append(f'#define RECOMP_ENTRY_SEG {ne.cs}')
    hdr.append(f'#define RECOMP_ENTRY_IP 0x{ne.ip:04X}u')
    hdr.append(f'#define RECOMP_STACK_SEG {stack_seg}')
    hdr.append(f'#define RECOMP_STACK_SP 0x{stack_sp:04X}u')
    hdr.append(f'#define RECOMP_AUTO_DATA_SEG {ne.auto_data_seg}')
    # Emit a compact base table for segment numbers 0..nseg; runtime expands
    # any other selector to the guard base.
    hdr.append(f'static const uint32_t SEG_SEGMENT_BASE[{nseg + 1}] = {{')
    row = []
    for n in range(0, nseg + 1):
        row.append(str(base[n]))
        if len(row) == 12:
            hdr.append('    ' + ','.join(row) + ',')
            row = []
    if row:
        hdr.append('    ' + ','.join(row) + ',')
    hdr.append('};')
    hdr.append(f'#endif /* {args.guard} */')

    os.makedirs(os.path.dirname(os.path.abspath(args.header)), exist_ok=True)
    with open(args.header, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(hdr) + '\n')

    print(f'image: {image_size} bytes ({image_size/1048576:.2f} MB) -> {img_path}')
    print(f'guard_base=0x{guard_base:X}  segments={nseg}  relocs applied={applied}  moveable skipped={skipped_move}')
    print(f'entry seg{ne.cs}:0x{ne.ip:04X}  stack seg{stack_seg}:0x{stack_sp:04X}')


if __name__ == '__main__':
    main()
