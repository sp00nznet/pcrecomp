"""
ne_decode.py - NE-aware 16-bit Disassembler

Disassembles all code segments from an NE executable, resolving relocation
targets so cross-segment far calls, imports, and data references are annotated
inline. Builds on the shared 16-bit decoder (disasm/decode16.py) and x87
decoder (disasm/fpu_decode.py).

Function detection is a basic-block model: prologue sites, every relative
branch target, and far-call targets carried by relocations all become entry
points. Optionally consumes an analyzer's exported code map (see
tools/ida/ida_export.py) for byte-accurate instruction heads on binaries with
data-in-code.

Usage:
    python ne_decode.py <ne_exe> [--seg N] [--summary] [--functions]
                        [--ida-json funcs.json]

The code map can also be supplied via the PCRECOMP_IDA_JSON environment
variable.
"""

import sys
import os
import struct
import json
from dataclasses import dataclass, field
from typing import Optional

# Import the shared decoders from the sibling disasm/ package.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'disasm')))
sys.path.insert(0, os.path.dirname(__file__))

from decode16 import Decoder, Instruction, OpType, Operand
from ne_parse import parse_ne, NEHeader, Segment, Relocation
from fpu_decode import decode_fpu, format_fpu


@dataclass
class RelocAnnotation:
    """Annotation for a relocation fixup at a specific offset."""
    offset: int              # Offset within segment
    reloc: Relocation        # The relocation entry
    target_desc: str = ''    # Human-readable description


@dataclass
class NEFunction:
    """A detected function within an NE code segment."""
    seg_num: int            # 1-based segment number
    offset: int             # Offset within segment
    end: int                # End offset (exclusive)
    size: int = 0
    is_far: bool = False    # Uses RETF
    local_size: int = 0     # Stack frame size
    calls: list = field(default_factory=list)       # (seg, off) near/far call targets
    far_calls: list = field(default_factory=list)    # (target_seg, target_off) via relocation
    inst_count: int = 0

    @property
    def label(self):
        return f"seg{self.seg_num:03d}_{self.offset:04X}"


def build_reloc_map(seg: Segment, ne: NEHeader) -> dict:
    """Build a map of offset -> RelocAnnotation for a segment."""
    reloc_map = {}
    for r in seg.relocations:
        target_type = r.flags & 3
        if target_type == 0:  # Internal
            if r.target_seg == 0xFF:
                desc = f"entry#{r.ordinal}"
            else:
                target_seg = ne.segments[r.target_seg - 1] if r.target_seg <= len(ne.segments) else None
                if target_seg:
                    seg_type = 'CODE' if target_seg.is_code else 'DATA'
                    desc = f"seg{r.target_seg}:{r.target_off:04X} ({seg_type})"
                else:
                    desc = f"seg{r.target_seg}:{r.target_off:04X}"
        elif target_type == 1:  # Import by ordinal
            mod_name = ne.module_names[r.module_idx - 1] if r.module_idx <= len(ne.module_names) else f"mod{r.module_idx}"
            desc = f"{mod_name}.{r.ordinal}"
        elif target_type == 2:  # Import by name
            mod_name = ne.module_names[r.module_idx - 1] if r.module_idx <= len(ne.module_names) else f"mod{r.module_idx}"
            desc = f"{mod_name}@{r.ordinal}"
        else:
            desc = f"OSFIXUP({r.target_seg},{r.target_off})"

        src_name = r.src_name
        full_desc = f"[{src_name}] {desc}"

        # NE relocations are chained: the record stores only the HEAD offset.
        # At each fixup location the (pre-relocation) WORD holds the offset of
        # the next location needing the same fixup, terminated by 0xFFFF.
        # Additive relocations are not chained (the location holds an addend).
        if r.additive or not seg.data:
            reloc_map[r.offset] = RelocAnnotation(offset=r.offset, reloc=r,
                                                  target_desc=full_desc)
            continue

        off = r.offset
        visited = set()
        while off != 0xFFFF and off not in visited and 0 <= off + 1 < len(seg.data):
            visited.add(off)
            reloc_map[off] = RelocAnnotation(offset=off, reloc=r, target_desc=full_desc)
            off = struct.unpack_from('<H', seg.data, off)[0]

    return reloc_map


def load_ida_data(ne: NEHeader, path: str = None) -> dict:
    """Load an analyzer-exported code map (see tools/ida/ida_export.py) if
    present. Maps NE segment number (str) -> {functions, heads, code_ranges}.
    Resolution order: explicit `path` arg, then the PCRECOMP_IDA_JSON env var.
    Cached on the NEHeader; returns {} when no file is found."""
    cache = getattr(ne, '_ida_data', None)
    if cache is not None:
        return cache
    path = path or os.environ.get('PCRECOMP_IDA_JSON')
    data = {}
    if path:
        try:
            with open(path, encoding='utf-8') as f:
                data = json.load(f)
        except (OSError, ValueError):
            data = {}
    ne._ida_data = data
    return data


def collect_internal_code_targets(ne: NEHeader) -> dict:
    """Map (1-based code seg index) -> set of offsets that are far-call/far-ptr
    targets from ANY segment's relocations. These are authoritative function
    entry points. Cached on the NEHeader. Only FAR_PTR(3)/PTR48(11) internal
    relocations carry a real code offset; SELECTOR(2) loads only set a segment."""
    cache = getattr(ne, '_internal_code_targets', None)
    if cache is not None:
        return cache
    m = {}
    for s in ne.segments:
        for r in s.relocations:
            if (r.flags & 3) != 0:          # not an internal reference
                continue
            if r.src_type not in (3, 11):   # FAR_PTR / PTR48 only
                continue
            tseg = r.target_seg
            if tseg == 0xFF or not (1 <= tseg <= len(ne.segments)):
                continue
            if ne.segments[tseg - 1].is_code:
                m.setdefault(tseg, set()).add(r.target_off)
    ne._internal_code_targets = m
    return m


_BRANCH = frozenset((
    'call', 'jmp',
    'jo', 'jno', 'jb', 'jae', 'je', 'jne', 'jbe', 'ja',
    'js', 'jns', 'jp', 'jnp', 'jl', 'jge', 'jle', 'jg',
    'loop', 'loopz', 'loopnz', 'jcxz',
))


def detect_functions(seg: Segment, instructions: list, forced_entries=None) -> list:
    """Detect function boundaries.

    Entry points are the union of:
      - prologue sites (push bp / mov bp, sp),
      - all call targets (near calls within this segment + far-call targets
        into this segment via relocations),
      - the first instruction (to capture any leading code).
    Functions span [entry, next_entry); this guarantees every call target that
    lands on a real instruction boundary becomes a defined function."""
    forced_entries = forced_entries or set()
    if not instructions:
        return []

    inst_off = [inst.offset - seg.file_offset for inst in instructions]
    valid = set(inst_off)
    # offset -> instruction index, for frame-size lookup
    idx_by_off = {off: i for i, off in enumerate(inst_off)}

    starts = set()

    # Prologue-based starts + near-call targets within this segment
    for i, inst in enumerate(instructions):
        local_off = inst_off[i]
        if (inst.mnemonic == 'push' and inst.op1 and
                inst.op1.type == OpType.REG16 and inst.op1.reg == 5):  # BP
            if i + 1 < len(instructions):
                nxt = instructions[i + 1]
                if (nxt.mnemonic == 'mov' and
                        nxt.op1 and nxt.op1.type == OpType.REG16 and nxt.op1.reg == 5 and
                        nxt.op2 and nxt.op2.type == OpType.REG16 and nxt.op2.reg == 4):
                    starts.add(local_off)
        if (inst.mnemonic in _BRANCH and inst.op1 and
                inst.op1.type in (OpType.REL8, OpType.REL16)):
            # Every relative branch target becomes an entry (basic-block model).
            # Over-splitting is safe: all state lives in the CPU struct/memory,
            # and fall-through/jmp/Jcc tail calls preserve control flow across
            # the split, so any cross-function branch resolves to a tail call.
            tgt = inst.op1.disp
            if tgt in valid:
                starts.add(tgt)

        # Immediate values that are valid instruction boundaries are likely
        # near function pointers (method tables, callbacks) loaded as bare
        # immediates with no relocation. Seed them so indirect near calls
        # through them resolve. Safe under the basic-block model.
        for opnd in (inst.op1, inst.op2):
            if opnd and opnd.type == OpType.IMM16:
                v = opnd.disp & 0xFFFF
                if v >= 0x10 and v in valid:
                    starts.add(v)

    # Far-call targets into this segment (only ones on instruction boundaries)
    for off in forced_entries:
        if off in valid:
            starts.add(off)

    # Always capture leading code
    starts.add(inst_off[0])

    starts = sorted(starts)
    functions = []
    for si, start in enumerate(starts):
        end = starts[si + 1] if si + 1 < len(starts) else seg.actual_size
        func_insts = [instructions[i] for i in range(idx_by_off[start], len(instructions))
                      if inst_off[i] < end]
        if not func_insts:
            continue
        is_far = any(fi.mnemonic in ('retf', 'iret') for fi in func_insts)
        func = NEFunction(seg_num=seg.index, offset=start, end=end,
                          size=end - start, is_far=is_far, inst_count=len(func_insts))
        # Frame size from SUB SP, N right after prologue
        si0 = idx_by_off[start]
        if (si0 + 2 < len(instructions)):
            sub = instructions[si0 + 2]
            if (sub.mnemonic == 'sub' and sub.op1 and sub.op1.type == OpType.REG16
                    and sub.op1.reg == 4 and sub.op2
                    and sub.op2.type in (OpType.IMM8, OpType.IMM16)):
                func.local_size = sub.op2.disp
        functions.append(func)

    return functions


def disassemble_segment(seg: Segment, ne: NEHeader, show_relocs: bool = True) -> tuple:
    """Disassemble a code segment. Returns (instructions, functions, reloc_map)."""
    if not seg.data or not seg.is_code:
        return [], [], {}

    reloc_map = build_reloc_map(seg, ne)
    decoder = Decoder(seg.data, base_offset=seg.file_offset)

    # If IDA exported accurate instruction heads for this segment, decode at
    # exactly those offsets. This eliminates linear-sweep desync on data-in-code
    # (every head is a true instruction boundary IDA already verified).
    seg_ida = load_ida_data(ne).get(str(seg.index))
    if seg_ida and seg_ida.get('heads'):
        instructions = []
        for h in seg_ida['heads']:
            if 0 <= h < len(seg.data):
                decoder.pos = h
                inst = decoder.decode_one()
                if inst is not None:
                    instructions.append(inst)
    else:
        instructions = decoder.decode_all()

    # Post-process: enhance FPU instructions with proper mnemonics
    # The base decoder's ESC handler reads ModR/M to advance position but
    # doesn't store the result. We re-decode it here from raw bytes.
    EA_BASES = [
        ('bx', 'si'), ('bx', 'di'), ('bp', 'si'), ('bp', 'di'),
        ('si', ''),   ('di', ''),   ('bp', ''),   ('bx', ''),
    ]
    EA_DEFAULT_SEG = ['ds', 'ds', 'ss', 'ss', 'ds', 'ds', 'ss', 'ds']

    for inst in instructions:
        if inst.mnemonic.startswith('esc_') or inst.mnemonic.startswith('fpu_'):
            raw = inst.raw
            skip = 0
            seg_override = ''
            if raw[0] in (0x26, 0x2E, 0x36, 0x3E):
                seg_override = {0x26: 'es', 0x2E: 'cs', 0x36: 'ss', 0x3E: 'ds'}[raw[0]]
                skip = 1
            if skip < len(raw) - 1 and 0xD8 <= raw[skip] <= 0xDF:
                opcode = raw[skip]
                modrm = raw[skip + 1]
                mod = (modrm >> 6) & 3
                reg = (modrm >> 3) & 7
                rm = modrm & 7

                # Re-decode ModR/M to build memory operand for the lifter
                mem_op = None
                if mod != 3:  # Memory operand
                    base_r, idx_r = EA_BASES[rm]
                    disp = 0
                    seg_name = seg_override

                    if mod == 0 and rm == 6:
                        # Direct address [disp16]
                        disp = int.from_bytes(raw[skip+2:skip+4], 'little', signed=True)
                        base_r = ''
                        idx_r = ''
                        if not seg_name: seg_name = 'ds'
                    elif mod == 1:
                        disp = raw[skip+2] if raw[skip+2] < 128 else raw[skip+2] - 256
                    elif mod == 2:
                        disp = int.from_bytes(raw[skip+2:skip+4], 'little', signed=True)

                    if not seg_name:
                        seg_name = EA_DEFAULT_SEG[rm] if not (mod == 0 and rm == 6) else 'ds'

                    mem_op = Operand(
                        type=OpType.MEM,
                        base=base_r,
                        index=idx_r,
                        disp=disp,
                        seg=seg_name,
                        size=2,  # Size doesn't matter for FPU; lifter uses operand_str
                    )

                mem_str = repr(mem_op) if mem_op else ''
                fpu = decode_fpu(opcode, modrm, mod, reg, rm, mem_str)
                inst.mnemonic = format_fpu(fpu)
                inst.op1 = mem_op  # Set to decoded memory operand or None for register ops
                inst.op2 = None

    forced_entries = set(collect_internal_code_targets(ne).get(seg.index, set()))
    if seg_ida and seg_ida.get('functions'):
        forced_entries.update(seg_ida['functions'])  # authoritative IDA entries
    functions = detect_functions(seg, instructions, forced_entries)

    return instructions, functions, reloc_map


def print_segment_disasm(seg: Segment, ne: NEHeader):
    """Print annotated disassembly for a single segment."""
    instructions, functions, reloc_map = disassemble_segment(seg, ne)

    # Build function start map for labels
    func_starts = {f.offset: f for f in functions}

    print(f"\n; === Segment {seg.index} ({seg.type_str}) ===")
    print(f"; File offset: 0x{seg.file_offset:08X}")
    print(f"; Size: 0x{seg.actual_size:04X} ({seg.actual_size} bytes)")
    print(f"; Relocations: {len(seg.relocations)}")
    print(f"; Functions detected: {len(functions)}")
    print()

    for inst in instructions:
        local_off = inst.offset - seg.file_offset

        # Function label
        if local_off in func_starts:
            f = func_starts[local_off]
            far_str = "FAR " if f.is_far else ""
            frame_str = f" frame={f.local_size}" if f.local_size else ""
            print(f"\n; --- {far_str}function {f.label} (size={f.size}){frame_str} ---")

        # Instruction
        hex_str = ' '.join(f'{b:02X}' for b in inst.raw[:8])

        # Relocation annotation
        reloc_str = ''
        if local_off in reloc_map:
            reloc_str = f'  ; RELOC: {reloc_map[local_off].target_desc}'
        # Also check offsets within the instruction (relocations can point to operand bytes)
        for off in range(local_off + 1, local_off + inst.length):
            if off in reloc_map:
                reloc_str = f'  ; RELOC @+{off - local_off}: {reloc_map[off].target_desc}'

        print(f'{seg.index:3d}:{local_off:04X}  {hex_str:<24s} {inst!r}{reloc_str}')

    print(f"\n; {len(instructions)} instructions, {len(functions)} functions")


def print_summary(ne: NEHeader):
    """Print analysis summary for all code segments."""
    total_funcs = 0
    total_insts = 0
    total_far = 0

    print(f"=== NE Disassembly Summary: {ne.filename} ===")
    print(f"{'Seg':>4s} {'Size':>6s} {'Insts':>6s} {'Funcs':>5s} {'Far':>4s} {'Relocs':>6s} {'IntRef':>6s} {'Import':>6s}")
    print("-" * 52)

    for seg in ne.code_segments:
        instructions, functions, reloc_map = disassemble_segment(seg, ne)
        n_inst = len(instructions)
        n_func = len(functions)
        n_far = sum(1 for f in functions if f.is_far)
        n_int = sum(1 for r in seg.relocations if (r.flags & 3) == 0)
        n_imp = sum(1 for r in seg.relocations if (r.flags & 3) != 0)

        total_funcs += n_func
        total_insts += n_inst
        total_far += n_far

        print(f"{seg.index:4d} {seg.actual_size:6d} {n_inst:6d} {n_func:5d} {n_far:4d} {len(seg.relocations):6d} {n_int:6d} {n_imp:6d}")

    print("-" * 52)
    print(f"{'':>4s} {ne.total_code_size:6d} {total_insts:6d} {total_funcs:5d} {total_far:4d} {ne.total_relocs:6d}")
    print()
    print(f"Total: {total_funcs} functions ({total_far} far), {total_insts} instructions")


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <ne_exe> [--seg N] [--summary] "
              f"[--functions] [--ida-json funcs.json]")
        sys.exit(1)

    filepath = sys.argv[1]
    ne = parse_ne(filepath)

    # An explicit code map populates the cache before any disassembly runs.
    if '--ida-json' in sys.argv:
        idx = sys.argv.index('--ida-json')
        load_ida_data(ne, sys.argv[idx + 1])

    if '--summary' in sys.argv:
        print_summary(ne)
        return

    if '--functions' in sys.argv:
        # List all detected functions
        print(f"=== Functions in {ne.filename} ===")
        for seg in ne.code_segments:
            instructions, functions, _ = disassemble_segment(seg, ne)
            for f in functions:
                far_str = "FAR " if f.is_far else "    "
                print(f"  {far_str}{f.label}  size={f.size:5d}  frame={f.local_size:4d}  insts={f.inst_count}")
        return

    if '--seg' in sys.argv:
        idx = sys.argv.index('--seg')
        seg_num = int(sys.argv[idx + 1])
        seg = next((s for s in ne.segments if s.index == seg_num), None)
        if not seg:
            print(f"Error: segment {seg_num} not found")
            sys.exit(1)
        if not seg.is_code:
            print(f"Error: segment {seg_num} is DATA, not CODE")
            sys.exit(1)
        print_segment_disasm(seg, ne)
    else:
        # Disassemble all code segments
        for seg in ne.code_segments:
            print_segment_disasm(seg, ne)


if __name__ == '__main__':
    main()
