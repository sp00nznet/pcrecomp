"""
ne_parse.py - NE (New Executable) Format Parser

Parses 16-bit "New Executable" binaries -- the segmented format used by
Windows 1.x-3.x, Win386, OS/2 1.x, and many self-loading DOS-extended games
of the early 1990s. Extracts the segment table, per-segment relocations, the
entry table, and the module/resident/non-resident name tables.

This is the foundation of the NE toolchain:
    ne_parse   -> structure (segments, relocations, imports, entry points)
    ne_decode  -> NE-aware 16-bit disassembly (resolves relocations)
    ne_xref    -> segment-level call graph / clustering

NE format reference: the OS/2 1.x "New Executable" specification (later
documented alongside the Microsoft PE/COFF spec).

Usage:
    python ne_parse.py <ne_executable>
"""

import struct
import sys
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Relocation:
    """A single relocation fixup within a segment."""
    src_type: int       # 0=lobyte, 2=selector, 3=far_ptr, 5=offset, 11=48-bit ptr, 13=offset32
    flags: int          # bit0-1: target type (0=internal, 1=import ordinal, 2=import name, 3=OSFIXUP)
    offset: int         # Offset within segment where fixup is applied
    # For internal refs:
    target_seg: int = 0     # 1-based segment number
    target_off: int = 0     # Offset within target segment
    # For import refs:
    module_idx: int = 0     # Module reference index (1-based)
    ordinal: int = 0        # Ordinal or name table offset
    additive: bool = False  # If True, add to existing value; if False, replace

    SRC_NAMES = {0: 'LOBYTE', 2: 'SELECTOR', 3: 'FAR_PTR', 5: 'OFFSET16', 11: 'PTR48', 13: 'OFFSET32'}
    FLAG_NAMES = {0: 'INTERNAL', 1: 'IMPORT_ORD', 2: 'IMPORT_NAME', 3: 'OSFIXUP'}

    @property
    def src_name(self):
        return self.SRC_NAMES.get(self.src_type, f'UNK_{self.src_type}')

    @property
    def target_type_name(self):
        return self.FLAG_NAMES.get(self.flags & 3, f'UNK_{self.flags & 3}')


@dataclass
class Segment:
    """An NE segment entry."""
    index: int          # 1-based segment number
    file_offset: int    # Absolute offset in file (sector << alignment_shift)
    file_size: int      # Size in file (0 = 64KB)
    flags: int          # Segment flags
    alloc_size: int     # Minimum allocation size (0 = 64KB)
    data: bytes = b''   # Raw segment data
    relocations: list = field(default_factory=list)  # List[Relocation]

    @property
    def is_code(self) -> bool:
        return not (self.flags & 0x0001)

    @property
    def is_data(self) -> bool:
        return bool(self.flags & 0x0001)

    @property
    def is_moveable(self) -> bool:
        return bool(self.flags & 0x0010)

    @property
    def has_relocs(self) -> bool:
        return bool(self.flags & 0x0100)

    @property
    def is_discardable(self) -> bool:
        return bool(self.flags & 0x1000)

    @property
    def actual_size(self) -> int:
        return 65536 if self.file_size == 0 else self.file_size

    @property
    def type_str(self) -> str:
        return 'CODE' if self.is_code else 'DATA'


@dataclass
class EntryPoint:
    """An entry in the NE entry table."""
    ordinal: int        # 1-based ordinal
    segment: int        # Segment number (1-based)
    offset: int         # Offset within segment
    flags: int          # Entry flags
    name: str = ''      # Name from resident/non-resident name table


@dataclass
class NEHeader:
    """Parsed NE executable."""
    # File data
    filename: str = ''
    raw_data: bytes = b''

    # MZ stub
    mz_header_size: int = 0
    ne_offset: int = 0

    # NE header fields
    linker_ver: int = 0
    linker_rev: int = 0
    flags: int = 0
    auto_data_seg: int = 0
    heap_size: int = 0
    stack_size: int = 0
    cs: int = 0         # Entry CS (segment number, 1-based)
    ip: int = 0         # Entry IP
    ss: int = 0         # Stack segment number
    sp: int = 0         # Stack pointer
    target_os: int = 0
    alignment_shift: int = 0

    # Tables
    segments: list = field(default_factory=list)       # List[Segment]
    entries: list = field(default_factory=list)         # List[EntryPoint]
    module_names: list = field(default_factory=list)    # Imported module names
    resident_names: list = field(default_factory=list)  # (name, ordinal) pairs
    nonresident_names: list = field(default_factory=list)

    @property
    def code_segments(self):
        return [s for s in self.segments if s.is_code and s.file_offset > 0]

    @property
    def data_segments(self):
        return [s for s in self.segments if s.is_data]

    @property
    def total_code_size(self):
        return sum(s.actual_size for s in self.code_segments)

    @property
    def total_relocs(self):
        return sum(len(s.relocations) for s in self.segments)


def parse_ne(filepath: str) -> NEHeader:
    """Parse an NE executable file."""
    with open(filepath, 'rb') as f:
        data = f.read()

    ne = NEHeader(filename=filepath, raw_data=data)

    # --- MZ Header ---
    if data[:2] != b'MZ':
        raise ValueError("Not an MZ executable")

    ne.ne_offset = struct.unpack_from('<I', data, 0x3C)[0]
    if ne.ne_offset == 0 or ne.ne_offset >= len(data):
        raise ValueError(f"Invalid NE offset: 0x{ne.ne_offset:X}")

    # --- NE Header ---
    nh = data[ne.ne_offset:]
    if nh[:2] != b'NE':
        raise ValueError(f"Not an NE executable (signature: {nh[:2]})")

    ne.linker_ver = nh[2]
    ne.linker_rev = nh[3]
    entry_table_off = struct.unpack_from('<H', nh, 4)[0]
    entry_table_len = struct.unpack_from('<H', nh, 6)[0]
    ne.flags = struct.unpack_from('<H', nh, 12)[0]
    ne.auto_data_seg = struct.unpack_from('<H', nh, 14)[0]
    ne.heap_size = struct.unpack_from('<H', nh, 16)[0]
    ne.stack_size = struct.unpack_from('<H', nh, 18)[0]

    cs_ip = struct.unpack_from('<I', nh, 20)[0]
    ne.ip = cs_ip & 0xFFFF
    ne.cs = (cs_ip >> 16) & 0xFFFF

    ss_sp = struct.unpack_from('<I', nh, 24)[0]
    ne.sp = ss_sp & 0xFFFF
    ne.ss = (ss_sp >> 16) & 0xFFFF

    seg_count = struct.unpack_from('<H', nh, 28)[0]
    mod_ref_count = struct.unpack_from('<H', nh, 30)[0]
    nonres_name_size = struct.unpack_from('<H', nh, 32)[0]
    seg_table_off = struct.unpack_from('<H', nh, 34)[0]
    res_table_off = struct.unpack_from('<H', nh, 36)[0]
    resname_table_off = struct.unpack_from('<H', nh, 38)[0]
    modref_table_off = struct.unpack_from('<H', nh, 40)[0]
    import_table_off = struct.unpack_from('<H', nh, 42)[0]
    nonres_name_off = struct.unpack_from('<I', nh, 44)[0]  # Absolute file offset
    ne.alignment_shift = struct.unpack_from('<H', nh, 50)[0]
    if ne.alignment_shift == 0:
        ne.alignment_shift = 9  # Default: 512-byte sectors
    ne.target_os = nh[54]

    # --- Segment Table ---
    seg_base = ne.ne_offset + seg_table_off
    for i in range(seg_count):
        off = seg_base + i * 8
        sector = struct.unpack_from('<H', data, off)[0]
        length = struct.unpack_from('<H', data, off + 2)[0]
        seg_flags = struct.unpack_from('<H', data, off + 4)[0]
        alloc = struct.unpack_from('<H', data, off + 6)[0]

        file_offset = sector << ne.alignment_shift if sector > 0 else 0
        seg = Segment(
            index=i + 1,
            file_offset=file_offset,
            file_size=length,
            flags=seg_flags,
            alloc_size=alloc,
        )

        # Read segment data
        if file_offset > 0 and file_offset < len(data):
            actual_len = seg.actual_size
            seg.data = data[file_offset:file_offset + actual_len]

        # Read relocations if present
        if seg.has_relocs and file_offset > 0:
            reloc_base = file_offset + seg.actual_size
            if reloc_base + 2 <= len(data):
                reloc_count = struct.unpack_from('<H', data, reloc_base)[0]
                reloc_off = reloc_base + 2
                for j in range(reloc_count):
                    if reloc_off + 8 > len(data):
                        break
                    r_data = data[reloc_off:reloc_off + 8]
                    src_type = r_data[0]
                    r_flags = r_data[1]
                    r_offset = struct.unpack_from('<H', r_data, 2)[0]
                    target_type = r_flags & 0x03
                    additive = bool(r_flags & 0x04)

                    rel = Relocation(
                        src_type=src_type,
                        flags=r_flags,
                        offset=r_offset,
                        additive=additive,
                    )

                    if target_type == 0:  # Internal reference
                        rel.target_seg = r_data[4]  # 1-byte segment number... but could be 0xFF
                        if rel.target_seg == 0xFF:
                            # Moveable entry point - use entry table ordinal
                            rel.ordinal = struct.unpack_from('<H', r_data, 5)[0]
                        else:
                            rel.target_off = struct.unpack_from('<H', r_data, 6)[0]
                    elif target_type == 1:  # Import by ordinal
                        rel.module_idx = struct.unpack_from('<H', r_data, 4)[0]
                        rel.ordinal = struct.unpack_from('<H', r_data, 6)[0]
                    elif target_type == 2:  # Import by name
                        rel.module_idx = struct.unpack_from('<H', r_data, 4)[0]
                        rel.ordinal = struct.unpack_from('<H', r_data, 6)[0]  # Name table offset
                    elif target_type == 3:  # OSFIXUP
                        rel.target_seg = struct.unpack_from('<H', r_data, 4)[0]
                        rel.target_off = struct.unpack_from('<H', r_data, 6)[0]

                    seg.relocations.append(rel)
                    reloc_off += 8

        ne.segments.append(seg)

    # --- Module Reference Table + Import Name Table ---
    modref_base = ne.ne_offset + modref_table_off
    import_base = ne.ne_offset + import_table_off
    for i in range(mod_ref_count):
        name_off = struct.unpack_from('<H', data, modref_base + i * 2)[0]
        abs_off = import_base + name_off
        if abs_off < len(data):
            name_len = data[abs_off]
            name = data[abs_off + 1:abs_off + 1 + name_len].decode('ascii', errors='replace')
            ne.module_names.append(name)

    # --- Resident Name Table ---
    pos = ne.ne_offset + resname_table_off
    while pos < len(data):
        name_len = data[pos]
        if name_len == 0:
            break
        name = data[pos + 1:pos + 1 + name_len].decode('ascii', errors='replace')
        ordinal = struct.unpack_from('<H', data, pos + 1 + name_len)[0]
        ne.resident_names.append((name, ordinal))
        pos += 1 + name_len + 2

    # --- Non-Resident Name Table ---
    if nonres_name_off > 0 and nonres_name_off < len(data):
        pos = nonres_name_off
        end = nonres_name_off + nonres_name_size
        while pos < end and pos < len(data):
            name_len = data[pos]
            if name_len == 0:
                break
            name = data[pos + 1:pos + 1 + name_len].decode('ascii', errors='replace')
            ordinal = struct.unpack_from('<H', data, pos + 1 + name_len)[0]
            ne.nonresident_names.append((name, ordinal))
            pos += 1 + name_len + 2

    # --- Entry Table ---
    pos = ne.ne_offset + entry_table_off
    end = pos + entry_table_len
    ordinal = 1
    while pos < end and pos < len(data):
        bundle_count = data[pos]
        bundle_type = data[pos + 1]
        pos += 2
        if bundle_count == 0:
            break
        if bundle_type == 0:
            # Unused entries - just skip ordinals
            ordinal += bundle_count
        elif bundle_type == 0xFF:
            # Moveable segment entries (6 bytes each)
            for _ in range(bundle_count):
                if pos + 6 > len(data):
                    break
                e_flags = data[pos]
                # pos+1,pos+2: INT 3Fh instruction (unused)
                e_seg = data[pos + 3]
                e_off = struct.unpack_from('<H', data, pos + 4)[0]
                entry = EntryPoint(ordinal=ordinal, segment=e_seg, offset=e_off, flags=e_flags)
                ne.entries.append(entry)
                ordinal += 1
                pos += 6
        else:
            # Fixed segment entries (3 bytes each), bundle_type = segment number
            for _ in range(bundle_count):
                if pos + 3 > len(data):
                    break
                e_flags = data[pos]
                e_off = struct.unpack_from('<H', data, pos + 1)[0]
                entry = EntryPoint(ordinal=ordinal, segment=bundle_type, offset=e_off, flags=e_flags)
                ne.entries.append(entry)
                ordinal += 1
                pos += 3

    # Map names to entries
    all_names = ne.resident_names + ne.nonresident_names
    name_map = {ordinal: name for name, ordinal in all_names}
    for entry in ne.entries:
        if entry.ordinal in name_map:
            entry.name = name_map[entry.ordinal]

    return ne


def print_summary(ne: NEHeader):
    """Print a summary of the parsed NE executable."""
    os_names = {0: 'Unknown', 1: 'OS/2', 2: 'Windows', 3: 'DOS 4.x', 4: 'Win386', 5: 'BOSS'}

    print(f"=== NE Executable: {ne.filename} ===")
    print(f"Linker: {ne.linker_ver}.{ne.linker_rev}")
    print(f"Target OS: {os_names.get(ne.target_os, f'Unknown({ne.target_os})')}")
    print(f"Flags: 0x{ne.flags:04X}", end='')
    flag_bits = []
    if ne.flags & 0x0002: flag_bits.append('GLOBALHEAP')
    if ne.flags & 0x0004: flag_bits.append('SELFLOAD')
    if ne.flags & 0x0008: flag_bits.append('PROTMODE')
    if ne.flags & 0x8000: flag_bits.append('DLL')
    if flag_bits:
        print(f" ({' | '.join(flag_bits)})")
    else:
        print()

    print(f"Entry: seg {ne.cs}:{ne.ip:04X}")
    print(f"Stack: seg {ne.ss}, SP=0x{ne.sp:04X}")
    print(f"Alignment shift: {ne.alignment_shift} (sector size: {1 << ne.alignment_shift})")
    print()

    code_segs = ne.code_segments
    data_segs = ne.data_segments
    print(f"Segments: {len(ne.segments)} total ({len(code_segs)} CODE, {len(data_segs)} DATA)")
    print(f"Code size: {ne.total_code_size:,} bytes")
    print(f"Relocations: {ne.total_relocs:,} total")
    print()

    if ne.module_names:
        print(f"Imported modules: {', '.join(ne.module_names)}")
        print()

    if ne.resident_names:
        print(f"Resident names ({len(ne.resident_names)}):")
        for name, ordinal in ne.resident_names[:5]:
            print(f"  {ordinal}: {name}")
        if len(ne.resident_names) > 5:
            print(f"  ... and {len(ne.resident_names) - 5} more")
        print()

    if ne.entries:
        print(f"Entry points ({len(ne.entries)}):")
        for e in ne.entries[:10]:
            name_str = f" ({e.name})" if e.name else ""
            print(f"  #{e.ordinal}: seg {e.segment}:0x{e.offset:04X}{name_str}")
        if len(ne.entries) > 10:
            print(f"  ... and {len(ne.entries) - 10} more")
        print()

    # Code segment summary
    print("=== Code Segments ===")
    for seg in code_segs:
        reloc_str = f", {len(seg.relocations)} relocs" if seg.relocations else ""
        disc_str = " DISC" if seg.is_discardable else ""
        print(f"  Seg {seg.index:3d}: 0x{seg.file_offset:08X}  size=0x{seg.actual_size:04X} ({seg.actual_size:6d}){reloc_str}{disc_str}")

    # Relocation analysis
    print()
    print("=== Relocation Summary ===")
    internal_count = 0
    import_count = 0
    for seg in ne.segments:
        for r in seg.relocations:
            if (r.flags & 3) == 0:
                internal_count += 1
            else:
                import_count += 1

    print(f"  Internal references: {internal_count}")
    print(f"  Import references: {import_count}")

    # Cross-reference matrix: which segments call which
    call_matrix = {}
    for seg in ne.segments:
        if seg.is_code:
            targets = set()
            for r in seg.relocations:
                if (r.flags & 3) == 0 and r.target_seg > 0:
                    targets.add(r.target_seg)
            if targets:
                call_matrix[seg.index] = targets

    if call_matrix:
        all_targets = set()
        for targets in call_matrix.values():
            all_targets.update(targets)
        code_targets = {t for t in all_targets
                        if any(s.index == t and s.is_code for s in ne.segments)}
        data_targets = {t for t in all_targets
                        if any(s.index == t and s.is_data for s in ne.segments)}
        print(f"  Code segments referenced by relocations: {len(code_targets)}")
        print(f"  Data segments referenced by relocations: {len(data_targets)}")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <ne_executable>")
        sys.exit(1)

    ne = parse_ne(sys.argv[1])
    print_summary(ne)
