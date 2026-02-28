"""
PE Binary Analyzer -- unified best-of-breed for pcrecomp.

Merges capabilities from several project-specific analyzers:
  - PEInfo dataclass with JSON export (from xwa)
  - MD5 / SHA1 hash verification (from gunman/catalog_dlls)
  - UPX packing detection (from gunman/catalog_dlls)
  - Detailed section / import / export / resource analysis (from all)
  - Pure-struct fallback when pefile is unavailable (from sof, gunman)

Typical usage:
    python pe_analyze.py <pe_file> [--json output.json] [--hash] [--all <dir>]

Requires: pip install pefile  (optional -- raw struct parsing used as fallback)
"""

import sys
import os
import json
import struct
import hashlib
import datetime
from pathlib import Path
from dataclasses import dataclass, asdict, field
from typing import Optional, List, Dict, Tuple


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class Section:
    """PE section header."""
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int

    @property
    def is_code(self) -> bool:
        """IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE"""
        return bool(self.characteristics & 0x20000020)

    @property
    def is_data(self) -> bool:
        """IMAGE_SCN_CNT_INITIALIZED_DATA"""
        return bool(self.characteristics & 0x00000040)

    @property
    def is_writable(self) -> bool:
        """IMAGE_SCN_MEM_WRITE"""
        return bool(self.characteristics & 0x80000000)

    @property
    def va_end(self) -> int:
        return self.virtual_address + self.virtual_size

    @property
    def flags_str(self) -> str:
        flags = []
        if self.characteristics & 0x20:       flags.append('CODE')
        if self.characteristics & 0x40:       flags.append('IDATA')
        if self.characteristics & 0x80:       flags.append('UDATA')
        if self.characteristics & 0x20000000: flags.append('EXEC')
        if self.characteristics & 0x40000000: flags.append('READ')
        if self.characteristics & 0x80000000: flags.append('WRITE')
        return '|'.join(flags)


@dataclass
class ImportEntry:
    """A single imported function."""
    dll: str
    name: Optional[str]
    ordinal: Optional[int]
    iat_rva: int          # IAT slot address (RVA)


@dataclass
class ExportEntry:
    """A single exported function."""
    name: Optional[str]
    ordinal: int
    rva: int


@dataclass
class PEInfo:
    """Complete PE metadata produced by the analyzer."""
    filename: str
    filepath: str
    filesize: int

    # Hashes (populated when --hash or compute_hashes=True)
    md5: str = ''
    sha1: str = ''

    # PE header info
    image_base: int = 0
    entry_point_rva: int = 0
    timestamp: int = 0
    timestamp_str: str = ''
    linker_version: str = ''
    machine: str = ''
    pe_type: str = ''          # PE32 or PE32+
    subsystem: str = ''
    is_dll: bool = False
    characteristics: int = 0
    dll_characteristics: int = 0

    # Sections
    sections: List = field(default_factory=list)

    # Imports / Exports
    imports: List = field(default_factory=list)
    exports: List = field(default_factory=list)
    import_dlls: List = field(default_factory=list)

    # Computed ranges
    code_start: int = 0      # VA of first code byte
    code_end: int = 0        # VA past last code byte
    data_start: int = 0      # VA of first data byte
    data_end: int = 0        # VA past last data byte

    # Packing detection
    packed_upx: bool = False
    overlay_size: int = 0


# ---------------------------------------------------------------------------
# Hash helpers
# ---------------------------------------------------------------------------

def compute_hashes(filepath: str) -> Tuple[str, str]:
    """Return (md5_hex, sha1_hex) for a file."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(1 << 20)
            if not chunk:
                break
            md5.update(chunk)
            sha1.update(chunk)
    return md5.hexdigest(), sha1.hexdigest()


# ---------------------------------------------------------------------------
# Core analyzer -- tries pefile first, falls back to struct parsing
# ---------------------------------------------------------------------------

def analyze_pe(filepath: str, do_hashes: bool = False) -> PEInfo:
    """
    Analyze a PE file and return structured metadata.

    Tries the ``pefile`` library first (richer import/export parsing).
    Falls back to manual struct parsing if pefile is unavailable.
    """
    path = Path(filepath)
    filesize = os.path.getsize(filepath)

    info = PEInfo(
        filename=path.name,
        filepath=str(path.resolve()),
        filesize=filesize,
    )

    if do_hashes:
        info.md5, info.sha1 = compute_hashes(filepath)

    try:
        import pefile as _pefile
        _analyze_with_pefile(filepath, info, _pefile)
    except ImportError:
        _analyze_with_struct(filepath, info)

    return info


def _analyze_with_pefile(filepath: str, info: PEInfo, pefile) -> None:
    """Rich analysis using the ``pefile`` library."""
    pe = pefile.PE(filepath)

    # ── Basic fields ──────────────────────────────────────────────
    oh = pe.OPTIONAL_HEADER
    fh = pe.FILE_HEADER

    info.image_base = oh.ImageBase
    info.entry_point_rva = oh.AddressOfEntryPoint
    info.timestamp = fh.TimeDateStamp
    try:
        info.timestamp_str = datetime.datetime.utcfromtimestamp(
            fh.TimeDateStamp).strftime('%Y-%m-%d %H:%M:%S UTC')
    except Exception:
        info.timestamp_str = 'invalid'
    info.linker_version = f"{oh.MajorLinkerVersion}.{oh.MinorLinkerVersion:02d}"
    info.characteristics = fh.Characteristics
    info.dll_characteristics = oh.DllCharacteristics
    info.is_dll = bool(fh.Characteristics & 0x2000)

    machine_map = {0x14c: 'i386', 0x8664: 'x86-64', 0x1c0: 'ARM'}
    info.machine = machine_map.get(fh.Machine, f'0x{fh.Machine:X}')
    info.pe_type = 'PE32' if oh.Magic == 0x10B else 'PE32+' if oh.Magic == 0x20B else 'unknown'

    subsys_map = {1: 'Native', 2: 'Windows GUI', 3: 'Windows Console'}
    info.subsystem = subsys_map.get(oh.Subsystem, str(oh.Subsystem))

    # ── Sections ──────────────────────────────────────────────────
    max_raw_end = 0
    for s in pe.sections:
        name = s.Name.rstrip(b'\x00').decode('ascii', errors='replace')
        sec = Section(
            name=name,
            virtual_address=s.VirtualAddress,
            virtual_size=s.Misc_VirtualSize,
            raw_offset=s.PointerToRawData,
            raw_size=s.SizeOfRawData,
            characteristics=s.Characteristics,
        )
        info.sections.append(sec)
        raw_end = s.PointerToRawData + s.SizeOfRawData
        if raw_end > max_raw_end:
            max_raw_end = raw_end

    # UPX detection
    section_names = [s.name for s in info.sections]
    info.packed_upx = 'UPX0' in section_names or 'UPX1' in section_names

    # Overlay
    info.overlay_size = max(0, info.filesize - max_raw_end)

    # ── Imports ───────────────────────────────────────────────────
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for dll_entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = dll_entry.dll.decode('ascii', errors='replace')
            info.import_dlls.append(dll_name)
            for imp in dll_entry.imports:
                info.imports.append(ImportEntry(
                    dll=dll_name,
                    name=imp.name.decode('ascii', errors='replace') if imp.name else None,
                    ordinal=imp.ordinal if not imp.name else None,
                    iat_rva=imp.address - oh.ImageBase,
                ))

    # ── Exports ───────────────────────────────────────────────────
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            info.exports.append(ExportEntry(
                name=exp.name.decode('ascii', errors='replace') if exp.name else None,
                ordinal=exp.ordinal,
                rva=exp.address,
            ))

    # ── Computed ranges ───────────────────────────────────────────
    code_sections = [s for s in info.sections
                     if s.is_code and s.name not in ('.bind', '.rsrc', '.reloc')]
    data_sections = [s for s in info.sections
                     if s.is_data and s.name not in ('.rsrc', '.bind', '.reloc')]

    if code_sections:
        info.code_start = info.image_base + min(s.virtual_address for s in code_sections)
        info.code_end = info.image_base + max(s.va_end for s in code_sections)
    if data_sections:
        info.data_start = info.image_base + min(s.virtual_address for s in data_sections)
        info.data_end = info.image_base + max(s.va_end for s in data_sections)

    pe.close()


def _analyze_with_struct(filepath: str, info: PEInfo) -> None:
    """
    Fallback analyzer using only ``struct`` -- no pefile dependency.
    Parses DOS header, PE signature, COFF, optional header, sections,
    and the import / export directories.
    """
    with open(filepath, 'rb') as f:
        data = f.read()

    if data[:2] != b'MZ':
        raise ValueError(f'{filepath}: not a valid PE (no MZ signature)')

    pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
    if data[pe_offset:pe_offset + 4] != b'PE\x00\x00':
        raise ValueError(f'{filepath}: invalid PE signature')

    coff = pe_offset + 4
    machine = struct.unpack_from('<H', data, coff)[0]
    num_sections = struct.unpack_from('<H', data, coff + 2)[0]
    timestamp = struct.unpack_from('<I', data, coff + 4)[0]
    opt_header_size = struct.unpack_from('<H', data, coff + 16)[0]
    characteristics = struct.unpack_from('<H', data, coff + 18)[0]

    machine_map = {0x14c: 'i386', 0x8664: 'x86-64', 0x1c0: 'ARM'}
    info.machine = machine_map.get(machine, f'0x{machine:X}')
    info.timestamp = timestamp
    try:
        info.timestamp_str = datetime.datetime.utcfromtimestamp(
            timestamp).strftime('%Y-%m-%d %H:%M:%S UTC')
    except Exception:
        info.timestamp_str = 'invalid'
    info.characteristics = characteristics
    info.is_dll = bool(characteristics & 0x2000)

    # Optional header
    opt = coff + 20
    opt_magic = struct.unpack_from('<H', data, opt)[0]
    info.pe_type = 'PE32' if opt_magic == 0x10B else 'PE32+' if opt_magic == 0x20B else 'unknown'

    linker_major = data[opt + 2]
    linker_minor = data[opt + 3]
    info.linker_version = f'{linker_major}.{linker_minor:02d}'

    if opt_magic == 0x10B:  # PE32
        info.entry_point_rva = struct.unpack_from('<I', data, opt + 16)[0]
        info.image_base = struct.unpack_from('<I', data, opt + 28)[0]
        subsystem = struct.unpack_from('<H', data, opt + 68)[0]
        info.dll_characteristics = struct.unpack_from('<H', data, opt + 70)[0]
        num_dirs = struct.unpack_from('<I', data, opt + 92)[0]
        dd_offset = opt + 96
    elif opt_magic == 0x20B:  # PE32+
        info.entry_point_rva = struct.unpack_from('<I', data, opt + 16)[0]
        info.image_base = struct.unpack_from('<Q', data, opt + 24)[0]
        subsystem = struct.unpack_from('<H', data, opt + 68)[0]
        info.dll_characteristics = struct.unpack_from('<H', data, opt + 70)[0]
        num_dirs = struct.unpack_from('<I', data, opt + 108)[0]
        dd_offset = opt + 112
    else:
        subsystem = 0
        num_dirs = 0
        dd_offset = opt + 96

    subsys_map = {1: 'Native', 2: 'Windows GUI', 3: 'Windows Console'}
    info.subsystem = subsys_map.get(subsystem, str(subsystem))

    # ── Sections ──────────────────────────────────────────────────
    section_start = opt + opt_header_size
    raw_sections = []   # (name, va, vsize, raw_ptr, raw_size, chars)
    max_raw_end = 0

    for i in range(num_sections):
        off = section_start + i * 40
        name = data[off:off + 8].rstrip(b'\x00').decode('ascii', errors='replace')
        vsize = struct.unpack_from('<I', data, off + 8)[0]
        va = struct.unpack_from('<I', data, off + 12)[0]
        raw_size = struct.unpack_from('<I', data, off + 16)[0]
        raw_ptr = struct.unpack_from('<I', data, off + 20)[0]
        chars = struct.unpack_from('<I', data, off + 36)[0]

        sec = Section(
            name=name,
            virtual_address=va,
            virtual_size=vsize,
            raw_offset=raw_ptr,
            raw_size=raw_size,
            characteristics=chars,
        )
        info.sections.append(sec)
        raw_sections.append((name, va, vsize, raw_ptr, raw_size, chars))

        raw_end = raw_ptr + raw_size
        if raw_end > max_raw_end:
            max_raw_end = raw_end

    section_names = [s.name for s in info.sections]
    info.packed_upx = 'UPX0' in section_names or 'UPX1' in section_names
    info.overlay_size = max(0, info.filesize - max_raw_end)

    # RVA -> file offset helper (local)
    def rva_to_offset(rva):
        for _name, va, vsize, rp, rs, _chars in raw_sections:
            if va <= rva < va + max(vsize, rs):
                return rva - va + rp
        return None

    # ── Imports ───────────────────────────────────────────────────
    if num_dirs >= 2:
        import_rva = struct.unpack_from('<I', data, dd_offset + 8)[0]
        if import_rva:
            import_off = rva_to_offset(import_rva)
            if import_off is not None:
                pos = import_off
                while pos + 20 <= len(data):
                    ilt_rva = struct.unpack_from('<I', data, pos)[0]
                    name_rva = struct.unpack_from('<I', data, pos + 12)[0]
                    iat_rva_base = struct.unpack_from('<I', data, pos + 16)[0]
                    if name_rva == 0:
                        break
                    name_off = rva_to_offset(name_rva)
                    if name_off:
                        end = data.index(b'\x00', name_off)
                        dll_name = data[name_off:end].decode('ascii', errors='replace')
                    else:
                        dll_name = '???'
                    info.import_dlls.append(dll_name)

                    # Walk ILT / IAT entries
                    lookup_rva = ilt_rva if ilt_rva else iat_rva_base
                    if lookup_rva:
                        loff = rva_to_offset(lookup_rva)
                        if loff:
                            slot_rva = lookup_rva
                            p = loff
                            while True:
                                entry = struct.unpack_from('<I', data, p)[0]
                                if entry == 0:
                                    break
                                if entry & 0x80000000:
                                    info.imports.append(ImportEntry(
                                        dll=dll_name,
                                        name=None,
                                        ordinal=entry & 0xFFFF,
                                        iat_rva=slot_rva,
                                    ))
                                else:
                                    hint_off = rva_to_offset(entry)
                                    if hint_off and hint_off + 2 < len(data):
                                        end2 = data.index(b'\x00', hint_off + 2)
                                        fname = data[hint_off + 2:end2].decode('ascii', errors='replace')
                                        info.imports.append(ImportEntry(
                                            dll=dll_name,
                                            name=fname,
                                            ordinal=None,
                                            iat_rva=slot_rva,
                                        ))
                                p += 4
                                slot_rva += 4
                    pos += 20

    # ── Exports ───────────────────────────────────────────────────
    if num_dirs >= 1:
        export_rva = struct.unpack_from('<I', data, dd_offset)[0]
        export_size = struct.unpack_from('<I', data, dd_offset + 4)[0]
        if export_rva and export_size:
            exp_off = rva_to_offset(export_rva)
            if exp_off:
                num_funcs = struct.unpack_from('<I', data, exp_off + 20)[0]
                num_names = struct.unpack_from('<I', data, exp_off + 24)[0]
                funcs_rva = struct.unpack_from('<I', data, exp_off + 28)[0]
                names_rva = struct.unpack_from('<I', data, exp_off + 32)[0]
                ords_rva = struct.unpack_from('<I', data, exp_off + 36)[0]

                names_off = rva_to_offset(names_rva)
                ords_off = rva_to_offset(ords_rva)
                funcs_off = rva_to_offset(funcs_rva)

                if names_off and ords_off and funcs_off:
                    for i in range(num_names):
                        n_rva = struct.unpack_from('<I', data, names_off + i * 4)[0]
                        ordinal = struct.unpack_from('<H', data, ords_off + i * 2)[0]
                        func_rva = struct.unpack_from('<I', data, funcs_off + ordinal * 4)[0]
                        noff = rva_to_offset(n_rva)
                        if noff:
                            end3 = data.index(b'\x00', noff)
                            ename = data[noff:end3].decode('ascii', errors='replace')
                        else:
                            ename = None
                        info.exports.append(ExportEntry(
                            name=ename,
                            ordinal=ordinal,
                            rva=func_rva,
                        ))

    # ── Computed ranges ───────────────────────────────────────────
    code_sections = [s for s in info.sections
                     if s.is_code and s.name not in ('.bind', '.rsrc', '.reloc')]
    data_sections = [s for s in info.sections
                     if s.is_data and s.name not in ('.rsrc', '.bind', '.reloc')]

    if code_sections:
        info.code_start = info.image_base + min(s.virtual_address for s in code_sections)
        info.code_end = info.image_base + max(s.va_end for s in code_sections)
    if data_sections:
        info.data_start = info.image_base + min(s.virtual_address for s in data_sections)
        info.data_end = info.image_base + max(s.va_end for s in data_sections)


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def va_to_file_offset(sections: list, va: int, image_base: int) -> Optional[int]:
    """Convert a virtual address to a file offset."""
    rva = va - image_base
    for s in sections:
        if s.virtual_address <= rva < s.virtual_address + s.raw_size:
            return s.raw_offset + (rva - s.virtual_address)
    return None


def read_bytes_at_va(filepath: str, sections: list, image_base: int,
                     va: int, size: int) -> Optional[bytes]:
    """Read *size* bytes from the PE file at a given virtual address."""
    offset = va_to_file_offset(sections, va, image_base)
    if offset is None:
        return None
    with open(filepath, 'rb') as f:
        f.seek(offset)
        return f.read(size)


def build_iat_map(info: PEInfo) -> dict:
    """Build a map from IAT VA -> (dll, function_name) for resolving import calls."""
    iat = {}
    for imp in info.imports:
        va = info.image_base + imp.iat_rva
        name = imp.name if imp.name else f"ordinal_{imp.ordinal}"
        iat[va] = (imp.dll, name)
    return iat


# ---------------------------------------------------------------------------
# Presentation
# ---------------------------------------------------------------------------

def print_summary(info: PEInfo):
    """Print a human-readable summary of the PE analysis."""
    print(f"\n{'=' * 72}")
    print(f"  PE Analysis: {info.filename}")
    print(f"  Path: {info.filepath}")
    print(f"  Size: {info.filesize:,} bytes")
    print(f"{'=' * 72}\n")

    if info.md5:
        print(f"  MD5:           {info.md5}")
        print(f"  SHA1:          {info.sha1}")
    print(f"  Machine:       {info.machine}")
    print(f"  Format:        {info.pe_type} ({'DLL' if info.is_dll else 'EXE'})")
    print(f"  Image Base:    0x{info.image_base:08X}")
    print(f"  Entry Point:   0x{info.image_base + info.entry_point_rva:08X} "
          f"(RVA 0x{info.entry_point_rva:08X})")
    print(f"  Linker:        {info.linker_version}")
    print(f"  Subsystem:     {info.subsystem}")
    print(f"  Timestamp:     {info.timestamp_str} (0x{info.timestamp:08X})")
    if info.packed_upx:
        print(f"  ** PACKED (UPX detected) **")
    if info.overlay_size > 0:
        print(f"  Overlay:       {info.overlay_size:,} bytes")

    if info.code_start:
        print(f"  Code Range:    0x{info.code_start:08X} - 0x{info.code_end:08X} "
              f"({info.code_end - info.code_start:,} bytes)")
    if info.data_start:
        print(f"  Data Range:    0x{info.data_start:08X} - 0x{info.data_end:08X} "
              f"({info.data_end - info.data_start:,} bytes)")

    # Sections
    print(f"\n  Sections ({len(info.sections)}):")
    for s in info.sections:
        print(f"    {s.name:8s}  VA 0x{s.virtual_address:08X}  "
              f"VSize 0x{s.virtual_size:08X}  Raw 0x{s.raw_offset:08X}  "
              f"RSize 0x{s.raw_size:08X}  [{s.flags_str}]")

    # Imports
    if info.imports:
        by_dll: Dict[str, list] = {}
        for imp in info.imports:
            by_dll.setdefault(imp.dll, []).append(imp)
        print(f"\n  Imports: {len(info.imports)} functions from "
              f"{len(by_dll)} DLLs")
        for dll, imps in sorted(by_dll.items()):
            print(f"\n    {dll} ({len(imps)} functions):")
            for imp in imps[:10]:
                name = imp.name if imp.name else f"ordinal {imp.ordinal}"
                print(f"      0x{info.image_base + imp.iat_rva:08X}  {name}")
            if len(imps) > 10:
                print(f"      ... and {len(imps) - 10} more")

    # Exports
    if info.exports:
        print(f"\n  Exports ({len(info.exports)}):")
        for exp in info.exports[:30]:
            name = exp.name if exp.name else f"ordinal_{exp.ordinal}"
            print(f"    [{exp.ordinal:3d}] 0x{exp.rva:08X}  {name}")
        if len(info.exports) > 30:
            print(f"    ... and {len(info.exports) - 30} more")


def export_json(info: PEInfo, output_path: str):
    """Export analysis to JSON for consumption by other tools."""
    data = {
        'filename': info.filename,
        'filepath': info.filepath,
        'filesize': info.filesize,
        'md5': info.md5,
        'sha1': info.sha1,
        'image_base': info.image_base,
        'entry_point': info.image_base + info.entry_point_rva,
        'entry_point_rva': info.entry_point_rva,
        'machine': info.machine,
        'pe_type': info.pe_type,
        'is_dll': info.is_dll,
        'linker_version': info.linker_version,
        'subsystem': info.subsystem,
        'timestamp': info.timestamp,
        'timestamp_str': info.timestamp_str,
        'packed_upx': info.packed_upx,
        'overlay_size': info.overlay_size,
        'code_start': info.code_start,
        'code_end': info.code_end,
        'data_start': info.data_start,
        'data_end': info.data_end,
        'sections': [asdict(s) for s in info.sections],
        'imports': [asdict(i) for i in info.imports],
        'exports': [asdict(e) for e in info.exports],
        'iat_map': {
            f"0x{info.image_base + imp.iat_rva:08X}": {
                'dll': imp.dll,
                'name': imp.name if imp.name else f"ordinal_{imp.ordinal}"
            }
            for imp in info.imports
        },
    }
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"Exported to {output_path}")


# ---------------------------------------------------------------------------
# Batch mode -- scan a directory for EXE/DLL files
# ---------------------------------------------------------------------------

def scan_directory(directory: str, do_hashes: bool = True):
    """Analyze every PE (*.exe, *.dll) under *directory*."""
    import glob
    targets = []
    for ext in ('*.exe', '*.dll', '*.EXE', '*.DLL'):
        targets.extend(glob.glob(os.path.join(directory, '**', ext), recursive=True))
    targets.sort()

    for t in targets:
        try:
            info = analyze_pe(t, do_hashes=do_hashes)
            print_summary(info)
        except Exception as e:
            print(f"\nERROR analyzing {t}: {e}")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <pe_file> [--json out.json] [--hash]")
        print(f"       {sys.argv[0]} --all <directory> [--hash]")
        sys.exit(1)

    do_hashes = '--hash' in sys.argv

    if sys.argv[1] == '--all':
        directory = sys.argv[2] if len(sys.argv) > 2 else '.'
        scan_directory(directory, do_hashes=do_hashes)
    else:
        filepath = sys.argv[1]
        info = analyze_pe(filepath, do_hashes=do_hashes)
        print_summary(info)

        if '--json' in sys.argv:
            idx = sys.argv.index('--json')
            if idx + 1 < len(sys.argv):
                export_json(info, sys.argv[idx + 1])
