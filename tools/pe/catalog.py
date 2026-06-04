"""
catalog.py - Recursively catalog every PE (DLL/EXE) under a directory.

Walks a game/app install tree and, for each PE, records hashes, machine type,
PE32/PE32+, linker version, subsystem, build timestamp, sections (with flags),
overlay size, UPX/packer status, imported DLLs, and exported symbols. The first
thing you want when staring at an unfamiliar install folder: what are all these
binaries, which is the engine, which are mods/plugins, which is the installer.

Categorization is heuristic and format-driven (no per-game filename lists):
  - INSTALLER   large trailing overlay, or name like setup/install/unwise/patch
  - PACKED      UPX or another recognized packer section
  - PLUGIN/LIB  DLL with exports
  - HELPER-DLL  DLL with no/few exports (resource or side-loaded dll)
  - APP         GUI executable
  - TOOL        console executable

Usage:
    python catalog.py <dir> [--json]
"""
import struct
import os
import sys
import json
import hashlib
import datetime


def analyze_pe(filepath):
    """Analyze a PE file and return a metadata dict."""
    info = {'path': filepath, 'size': os.path.getsize(filepath)}
    with open(filepath, 'rb') as f:
        data = f.read()

    info['md5'] = hashlib.md5(data).hexdigest()
    info['sha1'] = hashlib.sha1(data).hexdigest()

    if data[:2] != b'MZ':
        info['error'] = 'Not a PE file'
        return info
    pe = struct.unpack_from('<I', data, 0x3C)[0]
    if data[pe:pe + 4] != b'PE\x00\x00':
        info['error'] = 'Invalid PE signature'
        return info

    machine = struct.unpack_from('<H', data, pe + 4)[0]
    num_sections = struct.unpack_from('<H', data, pe + 6)[0]
    timestamp = struct.unpack_from('<I', data, pe + 8)[0]
    characteristics = struct.unpack_from('<H', data, pe + 22)[0]

    info['machine'] = {0x14c: 'x86', 0x8664: 'x86_64', 0x1c0: 'ARM',
                       0xaa64: 'ARM64'}.get(machine, f'0x{machine:X}')
    info['num_sections'] = num_sections
    info['timestamp'] = timestamp
    try:
        info['timestamp_str'] = datetime.datetime.fromtimestamp(
            timestamp, datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    except Exception:
        info['timestamp_str'] = 'invalid'
    info['is_dll'] = bool(characteristics & 0x2000)

    opt = pe + 24
    opt_magic = struct.unpack_from('<H', data, opt)[0]
    info['pe_type'] = {0x10b: 'PE32', 0x20b: 'PE32+'}.get(opt_magic, f'0x{opt_magic:X}')
    opt_header_size = struct.unpack_from('<H', data, pe + 20)[0]
    info['linker_version'] = f'{data[pe + 26]}.{data[pe + 27]}'

    # Subsystem sits at optional-header offset 68 for both PE32 and PE32+
    # (PE32's BaseOfData+ImageBase == PE32+'s 8-byte ImageBase, so they align).
    subsystem = struct.unpack_from('<H', data, opt + 68)[0]
    info['subsystem'] = {1: 'Native', 2: 'GUI', 3: 'Console',
                         9: 'WinCE GUI'}.get(subsystem, str(subsystem))

    section_offset = opt + opt_header_size
    sections = []
    max_end = 0
    for i in range(num_sections):
        o = section_offset + i * 40
        name = data[o:o + 8].rstrip(b'\x00').decode('ascii', errors='replace')
        vsize, vaddr, raw_size, raw_offset = struct.unpack_from('<IIII', data, o + 8)
        chars = struct.unpack_from('<I', data, o + 36)[0]
        flags = []
        if chars & 0x20: flags.append('CODE')
        if chars & 0x40: flags.append('IDATA')
        if chars & 0x80: flags.append('UDATA')
        if chars & 0x20000000: flags.append('EXEC')
        if chars & 0x40000000: flags.append('READ')
        if chars & 0x80000000: flags.append('WRITE')
        max_end = max(max_end, raw_offset + raw_size)
        sections.append({'name': name, 'vsize': vsize, 'vaddr': vaddr,
                         'raw_size': raw_size, 'raw_offset': raw_offset,
                         'flags': '|'.join(flags)})
    info['sections'] = sections

    names = [s['name'] for s in sections]
    info['packed_upx'] = 'UPX0' in names or 'UPX1' in names
    info['packer'] = next((p for p, sig in
                           {'UPX': 'UPX0', 'ASPack': '.aspack', 'Petite': '.petite',
                            'PECompact': 'PEC2', 'VMProtect': '.vmp0', 'Themida': '.themida'}.items()
                           if sig in names), None)
    info['overlay_size'] = len(data) - max_end

    dd = opt + (112 if opt_magic == 0x20b else 96)

    def rva_to_off(rva):
        for s in sections:
            if s['vaddr'] <= rva < s['vaddr'] + max(s['vsize'], s['raw_size']):
                return rva - s['vaddr'] + s['raw_offset']
        return None

    # Imports (DLL names only)
    imports = []
    import_rva = struct.unpack_from('<I', data, dd + 1 * 8)[0]
    off = rva_to_off(import_rva) if import_rva else None
    if off is not None:
        while off + 20 <= len(data):
            name_rva = struct.unpack_from('<I', data, off + 12)[0]
            if name_rva == 0:
                break
            n_off = rva_to_off(name_rva)
            if n_off is not None:
                end = data.find(b'\x00', n_off)
                imports.append(data[n_off:end].decode('ascii', errors='replace'))
            off += 20
    info['imports'] = imports

    # Exports (names)
    exports = []
    export_rva = struct.unpack_from('<I', data, dd + 0 * 8)[0]
    exp_off = rva_to_off(export_rva) if export_rva else None
    if exp_off is not None:
        num_names = struct.unpack_from('<I', data, exp_off + 24)[0]
        names_rva = struct.unpack_from('<I', data, exp_off + 32)[0]
        names_off = rva_to_off(names_rva) if names_rva else None
        if names_off is not None:
            for j in range(min(num_names, 200)):
                nr = struct.unpack_from('<I', data, names_off + j * 4)[0]
                n_off = rva_to_off(nr)
                if n_off is not None:
                    end = data.find(b'\x00', n_off)
                    exports.append(data[n_off:end].decode('ascii', errors='replace'))
    info['exports'] = exports
    info['num_exports'] = len(exports)
    return info


def categorize(info):
    name = os.path.basename(info['path']).lower()
    if 'error' in info:
        return 'UNKNOWN'
    if (any(k in name for k in ('setup', 'install', 'unwise', 'unins', 'patch', 'update'))
            or info.get('overlay_size', 0) > 256 * 1024):
        return 'INSTALLER'
    if info.get('packer'):
        return 'PACKED'
    if info['is_dll']:
        return 'PLUGIN/LIB' if info['num_exports'] > 0 else 'HELPER-DLL'
    return 'APP' if info['subsystem'] == 'GUI' else 'TOOL'


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <dir> [--json]")
        sys.exit(1)
    base = sys.argv[1]
    as_json = '--json' in sys.argv

    targets = []
    for root, _dirs, files in os.walk(base):
        for f in files:
            if f.lower().rsplit('.', 1)[-1] in ('dll', 'exe', 'ocx', 'sys'):
                targets.append(os.path.join(root, f))
    targets.sort()

    catalog = []
    for t in targets:
        info = analyze_pe(t)
        info['relpath'] = os.path.relpath(t, base).replace('\\', '/')
        info['category'] = categorize(info)
        catalog.append(info)

    if as_json:
        print(json.dumps(catalog, indent=2, default=str))
        return

    print("=" * 80)
    print(f"PE CATALOG: {base}  ({len(catalog)} binaries)")
    print("=" * 80)
    by_cat = {}
    for info in catalog:
        by_cat.setdefault(info['category'], []).append(info)

    for cat in ('APP', 'TOOL', 'PLUGIN/LIB', 'HELPER-DLL', 'PACKED', 'INSTALLER', 'UNKNOWN'):
        items = by_cat.get(cat)
        if not items:
            continue
        print(f"\n{'=' * 80}\n  {cat}\n{'=' * 80}")
        for info in items:
            print(f"\n  [{info['relpath']}]  {info['size']:,} bytes")
            print(f"  SHA1: {info['sha1']}")
            if 'error' in info:
                print(f"  Error: {info['error']}")
                continue
            print(f"  {info['pe_type']} {'DLL' if info['is_dll'] else 'EXE'} "
                  f"({info['machine']}), {info['subsystem']}, linker {info['linker_version']}, "
                  f"built {info['timestamp_str']}")
            extra = []
            if info['packer']:
                extra.append(f"packed:{info['packer']}")
            if info['overlay_size'] > 0:
                extra.append(f"overlay:{info['overlay_size']:,}B")
            if info['num_exports']:
                extra.append(f"exports:{info['num_exports']}")
            if extra:
                print(f"  {', '.join(extra)}")
            if info['imports']:
                print(f"  imports: {', '.join(info['imports'])}")


if __name__ == '__main__':
    main()
