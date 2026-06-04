#!/usr/bin/env python3
"""
analyze_sections.py - PE section + protection (DRM) static analyzer.

For each section: virtual/raw size, characteristics, Shannon entropy, and a
guess at whether it's code, data, or compressed/encrypted. Then it looks for
the tell-tale signs of copy protection:

  - entry point landing *inside* a non-.text section (classic wrapper behavior),
  - high-entropy executable sections (encrypted loader / packed code),
  - known SafeDisc / SecuROM / packer signatures and section names.

This is the static counterpart to drm/safedisc_dump.py (which dumps decrypted
code from a running process). Use this first to identify *what* protection a
binary has before deciding how to neutralize it.

Usage:
    python analyze_sections.py <file.exe> [--compare other.exe] [--section NAME]
"""
import struct
import os
import sys
import math


# (signature bytes, human label). Searched across whole sections.
PROTECTION_SIGS = [
    (b'BoG_',         'SafeDisc (BoG_ marker)'),
    (b'stxt',         'SafeDisc (stxt section)'),
    (b'SafeDisc',     'SafeDisc (string)'),
    (b'Macrovision',  'SafeDisc / Macrovision'),
    (b'secdrv',       'SafeDisc (secdrv driver)'),
    (b'~df39',        'SafeDisc marker'),
    (b'CLCD',         'SafeDisc CLCD'),
    (b'dplayerx.dll', 'SafeDisc loader dll'),
    (b'.icd',         'SafeDisc .icd payload'),
    (b'AddD',         'SecuROM (AddD marker)'),
    (b'SecuROM',      'SecuROM (string)'),
    (b'CMS_t',        'SecuROM marker'),
    (b'UPX!',         'UPX packer'),
    (b'.aspack',      'ASPack packer'),
    (b'.adata',       'ASProtect'),
    (b'PECompact',    'PECompact packer'),
    (b'.petite',      'Petite packer'),
    (b'.vmp0',        'VMProtect'),
    (b'.themida',     'Themida'),
]

# Section names that themselves indicate a protector/packer.
SUSPECT_SECTION_NAMES = {
    '.bind': 'SafeDisc wrapper',
    'stxt2': 'SafeDisc', 'stxt371': 'SafeDisc',
    '.cms_t': 'SecuROM', '.cms_d': 'SecuROM',
    'UPX0': 'UPX', 'UPX1': 'UPX',
    '.aspack': 'ASPack', '.adata': 'ASProtect',
    '.vmp0': 'VMProtect', '.vmp1': 'VMProtect',
    '.themida': 'Themida', '.petite': 'Petite',
}


def entropy(buf):
    if not buf:
        return 0.0
    freq = [0] * 256
    for b in buf:
        freq[b] += 1
    n = len(buf)
    e = 0.0
    for f in freq:
        if f:
            p = f / n
            e -= p * math.log2(p)
    return e


def parse_sections(data):
    """Return (pe_offset, entry_rva, [section dicts])."""
    if data[:2] != b'MZ':
        raise ValueError("Not an MZ/PE file")
    pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
    if data[pe_offset:pe_offset + 4] != b'PE\x00\x00':
        raise ValueError("No PE signature")
    num_sections = struct.unpack_from('<H', data, pe_offset + 6)[0]
    opt_header_size = struct.unpack_from('<H', data, pe_offset + 20)[0]
    entry_rva = struct.unpack_from('<I', data, pe_offset + 40)[0]
    sec_start = pe_offset + 24 + opt_header_size

    sections = []
    for i in range(num_sections):
        o = sec_start + i * 40
        name = data[o:o + 8].rstrip(b'\x00').decode('ascii', errors='replace')
        vsize, va, raw_size, raw_off = struct.unpack_from('<IIII', data, o + 8)
        chars = struct.unpack_from('<I', data, o + 36)[0]
        sections.append({
            'name': name, 'vsize': vsize, 'va': va,
            'raw_size': raw_size, 'raw_off': raw_off, 'chars': chars,
            'data': data[raw_off:raw_off + raw_size],
        })
    return pe_offset, entry_rva, sections


def describe_section(s, entry_rva):
    IMAGE_SCN_MEM_EXECUTE = 0x20000000
    IMAGE_SCN_CNT_CODE = 0x00000020
    is_exec = bool(s['chars'] & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE))
    ent = entropy(s['data'][:65536])
    has_entry = s['va'] <= entry_rva < s['va'] + max(s['vsize'], s['raw_size'])

    flags = []
    if is_exec:
        flags.append('EXEC')
    if ent > 7.5:
        flags.append('HIGH-ENTROPY')
    if has_entry:
        flags.append('ENTRY-POINT')
    return is_exec, ent, has_entry, flags


def analyze(filepath, only_section=None):
    print(f"\n{'=' * 78}")
    print(f"Sections in {os.path.basename(filepath)}")
    print(f"{'=' * 78}")
    with open(filepath, 'rb') as f:
        data = f.read()

    pe_offset, entry_rva, sections = parse_sections(data)
    print(f"Entry point RVA: 0x{entry_rva:08X}\n")
    print(f"{'name':10s} {'VA':>10s} {'vsize':>9s} {'rawsize':>9s} {'entropy':>8s}  flags")
    print('-' * 78)

    findings = []
    for s in sections:
        if only_section and s['name'] != only_section:
            continue
        is_exec, ent, has_entry, flags = describe_section(s, entry_rva)
        print(f"{s['name']:10s} 0x{s['va']:08X} {s['vsize']:9d} {s['raw_size']:9d} "
              f"{ent:8.4f}  {' '.join(flags)}")

        if s['name'] in SUSPECT_SECTION_NAMES:
            findings.append(f"section '{s['name']}' -> {SUSPECT_SECTION_NAMES[s['name']]}")
        if has_entry and not s['name'].startswith('.text') and s['name'] != 'CODE':
            findings.append(f"entry point is inside '{s['name']}' (wrapper / protector)")
        if has_entry and is_exec and ent > 7.5:
            findings.append(f"entry section '{s['name']}' is high-entropy executable "
                            f"(encrypted/packed loader)")

    # Signature scan across all sections.
    full = data
    for sig, label in PROTECTION_SIGS:
        idx = full.find(sig)
        if idx != -1:
            findings.append(f"signature '{sig.decode('ascii', errors='replace')}' "
                            f"@0x{idx:X} -> {label}")

    print()
    if findings:
        print("  Protection / packing indicators:")
        seen = set()
        for f in findings:
            if f not in seen:
                print(f"    - {f}")
                seen.add(f)
    else:
        print("  No known protection/packer indicators found.")
    return {s['name']: s['data'] for s in sections}


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <file.exe> [--compare other.exe] [--section NAME]")
        sys.exit(1)

    path = sys.argv[1]
    only_section = None
    compare = None
    if '--section' in sys.argv:
        only_section = sys.argv[sys.argv.index('--section') + 1]
    if '--compare' in sys.argv:
        compare = sys.argv[sys.argv.index('--compare') + 1]

    secs_a = analyze(path, only_section)

    if compare:
        secs_b = analyze(compare, only_section)
        print(f"\n{'=' * 78}")
        print(f"Comparing sections: {os.path.basename(path)} vs {os.path.basename(compare)}")
        print(f"{'=' * 78}")
        for name in sorted(set(secs_a) & set(secs_b)):
            a, b = secs_a[name], secs_b[name]
            if a == b:
                print(f"  {name:10s} IDENTICAL ({len(a):,} bytes)")
            elif len(a) == len(b):
                diffs = sum(1 for x, y in zip(a, b) if x != y)
                print(f"  {name:10s} differ: {diffs:,}/{len(a):,} bytes")
            else:
                print(f"  {name:10s} differ: sizes {len(a):,} vs {len(b):,}")


if __name__ == '__main__':
    main()
