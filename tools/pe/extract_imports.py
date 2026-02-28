#!/usr/bin/env python3
"""Extract all Win32 API imports from SoF game executables."""
import struct, os

def parse_pe_imports(filepath):
    """Parse PE import table and return {dll_name: [func_names]}."""
    with open(filepath, 'rb') as f:
        data = f.read()

    # DOS header
    if data[:2] != b'MZ':
        return {}
    pe_offset = struct.unpack_from('<I', data, 0x3C)[0]

    # PE signature
    if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
        return {}

    coff_offset = pe_offset + 4
    num_sections = struct.unpack_from('<H', data, coff_offset + 2)[0]
    optional_offset = coff_offset + 20
    optional_size = struct.unpack_from('<H', data, coff_offset + 16)[0]

    # Optional header - get image base and data directories
    magic = struct.unpack_from('<H', data, optional_offset)[0]
    if magic == 0x10B:  # PE32
        image_base = struct.unpack_from('<I', data, optional_offset + 28)[0]
        num_rva_sizes = struct.unpack_from('<I', data, optional_offset + 92)[0]
        dd_offset = optional_offset + 96
    else:
        return {}

    # Import directory is data directory entry 1
    import_rva = struct.unpack_from('<I', data, dd_offset + 8)[0]
    import_size = struct.unpack_from('<I', data, dd_offset + 12)[0]

    if import_rva == 0:
        return {}

    # Parse section headers to build RVA->file offset mapping
    section_offset = optional_offset + optional_size
    sections = []
    for i in range(num_sections):
        s_off = section_offset + i * 40
        s_name = data[s_off:s_off+8].rstrip(b'\x00').decode('ascii', errors='replace')
        s_vsize = struct.unpack_from('<I', data, s_off + 8)[0]
        s_rva = struct.unpack_from('<I', data, s_off + 12)[0]
        s_rawsize = struct.unpack_from('<I', data, s_off + 16)[0]
        s_rawptr = struct.unpack_from('<I', data, s_off + 20)[0]
        sections.append((s_name, s_rva, s_vsize, s_rawptr, s_rawsize))

    def rva_to_offset(rva):
        for name, s_rva, s_vsize, s_rawptr, s_rawsize in sections:
            if s_rva <= rva < s_rva + s_vsize:
                return rva - s_rva + s_rawptr
        return rva  # fallback: direct mapping (works for SoF since RVA == file offset)

    # Parse import directory table
    imports = {}
    imp_off = rva_to_offset(import_rva)

    while True:
        ilt_rva = struct.unpack_from('<I', data, imp_off)[0]      # Import Lookup Table RVA
        timestamp = struct.unpack_from('<I', data, imp_off + 4)[0]
        forwarder = struct.unpack_from('<I', data, imp_off + 8)[0]
        name_rva = struct.unpack_from('<I', data, imp_off + 12)[0]
        iat_rva = struct.unpack_from('<I', data, imp_off + 16)[0]  # Import Address Table RVA

        if ilt_rva == 0 and name_rva == 0 and iat_rva == 0:
            break  # Null terminator

        # DLL name
        name_off = rva_to_offset(name_rva)
        dll_name = b''
        i = name_off
        while i < len(data) and data[i] != 0:
            dll_name += bytes([data[i]])
            i += 1
        dll_name = dll_name.decode('ascii', errors='replace')

        # Parse Import Lookup Table (or IAT if ILT is 0)
        lookup_rva = ilt_rva if ilt_rva != 0 else iat_rva
        lookup_off = rva_to_offset(lookup_rva)

        funcs = []
        while True:
            entry = struct.unpack_from('<I', data, lookup_off)[0]
            if entry == 0:
                break

            if entry & 0x80000000:  # Import by ordinal
                ordinal = entry & 0xFFFF
                funcs.append(f"ordinal_{ordinal}")
            else:  # Import by name
                hint_off = rva_to_offset(entry)
                hint = struct.unpack_from('<H', data, hint_off)[0]
                func_name = b''
                j = hint_off + 2
                while j < len(data) and data[j] != 0:
                    func_name += bytes([data[j]])
                    j += 1
                func_name = func_name.decode('ascii', errors='replace')
                funcs.append(func_name)

            lookup_off += 4

        imports[dll_name] = funcs
        imp_off += 20

    return imports

# Analyze all game executables
game_dir = r'D:\recomp\pc\sof\_work\game'
executables = [
    'SoF.exe',
    'gamex86.dll',
    'ref_gl.dll',
    'player.dll',
    'Defsnd.dll',
    'EAXSnd.dll',
    'A3Dsnd.dll',
]

all_imports = {}

for exe_name in executables:
    path = os.path.join(game_dir, exe_name)
    if not os.path.exists(path):
        print(f"SKIP: {exe_name} not found")
        continue

    imports = parse_pe_imports(path)
    all_imports[exe_name] = imports

    print(f"\n{'='*70}")
    print(f" {exe_name}")
    print(f"{'='*70}")

    total = 0
    for dll_name in sorted(imports.keys()):
        funcs = imports[dll_name]
        total += len(funcs)
        print(f"\n  {dll_name} ({len(funcs)} functions):")
        for fn in sorted(funcs):
            print(f"    {fn}")

    print(f"\n  TOTAL: {total} imported functions")

# Summary: unique Win32 APIs across all modules
print(f"\n\n{'='*70}")
print(f" CROSS-MODULE SUMMARY")
print(f"{'='*70}")

# Collect all unique DLL+function pairs
all_apis = {}  # dll -> {func: [modules]}
for exe_name, imports in all_imports.items():
    for dll_name, funcs in imports.items():
        if dll_name not in all_apis:
            all_apis[dll_name] = {}
        for fn in funcs:
            if fn not in all_apis[dll_name]:
                all_apis[dll_name][fn] = []
            all_apis[dll_name][fn].append(exe_name)

for dll_name in sorted(all_apis.keys()):
    funcs = all_apis[dll_name]
    print(f"\n{dll_name} ({len(funcs)} unique functions):")
    for fn in sorted(funcs.keys()):
        modules = funcs[fn]
        mod_str = ", ".join(modules)
        shared = " [SHARED]" if len(modules) > 1 else ""
        print(f"  {fn:45s} <- {mod_str}{shared}")
