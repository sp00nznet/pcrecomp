"""
resolve_stubs.py - Resolve unresolved function stubs

Maps far call targets (far_SSSS_XXXX) to existing function addresses
by computing the flat file offset from the segment:offset values.
Also identifies common MSC 5.x C library functions by their positions
and byte patterns.

Part of the Civ Recomp project (sp00nznet/civ)
"""

import struct
import sys
import os
import re

LOAD_SEG = 0x0100  # DOS load segment


def compute_file_offset(seg, off, hdr_size=0x200):
    """Convert segment:offset to file offset."""
    mem_addr = (seg + LOAD_SEG) * 16 + off
    file_off = mem_addr - (LOAD_SEG * 16) + hdr_size
    return file_off


def parse_stub_names(stubs_path):
    """Extract function names from civ_stubs.c."""
    names = []
    with open(stubs_path, 'r') as f:
        for line in f:
            m = re.match(r'^void ((?:far|res|ovl)\S+)\(CPU \*cpu\)', line)
            if m:
                names.append(m.group(1))
    return names


def parse_function_names(header_path):
    """Extract all known function names from civ_recomp.h."""
    names = {}
    with open(header_path, 'r') as f:
        for line in f:
            m = re.match(r'^void ((?:res|ovl)\w+)\(CPU \*cpu\);', line)
            if m:
                name = m.group(1)
                # Extract address from name
                if name.startswith('res_'):
                    addr = int(name[4:], 16)
                    names[addr] = name
                elif name.startswith('ovl'):
                    parts = name.split('_', 1)
                    addr = int(parts[1], 16)
                    names[addr] = name
    return names


def identify_msc_library(data, file_offset):
    """Try to identify MSC 5.x C library functions by patterns."""
    if file_offset < 0 or file_offset + 16 > len(data):
        return None

    b = data[file_offset:file_offset + 16]

    # Common MSC 5.x library patterns
    # These are heuristic - match prologue and first few instructions

    # PUSH BP / MOV BP, SP pattern
    if b[0] == 0x55 and b[1] == 0x8B and b[2] == 0xEC:
        # Check for common library signatures
        # SUB SP, N followed by characteristic patterns
        pass

    # RET/RETF patterns (thunks)
    if b[0] == 0xCB:  # RETF
        return "retf_thunk"
    if b[0] == 0xC3:  # RET
        return "ret_thunk"

    # JMP FAR (thunk/trampoline)
    if b[0] == 0xEA:
        return "far_jmp_thunk"

    # MOV AX, ... / RET (simple accessor)
    if b[0] == 0xB8 and b[3] in (0xC3, 0xCB):
        return "const_accessor"

    return None


def main():
    if len(sys.argv) < 2:
        print("Usage: resolve_stubs.py <civ.exe> [RecompiledFuncs/]")
        sys.exit(1)

    exe_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) >= 3 else 'RecompiledFuncs'

    with open(exe_path, 'rb') as f:
        data = f.read()

    hdr_size = struct.unpack_from('<H', data, 8)[0] * 16

    # Load existing functions
    header_path = os.path.join(output_dir, 'civ_recomp.h')
    known_funcs = parse_function_names(header_path)
    print(f"Known functions: {len(known_funcs)}")

    # Load stub names
    stubs_path = os.path.join(output_dir, 'civ_stubs.c')
    stub_names = parse_stub_names(stubs_path)
    print(f"Stub functions: {len(stub_names)}")

    # Categorize and resolve
    resolved = {}      # stub_name -> existing_func_name
    aliases = {}       # stub_name -> file_offset (close match)
    c_library = {}     # stub_name -> likely C function
    unresolvable = []  # truly unknown

    # Known MSC 5.x C library function offsets (segment 0000)
    # These are typical offsets for MSC 5.x library in a medium/large model program
    msc_lib_funcs = {}

    for name in stub_names:
        file_off = None

        if name.startswith('far_'):
            # Parse far_SSSS_XXXX
            parts = name.split('_')
            seg = int(parts[1], 16)
            off = int(parts[2], 16)
            file_off = compute_file_offset(seg, off, hdr_size)

        elif name.startswith('res_'):
            # Parse res_XXXXXX - this IS the file offset already
            file_off = int(name[4:], 16)

        elif name.startswith('ovl'):
            # Parse ovlNN_XXXXXX
            parts = name.split('_', 1)
            file_off = int(parts[1], 16)

        if file_off is None:
            unresolvable.append(name)
            continue

        # Check for exact match
        if file_off in known_funcs:
            resolved[name] = known_funcs[file_off]
            continue

        # Check for near match (within 16 bytes - might be a mid-function entry)
        found_near = False
        for delta in range(-16, 17):
            addr = file_off + delta
            if addr in known_funcs:
                aliases[name] = (known_funcs[addr], delta)
                found_near = True
                break

        if found_near:
            continue

        # Check if it's in the code range at all
        if 0 < file_off < len(data):
            lib_id = identify_msc_library(data, file_off)
            if lib_id:
                c_library[name] = (file_off, lib_id)
            else:
                c_library[name] = (file_off, "unknown")
        else:
            unresolvable.append(name)

    # Report
    print(f"\n{'='*60}")
    print(f"  Stub Resolution Report")
    print(f"{'='*60}")
    print(f"\n  Exact matches (can be aliased):  {len(resolved)}")
    print(f"  Near matches (within 16 bytes):  {len(aliases)}")
    print(f"  In code range (need impl):       {len(c_library)}")
    print(f"  Unresolvable:                    {len(unresolvable)}")

    if resolved:
        print(f"\n--- Exact Matches (generate #define aliases) ---")
        for stub, target in sorted(resolved.items()):
            print(f"  {stub} -> {target}")

    if aliases:
        print(f"\n--- Near Matches (mid-function entries) ---")
        for stub, (target, delta) in sorted(aliases.items()):
            sign = '+' if delta > 0 else ''
            print(f"  {stub} -> {target}{sign}{delta}")

    # Generate alias header
    alias_header = os.path.join(output_dir, 'civ_aliases.h')
    alias_impl = os.path.join(output_dir, 'civ_aliases.c')

    # Write resolved aliases as wrapper functions
    with open(alias_impl, 'w') as f:
        f.write('/*\n * civ_aliases.c - Resolved function aliases\n')
        f.write(' * AUTO-GENERATED by resolve_stubs.py\n')
        f.write(' *\n * These functions were called by name but actually map\n')
        f.write(' * to existing recompiled functions.\n */\n\n')
        f.write('#include "recomp/cpu.h"\n\n')
        for stub, target in sorted(resolved.items()):
            f.write(f'extern void {target}(CPU *cpu);\n')
        f.write('\n')
        for stub, target in sorted(resolved.items()):
            f.write(f'void {stub}(CPU *cpu) {{ {target}(cpu); }}\n')

    print(f"\nWrote {len(resolved)} aliases to {alias_impl}")

    # Summary of what remains
    remaining = len(stub_names) - len(resolved)
    print(f"\n--- Summary ---")
    print(f"  Total stubs:     {len(stub_names)}")
    print(f"  Resolved:        {len(resolved)} (-> direct aliases)")
    print(f"  Remaining:       {remaining}")
    print(f"  Near matches:    {len(aliases)} (mid-function entries, need analysis)")

    # Scan for string references near C library functions
    print(f"\n--- String Signatures Near far_0000_* Functions ---")
    for name in sorted(stub_names):
        if not name.startswith('far_0000_'):
            continue
        parts = name.split('_')
        off = int(parts[2], 16)
        file_off = compute_file_offset(0, off, hdr_size)
        if 0 < file_off < len(data):
            # Look for nearby ASCII strings
            for scan in range(max(0, file_off - 64), min(len(data) - 4, file_off + 128)):
                chunk = data[scan:scan+32]
                try:
                    s = chunk.split(b'\x00')[0].decode('ascii')
                    if len(s) >= 4 and s.isprintable():
                        if any(kw in s.lower() for kw in ['alloc', 'free', 'print',
                              'str', 'mem', 'file', 'open', 'close', 'read', 'write',
                              'exit', 'abort', 'math', 'sqrt', 'rand', 'atoi', 'itoa',
                              'sprintf', 'sscanf', 'errno', 'div', 'overflow', 'stack',
                              'error', 'null', 'heap']):
                            print(f"  {name} (0x{file_off:06X}): nearby string '{s}'")
                            break
                except:
                    pass


if __name__ == '__main__':
    main()
