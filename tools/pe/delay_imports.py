#!/usr/bin/env python3
"""
delay_imports.py - Dump a PE's delay-loaded imports.

Delay imports (the .didat directory / ImgDelayDescr table) name DLLs the loader
only binds on first use. They're easy to miss with a normal import dump but
matter for recompilation: a delay-loaded DLL (renderer, codec, optional
subsystem) is a runtime dependency you still have to shim.

Prefers pefile when available; otherwise falls back to a pure-struct parser
that derives the delay-import directory's file offset from the data directory
and section headers (no hardcoded offsets).

Usage:
    python delay_imports.py <file.exe>
"""
import sys
import struct


def _rva_to_off(rva, sections):
    for s in sections:
        if s['va'] <= rva < s['va'] + max(s['vsize'], s['raw_size']):
            return s['raw_off'] + (rva - s['va'])
    return None


def _read_cstr(data, off, maxlen=256):
    end = data.find(b'\x00', off, off + maxlen)
    if end == -1:
        end = off + maxlen
    return data[off:end].decode('ascii', errors='replace')


def parse_with_pefile(filepath):
    import pefile
    pe = pefile.PE(filepath)
    if not hasattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
        pe.close()
        return False
    print("Delay-loaded imports (via pefile):")
    for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
        dll = entry.dll.decode('utf-8', errors='replace')
        print(f"\n  {dll}:")
        for func in entry.imports:
            if func.name:
                print(f"    {func.name.decode('utf-8', errors='replace')}")
            else:
                print(f"    Ordinal_{func.ordinal}")
    pe.close()
    return True


def parse_manual(filepath):
    """Pure-struct fallback: locate the delay-import directory via the optional
    header's data directory (entry 13) and walk ImgDelayDescr records."""
    with open(filepath, 'rb') as f:
        data = f.read()

    pe = struct.unpack_from('<I', data, 0x3C)[0]
    if data[pe:pe + 4] != b'PE\x00\x00':
        raise ValueError("No PE signature")
    num_sections = struct.unpack_from('<H', data, pe + 6)[0]
    opt_size = struct.unpack_from('<H', data, pe + 20)[0]
    opt = pe + 24
    magic = struct.unpack_from('<H', data, opt)[0]
    is_pe32_plus = (magic == 0x20b)
    # Data directories start at offset 96 (PE32) / 112 (PE32+) into the opt header.
    dd_base = opt + (112 if is_pe32_plus else 96)
    DELAY_IMPORT_DIR = 13
    delay_rva = struct.unpack_from('<I', data, dd_base + DELAY_IMPORT_DIR * 8)[0]
    if delay_rva == 0:
        print("No delay-import directory in this PE.")
        return

    sec_start = opt + opt_size
    sections = []
    for i in range(num_sections):
        o = sec_start + i * 40
        name = data[o:o + 8].rstrip(b'\x00').decode('ascii', errors='replace')
        vsize, va, raw_size, raw_off = struct.unpack_from('<IIII', data, o + 8)
        sections.append({'name': name, 'va': va, 'vsize': vsize,
                         'raw_size': raw_size, 'raw_off': raw_off})

    print("Delay-loaded imports (manual parse):")
    pos = _rva_to_off(delay_rva, sections)
    if pos is None:
        print(f"  Could not map delay-import RVA 0x{delay_rva:X} to a file offset.")
        return

    while pos + 32 <= len(data):
        attrs, name_rva, mod_handle, iat_rva, int_rva, bound_iat, unload_iat, ts = \
            struct.unpack_from('<8I', data, pos)
        if name_rva == 0 and iat_rva == 0:
            break

        # In newer linkers attrs bit0 means RVAs are real RVAs (the common case).
        name_off = _rva_to_off(name_rva, sections)
        dll = _read_cstr(data, name_off) if name_off is not None else f"<rva 0x{name_rva:X}>"
        print(f"\n  {dll} (attrs=0x{attrs:X}):")

        int_off = _rva_to_off(int_rva, sections) if int_rva else None
        if int_off is not None:
            k = 0
            while int_off + (k + 1) * 4 <= len(data):
                thunk = struct.unpack_from('<I', data, int_off + k * 4)[0]
                if thunk == 0:
                    break
                if thunk & 0x80000000:
                    print(f"    Ordinal_{thunk & 0xFFFF}")
                else:
                    hint_off = _rva_to_off(thunk, sections)
                    if hint_off is not None:
                        hint = struct.unpack_from('<H', data, hint_off)[0]
                        fname = _read_cstr(data, hint_off + 2)
                        print(f"    [{hint:4d}] {fname}")
                k += 1
        pos += 32


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <file.exe>")
        sys.exit(1)
    filepath = sys.argv[1]
    try:
        if parse_with_pefile(filepath):
            return
        print("No delay imports found via pefile.")
    except ImportError:
        parse_manual(filepath)
    except Exception as e:
        print(f"pefile path failed ({e}); falling back to manual parse.")
        parse_manual(filepath)


if __name__ == '__main__':
    main()
