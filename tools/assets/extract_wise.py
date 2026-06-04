"""
extract_wise.py - Inspect / extract a Wise Installation System installer.

Wise installers (very common for late-90s / early-2000s Windows games and
apps) carry their payload in the PE *overlay* -- the bytes after the last
section. The overlay holds a compressed install script (file list, paths,
registry ops) followed by the file data blobs. Compression is usually raw
DEFLATE or, on older installers, PKWARE DCL "implode".

This tool locates the overlay, tries hard to inflate the script, scans it for
path-like strings (the file list), and signature-scans the overlay for
embedded archives/binaries. It is deliberately format-tolerant rather than a
full Wise script interpreter: enough to see what an installer contains and pull
the obvious blobs out.

Note: DCL-imploded scripts won't inflate with zlib -- those need a PKWARE DCL
("blast") decompressor, which is out of scope here; the script reports the
limitation rather than failing silently.

Usage:
    python extract_wise.py <installer.exe> [out_dir]
"""
import struct
import zlib
import os
import sys


def find_overlay(data):
    """Find the PE overlay start (offset just past the last raw section)."""
    if data[:2] != b'MZ':
        raise ValueError("Not a PE file")
    pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
    num_sections = struct.unpack_from('<H', data, pe_offset + 6)[0]
    opt_header_size = struct.unpack_from('<H', data, pe_offset + 20)[0]
    section_offset = pe_offset + 24 + opt_header_size

    max_end = 0
    for i in range(num_sections):
        off = section_offset + i * 40
        raw_size = struct.unpack_from('<I', data, off + 16)[0]
        raw_offset = struct.unpack_from('<I', data, off + 20)[0]
        end = raw_offset + raw_size
        if end > max_end:
            max_end = end

    return max_end


def try_inflate(data, offset, max_size=50 * 1024 * 1024):
    """Try raw/zlib/gzip DEFLATE at the given offset; return bytes or None."""
    for wbits in [-15, -14, -13, -12, -11, -10, -9, -8, 15, 31, 47]:
        try:
            dec = zlib.decompressobj(wbits)
            result = dec.decompress(data[offset:offset + max_size])
            if len(result) > 100:
                return result
        except Exception:
            pass
    return None


def extract_wise_script(data, overlay_start):
    """Try to locate and decompress the Wise installer script."""
    vals = struct.unpack_from('<8I', data, overlay_start)
    print(f"Overlay header values: {[f'0x{v:X}' for v in vals]}")

    # Strategy 1: compressed data tends to start a few dwords into the overlay.
    for test_offset in [4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48]:
        result = try_inflate(data, overlay_start + test_offset)
        if result:
            print(f"Decompressed script from overlay+{test_offset}: {len(result)} bytes")
            return result

    # Strategy 2: scan the first 1KB of overlay for a zlib stream header.
    for i in range(min(1024, len(data) - overlay_start - 1)):
        abs_i = overlay_start + i
        b0 = data[abs_i]
        b1 = data[abs_i + 1] if abs_i + 1 < len(data) else 0
        if b0 == 0x78 and b1 in (0x01, 0x5E, 0x9C, 0xDA):
            result = try_inflate(data, abs_i)
            if result:
                print(f"Found zlib stream at overlay+{i}: {len(result)} bytes")
                return result

    return None


def parse_script_for_filenames(script_data):
    """Heuristically pull path-like strings (the file list) out of the script."""
    filenames = []
    i = 0
    while i < len(script_data):
        if script_data[i:i + 2] in [b'C:', b'c:', b'%S', b'%s'] or \
           (0x20 < script_data[i] < 0x7f and script_data[i:i + 1] in [b'\\', b'/']):
            end = i
            while end < len(script_data) and script_data[end] != 0:
                end += 1
            try:
                s = script_data[i:end].decode('ascii')
                if len(s) > 2:
                    filenames.append((i, s))
            except Exception:
                pass
            i = end + 1
        else:
            i += 1
    return filenames


def scan_signatures(data, overlay_start):
    """Scan the overlay for recognizable embedded-file signatures."""
    print("\nScanning overlay for known file signatures...")
    sigs = {
        b'MZ': 'exe_or_dll',
        b'MSCF': 'cab',
        b'PK\x03\x04': 'zip',
        b'Rar!': 'rar',
        b'RIFF': 'riff',
    }
    found = []
    pos = overlay_start
    while pos < len(data) - 4:
        for sig, ftype in sigs.items():
            if data[pos:pos + len(sig)] == sig:
                found.append((pos, ftype))
                print(f"  Found {ftype} signature at offset 0x{pos:X}")
        pos += 512  # coarse scan for speed
    return found


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <installer.exe> [out_dir]")
        sys.exit(1)
    installer_path = sys.argv[1]
    out_dir = sys.argv[2] if len(sys.argv) > 2 else os.path.join(
        os.path.dirname(os.path.abspath(installer_path)), 'wise_extracted')

    print(f"Reading {installer_path}...")
    with open(installer_path, 'rb') as f:
        data = f.read()
    print(f"File size: {len(data):,} bytes")

    overlay_start = find_overlay(data)
    print(f"PE overlay at 0x{overlay_start:X}, size: {len(data) - overlay_start:,} bytes")

    print("\nAttempting to decompress installer script...")
    script = extract_wise_script(data, overlay_start)

    if script:
        os.makedirs(out_dir, exist_ok=True)
        script_path = os.path.join(out_dir, '_wise_script.bin')
        with open(script_path, 'wb') as f:
            f.write(script)
        print(f"Saved script to {script_path}")

        filenames = parse_script_for_filenames(script)
        if filenames:
            print(f"\nFound {len(filenames)} path-like strings in script:")
            for offset, fn in filenames[:50]:
                print(f"  0x{offset:X}: {fn}")
            if len(filenames) > 50:
                print(f"  ... and {len(filenames) - 50} more")
    else:
        print("Could not decompress script with standard DEFLATE methods.")
        print("This installer likely uses PKWARE DCL Implode compression,")
        print("which needs a 'blast'-style DCL decompressor (not included).")

    found = scan_signatures(data, overlay_start)
    print(f"\nTotal signatures found in overlay: {len(found)}")


if __name__ == '__main__':
    main()
