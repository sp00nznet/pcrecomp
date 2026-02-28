#!/usr/bin/env python3
"""
InstallShield v5/v6 Cabinet Extractor

Extracts files from InstallShield cabinet archives (data1.hdr + data1.cab format).
Based on the unshield project's format documentation:
  https://github.com/twogood/unshield

The .hdr file contains the file directory (names, sizes, offsets, compression info).
The .cab file contains the actual compressed file data (zlib raw deflate).

Supports:
  - Compressed files (FILE_COMPRESSED flag 0x04) stored in the .cab file
  - Uncompressed files (flags=0) stored as loose files alongside the installer
  - Directory structure reconstruction
"""

import struct
import sys
import os
import zlib
import hashlib
import argparse
import time

# --- Constants ---
CAB_SIGNATURE = 0x28635349   # "ISc("
COMMON_HEADER_SIZE = 20
MAX_FILE_GROUP_COUNT = 71
MAX_COMPONENT_COUNT = 71

# File flags
FILE_SPLIT = 1
FILE_OBFUSCATED = 2
FILE_COMPRESSED = 4
FILE_INVALID = 8


class CommonHeader:
    """First 20 bytes of any .hdr or .cab file."""
    def __init__(self, data, offset=0):
        (self.signature,
         self.version,
         self.volume_info,
         self.cab_descriptor_offset,
         self.cab_descriptor_size) = struct.unpack_from('<IIIII', data, offset)

    @property
    def major_version(self):
        return (self.version >> 12) & 0xF


class CabDescriptor:
    """Cabinet descriptor inside the .hdr file."""
    def __init__(self, data, base_offset):
        self.file_table_offset = struct.unpack_from('<I', data, base_offset + 0x0C)[0]
        self.file_table_size = struct.unpack_from('<I', data, base_offset + 0x14)[0]
        self.file_table_size2 = struct.unpack_from('<I', data, base_offset + 0x18)[0]
        self.directory_count = struct.unpack_from('<I', data, base_offset + 0x1C)[0]
        self.file_count = struct.unpack_from('<I', data, base_offset + 0x28)[0]
        self.file_table_offset2 = struct.unpack_from('<I', data, base_offset + 0x2C)[0]

        # File group offsets (71 entries at +0x3e)
        self.file_group_offsets = []
        for i in range(MAX_FILE_GROUP_COUNT):
            val = struct.unpack_from('<I', data, base_offset + 0x3E + i * 4)[0]
            self.file_group_offsets.append(val)

        # Component offsets (71 entries at +0x15a)
        self.component_offsets = []
        for i in range(MAX_COMPONENT_COUNT):
            val = struct.unpack_from('<I', data, base_offset + 0x15A + i * 4)[0]
            self.component_offsets.append(val)


class FileDescriptor:
    """
    File descriptor for InstallShield v5.

    Binary layout (0x3a = 58 bytes):
      +0x00  uint32  name_offset       (offset to filename string in file table)
      +0x04  uint16  directory_index
      +0x06  uint16  (padding)
      +0x08  uint16  flags
      +0x0a  uint32  expanded_size
      +0x0e  uint32  compressed_size
      +0x12  (20 bytes skipped - timestamps, attributes, etc.)
      +0x26  uint32  data_offset       (offset into .cab file)
      +0x2a  (16 bytes) md5 checksum
    """
    SIZE_V5 = 0x3A  # 58 bytes

    def __init__(self, data, offset):
        self.name_offset = struct.unpack_from('<I', data, offset + 0x00)[0]
        self.directory_index = struct.unpack_from('<H', data, offset + 0x04)[0]
        self.flags = struct.unpack_from('<H', data, offset + 0x08)[0]
        self.expanded_size = struct.unpack_from('<I', data, offset + 0x0A)[0]
        self.compressed_size = struct.unpack_from('<I', data, offset + 0x0E)[0]
        self.data_offset = struct.unpack_from('<I', data, offset + 0x26)[0]
        self.md5 = data[offset + 0x2A:offset + 0x3A]

    @property
    def is_compressed(self):
        return bool(self.flags & FILE_COMPRESSED)

    @property
    def is_invalid(self):
        return bool(self.flags & FILE_INVALID)

    @property
    def is_split(self):
        return bool(self.flags & FILE_SPLIT)


class FileGroupDescriptor:
    """File group descriptor parsed from the header."""
    def __init__(self, name, first_file, last_file):
        self.name = name
        self.first_file = first_file
        self.last_file = last_file


class ISCabinet:
    """
    Parser for InstallShield v5/v6 cabinet files.

    Reads the .hdr file to build a directory of files,
    then extracts compressed data from the .cab file.
    """

    def __init__(self, hdr_path, cab_path):
        self.hdr_path = hdr_path
        self.cab_path = cab_path
        self.setup_dir = os.path.dirname(hdr_path)

        # Read entire header into memory
        with open(hdr_path, 'rb') as f:
            self.hdr_data = f.read()

        # Parse common header
        self.common = CommonHeader(self.hdr_data)
        if self.common.signature != CAB_SIGNATURE:
            raise ValueError(
                f"Invalid header signature: 0x{self.common.signature:08x} "
                f"(expected 0x{CAB_SIGNATURE:08x})"
            )

        self.major_version = self.common.major_version
        print(f"Header: {os.path.basename(hdr_path)} ({len(self.hdr_data)} bytes)")
        print(f"Version: 0x{self.common.version:08x} (major={self.major_version})")
        print(f"Cab descriptor at offset 0x{self.common.cab_descriptor_offset:x}, "
              f"size {self.common.cab_descriptor_size}")

        # Parse cab descriptor
        self.cab_desc = CabDescriptor(self.hdr_data, self.common.cab_descriptor_offset)
        print(f"Directories: {self.cab_desc.directory_count}")
        print(f"Files: {self.cab_desc.file_count}")

        # Compute absolute base for file table lookups
        self._ft_base = self.common.cab_descriptor_offset + self.cab_desc.file_table_offset

        # Read file table (array of uint32 offsets)
        total_entries = self.cab_desc.directory_count + self.cab_desc.file_count
        self.file_table = []
        for i in range(total_entries):
            val = struct.unpack_from('<I', self.hdr_data, self._ft_base + i * 4)[0]
            self.file_table.append(val)

        # Parse directory names
        self.directories = []
        for i in range(self.cab_desc.directory_count):
            name = self._read_string(self.file_table[i])
            self.directories.append(name)

        # Parse file descriptors
        self.files = []
        for i in range(self.cab_desc.file_count):
            table_idx = self.cab_desc.directory_count + i
            fd_offset = self._ft_base + self.file_table[table_idx]
            fd = FileDescriptor(self.hdr_data, fd_offset)
            fd.name = self._read_string(fd.name_offset)
            fd.index = i

            # Resolve directory path
            if fd.directory_index < len(self.directories):
                fd.directory = self.directories[fd.directory_index]
            else:
                fd.directory = ""

            self.files.append(fd)

        # Parse file groups
        self.file_groups = self._parse_file_groups()

    def _read_string(self, ft_relative_offset):
        """Read a null-terminated string from the file table area."""
        abs_offset = self._ft_base + ft_relative_offset
        end = self.hdr_data.index(b'\x00', abs_offset)
        return self.hdr_data[abs_offset:end].decode('ascii', errors='replace')

    def _parse_file_groups(self):
        """Parse file group descriptors from the header."""
        groups = []
        cd_base = self.common.cab_descriptor_offset

        for i in range(MAX_FILE_GROUP_COUNT):
            fg_off = self.cab_desc.file_group_offsets[i]
            if fg_off == 0:
                continue

            # OffsetList: name_offset(4), descriptor_offset(4), next_offset(4)
            ol_base = cd_base + fg_off
            name_off = struct.unpack_from('<I', self.hdr_data, ol_base)[0]
            desc_off = struct.unpack_from('<I', self.hdr_data, ol_base + 4)[0]

            # Read name from OffsetList
            ol_name_abs = cd_base + name_off
            end = self.hdr_data.index(b'\x00', ol_name_abs)
            group_name = self.hdr_data[ol_name_abs:end].decode('ascii', errors='replace')

            # Parse group descriptor
            desc_base = cd_base + desc_off
            # For v5: first_file at +0x4c, last_file at +0x50
            first_file = struct.unpack_from('<I', self.hdr_data, desc_base + 0x4C)[0]
            last_file = struct.unpack_from('<I', self.hdr_data, desc_base + 0x50)[0]

            fg = FileGroupDescriptor(group_name, first_file, last_file)
            groups.append(fg)

        return groups

    def list_files(self):
        """Print a listing of all files in the cabinet."""
        print(f"\n{'Idx':>4s}  {'Flags':>5s}  {'Expanded':>12s}  {'Compressed':>12s}  "
              f"{'Offset':>10s}  Path")
        print("-" * 80)

        for fd in self.files:
            if fd.directory:
                path = f"{fd.directory}/{fd.name}"
            else:
                path = fd.name

            flag_str = []
            if fd.is_compressed:
                flag_str.append("C")
            if fd.is_invalid:
                flag_str.append("X")
            if fd.is_split:
                flag_str.append("S")
            flags = "".join(flag_str) if flag_str else "-"

            print(f"{fd.index:4d}  {flags:>5s}  {fd.expanded_size:12d}  "
                  f"{fd.compressed_size:12d}  0x{fd.data_offset:08x}  {path}")

        # Summary
        n_compressed = sum(1 for fd in self.files if fd.is_compressed)
        n_uncompressed = sum(1 for fd in self.files if not fd.is_compressed and not fd.is_invalid)
        n_invalid = sum(1 for fd in self.files if fd.is_invalid)
        print(f"\nTotal: {len(self.files)} files "
              f"({n_compressed} compressed in cab, "
              f"{n_uncompressed} uncompressed/loose, "
              f"{n_invalid} invalid)")

    def extract_all(self, output_dir, include_loose=True):
        """
        Extract all files to the given output directory.

        Args:
            output_dir: Directory to write extracted files to.
            include_loose: If True, also copy loose (uncompressed) files from
                           the setup directory.
        """
        os.makedirs(output_dir, exist_ok=True)

        total = len(self.files)
        extracted = 0
        skipped = 0
        errors = 0
        loose_copied = 0
        loose_missing = 0

        start_time = time.time()

        with open(self.cab_path, 'rb') as cab:
            for fd in self.files:
                if fd.is_invalid:
                    skipped += 1
                    continue

                # Build output path
                if fd.directory:
                    rel_path = os.path.join(fd.directory.replace('\\', os.sep), fd.name)
                else:
                    rel_path = fd.name

                out_path = os.path.join(output_dir, rel_path)
                os.makedirs(os.path.dirname(out_path), exist_ok=True)

                if fd.is_compressed:
                    # Extract from cab file
                    try:
                        self._extract_compressed(cab, fd, out_path)
                        extracted += 1
                        self._print_progress(fd.index, total, rel_path, "extracted")
                    except Exception as e:
                        errors += 1
                        print(f"\n  ERROR extracting {rel_path}: {e}")
                else:
                    # Loose file: try to copy from setup directory
                    if include_loose:
                        src_path = self._find_loose_file(fd)
                        if src_path and os.path.isfile(src_path):
                            try:
                                self._copy_file(src_path, out_path)
                                loose_copied += 1
                                self._print_progress(fd.index, total, rel_path, "copied")
                            except Exception as e:
                                errors += 1
                                print(f"\n  ERROR copying {rel_path}: {e}")
                        else:
                            loose_missing += 1
                            self._print_progress(fd.index, total, rel_path, "MISSING loose file")
                    else:
                        skipped += 1

        elapsed = time.time() - start_time
        print(f"\n\nExtraction complete in {elapsed:.1f}s:")
        print(f"  Extracted from cab: {extracted}")
        print(f"  Copied loose files: {loose_copied}")
        if loose_missing:
            print(f"  Missing loose files: {loose_missing}")
        if skipped:
            print(f"  Skipped: {skipped}")
        if errors:
            print(f"  Errors: {errors}")

    def extract_cab_only(self, output_dir):
        """Extract only compressed files from the .cab file."""
        os.makedirs(output_dir, exist_ok=True)

        cab_files = [fd for fd in self.files if fd.is_compressed and not fd.is_invalid]
        total = len(cab_files)
        extracted = 0
        errors = 0

        start_time = time.time()

        with open(self.cab_path, 'rb') as cab:
            for i, fd in enumerate(cab_files):
                if fd.directory:
                    rel_path = os.path.join(fd.directory.replace('\\', os.sep), fd.name)
                else:
                    rel_path = fd.name

                out_path = os.path.join(output_dir, rel_path)
                os.makedirs(os.path.dirname(out_path), exist_ok=True)

                try:
                    self._extract_compressed(cab, fd, out_path)
                    extracted += 1
                    self._print_progress(i, total, rel_path, "extracted")
                except Exception as e:
                    errors += 1
                    print(f"\n  ERROR extracting {rel_path}: {e}")

        elapsed = time.time() - start_time
        print(f"\n\nExtraction complete in {elapsed:.1f}s:")
        print(f"  Extracted: {extracted}/{total}")
        if errors:
            print(f"  Errors: {errors}")

    def _extract_compressed(self, cab_file, fd, out_path):
        """
        Extract a compressed file from the cab.

        Compressed data format:
          - Sequential chunks, each prefixed with a 2-byte little-endian size
          - Each chunk is raw deflate compressed (zlib with wbits=-15)
          - Read chunks until expanded_size bytes have been decompressed
        """
        cab_file.seek(fd.data_offset)

        total_written = 0
        total_comp_read = 0
        md5_ctx = hashlib.md5()

        with open(out_path, 'wb') as out:
            while total_written < fd.expanded_size:
                # Read 2-byte chunk size
                size_bytes = cab_file.read(2)
                if len(size_bytes) < 2:
                    raise IOError(
                        f"Unexpected end of cab at offset "
                        f"0x{cab_file.tell():x} reading chunk size"
                    )
                total_comp_read += 2
                chunk_size = struct.unpack('<H', size_bytes)[0]

                if chunk_size == 0:
                    break

                # Read compressed chunk
                chunk_data = cab_file.read(chunk_size)
                if len(chunk_data) < chunk_size:
                    raise IOError(
                        f"Unexpected end of cab reading chunk data "
                        f"({len(chunk_data)}/{chunk_size} bytes)"
                    )
                total_comp_read += chunk_size

                # Decompress with raw deflate (no zlib header)
                try:
                    decompressed = zlib.decompress(chunk_data, -15)
                except zlib.error as e:
                    raise IOError(
                        f"Decompression failed at compressed offset "
                        f"{total_comp_read}: {e}"
                    )

                out.write(decompressed)
                md5_ctx.update(decompressed)
                total_written += len(decompressed)

        # Verify size
        if total_written != fd.expanded_size:
            print(f"\n  WARNING: {fd.name}: extracted {total_written} bytes, "
                  f"expected {fd.expanded_size}")

        # Verify MD5 if available (non-zero)
        if fd.md5 != b'\x00' * 16:
            computed_md5 = md5_ctx.digest()
            if computed_md5 != fd.md5:
                print(f"\n  WARNING: {fd.name}: MD5 mismatch "
                      f"(got {computed_md5.hex()}, expected {fd.md5.hex()})")

    def _find_loose_file(self, fd):
        """
        Locate a loose (uncompressed) file in the setup directory.

        These files exist as regular files in the installer directory tree.
        The directory mapping is:
          dir index -> directory name -> subdirectory in setup folder
        """
        dir_name = fd.directory
        if dir_name:
            # Try the setup directory with the mapped path
            candidate = os.path.join(self.setup_dir, dir_name.replace('\\', os.sep), fd.name)
        else:
            candidate = os.path.join(self.setup_dir, fd.name)

        if os.path.isfile(candidate):
            return candidate

        # Try case-insensitive search in the directory
        search_dir = os.path.dirname(candidate)
        target_name = os.path.basename(candidate).lower()
        if os.path.isdir(search_dir):
            for entry in os.listdir(search_dir):
                if entry.lower() == target_name:
                    return os.path.join(search_dir, entry)

        return None

    def _copy_file(self, src, dst):
        """Copy a file from src to dst."""
        buf_size = 64 * 1024
        with open(src, 'rb') as fin, open(dst, 'wb') as fout:
            while True:
                chunk = fin.read(buf_size)
                if not chunk:
                    break
                fout.write(chunk)

    def _print_progress(self, current, total, name, status):
        """Print extraction progress."""
        pct = (current + 1) * 100 // total if total > 0 else 100
        # Truncate long names for display
        display_name = name if len(name) <= 50 else "..." + name[-47:]
        sys.stdout.write(f"\r  [{pct:3d}%] {current+1}/{total}  {status}: {display_name:<54s}")
        sys.stdout.flush()


def main():
    parser = argparse.ArgumentParser(
        description="Extract files from InstallShield v5/v6 cabinet archives.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s data1.hdr data1.cab -o output/
  %(prog)s data1.hdr data1.cab -o output/ --list
  %(prog)s data1.hdr data1.cab -o output/ --cab-only
        """
    )
    parser.add_argument('hdr', help='Path to the .hdr file (e.g., data1.hdr)')
    parser.add_argument('cab', help='Path to the .cab file (e.g., data1.cab)')
    parser.add_argument('-o', '--output', default='extracted',
                        help='Output directory (default: extracted)')
    parser.add_argument('--list', action='store_true',
                        help='List files without extracting')
    parser.add_argument('--cab-only', action='store_true',
                        help='Extract only compressed files from the .cab '
                             '(skip loose files)')
    parser.add_argument('--no-loose', action='store_true',
                        help='Do not copy loose (uncompressed) files from the '
                             'setup directory')
    parser.add_argument('--groups', action='store_true',
                        help='Show file group information')

    args = parser.parse_args()

    # Parse the cabinet
    cabinet = ISCabinet(args.hdr, args.cab)

    # Show file groups if requested
    if args.groups:
        print("\nFile Groups:")
        for fg in cabinet.file_groups:
            print(f"  {fg.name}: files {fg.first_file}-{fg.last_file}")

    # List or extract
    if args.list:
        cabinet.list_files()
    elif args.cab_only:
        cabinet.extract_cab_only(args.output)
    else:
        cabinet.extract_all(args.output, include_loose=not args.no_loose)


if __name__ == '__main__':
    main()
