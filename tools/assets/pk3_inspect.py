#!/usr/bin/env python3
"""
pk3_inspect.py -- PK3 (ZIP) archive inspector for FAKK2

Lists and categorizes the contents of FAKK2's PK3 archives.
Useful for understanding the game's asset structure.

Usage:
    python3.13 pk3_inspect.py <pk3_path>
    python3.13 pk3_inspect.py --summary <pk3_directory>
"""

import sys
import os
import zipfile
from collections import defaultdict


def inspect_pk3(filepath):
    """Inspect a single PK3 archive."""
    filename = os.path.basename(filepath)
    filesize = os.path.getsize(filepath)

    print(f"\n{'='*60}")
    print(f"  PK3: {filename}")
    print(f"  Size: {filesize:,} bytes ({filesize / 1024 / 1024:.1f} MB)")
    print(f"{'='*60}")

    try:
        with zipfile.ZipFile(filepath, 'r') as zf:
            infos = zf.infolist()
            total_compressed = sum(i.compress_size for i in infos)
            total_uncompressed = sum(i.file_size for i in infos)

            print(f"\n  Files: {len(infos)}")
            print(f"  Compressed:   {total_compressed:>12,} bytes")
            print(f"  Uncompressed: {total_uncompressed:>12,} bytes")

            if total_compressed > 0:
                ratio = (1 - total_compressed / max(total_uncompressed, 1)) * 100
                print(f"  Compression:  {ratio:.1f}%")

            # Categorize by extension
            ext_stats = defaultdict(lambda: {'count': 0, 'size': 0})
            dir_stats = defaultdict(lambda: {'count': 0, 'size': 0})

            for info in infos:
                if info.is_dir():
                    continue
                name = info.filename
                ext = os.path.splitext(name)[1].lower()
                if not ext:
                    ext = '(none)'

                ext_stats[ext]['count'] += 1
                ext_stats[ext]['size'] += info.file_size

                # Top-level directory
                parts = name.split('/')
                if len(parts) > 1:
                    topdir = parts[0]
                else:
                    topdir = '(root)'
                dir_stats[topdir]['count'] += 1
                dir_stats[topdir]['size'] += info.file_size

            # Print by extension
            print(f"\n  --- By Extension ---")
            print(f"  {'Extension':<12} {'Count':>8} {'Size':>14}")
            for ext, stats in sorted(ext_stats.items(), key=lambda x: -x[1]['size']):
                size_str = f"{stats['size']:,}"
                print(f"  {ext:<12} {stats['count']:>8} {size_str:>14}")

            # Print by directory
            print(f"\n  --- By Directory ---")
            print(f"  {'Directory':<24} {'Count':>8} {'Size':>14}")
            for dirname, stats in sorted(dir_stats.items(), key=lambda x: -x[1]['size']):
                size_str = f"{stats['size']:,}"
                print(f"  {dirname:<24} {stats['count']:>8} {size_str:>14}")

            # List TIKI files specifically (key for understanding models)
            tiki_files = [i for i in infos if i.filename.lower().endswith('.tik')]
            if tiki_files:
                print(f"\n  --- TIKI Models ({len(tiki_files)}) ---")
                for info in sorted(tiki_files, key=lambda x: x.filename):
                    print(f"  {info.filename} ({info.file_size:,} bytes)")

            # List shader files
            shader_files = [i for i in infos if i.filename.lower().endswith('.shader')]
            if shader_files:
                print(f"\n  --- Shaders ({len(shader_files)}) ---")
                for info in sorted(shader_files, key=lambda x: x.filename):
                    print(f"  {info.filename} ({info.file_size:,} bytes)")

            # List BSP maps
            bsp_files = [i for i in infos if i.filename.lower().endswith('.bsp')]
            if bsp_files:
                print(f"\n  --- BSP Maps ({len(bsp_files)}) ---")
                for info in sorted(bsp_files, key=lambda x: x.filename):
                    size_mb = info.file_size / 1024 / 1024
                    print(f"  {info.filename} ({size_mb:.1f} MB)")

    except zipfile.BadZipFile:
        print(f"  ERROR: Not a valid ZIP/PK3 file")
    except Exception as e:
        print(f"  ERROR: {e}")


def summary(directory):
    """Summarize all PK3 files in a directory."""
    pk3_files = sorted([
        os.path.join(directory, f)
        for f in os.listdir(directory)
        if f.lower().endswith('.pk3')
    ])

    if not pk3_files:
        print(f"No PK3 files found in {directory}")
        return

    print(f"Found {len(pk3_files)} PK3 files in {directory}")
    for filepath in pk3_files:
        inspect_pk3(filepath)


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <pk3_path>")
        print(f"       {sys.argv[0]} --summary <directory>")
        sys.exit(1)

    if sys.argv[1] == '--summary':
        directory = sys.argv[2] if len(sys.argv) > 2 else '.'
        summary(directory)
    else:
        inspect_pk3(sys.argv[1])


if __name__ == '__main__':
    main()
