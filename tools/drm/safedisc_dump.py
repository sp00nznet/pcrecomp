"""
Memory Dumper for X-Wing Alliance.

The Steam distribution of XWA has SafeDisc v1 encryption on the .text section.
The code is decrypted at runtime by the .bind section's entry point stub.
This tool launches the game, waits for decryption, and dumps the decrypted
.text section from process memory.

Usage:
    python tools/dump_memory.py "path/to/xwingalliance.exe" [output.bin]

The output is a patched copy of the original PE with the .text section replaced
by decrypted code from memory.
"""

import sys
import os
import struct
import time
import ctypes
from ctypes import wintypes
import pefile

# Windows API constants
PROCESS_ALL_ACCESS = 0x001F0FFF
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
PAGE_READWRITE = 0x04
CREATE_SUSPENDED = 0x00000004
INFINITE = 0xFFFFFFFF

# Windows API functions
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
user32 = ctypes.WinDLL('user32', use_last_error=True)

OpenProcess = kernel32.OpenProcess
OpenProcess.restype = wintypes.HANDLE
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]

ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.restype = wintypes.BOOL
ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]

CloseHandle = kernel32.CloseHandle
TerminateProcess = kernel32.TerminateProcess

VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.restype = ctypes.c_void_p

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.restype = wintypes.BOOL

CreateProcessA = kernel32.CreateProcessA
CreateProcessA.restype = wintypes.BOOL

ResumeThread = kernel32.ResumeThread
WaitForInputIdle = user32.WaitForInputIdle


class STARTUPINFOA(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", ctypes.c_char_p),
        ("lpDesktop", ctypes.c_char_p),
        ("lpTitle", ctypes.c_char_p),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.c_void_p),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


def read_process_memory(handle, address, size):
    """Read memory from a process."""
    buf = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t(0)
    ok = ReadProcessMemory(handle, ctypes.c_void_p(address), buf, size, ctypes.byref(bytes_read))
    if not ok:
        err = ctypes.get_last_error()
        raise OSError(f"ReadProcessMemory failed at 0x{address:08X} (size={size}): error {err}")
    return buf.raw[:bytes_read.value]


def launch_and_dump(exe_path, output_path=None):
    """Launch the game, wait for SafeDisc to decrypt, dump memory."""

    if output_path is None:
        output_path = os.path.splitext(exe_path)[0] + '_decrypted.exe'

    print(f"[*] Launching: {exe_path}")
    print(f"[*] Output:    {output_path}")

    # Parse PE to know section layout
    pe = pefile.PE(exe_path)
    image_base = pe.OPTIONAL_HEADER.ImageBase

    text_section = None
    for s in pe.sections:
        name = s.Name.rstrip(b'\x00').decode('ascii', errors='replace')
        if name == '.text':
            text_section = s
            break

    if not text_section:
        print("ERROR: No .text section found!")
        return False

    text_va = image_base + text_section.VirtualAddress
    text_vsize = text_section.Misc_VirtualSize
    text_raw_offset = text_section.PointerToRawData
    text_raw_size = text_section.SizeOfRawData

    print(f"[*] .text section: VA 0x{text_va:08X}, size 0x{text_vsize:X}")
    print(f"[*]   raw offset: 0x{text_raw_offset:X}, raw size: 0x{text_raw_size:X}")

    # Also dump .rdata and .data sections
    sections_to_dump = []
    for s in pe.sections:
        name = s.Name.rstrip(b'\x00').decode('ascii', errors='replace')
        if name in ('.text', '.rdata', '.data'):
            sections_to_dump.append({
                'name': name,
                'va': image_base + s.VirtualAddress,
                'vsize': s.Misc_VirtualSize,
                'raw_offset': s.PointerToRawData,
                'raw_size': s.SizeOfRawData,
            })

    pe.close()

    # Launch the process
    exe_dir = os.path.dirname(os.path.abspath(exe_path))
    si = STARTUPINFOA()
    si.cb = ctypes.sizeof(STARTUPINFOA)
    pi = PROCESS_INFORMATION()

    exe_bytes = os.path.abspath(exe_path).encode('ascii')

    ok = CreateProcessA(
        exe_bytes,
        None,
        None, None,
        False,
        0,  # Normal creation (not suspended - SafeDisc needs to run)
        None,
        exe_dir.encode('ascii'),
        ctypes.byref(si),
        ctypes.byref(pi),
    )

    if not ok:
        err = ctypes.get_last_error()
        print(f"ERROR: CreateProcess failed: error {err}")
        return False

    print(f"[*] Process created: PID {pi.dwProcessId}")
    print(f"[*] Waiting for SafeDisc to decrypt code section...")

    # Wait for the process to initialize (SafeDisc decrypts on startup)
    # WaitForInputIdle waits until the process has finished initializing
    WaitForInputIdle(pi.hProcess, 10000)  # 10 second timeout
    time.sleep(3)  # Extra wait for good measure

    print(f"[*] Dumping memory sections...")

    # Read the original file
    with open(exe_path, 'rb') as f:
        pe_data = bytearray(f.read())

    # Dump each section from process memory and patch into the PE
    for sect in sections_to_dump:
        print(f"[*] Dumping {sect['name']}: VA 0x{sect['va']:08X}, size 0x{sect['vsize']:X}")
        try:
            # Read the virtual size (may be larger than raw size for .data)
            dump_size = min(sect['vsize'], sect['raw_size'])
            mem = read_process_memory(pi.hProcess, sect['va'], dump_size)
            print(f"    Read {len(mem)} bytes")

            # Check entropy to verify decryption
            import math
            freq = [0] * 256
            for b in mem[:256]:
                freq[b] += 1
            ent = 0
            for fr in freq:
                if fr > 0:
                    p = fr / 256
                    ent -= p * math.log2(p)
            print(f"    Entropy (first 256 bytes): {ent:.2f}")

            # Patch into PE data
            if sect['raw_offset'] + len(mem) <= len(pe_data):
                pe_data[sect['raw_offset']:sect['raw_offset'] + len(mem)] = mem
                print(f"    Patched at raw offset 0x{sect['raw_offset']:X}")
            else:
                print(f"    WARNING: Section too large to patch ({len(mem)} > available)")

        except OSError as e:
            print(f"    ERROR: {e}")

    # Terminate the game process
    print(f"[*] Terminating game process...")
    TerminateProcess(pi.hProcess, 0)
    CloseHandle(pi.hThread)
    CloseHandle(pi.hProcess)

    # Fix the entry point to skip SafeDisc
    # The original entry point is in .bind (SafeDisc wrapper).
    # After decryption, the real entry point is the standard CRT startup.
    # We need to find it - typically it's at the start of .text or can be found
    # by looking for the CRT startup pattern.

    # Write the patched PE
    with open(output_path, 'wb') as f:
        f.write(pe_data)

    print(f"[*] Wrote decrypted PE to: {output_path}")
    print(f"[*] File size: {len(pe_data):,} bytes")

    # Verify: check entropy of dumped .text
    print(f"\n[*] Verification:")
    with open(output_path, 'rb') as f:
        verify_data = f.read()

    text_bytes = verify_data[text_raw_offset:text_raw_offset + min(text_vsize, text_raw_size)]
    # Check entropy at multiple points
    import math
    for off in [0, 0x1000, 0x10000, 0x50000, 0xA0000]:
        if off + 256 <= len(text_bytes):
            freq = [0] * 256
            for b in text_bytes[off:off+256]:
                freq[b] += 1
            ent = 0
            for fr in freq:
                if fr > 0:
                    p = fr / 256
                    ent -= p * math.log2(p)
            va = text_va + off
            print(f"  0x{va:08X}: entropy={ent:.2f}  bytes={text_bytes[off:off+8].hex()}")

    return True


def dump_from_pid(pid, exe_path, output_path=None):
    """Dump from an already-running process by PID."""
    if output_path is None:
        output_path = os.path.splitext(exe_path)[0] + '_decrypted.exe'

    print(f"[*] Attaching to PID: {pid}")

    handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        err = ctypes.get_last_error()
        print(f"ERROR: OpenProcess failed: error {err}")
        return False

    # Parse PE for section info
    pe = pefile.PE(exe_path)
    image_base = pe.OPTIONAL_HEADER.ImageBase

    with open(exe_path, 'rb') as f:
        pe_data = bytearray(f.read())

    for s in pe.sections:
        name = s.Name.rstrip(b'\x00').decode('ascii', errors='replace')
        if name in ('.text', '.rdata', '.data'):
            va = image_base + s.VirtualAddress
            dump_size = min(s.Misc_VirtualSize, s.SizeOfRawData)
            print(f"[*] Dumping {name}: VA 0x{va:08X}, size 0x{dump_size:X}")
            try:
                mem = read_process_memory(handle, va, dump_size)
                pe_data[s.PointerToRawData:s.PointerToRawData + len(mem)] = mem
                print(f"    OK: {len(mem)} bytes")
            except OSError as e:
                print(f"    ERROR: {e}")

    pe.close()
    CloseHandle(handle)

    with open(output_path, 'wb') as f:
        f.write(pe_data)
    print(f"[*] Wrote: {output_path}")
    return True


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <xwingalliance.exe> [output.exe]")
        print(f"       {sys.argv[0]} --pid <PID> <xwingalliance.exe> [output.exe]")
        sys.exit(1)

    if sys.argv[1] == '--pid':
        pid = int(sys.argv[2])
        exe = sys.argv[3]
        out = sys.argv[4] if len(sys.argv) > 4 else None
        dump_from_pid(pid, exe, out)
    else:
        exe = sys.argv[1]
        out = sys.argv[2] if len(sys.argv) > 2 else None
        launch_and_dump(exe, out)
