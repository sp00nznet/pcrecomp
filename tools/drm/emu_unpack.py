"""Unpack a compressed PE32 by emulating its loader stub, headless.

Runtime packers (PECompact 2.x, UPX, ASPack and kin) decompress the real image
into place, resolve its imports with LoadLibraryA/GetProcAddress, then jump to
the original entry point (OEP). None of that needs Windows: this runs the stub
under Unicorn with those few kernel32 calls answered in Python, and stops at
the first instruction fetched from the image below the stub. No window, no
process, nothing launched -- so it works over RDP and in CI, which a
run-and-dump tool (safedisc_dump.py) cannot.

How the OEP is caught: everything in the image below the stub's page is mapped
read/write but not executable. Decompressing into it is fine; the first fetch
from it faults, and that address is the OEP. So a stub that decompresses into
the image and jumps back is covered by construction, and no per-instruction
hook slows the decompressor down.

How the imports come back: every GetProcAddress hands out a fresh thunk
address, remembered as (dll, name). After the stop, the dumped image is swept
for runs of those addresses -- those runs are the original IAT -- and a new
import directory is written in an appended section pointing its FirstThunks at
them. The IAT stays where the original code expects it, so the result is a
normal PE that pe_analyze and the lifters read like any other.

    py -3 tools/drm/emu_unpack.py packed.exe unpacked.exe
    py -3 tools/drm/emu_unpack.py packed.exe unpacked.exe --stub-low 0x1100000

The stub must stay inside the API set below. An unknown call stops the run and
names the import, which is the next line to add to APIS.
"""
import argparse
import re
import struct
import sys
import types

import pefile
from unicorn import (Uc, UcError, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE,
                     UC_HOOK_MEM_FETCH_PROT, UC_PROT_ALL, UC_PROT_READ,
                     UC_PROT_WRITE)
from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_ESP, UC_X86_REG_EIP,
                               UC_X86_REG_FS,
                               UC_X86_REG_SS, UC_X86_REG_GDTR)

PAGE = 0x1000
THUNKS = 0x70000000      # fake API entry points, one dword apart
MODULES = 0x71000000     # fake HMODULEs, one page apart
HEAP = 0x60000000        # VirtualAlloc bump allocator
HEAP_SIZE = 0x08000000
STACK, STACK_SIZE = 0x5F000000, 0x100000
TEB = 0x5E000000
GDT = 0x5D000000
CODE = 0xE0000020        # code, RWX: the unpacked code may still patch itself
DATA = 0xC0000040        # initialised data, RW


def align(v, a=PAGE):
    return (v + a - 1) & ~(a - 1)


class Unpacker:
    def __init__(self, path, stub_low=None):
        self.pe = pefile.PE(path)
        oh = self.pe.OPTIONAL_HEADER
        self.base, self.size = oh.ImageBase, align(oh.SizeOfImage)
        self.entry = self.base + oh.AddressOfEntryPoint
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        self.thunks = {}          # thunk address -> (dll, name or ordinal)
        self.modules = {}         # HMODULE -> dll name
        self.heap = HEAP
        self.stub_low = stub_low
        self.oep = None
        self.stopped = None

    # ---------------------------------------------------------------- setup
    def map(self):
        uc = self.uc
        uc.mem_map(self.base, self.size, UC_PROT_ALL)
        uc.mem_write(self.base, self.pe.get_memory_mapped_image()[:self.size])
        for addr, size in ((THUNKS, 0x100000), (MODULES, 0x100000),
                           (HEAP, HEAP_SIZE), (STACK, STACK_SIZE),
                           (TEB, PAGE), (GDT, PAGE)):
            uc.mem_map(addr, size, UC_PROT_ALL)
        # A flat FS pointing at a zeroed TEB whose SEH list head is -1: enough
        # for a stub that installs an SEH frame, which PECompact does.
        uc.mem_write(TEB, struct.pack('<III', 0xFFFFFFFF, STACK + STACK_SIZE,
                                      STACK) + b'\0' * 0x0C + struct.pack('<I', TEB))
        # Segments need a GDT in 32-bit Unicorn (FS_BASE is a no-op there),
        # and once one is loaded SS needs a descriptor of its own too.
        uc.mem_write(GDT + 0x08, self._gdt_entry(TEB, PAGE - 1))
        uc.mem_write(GDT + 0x10, self._gdt_entry(0, 0xFFFFF, 0xC0))
        uc.reg_write(UC_X86_REG_GDTR, (0, GDT, 0x18 - 1, 0))
        uc.reg_write(UC_X86_REG_FS, 0x08)
        uc.reg_write(UC_X86_REG_SS, 0x10)
        uc.reg_write(UC_X86_REG_ESP, STACK + STACK_SIZE - 0x100)
        # The packed IAT: give each entry a thunk, like the Windows loader.
        for imp in getattr(self.pe, 'DIRECTORY_ENTRY_IMPORT', []):
            dll = imp.dll.decode().lower()
            for i in imp.imports:
                self._write32(i.address, self._thunk(dll, i.name.decode() if i.name else i.ordinal))
        uc.hook_add(UC_HOOK_CODE, self._api, begin=THUNKS, end=THUNKS + 0xFFFFF)
        uc.hook_add(UC_HOOK_MEM_FETCH_PROT, self._fetch_prot)

    @staticmethod
    def _gdt_entry(base, limit, flags=0x40):
        # Writable data segment, present, DPL 0; flags 0xC0 = 4 KB granular.
        return struct.pack('<HHBBBB', limit & 0xFFFF, base & 0xFFFF, (base >> 16) & 0xFF,
                           0x93, flags | ((limit >> 16) & 0xF), (base >> 24) & 0xFF)

    def _thunk(self, dll, name):
        addr = THUNKS + 4 * len(self.thunks)
        self.thunks[addr] = (dll, name)
        return addr

    def _module(self, dll):
        dll = dll.lower()
        if not dll.endswith('.dll'):
            dll += '.dll'
        for h, n in self.modules.items():
            if n == dll:
                return h
        h = MODULES + PAGE * len(self.modules)
        self.modules[h] = dll
        return h

    def _read32(self, a):
        return struct.unpack('<I', self.uc.mem_read(a, 4))[0]

    def _write32(self, a, v):
        self.uc.mem_write(a, struct.pack('<I', v & 0xFFFFFFFF))

    def _cstr(self, a):
        out = bytearray()
        while (b := self.uc.mem_read(a + len(out), 1)[0]):
            out.append(b)
        return out.decode('latin-1')

    # ---------------------------------------------------------------- the API
    def _api(self, uc, addr, size, _):
        dll, name = self.thunks[addr]
        esp = uc.reg_read(UC_X86_REG_ESP)
        arg = lambda n: self._read32(esp + 4 + 4 * n)  # noqa: E731
        handler = APIS.get(name)
        if handler is None:
            self.stopped = f'unhandled import {dll}!{name}, called from 0x{self._read32(esp):08X}'
            uc.emu_stop()
            return
        argc, fn = handler
        uc.reg_write(UC_X86_REG_EAX, fn(self, arg) & 0xFFFFFFFF)
        uc.reg_write(UC_X86_REG_ESP, esp + 4 + 4 * argc)       # argc 0 = cdecl
        uc.reg_write(UC_X86_REG_EIP, self._read32(esp))

    def _fetch_prot(self, uc, access, addr, size, value, _):
        self.oep = addr
        uc.emu_stop()
        return False

    def get_proc(self, hmod, name_ptr):
        dll = self.modules.get(hmod, f'hmodule_{hmod:08x}')
        name = name_ptr if name_ptr < 0x10000 else self._cstr(name_ptr)
        for a, v in self.thunks.items():
            if v == (dll, name):
                return a
        return self._thunk(dll, name)

    def virtual_alloc(self, addr, size):
        if addr:                                # the image itself: already mapped
            return addr
        a, self.heap = self.heap, self.heap + align(size)
        if self.heap > HEAP + HEAP_SIZE:
            raise MemoryError('emu heap exhausted')
        return a

    # ---------------------------------------------------------------- run
    def run(self):
        self.map()
        stub_page = self.entry & ~(PAGE - 1)
        # The entry is usually `mov eax, stub ; jmp eax` sitting on the code's
        # first page, so follow that one hop before fencing the image off.
        head = bytes(self.uc.mem_read(self.entry, 7))
        start = self.entry
        if head[0] == 0xB8 and head[5:7] == b'\xFF\xE0':
            start = struct.unpack('<I', head[1:5])[0]
            self.uc.reg_write(UC_X86_REG_EAX, start)
            stub_page = start & ~(PAGE - 1)
        low = self.stub_low or stub_page
        text = self.base + PAGE
        self.uc.mem_protect(text, low - text, UC_PROT_READ | UC_PROT_WRITE)
        try:
            self.uc.emu_start(start, 0xFFFFFFFF)
        except UcError as e:
            if self.oep is None:
                eip = self.uc.reg_read(UC_X86_REG_EIP)
                raise SystemExit(f'stub faulted at 0x{eip:08X}: {e}')
        if self.oep is None:
            raise SystemExit(f'stopped before the OEP: {self.stopped or "stub returned"}')
        return self.oep

    # ---------------------------------------------------------------- rebuild
    def find_iat(self, image):
        """The IAT in the dumped image: {rva: [(dll, name)...]}, one run per DLL.

        Thunk values turn up in more places than the IAT: a CRT that caches a
        GetProcAddress result in a global, and whole second copies of the table
        (The Movies keeps one 1.2 MB further on). The IAT is the block of runs,
        each separated by one null, that the code calls through with
        `call/jmp [abs32]`, so that is how it is picked.
        """
        runs, cur, prev_end = [], None, None
        for off in range(0, len(image) - 3, 4):
            v = struct.unpack_from('<I', image, off)[0]
            if v not in self.thunks:
                cur = None
                continue
            if cur is None or self.thunks[v][0] != cur[1][-1][0]:
                cur = (off, [])
                runs.append(cur)
            cur[1].append(self.thunks[v])
        blocks = []
        for off, entries in runs:
            if blocks and off in (prev_end, prev_end + 4):   # 0 or 1 null between DLLs
                blocks[-1].append((off, entries))
            else:
                blocks.append([(off, entries)])
            prev_end = off + 4 * len(entries)
        called = {struct.unpack('<I', m.group(1))[0] - self.base
                  for m in re.finditer(rb'\xff[\x15\x25](....)', bytes(image), re.S)}

        def score(block):
            return sum(1 for off, e in block for k in range(len(e)) if off + 4 * k in called)
        best = max(blocks, key=score, default=[])
        if not best or not score(best):
            raise SystemExit('no IAT block is called through; is the OEP right?')
        return dict(best)

    def layout(self, iat_rva):
        """The rebuilt section table: [(name, rva, size, characteristics)].

        A packer merges the original sections into one, so the dump has code,
        read-only data and data in a single executable section, and a
        disassembler decodes the data as code (The Movies: 22,355 invented
        functions out of 61,502). Two facts put the boundaries back:
        the original code is in the section the OEP is in, and MSVC's linker
        starts .rdata with the IAT. So only the OEP's section stays
        executable, and it is cut at the IAT when the IAT is inside it.
        """
        out = []
        oep = self.oep - self.base
        for s in self.pe.sections:
            rva, vs = s.VirtualAddress, align(max(s.Misc_VirtualSize, s.SizeOfRawData))
            name = s.Name.rstrip(b'\0')
            if not rva <= oep < rva + vs:
                out.append((name, rva, vs, DATA))
            elif oep < iat_rva < rva + vs and iat_rva % PAGE == 0:
                out.append((name, rva, iat_rva - rva, CODE))
                out.append((b'.rdata', iat_rva, rva + vs - iat_rva, DATA))
            else:
                out.append((name, rva, vs, CODE))
        return out

    def write(self, out):
        image = bytearray(self.uc.mem_read(self.base, self.size))
        runs = self.find_iat(image)

        # New section: descriptors, then per run an OFT array, then names.
        sect_rva = self.size
        desc_size = 20 * (len(runs) + 1)
        blob = bytearray(desc_size)
        strings = {}

        def put_str(b):
            if b not in strings:
                strings[b] = len(blob)
                blob.extend(b + b'\0' + (b'\0' if len(b) % 2 == 0 else b''))
            return sect_rva + strings[b]

        for n, (rva, entries) in enumerate(sorted(runs.items())):
            oft = len(blob)
            blob.extend(b'\0' * 4 * (len(entries) + 1))
            for k, (dll, name) in enumerate(entries):
                if isinstance(name, int):
                    val = 0x80000000 | name
                else:
                    val = put_str(b'\0\0' + name.encode())  # hint 0, then name
                struct.pack_into('<I', blob, oft + 4 * k, val)
                struct.pack_into('<I', image, rva + 4 * k, val)   # unbound IAT
            struct.pack_into('<IIIII', blob, 20 * n, sect_rva + oft, 0, 0,
                             put_str(entries[0][0].encode()), rva)
        blob.extend(b'\0' * (align(len(blob), 0x200) - len(blob)))

        pe = self.pe
        fa = pe.OPTIONAL_HEADER.FileAlignment
        sections = self.layout(min(runs))
        sections.append((b'.idata2', sect_rva, len(blob), DATA))
        # Every section becomes raw == virtual: the dump is the file.
        hdr = bytearray(image[:pe.OPTIONAL_HEADER.SizeOfHeaders])
        sec_off = pe.sections[0].get_file_offset()
        if sec_off + 40 * len(sections) > pe.OPTIONAL_HEADER.SizeOfHeaders:
            raise SystemExit('no room in the headers for the rebuilt section table')
        body = bytearray()
        raw_ptr = align(len(hdr), fa)
        for i, (name, rva, vs, flags) in enumerate(sections):
            struct.pack_into('<8sIIII', hdr, sec_off + 40 * i, name, vs, rva, vs, raw_ptr + len(body))
            struct.pack_into('<IIHHI', hdr, sec_off + 40 * i + 24, 0, 0, 0, 0, flags)
            body.extend(blob if name == b'.idata2' else image[rva:rva + vs])

        nt = pe.DOS_HEADER.e_lfanew
        opt = nt + 24
        struct.pack_into('<H', hdr, nt + 6, len(sections))
        struct.pack_into('<I', hdr, opt + 16, self.oep - self.base)          # entry
        struct.pack_into('<I', hdr, opt + 56, sect_rva + len(blob))          # SizeOfImage
        struct.pack_into('<I', hdr, opt + 64, 0)                             # checksum
        dd = opt + 96
        struct.pack_into('<II', hdr, dd + 8, sect_rva, desc_size)            # import dir
        first = min(runs)
        last = max(r + 4 * len(e) for r, e in runs.items())
        struct.pack_into('<II', hdr, dd + 8 * 12, first, last - first)       # IAT dir
        struct.pack_into('<II', hdr, dd + 8 * 5, 0, 0)                       # relocs
        hdr.extend(b'\0' * (raw_ptr - len(hdr)))
        with open(out, 'wb') as f:
            f.write(hdr + body)
        return runs


def _load_library(u, a):
    return u._module(u._cstr(a(0)))


# name -> (stdcall argc, handler). Handlers get the unpacker and arg(n).
APIS = {
    'LoadLibraryA': (1, _load_library),
    'GetModuleHandleA': (1, lambda u, a: u.base if a(0) == 0 else _load_library(u, a)),
    'GetProcAddress': (2, lambda u, a: u.get_proc(a(0), a(1))),
    'VirtualAlloc': (4, lambda u, a: u.virtual_alloc(a(0), a(1))),
    'VirtualFree': (3, lambda u, a: 1),
    'VirtualProtect': (4, lambda u, a: (u._write32(a(3), 0x40) if a(3) else None) or 1),
    'FlushInstructionCache': (3, lambda u, a: 1),
    'FreeLibrary': (1, lambda u, a: 1),
    # Steam2 (2004-2008) DRM wrapper: a PECompact loader plugin that asks
    # steam.dll whether the app is owned before it jumps to the OEP. cdecl.
    # Answer "started, subscribed, not pending" -- no Steam is involved.
    'SteamStartup': (0, lambda u, a: 1),
    'SteamCleanup': (0, lambda u, a: 1),
    'SteamIsAppSubscribed': (0, lambda u, a: (u._write32(a(1), 1), u._write32(a(2), 0), 1)[2]),
}


def selftest():
    """IAT picking: the real table, a second copy of it, and a stray cached
    pointer are all runs of thunks; only the table the code calls through wins."""
    u = object.__new__(Unpacker)
    u.base = 0x400000
    u.thunks = {THUNKS: ('kernel32.dll', 'A'), THUNKS + 4: ('kernel32.dll', 'B'),
                THUNKS + 8: ('user32.dll', 'C')}
    img = bytearray(0x1000)
    for at in (0x100, 0x400):                                  # table, and its copy
        struct.pack_into('<IIII', img, at, THUNKS, THUNKS + 4, 0, THUNKS + 8)
    struct.pack_into('<I', img, 0x800, THUNKS + 4)             # cached GetProcAddress
    img[0x900:0x906] = b'\xff\x15' + struct.pack('<I', u.base + 0x10C)
    got = u.find_iat(img)
    assert got == {0x100: [u.thunks[THUNKS], u.thunks[THUNKS + 4]],
                   0x10C: [u.thunks[THUNKS + 8]]}, got
    # Layout: the OEP's merged section is cut at the IAT; the stub's is data.
    sec = lambda n, rva, size: types.SimpleNamespace(  # noqa: E731
        Name=n, VirtualAddress=rva, Misc_VirtualSize=size, SizeOfRawData=0)
    u.pe = types.SimpleNamespace(sections=[sec(b'.text', 0x1000, 0x9000), sec(b'.rsrc', 0xA000, 0x1000)])
    u.oep = u.base + 0x2000
    assert u.layout(0x6000) == [(b'.text', 0x1000, 0x5000, CODE), (b'.rdata', 0x6000, 0x4000, DATA),
                                (b'.rsrc', 0xA000, 0x1000, DATA)], u.layout(0x6000)
    assert u.layout(0x6004)[0] == (b'.text', 0x1000, 0x9000, CODE)   # unaligned: no cut
    print('emu_unpack selftest: ok')


def main():
    if '--selftest' in sys.argv:
        return selftest()
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('packed')
    ap.add_argument('out')
    ap.add_argument('--stub-low', type=lambda s: int(s, 0),
                    help='lowest address of the stub; fetches below it are the OEP '
                         '(default: the stub entry\'s page)')
    args = ap.parse_args()
    u = Unpacker(args.packed, args.stub_low)
    oep = u.run()
    runs = u.write(args.out)
    n = sum(len(v) for v in runs.values())
    dlls = sorted({e[0] for v in runs.values() for e in v})
    print(f'OEP 0x{oep:08X}; {n} imports in {len(runs)} IAT runs from {len(dlls)} DLLs; '
          f'{len(u.thunks)} thunks handed out')
    for d in dlls:
        print(f'  {d}: {sum(1 for v in runs.values() for e in v if e[0] == d)}')
    print(f'wrote {args.out}')


if __name__ == '__main__':
    sys.exit(main())
