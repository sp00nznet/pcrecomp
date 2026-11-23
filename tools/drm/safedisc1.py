r"""Unwrap a SafeDisc 1.x title by emulating its loader, headless (WORK IN PROGRESS).

A SafeDisc 1 game ships a cleartext loader EXE and an encrypted .ICD holding the
real program (its .text is ~8 bits/byte and its kernel32/user32 imports are
stripped). The loader decrypts the ICD and process-hollows it into a child. None
of that needs Windows: this runs the loader under Unicorn with its kernel32 /
user32 / ntdll calls answered in Python, the way drm/emu_unpack.py runs a packer
stub -- no window, no process, nothing launched, so it works over RDP and in CI,
which the run-and-dump drm/safedisc_dump.py cannot.

Status: the loader is driven from its clean MSVC entry point through CRT start-up,
the C-DILLA set-up, the SoftICE / NtQueryInformationProcess / KUSER_SHARED_DATA /
IsDebuggerPresent anti-debug gauntlet (all answered "no debugger"), and up to the
driver authentication:

    DeviceIoControl(\\.\Secdrv, 0xEF002407, in=1300, out=1552)

The loader will not decrypt until that 1552-byte challenge response is right, so
the remaining work is: (1) emulate SECDRV.SYS's IOCTL handler (8 KB, no disk I/O,
pure computation -- emulatable with a fake IRP) to answer the challenge; (2) let
the loader decrypt and process-hollow the child; (3) model the child's memory so
the decrypted image written with WriteProcessMemory is captured; (4) rebuild the
PE and its import table (drm/emu_unpack.py's find_iat/write do this). secdrv is the
same for every SafeDisc 1 title, so once it lands this unwraps Crimson Skies and
X-Wing Alliance too. docs/safedisc1.md has the full mechanism.

    py -3 -E tools/drm/safedisc1.py LOADER.EXE GAME.ICD [max_insns]
"""
import os
import struct
import sys

import pefile
from unicorn import *
from unicorn.x86_const import *

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)                                   # our own dir (py -P strips it)
sys.path.insert(0, os.path.join(_HERE, '..', 'pe'))
try:
    from stdcall_argc import ArgcResolver
    _ARGC = ArgcResolver()
except Exception as _e:               # noqa: BLE001 -- the default stays usable without it
    print('note: stdcall_argc unavailable (%s); unknown stdcall purges default to 0' % _e, file=sys.stderr)
    _ARGC = None

PAGE = 0x1000
THUNKS = 0x70000000
MODULES = 0x71000000
HEAP = 0x60000000
HEAP_SIZE = 0x10000000
STACK, STACK_SIZE = 0x5F000000, 0x200000
TEB = 0x5E000000
PEB = 0x5E010000
GDT = 0x5D000000
FILEBUF = 0x50000000            # where CreateFileMapping views land
FILEBUF_SIZE = 0x04000000


def align(v, a=PAGE):
    return (v + a - 1) & ~(a - 1)


class Tracer:
    def __init__(self, loader, icd):
        self.pe = pefile.PE(loader)
        self.loader_path = loader
        self.loader_base = os.path.basename(loader).lower()
        self.loader_bytes = open(loader, 'rb').read()
        self.icd_path = icd
        self.icd = open(icd, 'rb').read()
        self.fdata = {}                 # file HANDLE -> [bytes, position]
        oh = self.pe.OPTIONAL_HEADER
        self.base, self.size = oh.ImageBase, align(oh.SizeOfImage)
        self.entry = self.base + oh.AddressOfEntryPoint
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        self.thunks = {}
        self.modules = {}
        self.heap = HEAP
        self.filebuf = FILEBUF
        self.handles = {}           # HANDLE -> description
        self.next_handle = 0x100
        self.mappings = {}          # mapping handle -> (name, size)
        self.log = []
        self.calls = []
        self.ring = [0] * 64
        self.ri = 0
        self.icount = 0
        self.stop_reason = None

    # ---- memory helpers
    def r32(self, a):
        return struct.unpack('<I', self.uc.mem_read(a, 4))[0]

    def w32(self, a, v):
        self.uc.mem_write(a, struct.pack('<I', v & 0xFFFFFFFF))

    def cstr(self, a, w=False):
        if not a:
            return None
        out = bytearray()
        try:
            if w:
                while (c := self.uc.mem_read(a + len(out), 2)) != b'\0\0':
                    out += c
                    if len(out) > 520:
                        break
                return out.decode('utf-16le', 'replace')
            while (b := self.uc.mem_read(a + len(out), 1)[0]):
                out.append(b)
                if len(out) > 260:
                    break
        except UcError:
            return '<unmapped 0x%08x>' % a
        return out.decode('latin-1')

    def handle(self, desc):
        h = self.next_handle
        self.next_handle += 4
        self.handles[h] = desc
        return h

    # ---- setup
    def map(self):
        uc = self.uc
        uc.mem_map(self.base, self.size, UC_PROT_ALL)
        uc.mem_write(self.base, self.pe.get_memory_mapped_image()[:self.size])
        for addr, size in ((THUNKS, 0x100000), (MODULES, 0x100000), (HEAP, HEAP_SIZE),
                           (STACK, STACK_SIZE), (TEB, 0x20000), (GDT, PAGE),
                           (FILEBUF, FILEBUF_SIZE), (0x7FFE0000, PAGE)):
            uc.mem_map(addr, size, UC_PROT_ALL)
        # KUSER_SHARED_DATA: zeros satisfy the time/version reads; KdDebuggerEnabled
        # (+0x2D0) stays 0 = no kernel debugger.
        uc.mem_write(0x7FFE0000, b'\0' * PAGE)
        # TEB: SEH list = -1, stack base/limit, self ptr at +0x18, PEB at +0x30.
        uc.mem_write(TEB, struct.pack('<III', 0xFFFFFFFF, STACK + STACK_SIZE, STACK))
        self.w32(TEB + 0x18, TEB)
        self.w32(TEB + 0x30, PEB)
        self.w32(PEB + 0x08, self.base)        # PEB.ImageBaseAddress
        uc.mem_write(GDT + 0x08, self._gdt(TEB, 0x1FFFF))
        uc.mem_write(GDT + 0x10, self._gdt(0, 0xFFFFF, 0xC0))
        uc.reg_write(UC_X86_REG_GDTR, (0, GDT, 0x18 - 1, 0))
        uc.reg_write(UC_X86_REG_FS, 0x08)
        uc.reg_write(UC_X86_REG_SS, 0x10)
        uc.reg_write(UC_X86_REG_ESP, STACK + STACK_SIZE - 0x1000)
        for imp in getattr(self.pe, 'DIRECTORY_ENTRY_IMPORT', []):
            dll = imp.dll.decode().lower()
            for i in imp.imports:
                self.w32(i.address, self.thunk(dll, i.name.decode() if i.name else i.ordinal))
        self._seh_ret_thunk = self.thunk('__seh', 'ret')
        uc.hook_add(UC_HOOK_CODE, self._api, begin=THUNKS, end=THUNKS + 0xFFFFF)
        uc.hook_add(UC_HOOK_MEM_UNMAPPED, self._unmapped)
        uc.hook_add(UC_HOOK_INTR, self._intr)

    def _intr(self, uc, intno, _):
        # Software traps, with NT's user-mode semantics. Unicorn calls this with
        # EIP already *past* the instruction. On a clean NT box:
        #   CC / CD 03  -> STATUS_BREAKPOINT (0x80000003), Eip backed up by 1
        #   CD nn (other, e.g. CD 01) -> the IDT gate is DPL 0, so #GP ->
        #                 STATUS_ACCESS_VIOLATION (0xC0000005) at the instruction
        # and the fault goes to the thread's SEH chain. SafeDisc relies on this:
        # its `int 1` check records the exception code in an __except filter and
        # penalises the decryption key unless it saw 0xC0000005 (a debugger would
        # swallow the trap instead). Simply stepping past -- what this used to do --
        # is the *debugger* behaviour and corrupted every page after the first.
        eip = uc.reg_read(UC_X86_REG_EIP)
        self.intr_count = getattr(self, 'intr_count', 0) + 1
        prev = bytes(uc.mem_read(eip - 2, 2))
        if intno == 3:
            start = eip - 1 if prev[1] == 0xCC else eip - 2
            self._seh(uc, 0x80000003, start, eip - 1)
        else:
            start = eip - 2 if prev[0] == 0xCD else eip
            self._seh(uc, 0xC0000005, start, start, params=(0, 0xFFFFFFFF))

    @staticmethod
    def _gdt(base, limit, flags=0x40):
        return struct.pack('<HHBBBB', limit & 0xFFFF, base & 0xFFFF, (base >> 16) & 0xFF,
                           0x93, flags | ((limit >> 16) & 0xF), (base >> 24) & 0xFF)

    def thunk(self, dll, name):
        a = THUNKS + 4 * len(self.thunks)
        self.thunks[a] = (dll, name)
        return a

    def module(self, dll):
        dll = dll.lower()
        if not dll.endswith('.dll'):
            dll += '.dll'
        for h, n in self.modules.items():
            if n == dll:
                return h
        h = MODULES + PAGE * len(self.modules)
        self.modules[h] = dll
        return h

    def valloc(self, size):
        a, self.heap = self.heap, self.heap + align(size, PAGE)
        return a

    def _secdrv(self):
        # Lazily bring up the SECDRV.SYS emulator; it sits beside the ICD/loader.
        if getattr(self, '_sd', 'unset') == 'unset':
            self._sd = None
            from secdrv import Secdrv
            for d in (os.path.dirname(os.path.abspath(self.icd_path)),
                      os.path.dirname(os.path.abspath(self.loader_path))):
                p = os.path.join(d, 'SECDRV.SYS')
                if os.path.exists(p):
                    self._sd = Secdrv(p)
                    break
            if self._sd is None:
                self.log.append(('!secdrv', 'SECDRV.SYS not found beside ICD'))
        return self._sd

    # ---- API dispatch
    def _api(self, uc, addr, size, _):
        dll, name = self.thunks[addr]
        if dll == '__seh':
            self._seh_ret(uc)
            return
        esp = uc.reg_read(UC_X86_REG_ESP)
        ret = self.r32(esp)
        a = lambda n: self.r32(esp + 4 + 4 * n)  # noqa: E731
        self.calls.append('%s!%s <-%08x' % (dll.split('.')[0], name, ret))
        fn = getattr(self, 'api_' + name, None)
        if fn is None:
            # benign default: return 1, purge the real stdcall arg count from
            # the SDK import libs (ArgcResolver) so the stack stays in sync.
            # None -> cdecl/unknown -> purge 0 and log loudly.
            argc = None
            if _ARGC and isinstance(name, str):
                argc = _ARGC.lookup(dll if dll.endswith('.dll') else dll + '.dll', name)
            self.log.append(('?API', dll, name, 'argc=%s' % argc, 'ret->0x%08x' % ret))
            uc.reg_write(UC_X86_REG_EAX, 1)
            uc.reg_write(UC_X86_REG_EIP, ret)
            uc.reg_write(UC_X86_REG_ESP, esp + 4 + 4 * (argc or 0))
            return
        argc, val = fn(a)
        uc.reg_write(UC_X86_REG_EAX, val & 0xFFFFFFFF)
        uc.reg_write(UC_X86_REG_EIP, ret)
        uc.reg_write(UC_X86_REG_ESP, esp + 4 + 4 * argc)

    # x86 CONTEXT field offsets (winnt.h) for the registers SEH handlers touch.
    _CTX = (('Edi', 0x9C, UC_X86_REG_EDI), ('Esi', 0xA0, UC_X86_REG_ESI),
            ('Ebx', 0xA4, UC_X86_REG_EBX), ('Edx', 0xA8, UC_X86_REG_EDX),
            ('Ecx', 0xAC, UC_X86_REG_ECX), ('Eax', 0xB0, UC_X86_REG_EAX),
            ('Ebp', 0xB4, UC_X86_REG_EBP), ('Eip', 0xB8, UC_X86_REG_EIP),
            ('EFlags', 0xC0, UC_X86_REG_EFLAGS), ('Esp', 0xC4, UC_X86_REG_ESP))

    def _seh(self, uc, code, fault_eip, ctx_eip, params=()):
        """Raise `code` at `fault_eip` the way KiUserExceptionDispatcher does:
        build an EXCEPTION_RECORD and a CONTEXT (Eip = `ctx_eip`) below the stack,
        then call each fs:[0] handler(rec, frame, ctx, dispatcher) in turn; the
        return comes back through the '__seh!ret' thunk (`_seh_ret`)."""
        esp = uc.reg_read(UC_X86_REG_ESP)
        base = (esp - 0x800) & ~0xF
        rec, ctx = base + 0x10, base + 0x80
        uc.mem_write(rec, bytes(1) * 0x50)
        uc.mem_write(rec, struct.pack('<IIIII', code, 0, 0, fault_eip, len(params)))
        for i, v in enumerate(params):
            self.w32(rec + 0x14 + 4 * i, v)
        uc.mem_write(ctx, bytes(1) * 0x2CC)
        self.w32(ctx, 0x1003F)                       # CONTEXT_ALL
        for _, off, reg in self._CTX:
            self.w32(ctx + off, uc.reg_read(reg))
        self.w32(ctx + 0xB8, ctx_eip)
        self.w32(ctx + 0xBC, 0x1B); self.w32(ctx + 0xC8, 0x23)
        self.w32(ctx + 0x8C, 0); self.w32(ctx + 0x90, 0x3B)
        self._seh_state = {'rec': rec, 'ctx': ctx, 'base': base,
                           'frame': self.r32(TEB), 'depth': 0}
        self._seh_call(uc)

    def _seh_call(self, uc):
        st = self._seh_state
        frame = st['frame']
        if frame in (0, 0xFFFFFFFF) or st['depth'] > 64:
            self.stop_reason = 'unhandled exception 0x%08X at 0x%08X' % (
                self.r32(st['rec']), self.r32(st['rec'] + 12))
            uc.emu_stop()
            return
        st['depth'] += 1
        sp = st['base'] - 0x14
        uc.mem_write(sp, struct.pack('<5I', self._seh_ret_thunk, st['rec'], frame,
                                     st['ctx'], st['base']))
        uc.reg_write(UC_X86_REG_ESP, sp)
        uc.reg_write(UC_X86_REG_EIP, self.r32(frame + 4))

    def _seh_ret(self, uc):
        # A handler returned: 0 = ExceptionContinueExecution (resume from the
        # possibly-edited CONTEXT), 1 = ExceptionContinueSearch (next frame).
        # An __except handler (_except_handler3) never returns here; it unwinds
        # with RtlUnwind and jumps into the __except block itself.
        st = self._seh_state
        disp = uc.reg_read(UC_X86_REG_EAX)
        if disp == 0:
            for _, off, reg in self._CTX:
                uc.reg_write(reg, self.r32(st['ctx'] + off))
            return
        st['frame'] = self.r32(st['frame'])
        self._seh_call(uc)

    def _unmapped(self, uc, access, addr, size, value, _):
        self.stop_reason = 'unmapped %s at 0x%08X from eip 0x%08X' % (
            {16: 'read', 17: 'write', 18: 'fetch'}.get(access, access), addr,
            uc.reg_read(UC_X86_REG_EIP))
        uc.emu_stop()
        return False

    # ---- kernel32 the CRT + loader need (argc, return)
    def api_GetVersion(self, a):
        return 0, 0xC0000A28            # NT 5.0-ish in the low word, Win9x bit clear
    def api_GetVersionExA(self, a):
        p = a(0); self.w32(p + 4, 5); self.w32(p + 8, 0); self.w32(p + 16, 2); return 1, 1
    def api_GetModuleHandleA(self, a):
        s = self.cstr(a(0)); return 1, (self.base if not s else self.module(s))
    def api_GetModuleFileNameA(self, a):
        # NULL module = the loader itself; it reopens this path to read its payload.
        path = (self.loader_path if not a(0) or a(0) == self.base
                else self.icd_path).encode()[:a(2) - 1]
        self.uc.mem_write(a(1), path + b'\0'); return 3, len(path)
    def api_LoadLibraryA(self, a):
        return 1, self.module(self.cstr(a(0)))
    def api_LoadLibraryExA(self, a):
        return 3, self.module(self.cstr(a(0)))
    def api_FreeLibrary(self, a):
        return 1, 1
    def api_GetProcAddress(self, a):
        h, n = a(0), a(1)
        dll = self.modules.get(h, 'mod_%08x' % h)
        name = n if n < 0x10000 else self.cstr(n)
        self.log.append(('GetProcAddress', dll, name))
        for t, v in self.thunks.items():
            if v == (dll, name):
                return 2, t
        return 2, self.thunk(dll, name)
    def api_VirtualAlloc(self, a):
        return 4, (a(0) if a(0) else self.valloc(a(1)))
    def api_VirtualFree(self, a):
        return 3, 1
    def api_VirtualProtect(self, a):
        if a(3):
            self.w32(a(3), 0x40)
        return 4, 1
    def api_VirtualQuery(self, a):
        return 3, 0
    def api_HeapCreate(self, a):
        return 3, self.handle('heap')
    def api_HeapDestroy(self, a):
        return 1, 1
    def api_HeapAlloc(self, a):
        return 3, self.valloc(max(a(2), 4))
    def api_HeapReAlloc(self, a):
        return 4, self.valloc(max(a(3), 4))
    def api_HeapFree(self, a):
        return 3, 1
    def api_GetProcessHeap(self, a):
        return 0, self.handle('heap')
    def api_LocalAlloc(self, a):
        return 2, self.valloc(max(a(1), 4))
    def api_GlobalAlloc(self, a):
        return 2, self.valloc(max(a(1), 4))
    def api_GetCommandLineA(self, a):
        s = FILEBUF + FILEBUF_SIZE - 0x100
        self.uc.mem_write(s, b'"' + self.icd_path.encode() + b'"\0'); return 0, s
    def api_GetStartupInfoA(self, a):
        self.uc.mem_write(a(0), b'\0' * 68); self.w32(a(0), 68); return 1, 0
    ENVIRON = b'SystemRoot=C:\\WINDOWS\0OS=Windows_NT\0\0'
    def api_GetEnvironmentStrings(self, a):
        s = FILEBUF + FILEBUF_SIZE - 0x1000; self.uc.mem_write(s, self.ENVIRON); return 0, s
    def api_GetEnvironmentStringsA(self, a):
        return self.api_GetEnvironmentStrings(a)
    def api_GetEnvironmentStringsW(self, a):
        s = FILEBUF + FILEBUF_SIZE - 0x2000
        self.uc.mem_write(s, self.ENVIRON.decode('latin-1').encode('utf-16le')); return 0, s
    def api_FreeEnvironmentStringsA(self, a):
        return 1, 1
    def api_FreeEnvironmentStringsW(self, a):
        return 1, 1
    def api_GetStdHandle(self, a):
        return 1, self.handle('std')
    def api_GetModuleHandleW(self, a):
        return 1, self.base
    # TLS / critical sections / errors -- no-ops
    def api_TlsAlloc(self, a):
        return 0, 1
    def api_TlsSetValue(self, a):
        return 2, 1
    def api_TlsGetValue(self, a):
        return 1, 0
    def api_TlsFree(self, a):
        return 1, 1
    def api_InitializeCriticalSection(self, a):
        return 1, 0
    def api_DeleteCriticalSection(self, a):
        return 1, 0
    def api_EnterCriticalSection(self, a):
        return 1, 0
    def api_LeaveCriticalSection(self, a):
        return 1, 0
    def api_SetLastError(self, a):
        return 1, 0
    def api_GetLastError(self, a):
        return 0, 0
    def api_GetCurrentProcess(self, a):
        return 0, 0xFFFFFFFF
    def api_GetCurrentProcessId(self, a):
        return 0, 0x1234
    def api_GetCurrentThreadId(self, a):
        return 0, 0x5678
    def api_GetTickCount(self, a):
        self.icount += 1; return 0, self.icount * 10
    def api_QueryPerformanceCounter(self, a):
        self.w32(a(0), self.icount); self.w32(a(0) + 4, 0); return 1, 1
    # locale / cp -- enough to get the CRT through _setmbcp
    def api_GetACP(self, a):
        return 0, 1252
    def api_GetOEMCP(self, a):
        return 0, 437
    def api_GetCPInfo(self, a):
        self.uc.mem_write(a(1), b'\x01' + b'\0' * 19); return 2, 1
    def api_GetStringTypeA(self, a):
        return 5, 1
    def api_GetStringTypeW(self, a):
        return 5, 1
    def api_MultiByteToWideChar(self, a):
        # (cp, flags, src, cbSrc, dst, cchDst)
        n = a(3)
        src = self.uc.mem_read(a(2), n if n != 0xFFFFFFFF else self._slen(a(2)) + 1)
        w = src.decode('latin-1').encode('utf-16le')
        if a(4) and a(5):
            self.uc.mem_write(a(4), w[:a(5) * 2])
        return 6, len(w) // 2
    def api_WideCharToMultiByte(self, a):
        # (cp, flags, wsrc, cchSrc, dst, cbDst, defchar, useddef)
        n = a(3)
        if n == 0xFFFFFFFF:
            n = self._wlen(a(2)) + 1
        w = self.uc.mem_read(a(2), n * 2)
        s = w.decode('utf-16le', 'replace').encode('latin-1', 'replace')
        if a(4) and a(5):
            self.uc.mem_write(a(4), s[:a(5)])
        return 8, len(s)
    def _slen(self, p):
        n = 0
        while self.uc.mem_read(p + n, 1)[0]:
            n += 1
        return n
    def _wlen(self, p):
        n = 0
        while self.uc.mem_read(p + 2 * n, 2) != b'\0\0':
            n += 1
        return n
    def api_LCMapStringA(self, a):
        return 6, 0
    def api_GetLocaleInfoA(self, a):
        return 4, 0
    def api_InterlockedIncrement(self, a):
        v = self.r32(a(0)) + 1; self.w32(a(0), v); return 1, v
    def api_InterlockedDecrement(self, a):
        v = self.r32(a(0)) - 1; self.w32(a(0), v); return 1, v
    def api_GetProfileIntA(self, a):
        self.log.append(('GetProfileIntA', self.cstr(a(0)), self.cstr(a(1)), a(2))); return 3, a(2)
    def api_GetPrivateProfileIntA(self, a):
        return 4, a(3)
    # ---- the interesting ones: files, mappings, the driver
    DBG_DEVICES = ('sice', 'ntice', 'siwvid', 'syser', 'trw', 'regsys', 'filevxd', 'icedump')
    def api_CreateFileA(self, a):
        name = self.cstr(a(0))
        self.log.append(('CreateFileA', name))
        tail = (name or '').lower().lstrip('\\.').strip('\\')
        if (name or '').startswith('\\\\.\\') and tail in self.DBG_DEVICES:
            return 7, 0xFFFFFFFF        # INVALID_HANDLE_VALUE: no such debugger
        h = self.handle(('file', name))
        # Back the loader's self-reopen (it reads its own appended SafeDisc payload)
        # and the ICD with real bytes, so reads deliver the right data -- else the
        # shell reconstructs code from zeros and decrypts to junk.
        low = (name or '').lower()
        if low.endswith('.icd') or 'icd' in low:
            self.fdata[h] = [self.icd, 0]
        elif self.loader_base in low or self.loader_base[:-4] in low:
            self.fdata[h] = [self.loader_bytes, 0]
        return 7, h
    def api_NtQueryInformationProcess(self, a):
        # (handle, class, out, len, retlen); class 7 = ProcessDebugPort.
        if a(2):
            self.uc.mem_write(a(2), b'\0' * min(a(3), 8))   # no debug port / handle
        if a(4):
            self.w32(a(4), min(a(3), 4))
        return 5, 0                     # STATUS_SUCCESS
    def api_CheckRemoteDebuggerPresent(self, a):
        if a(1):
            self.w32(a(1), 0)
        return 2, 1
    def api_CreateFileMappingA(self, a):
        fh, size, nm = a(0), a(4), self.cstr(a(5))
        self.log.append(('CreateFileMappingA', self.handles.get(fh, fh), 'size=0x%x' % size, nm))
        h = self.handle(('mapping', nm, size))
        self.mappings[h] = (nm, size, fh)
        return 6, h
    def api_OpenFileMappingA(self, a):
        nm = self.cstr(a(2)); self.log.append(('OpenFileMappingA', nm)); return 3, self.handle(('mapping', nm))
    def api_UnmapViewOfFile(self, a):
        return 1, 1
    def api_MapViewOfFile(self, a):
        h = a(0)
        view = self.filebuf
        self.filebuf += align(0x400000, PAGE)
        desc = self.handles.get(h)
        self.log.append(('MapViewOfFile', desc, '-> 0x%08x' % view))
        # If this maps the ICD file, drop its bytes in so the loader can read them.
        if isinstance(desc, tuple) and desc[0] == 'mapping':
            fh = self.mappings.get(h, (None, None, None))[2]
            fdesc = self.handles.get(fh)
            if isinstance(fdesc, tuple) and fdesc[0] == 'file' and fdesc[1] and 'icd' in fdesc[1].lower():
                self.uc.mem_write(view, self.icd[:FILEBUF_SIZE])
        return 5, view
    def api_DeviceIoControl(self, a):
        code, inbuf, inlen, outbuf, outlen = a(1), a(2), a(3), a(4), a(5)
        self.log.append(('DeviceIoControl', 'code=0x%x' % code, 'in=0x%x/%d' % (inbuf, inlen),
                         'out=0x%x/%d' % (outbuf, outlen)))
        # SafeDisc's secdrv authentication: the loader hands the driver a challenge
        # and will not decrypt the ICD until the response is right. secdrv.py runs
        # the real SECDRV.SYS headless to produce it (see docs/safedisc1.md).
        if code in (0xEF002407,) and inbuf and self._secdrv():
            challenge = bytes(self.uc.mem_read(inbuf, inlen)) if inlen else b''
            status, info, resp = self._secdrv().ioctl(code, challenge, outlen)
            self.log.append(('secdrv', 'status=0x%08x' % status, 'info=%d' % info))
            if outbuf and resp:
                self.uc.mem_write(outbuf, resp[:outlen])
            if a(6):
                self.w32(a(6), info)
            return 8, (1 if status == 0 else 0)
        if a(6):
            self.w32(a(6), outlen)    # bytes returned = out buffer size
        return 8, 1
    def api_CreateProcessA(self, a):
        self.log.append(('CreateProcessA', self.cstr(a(0)), self.cstr(a(1))))
        pi = a(9)
        if pi:
            self.w32(pi, self.handle('proc')); self.w32(pi + 4, self.handle('thread'))
            self.w32(pi + 8, 0x4321); self.w32(pi + 12, 0x8765)
        return 10, 1
    def api_WriteProcessMemory(self, a):
        self.log.append(('WriteProcessMemory', 'dst=0x%08x' % a(1), 'len=0x%x' % a(3)))
        return 5, 1
    def api_ReadProcessMemory(self, a):
        return 5, 1
    def api_GetThreadContext(self, a):
        return 2, 1
    def api_SetThreadContext(self, a):
        return 2, 1
    def api_ResumeThread(self, a):
        return 1, 1
    def api_CreateEventA(self, a):
        return 4, self.handle('event')
    def api_SetEvent(self, a):
        return 1, 1
    def api_WaitForSingleObject(self, a):
        return 2, 0
    def api_Sleep(self, a):
        return 1, 0
    def api_CloseHandle(self, a):
        return 1, 1
    def api_ReadFile(self, a):
        # (handle, buf, nbytes, pBytesRead, overlapped)
        f = self.fdata.get(a(0))
        n = 0
        if f and a(1):
            chunk = f[0][f[1]:f[1] + a(2)]
            self.uc.mem_write(a(1), chunk)
            f[1] += len(chunk)
            n = len(chunk)
        if a(3):
            self.w32(a(3), n)
        return 5, 1
    def api_SetFilePointer(self, a):
        # (handle, distLow, pDistHigh, method); methods 0 BEGIN, 1 CURRENT, 2 END.
        f = self.fdata.get(a(0))
        dist = a(1) - (0x100000000 if a(1) >= 0x80000000 else 0)
        if not f:
            return 4, a(1)
        f[1] = {0: dist, 1: f[1] + dist, 2: len(f[0]) + dist}.get(a(3), dist)
        return 4, f[1] & 0xFFFFFFFF
    def api_GetFileSize(self, a):
        f = self.fdata.get(a(0))
        return 2, (len(f[0]) if f else len(self.icd))
    def api_GetFileAttributesA(self, a):
        return 1, 0x80
    def api_GetLogicalDriveStringsA(self, a):
        self.uc.mem_write(a(1), b'C:\\\0D:\\\0\0'); return 2, 8
    def api_GetDriveTypeA(self, a):
        return 1, 5           # DRIVE_CDROM
    def api_RegOpenKeyExA(self, a):
        if a(4):
            self.w32(a(4), self.handle('key'))
        return 5, 0
    def api_RegQueryValueExA(self, a):
        return 6, 2           # ERROR_FILE_NOT_FOUND
    def api_RegCloseKey(self, a):
        return 1, 0
    # user32
    def api_MessageBoxA(self, a):
        self.log.append(('MessageBoxA', self.cstr(a(1)), self.cstr(a(2))))
        self.stop_reason = 'MessageBox: %r' % self.cstr(a(1)); self.uc.emu_stop(); return 4, 1
    def api_wsprintfA(self, a):
        # cdecl, variadic -- leave stack to caller. The shell builds the Secdrv device name
        # with it, so it must really format (a no-op left the device name empty).
        # ponytail: %s %c %d %u %x/%X with flags/width only; add more if a title needs it.
        import re
        fmt, k = self.cstr(a(1)), [2]
        def arg():
            v = a(k[0]); k[0] += 1; return v
        def sub(m):
            flags, width, conv = m.group(1), m.group(2), m.group(3)
            if conv == '%':
                return '%'
            v = arg()
            if conv == 's':
                v = self.cstr(v) or ''
            elif conv == 'c':
                v = chr(v & 0xFF)
            elif conv == 'd':
                v = v - (1 << 32) if v & 0x80000000 else v
            return ('%' + flags + width + {'u': 'd'}.get(conv, conv)) % v
        out = re.sub(r'%([-0#]*)(\d*)l?([%scduxX])', sub, fmt).encode('latin-1', 'replace')
        self.uc.mem_write(a(0), out + bytes(1))
        return 0, len(out)
    def api_GetKeyboardType(self, a):
        return 1, 4
    def api_GetDesktopWindow(self, a):
        return 0, self.handle('hwnd')
    def api_RegisterClassA(self, a):
        return 1, 1
    def api_CreateWindowExA(self, a):
        return 12, self.handle('hwnd')

    def api_GetFileType(self, a):
        return 1, 2
    def api_SetHandleCount(self, a):
        return 1, a(0)
    def api_SetStdHandle(self, a):
        return 2, 1
    def api_WriteFile(self, a):
        return 5, 1
    def api_FlushFileBuffers(self, a):
        return 1, 1
    def api_RtlUnwind(self, a):
        # (TargetFrame, TargetIp, ExceptionRecord, ReturnValue). _global_unwind2
        # passes the address right after its call as TargetIp, so a normal return
        # is the same as jumping there; unlink every frame above the target.
        # ponytail: frames above the target are dropped without calling their
        # unwind handlers -- SafeDisc's checks raise in the top frame. Call them
        # (EXCEPTION_UNWINDING) if a title nests __try blocks across the raise.
        if a(0):
            self.w32(TEB, a(0))
        return 4, a(3)
    def api_UnhandledExceptionFilter(self, a):
        return 1, 0
    def api_SetUnhandledExceptionFilter(self, a):
        return 1, 0
    def api_SetEnvironmentVariableA(self, a):
        return 2, 1
    def api_GetEnvironmentVariableA(self, a):
        return 3, 0
    def api_ExitProcess(self, a):
        self.stop_reason = 'clean: ExitProcess(%d)' % a(0); self.uc.emu_stop(); return 1, 0
    def api_TerminateProcess(self, a):
        self.stop_reason = 'clean: TerminateProcess'; self.uc.emu_stop(); return 2, 0
    def api_GetSystemDefaultLCID(self, a):
        return 0, 0x409
    def api_GetTimeZoneInformation(self, a):
        return 1, 0
    def api_GetSystemTime(self, a):
        return 1, 0
    def api_GetLocalTime(self, a):
        return 1, 0
    def api_FileTimeToSystemTime(self, a):
        return 2, 1
    def api_FileTimeToLocalFileTime(self, a):
        return 2, 1
    def api_GetFileTime(self, a):
        return 4, 1
    def api_FindFirstFileA(self, a):
        return 2, 0xFFFFFFFF
    def api_FindNextFileA(self, a):
        return 2, 0
    def api_FindClose(self, a):
        return 1, 1
    def api_CopyFileA(self, a):
        return 3, 1
    def api_SetFileAttributesA(self, a):
        return 2, 1
    def api_CompareStringA(self, a):
        return 6, 2
    def api_CompareStringW(self, a):
        return 6, 2
    def api_GetLocaleInfoW(self, a):
        return 4, 0
    def api_LCMapStringW(self, a):
        return 6, 0
    def api_IsBadReadPtr(self, a):
        return 2, 0
    def api_IsBadWritePtr(self, a):
        return 2, 0
    def api_IsBadCodePtr(self, a):
        return 1, 0
    def api_OutputDebugStringA(self, a):
        return 1, 0
    def api_IsDebuggerPresent(self, a):
        return 0, 0

    def run(self, max_insn=50_000_000):
        self.map()
        ring = [0] * 96
        ri = [0]
        watch = getattr(self, 'watch_ret', None)   # (ret_addr) -> dump eax and ring
        def count(uc, addr, size, _):
            self.icount += 1
            self.ring[self.ri % 64] = addr
            self.ri += 1
            if watch and addr == watch:
                eax = uc.reg_read(UC_X86_REG_EAX)
                self.ring_dump = (eax, [ring[(ri[0] + k) % 96] for k in range(96)])
                self.stop_reason = 'reached watch 0x%08X eax=0x%08X' % (addr, eax)
                uc.emu_stop()
        self.uc.hook_add(UC_HOOK_CODE, count)
        try:
            self.uc.emu_start(self.entry, 0xFFFFFFFF, count=max_insn)
        except UcError as e:
            if not self.stop_reason:
                self.stop_reason = '%s at eip 0x%08X (insn %d)' % (
                    e, self.uc.reg_read(UC_X86_REG_EIP), self.icount)
        if not self.stop_reason:
            self.stop_reason = 'ran %d insns without stopping' % self.icount
        return self.stop_reason


def main():
    global _ARGC
    if len(sys.argv) < 3:
        sys.exit('usage: safedisc1.py LOADER.EXE GAME.ICD [max_insns]')
    loader, icd = sys.argv[1], sys.argv[2]
    # The game's own drvmgt.dll sits beside the loader; its export purge counts
    # come from the binary itself (ArgcResolver reads `ret N`).
    if _ARGC is not None:
        try:
            _ARGC = ArgcResolver(dll_dirs=[os.path.dirname(os.path.abspath(loader))])
        except Exception:               # noqa: BLE001
            pass
    t = Tracer(loader, icd)
    reason = t.run(int(sys.argv[3]) if len(sys.argv) > 3 else 40_000_000)
    print('--- loader events ---')
    for e in t.log[-60:]:
        print('  ', ' '.join(str(x) for x in e).encode('ascii', 'replace').decode())
    print('--- stopped:', reason)
    print('    instructions:', t.icount)
    if 'Secdrv' in ' '.join(map(str, t.log)) or any('Secdrv' in str(e) for e in t.log):
        print('    reached the secdrv authentication; see docs/safedisc1.md for what is left')


if __name__ == '__main__':
    main()
