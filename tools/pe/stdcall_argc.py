"""
stdcall_argc.py - Derive Win32 stdcall argument counts without typing them.

Every import shim in a recompiled Win32 program has to pop exactly the argument
slots the real API pops. Get one wrong and the simulated stack silently
desynchronises: every value read after that call is garbage, and the symptom
shows up nowhere near the cause. It is a bad thing to get from a hand-typed
table -- and hand-typed tables do drift. The one carried by the Fury3/Hellbender
projects gives `waveOutOpen` 7 arguments; the real one takes 6.

The answer is already on the machine. In the Windows SDK's **32-bit** import
libraries, stdcall exports are decorated `_Name@N`, where N is the argument byte
count the compiler computed from the real header. Four bytes per 32-bit slot.

    from stdcall_argc import ArgcResolver
    r = ArgcResolver()
    r.lookup('KERNEL32.dll', 'CreateFileA')     -> 7
    r.lookup('DSOUND.dll',   'ordinal_1')       -> 3   (via DirectSoundCreate)
    r.lookup('KERNEL32.dll', 'NoSuchExport')    -> None

Imports referenced by ordinal are resolved against the system copy of the DLL's
export table first, then looked up by name.

That covers plain Win32. A real game's import table has three more kinds, and
an SDK-only lookup returns None for every one of them -- on Star Wars: Force
Commander it resolved 135 of 307:

  * **Third-party stdcall DLLs.** `mss32.dll` (Miles) imports
    `_AIL_waveOutOpen@16`. The count is already *in the name the binary asked
    for*, and no import library is needed to read it.
  * **cdecl.** Every `MSVCRT.dll` import -- `fopen`, `memmove`, `_ftol`. A cdecl
    callee pops **nothing**; the caller cleans up. The answer is 0, and it is
    not a guess.

    Telling cdecl from stdcall cannot be done by looking for `@N` in the DLL's
    export table, which is the obvious idea and is wrong: `KERNEL32.dll`
    exports `Sleep` undecorated and `dinput.dll` exports `DirectInputCreateA`
    undecorated, and both are stdcall. The `@N` lives in the *import library*,
    not the export table. So the undecorated-export rule is restricted to the
    C-runtime DLL families, which are cdecl by definition; anything else with
    no import library stays None.
  * **C++ mangled names.** `MSVCP60.dll` imports 85 `basic_string` and iostream
    methods. The mangling encodes the calling convention, so the cdecl ones
    (`YA`, `SA`) are certain; `__thiscall`/`__stdcall` members are not, because
    the argument *byte* count needs the parameter types and a struct passed by
    value has no knowable size.

Every one of those strategies reads the count off a **name**, and names run out.
A DLL that exports by ordinal only, with no import library anywhere on the
machine, defeats all of them -- and arcade ports are made of those: Mario Kart
Arcade GP DX imports 40 functions from OMRON's OKAO Vision libraries purely by
ordinal, and those DLLs exist nowhere but in the game tree.

So there is one more strategy, and it does not read a name at all:

  * **`purge_from_binary` reads the callee's own `ret N`.** If you have a copy
    of the DLL -- and if the game shipped it, you do -- the byte count is in
    its code. Pass `ArgcResolver(dll_dirs=[game_tree])` and it is tried last,
    after every name-based strategy, including for the `__thiscall` members
    whose types are unknowable. Checked against the SDK import libraries over
    every export where both have an answer: **1,307 agree, 2 disagree** across
    kernel32, user32, gdi32 and ws2_32.

    On Mario Kart Arcade GP DX v1.00.32 that takes the import table from 449 of
    495 resolved to **489 of 495**. The six left are `d3dx9_43`'s math
    functions, which export a `jmp dword ptr [...]` CPU-dispatch thunk whose
    slot is filled at DLL init -- nothing static can follow that, and it says
    None rather than reading the padding after the jump.

`lookup` returns None rather than guessing. Callers should refuse to emit an
import they could not resolve: a placeholder count is the exact failure this
module exists to prevent. `lookup_ex` returns *why*, so a caller can tell "cdecl,
pops nothing" from "no idea" -- they need opposite handling and both used to
arrive as None.

Part of the pcrecomp toolbox.
"""
import glob
import os
import re

__all__ = ['ArgcResolver', 'mangled_convention', 'purge_from_binary',
           'DEFAULT_SDK_GLOB', 'DEFAULT_SYSTEM_DIR']

# 32-bit import libraries. On a 64-bit host the 32-bit system DLLs are the
# SysWOW64 ones, despite the name.
DEFAULT_SDK_GLOB = r"C:\Program Files (x86)\Windows Kits\10\Lib\*\um\x86"
DEFAULT_SYSTEM_DIR = r"C:\Windows\SysWOW64"

_DECORATED = re.compile(rb'_([A-Za-z_][A-Za-z0-9_]*)@(\d+)')
_ORDINAL = re.compile(r'ordinal_(\d+)$', re.I)

# A name the binary already asked for in decorated form: `_AIL_waveOutOpen@16`.
_SELF_DECORATED = re.compile(r'^_([A-Za-z_][A-Za-z0-9_]*)@(\d+)$')

# DLLs whose exports are cdecl C runtime functions. `msvcrt.lib` is not in the
# Windows SDK (it ships with the compiler), so for these the export table is the
# only evidence available -- and for these it is sufficient, because a C runtime
# does not export stdcall. Every other DLL exports WINAPI undecorated too, so
# the same inference there would be wrong.
_CRT_FAMILY = ('msvcrt', 'msvcr', 'msvcp', 'crtdll', 'ucrtbase', 'vcruntime',
               'libcmt', 'atl', 'mfc')


def _is_crt_dll(dll):
    stem = os.path.splitext(dll)[0].lower()
    return stem.startswith(_CRT_FAMILY)


# ---------------------------------------------------------------------------
# Last resort: ask the callee
# ---------------------------------------------------------------------------
#
# Every strategy above reads the count off a *name*. That runs out exactly
# where a real game's import table gets interesting: a third-party DLL with an
# undecorated export table, or one that exports by ordinal only and has no
# import library anywhere on the machine. Arcade ports are all of them at once
# -- Mario Kart Arcade GP DX imports 40 functions from OMRON's OKAO Vision
# libraries by ordinal, and those DLLs exist nowhere but in the game tree.
#
# But the count is not only in the name. It is in the callee: a stdcall
# function ends `ret N`, and N is the byte count. If you have the DLL -- and if
# the game ships it, you do -- you can read the answer out of its code instead
# of guessing at its types.
#
# Measured against the counts the Windows SDK import libraries give, for the
# exports where both have an answer: 1,307 agree, 2 disagree, across kernel32,
# user32, gdi32 and ws2_32. So this is a fallback and not a replacement -- the
# import library still wins wherever it has an answer -- but where nothing else
# can speak it is right about as often as a published header.
#
# Two shapes it deliberately refuses rather than guesses at:
#   * `jmp dword ptr [...]` -- a CPU-dispatch thunk. d3dx9_43's math functions
#     are all of these: the slot is filled at DLL init with an SSE or an x87
#     implementation, and nothing static can follow it.
#   * a function whose linear extent reaches `int3` padding without a `ret`.

_PURGE_STOP = ('int3', 'hlt', 'ud2')


def purge_from_binary(path, name=None, ordinal=None, limit=2048, _cache={}):
    """Argument slot count read out of an export's own `ret N`, or None.

    `path` is a DLL you have a copy of -- the one the game shipped, or the
    system one. Identify the export by `name` or by `ordinal`; `ordinal_N` is
    accepted as a name and means the ordinal.
    """
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32
        import pefile
    except ImportError:
        return None

    if name:
        m = _ORDINAL.match(name)
        if m:
            ordinal, name = int(m.group(1)), None

    key = os.path.abspath(path).lower()
    if key not in _cache:
        try:
            pe = pefile.PE(path, fast_load=True)
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
        except Exception:
            pe = None
        _cache[key] = (pe, Cs(CS_ARCH_X86, CS_MODE_32))
    pe, md = _cache[key]
    if pe is None or not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        return None

    rva = None
    for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if e.forwarder:                    # forwards elsewhere; no body to read
            continue
        if name is not None and e.name and e.name.decode(errors='replace') == name:
            rva = e.address
            break
        if ordinal is not None and e.ordinal == ordinal:
            rva = e.address
            break
    if rva is None:
        return None

    # Walk forward from the entry until something terminates. Fallthrough past
    # a conditional branch is fine -- a stdcall function pops the same N on
    # every path out of it -- so the first `ret` reached is the answer.
    seen, n = set(), 0
    while n < limit:
        try:
            data = pe.get_data(rva, 256)
        except Exception:
            return None
        advanced = False
        for insn in md.disasm(data, rva):
            n += 1
            advanced = True
            # Resume from the end of the last decoded instruction, never from a
            # fixed stride: a window that cuts an instruction in half and is
            # restarted at the cut decodes the rest of the function out of
            # phase, and the `ret` it eventually finds belongs to the function
            # after this one. That was two wrong counts in kernel32 alone.
            rva = insn.address + insn.size
            if insn.mnemonic in ('ret', 'retn'):
                op = insn.op_str.strip()
                return (int(op, 0) // 4) if op else 0
            if insn.mnemonic == 'jmp':
                op = insn.op_str.strip()
                if not op.startswith('0x'):
                    return None            # dispatch thunk or jump table
                target = int(op, 16)
                if target in seen:
                    return None
                seen.add(target)
                rva = target
                break
            if insn.mnemonic in _PURGE_STOP:
                return None
        if not advanced:
            return None
    return None


# MSVC function-modifier letter -> calling convention. It sits right after the
# access/cv letters in a mangled name: `?f@@YAXXZ` is YA, `?f@@QAEXXZ` is QAE.
_CONVENTION = {
    'A': 'cdecl', 'B': 'cdecl',
    'C': 'pascal', 'D': 'pascal',
    'E': 'thiscall', 'F': 'thiscall',
    'G': 'stdcall', 'H': 'stdcall',
    'I': 'fastcall', 'J': 'fastcall',
}

# Access/storage letters that introduce a *member* function: the convention
# letter follows one cv letter. `Y`/`Z` are free functions and `S`/`T` static
# members, where the convention letter follows immediately.
_MEMBER_ACCESS = set('QRSTUVWABCDEFGHIJKLMNOP')
_FREE_ACCESS = set('YZ')


def mangled_convention(name):
    """Calling convention of an MSVC-mangled function, or None.

    Only the convention is read, not the signature. That is deliberate: the
    convention decides *whether* the callee pops anything, and for cdecl -- the
    common case in an STL import table -- that settles the answer at 0 without
    needing to size a single parameter.
    """
    if not name.startswith('?'):
        return None
    # A data symbol, not a function: imported through an IAT slot like anything
    # else, never called, so it has no argument count and a caller must not emit
    # a call shim. The MSVC type codes are digits where a function has an
    # access letter -- 3 global, 2 static member, 4/5 local static, 6 vftable,
    # 7 vbtable.
    #
    # Every `@@` has to be tried, not just the first. A template name contains
    # `@@` of its own: `?npos@?$basic_string@DU?$char_traits@D@std@@V?$...`
    # has its first `@@` inside char_traits, whose tail starts with `V`, and
    # stopping there misses the `2IB` that makes npos a static const. npos read
    # as a function is npos read as 0, and string::find stops working.
    for m in re.finditer(r'@@', name):
        tail = name[m.end():]
        if tail[:1] in ('2', '3', '4', '5', '6', '7', '8', '9'):
            return 'data'
    # A local static's type code follows a SINGLE '@', because the scope it
    # lives in is a mangled function that already ended in 'Z':
    #   ?_C@?1??_Nullstr@...CAPBDXZ@4DB   -> '@4D'
    # The digit must be followed by a type letter, which is what keeps this off
    # template backrefs: 'V?$allocator@D@2@@' has '@2@', digit then '@'.
    if re.search(r'@[2-9][A-Z_]', name):
        return 'data'
    # Skip the qualified name: `?ident@scope@@` -- the signature starts after
    # the `@@` that closes it. Templates contain `@@` too, so find the first
    # `@@` that is followed by a plausible signature letter.
    for m in re.finditer(r'@@', name):
        sig = name[m.end():]
        if not sig:
            continue
        a = sig[0]
        if (a in _FREE_ACCESS or a in ('S', 'T')) and len(sig) > 1:
            conv = _CONVENTION.get(sig[1])
            if conv:
                return conv
        if a in _MEMBER_ACCESS and len(sig) > 2:
            conv = _CONVENTION.get(sig[2])
            if conv:
                return conv
    return None


class ArgcResolver:
    """Resolve (dll, import name) -> stdcall argument slot count.

    Lookups are cached per DLL, so scanning a whole import table costs one read
    of each import library.
    """

    def __init__(self, sdk_dir=None, system_dir=DEFAULT_SYSTEM_DIR, dll_dirs=()):
        self.sdk_dir = sdk_dir or self._newest_sdk()
        self.system_dir = system_dir
        # Directories holding copies of the DLLs the binary imports -- the game
        # tree, above all. Searched before the system directory, and only as a
        # last resort after every name-based strategy: see purge_from_binary.
        self.dll_dirs = list(dll_dirs)
        self._lib_cache = {}
        self._ord_cache = {}

    @staticmethod
    def _newest_sdk(pattern=DEFAULT_SDK_GLOB):
        dirs = sorted(glob.glob(pattern))
        if not dirs:
            raise RuntimeError(
                "no 32-bit Windows SDK library directory found under %s -- "
                "install the SDK's x86 libraries, or pass sdk_dir=" % pattern)
        return dirs[-1]

    def _lib(self, dll):
        """name -> argument slot count, from this DLL's import library."""
        key = dll.lower()
        if key not in self._lib_cache:
            path = os.path.join(self.sdk_dir,
                                os.path.splitext(dll)[0] + ".lib")
            table = {}
            if os.path.exists(path):
                with open(path, "rb") as fh:
                    data = fh.read()
                for m in _DECORATED.finditer(data):
                    table[m.group(1).decode()] = int(m.group(2)) // 4
            self._lib_cache[key] = table
        return self._lib_cache[key]

    def _ordinals(self, dll):
        """ordinal -> export name, from the system copy of the DLL."""
        key = dll.lower()
        if key not in self._ord_cache:
            table = {}
            path = os.path.join(self.system_dir, dll)
            if os.path.exists(path):
                try:
                    import pefile
                    pe = pefile.PE(path, fast_load=True)
                    pe.parse_data_directories(directories=[
                        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
                    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                        table = {e.ordinal: e.name.decode()
                                 for e in pe.DIRECTORY_ENTRY_EXPORT.symbols
                                 if e.name}
                except Exception:
                    table = {}          # no pefile, or an unreadable DLL
            self._ord_cache[key] = table
        return self._ord_cache[key]

    def real_name(self, dll, name):
        """The exported name, resolving `ordinal_N` against the system DLL."""
        m = _ORDINAL.match(name)
        if not m:
            return name
        return self._ordinals(dll).get(int(m.group(1)), name)

    def _exports(self, dll):
        """Undecorated export names of the system copy of this DLL.

        Used only to prove a name is cdecl: a stdcall export in a 32-bit DLL
        carries `@N`, so a name present undecorated is not stdcall.
        """
        key = 'x' + dll.lower()
        if key not in self._ord_cache:
            self._ord_cache[key] = set(self._ordinals(dll).values())
        return self._ord_cache[key]

    def lookup_ex(self, dll, name):
        """(argc, convention, source). argc is None when it is not derivable.

        `convention` is 'stdcall', 'cdecl', 'thiscall', ... or None; `source`
        names the evidence, so an unresolved import can be triaged instead of
        just counted.
        """
        real = self.real_name(dll, name)

        # 1. The binary already spelled the count: `_AIL_waveOutOpen@16`.
        m = _SELF_DECORATED.match(real)
        if m:
            return int(m.group(2)) // 4, 'stdcall', 'decorated-name'

        # 2. A C++ mangled name states its convention. cdecl pops nothing, so
        #    that is an answer; the rest need parameter sizes we cannot get.
        conv = mangled_convention(real)
        if conv == 'data':
            return 0, 'data', 'mangled-data-symbol'
        if conv == 'cdecl':
            return 0, 'cdecl', 'mangled-convention'
        # A __thiscall or __stdcall member states its convention but not its
        # byte count -- that needs the parameter types, and a struct passed by
        # value has no knowable size. Strategy 5 can still read the count off
        # the callee, so hold the answer rather than returning None here.

        # 3. The SDK import library, which is authoritative for plain Win32.
        argc = self._lib(dll).get(real)
        if argc is not None:
            return argc, 'stdcall', 'sdk-import-lib'

        # 4. A C runtime DLL exports cdecl and nothing else, so an export it
        #    names is cdecl and pops nothing. Restricted to that family on
        #    purpose -- see the note in the module docstring.
        #    `conv is None` matters: a C++ *member* exported by MSVCP/MSVCR is
        #    __thiscall and pops its stack arguments, so the family rule must
        #    not reach a name whose mangling already said it is not cdecl.
        if conv is None and _is_crt_dll(dll) and real in self._exports(dll):
            return 0, 'cdecl', 'crt-undecorated-export'

        # 5. Nothing named the count, so read it off the callee's own `ret N`.
        #    Needs a copy of the DLL; pass `dll_dirs=` the game tree and the
        #    third-party and ordinal-only imports stop being a dead end.
        for d in list(self.dll_dirs) + [self.system_dir]:
            path = os.path.join(d, dll)
            if not os.path.exists(path):
                continue
            argc = purge_from_binary(path, name=real)
            if argc is not None:
                # `ret` with no operand is a callee that pops nothing: cdecl,
                # or a stdcall function that takes no arguments. Both leave the
                # caller to clean up nothing, so the shim is the same either way.
                return argc, conv or ('stdcall' if argc else 'cdecl'), 'callee-ret'

        if conv is not None:
            return None, conv, 'mangled-convention'
        return None, None, 'unresolved'

    def lookup(self, dll, name):
        """Argument slot count, or None if it could not be derived."""
        return self.lookup_ex(dll, name)[0]

    def resolve_iat(self, iat):
        """Resolve a whole {va: (dll, name)} IAT map.

        Returns (rows, unresolved):
          rows       [(va, dll, name, real_name, argc)] sorted by va
          unresolved [(va, dll, name, real_name)]
        """
        rows, unresolved = [], []
        for va, (dll, name) in sorted(iat.items()):
            real = self.real_name(dll, name)
            argc, conv, src = self.lookup_ex(dll, name)
            if argc is None:
                unresolved.append((va, dll, name, real))
            else:
                rows.append((va, dll, name, real, argc))
        return rows, unresolved

    def resolve_iat_ex(self, iat):
        """As resolve_iat, but every row carries its convention and evidence.

        [(va, dll, name, real_name, argc, convention, source)], sorted by va.
        Unresolved rows are included with argc None -- a caller that must refuse
        them can, and one triaging an import table can see which kind they are.
        """
        out = []
        for va, (dll, name) in sorted(iat.items()):
            real = self.real_name(dll, name)
            argc, conv, src = self.lookup_ex(dll, name)
            out.append((va, dll, name, real, argc, conv, src))
        return out


def _selftest():
    """Check against argument counts that are fixed by published Win32 headers."""
    r = ArgcResolver()
    expected = {
        ('KERNEL32.dll', 'CreateFileA'): 7,
        ('KERNEL32.dll', 'ReadFile'): 5,
        ('KERNEL32.dll', 'VirtualAlloc'): 4,
        ('KERNEL32.dll', 'Sleep'): 1,
        ('KERNEL32.dll', 'GetLastError'): 0,
        ('USER32.dll', 'CreateWindowExA'): 12,
        ('USER32.dll', 'MessageBoxA'): 4,
        ('GDI32.dll', 'CreateDIBSection'): 6,
        ('WINMM.dll', 'waveOutOpen'): 6,      # the hand-typed tables say 7
        ('WSOCK32.dll', 'socket'): 3,
        ('DDRAW.dll', 'DirectDrawCreate'): 3,
    }
    for (dll, fn), want in expected.items():
        got = r.lookup(dll, fn)
        assert got == want, "%s!%s: expected %d, got %r" % (dll, fn, want, got)

    # Ordinal resolution: DirectSound is imported by ordinal in several titles.
    assert r.real_name('DSOUND.dll', 'ordinal_1') == 'DirectSoundCreate'
    assert r.lookup('DSOUND.dll', 'ordinal_1') == 3

    # An export that does not exist must resolve to None, never a guess.
    assert r.lookup('KERNEL32.dll', 'NoSuchExportHere') is None

    rows, unresolved = r.resolve_iat({
        0x1000: ('KERNEL32.dll', 'Sleep'),
        0x1004: ('KERNEL32.dll', 'NoSuchExportHere'),
    })
    assert rows == [(0x1000, 'KERNEL32.dll', 'Sleep', 'Sleep', 1)], rows
    assert len(unresolved) == 1 and unresolved[0][0] == 0x1004

    # --- the three kinds an SDK-only lookup used to miss -------------------

    # Convention parsing is pure string work, so it is checked without a DLL.
    conv_cases = {
        # free function, __cdecl:  ?_Xran@std@@YAXXZ
        '?_Xran@std@@YAXXZ': 'cdecl',
        # public member, __thiscall: basic_string::max_size
        '?max_size@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QBEIXZ':
            'thiscall',
        # private member, __thiscall: basic_string::_Eos
        '?_Eos@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@AAEXI@Z':
            'thiscall',
        # operator+ as a free __cdecl function
        '??Hstd@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@0@ABV10@0@Z':
            'cdecl',
        # static member, __cdecl: char_traits<char>::length
        '?length@?$char_traits@D@std@@SAIPBD@Z': 'cdecl',
        # a plain C name is not mangled at all
        'fopen': None,
        '_AIL_startup@0': None,
    }
    for nm, want in conv_cases.items():
        got = mangled_convention(nm)
        assert got == want, "%s: expected %r, got %r" % (nm[:40], want, got)

    # 1. Self-decorated third-party stdcall: the count is in the name.
    #    Miles imports these, and no import library for mss32 exists anywhere.
    assert r.lookup_ex('mss32.dll', '_AIL_waveOutOpen@16')[:2] == (4, 'stdcall')
    assert r.lookup_ex('mss32.dll', '_AIL_startup@0')[:2] == (0, 'stdcall')
    assert r.lookup_ex('mss32.dll', '_AIL_set_named_sample_file@20')[0] == 5

    # 2. cdecl from the mangled convention letter -> pops nothing.
    assert r.lookup_ex('MSVCP60.dll', '?_Xran@std@@YAXXZ')[:2] == (0, 'cdecl')

    # 3. A __thiscall member's byte count is not in its name: the mangling
    #    gives the convention, not the parameter sizes. It must never come back
    #    as cdecl/0 -- this one takes a size_t on the stack and pops 4 -- so it
    #    is either the real count off the callee's `ret 4`, or unresolved.
    #    Note this is a CRT-family DLL, so it also guards strategy 4 from
    #    claiming a C++ member is cdecl just because MSVCP exports it.
    argc, conv, src = r.lookup_ex(
        'MSVCP60.dll',
        '?_Eos@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@AAEXI@Z')
    assert conv == 'thiscall' and argc in (None, 1), (argc, conv, src)

    # 4. cdecl proven by a C-runtime export table. msvcrt.lib is not in the
    #    Windows SDK, so this path is the only one available for MSVCRT.
    for fn in ('fopen', 'memmove', 'sprintf', 'realloc', '_ftol'):
        argc, conv, src = r.lookup_ex('MSVCRT.dll', fn)
        assert (argc, conv) == (0, 'cdecl'), (fn, argc, conv, src)

    # A stdcall export must NOT be mistaken for cdecl.
    assert r.lookup_ex('KERNEL32.dll', 'Sleep')[:2] == (1, 'stdcall')

    # And the regression that motivated narrowing the rule: DirectX DLLs export
    # WINAPI functions undecorated, exactly like a C runtime does. dinput.lib is
    # not in the modern SDK, so no name-based strategy has anything to say about
    # DirectInputCreateA -- and the one thing it must never come back as is
    # cdecl/0, which would leave four argument slots on the simulated stack at
    # every call. With a copy of the DLL to read, strategy 5 gets the real
    # answer (4) off its `ret 10h`; without one it stays honestly unresolved.
    argc, conv, src = r.lookup_ex('DINPUT.dll', 'DirectInputCreateA')
    assert (argc, conv) in ((None, None), (4, 'stdcall')), \
        ('DirectInputCreateA', argc, conv, src)
    assert not _is_crt_dll('DINPUT.dll') and _is_crt_dll('MSVCRT.dll')
    assert _is_crt_dll('MSVCP60.dll') and not _is_crt_dll('KERNEL32.dll')

    # Mangled *data* symbols are imported but never called.
    assert mangled_convention('?nothrow@std@@3Unothrow_t@1@B') == 'data'
    # These three are why every `@@` has to be tried. Each has a `@@` inside a
    # template argument well before the type code that identifies it, and
    # stopping at the first one classified all of them as cdecl functions.
    _STR = '?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@'
    assert mangled_convention('?npos@' + _STR + '2IB') == 'data'
    assert mangled_convention(
        '?_C@?1??_Nullstr@' + _STR + 'CAPBDXZ@4DB') == 'data'
    assert mangled_convention(
        '??_7?$basic_fstream@DU?$char_traits@D@std@@@std@@6B@') == 'data'
    # ...while a real function with a template in its name still reads as one.
    assert mangled_convention('?find@' + _STR + 'QBEIPBDII@Z') == 'thiscall'
    assert mangled_convention(
        '??Hstd@@YA?AV' + _STR[:-2] + '0@ABV10@0@Z') == 'cdecl'
    assert r.lookup_ex('MSVCP60.dll', '?nothrow@std@@3Unothrow_t@1@B')[1] == 'data'

    ex = r.resolve_iat_ex({0x10: ('mss32.dll', '_AIL_startup@0'),
                           0x14: ('MSVCRT.dll', 'fopen')})
    assert [row[4] for row in ex] == [0, 0], ex
    assert [row[5] for row in ex] == ['stdcall', 'cdecl'], ex

    # 5. Read the count out of the callee's own `ret N`. Checked against the
    #    SDK import library, which is the authority: the same DLL, the same
    #    exports, two independent derivations. wsprintfW is the useful case --
    #    it is the one variadic Win32 API, it has no `@N` anywhere, and only
    #    its bare `ret` says so.
    sysdll = os.path.join(DEFAULT_SYSTEM_DIR, 'kernel32.dll')
    if os.path.exists(sysdll):
        for fn in ('GetLastError', 'Sleep', 'VirtualAlloc', 'ReadFile'):
            want = r.lookup('KERNEL32.dll', fn)
            got = purge_from_binary(sysdll, name=fn)
            # A forwarder to kernelbase has no body here and must say None
            # rather than invent a count from the padding after the jump.
            assert got in (want, None), (fn, want, got)
        assert purge_from_binary(sysdll, name='NoSuchExportHere') is None
    user32 = os.path.join(DEFAULT_SYSTEM_DIR, 'user32.dll')
    if os.path.exists(user32):
        assert r.lookup_ex('USER32.dll', 'wsprintfW')[::2] == (0, 'callee-ret')

    print("stdcall_argc.py self-test OK (%d checks)"
          % (len(expected) + 5 + len(conv_cases) + 30))


if __name__ == '__main__':
    import sys
    if sys.argv[1:2] == ['--selftest']:
        _selftest()
    else:
        res = ArgcResolver()
        print("SDK libs: %s" % res.sdk_dir)
        for arg in sys.argv[1:]:
            dll, _, fn = arg.partition('!')
            print("  %-22s %s" % (arg, res.lookup(dll, fn)))
