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

`lookup` returns None rather than guessing. Callers should refuse to emit an
import they could not resolve: a placeholder count is the exact failure this
module exists to prevent.

Part of the pcrecomp toolbox.
"""
import glob
import os
import re

__all__ = ['ArgcResolver', 'DEFAULT_SDK_GLOB', 'DEFAULT_SYSTEM_DIR']

# 32-bit import libraries. On a 64-bit host the 32-bit system DLLs are the
# SysWOW64 ones, despite the name.
DEFAULT_SDK_GLOB = r"C:\Program Files (x86)\Windows Kits\10\Lib\*\um\x86"
DEFAULT_SYSTEM_DIR = r"C:\Windows\SysWOW64"

_DECORATED = re.compile(rb'_([A-Za-z_][A-Za-z0-9_]*)@(\d+)')
_ORDINAL = re.compile(r'ordinal_(\d+)$', re.I)


class ArgcResolver:
    """Resolve (dll, import name) -> stdcall argument slot count.

    Lookups are cached per DLL, so scanning a whole import table costs one read
    of each import library.
    """

    def __init__(self, sdk_dir=None, system_dir=DEFAULT_SYSTEM_DIR):
        self.sdk_dir = sdk_dir or self._newest_sdk()
        self.system_dir = system_dir
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

    def lookup(self, dll, name):
        """Argument slot count, or None if it could not be derived."""
        return self._lib(dll).get(self.real_name(dll, name))

    def resolve_iat(self, iat):
        """Resolve a whole {va: (dll, name)} IAT map.

        Returns (rows, unresolved):
          rows       [(va, dll, name, real_name, argc)] sorted by va
          unresolved [(va, dll, name, real_name)]
        """
        rows, unresolved = [], []
        for va, (dll, name) in sorted(iat.items()):
            real = self.real_name(dll, name)
            argc = self._lib(dll).get(real)
            if argc is None:
                unresolved.append((va, dll, name, real))
            else:
                rows.append((va, dll, name, real, argc))
        return rows, unresolved


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
    print("stdcall_argc.py self-test OK (%d checks)" % (len(expected) + 5))


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
