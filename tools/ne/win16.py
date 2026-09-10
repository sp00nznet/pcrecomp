"""
win16.py - Win16 import resolver for NE recompilation.

An NE import relocation carries a `module_idx` (1-based into ne.module_names)
plus an ordinal, and nothing else. Turning that into a C shim needs two things
this module supplies:

  1. A NAME. Authoritative names come from IDA, which ships the Win16
     ordinal->API maps; tools/ne/ida_export.py writes them to a JSON map that
     this module loads. Failing that there is a built-in seed of
     high-confidence ordinals, and finally a `MODULE_OrdN` stub name so the
     recomp always links.

  2. A STACK PURGE. This is the part that bites. Win16 is PASCAL: the CALLEE
     pops the arguments. A shim that pops the wrong number does not fail at the
     call - it shifts the CALLER's frame, so the caller's epilogue restores DS
     (or BP, or a return address) from the wrong slot, and the damage surfaces
     somewhere else entirely. The PURGE table below is keyed by (MODULE, API)
     and is the accumulated answer; add to it rather than guessing at a call
     site.

Where the JSON map is found, in order:
  - the path in $PCRECOMP_WIN16_IMPORTS
  - win16.IMPORTS_JSON, if a project sets it before resolving
  - <project>/work/win16_imports.json, then <project>/analysis/win16_imports.json,
    walking up from this file - which covers the layouts in use

Each resolved import becomes a C shim `void MODULE_APINAME(CPU *cpu)`.
"""

import os
import json
from dataclasses import dataclass

# A project can set this before resolving; otherwise the search below applies.
IMPORTS_JSON = None


def _find_map():
    """Locate the IDA-derived ordinal map, or return None."""
    env = os.environ.get('PCRECOMP_WIN16_IMPORTS')
    if env and os.path.exists(env):
        return env
    if IMPORTS_JSON and os.path.exists(IMPORTS_JSON):
        return IMPORTS_JSON
    # Walk up from the CWD, not from this file: this module lives in the
    # toolbox, and the map belongs to whichever project is being lifted. A
    # project is normally lifted from its own root, so the first hop usually
    # wins; the walk covers being run from a subdirectory.
    here = os.path.abspath(os.getcwd())
    while True:
        for sub in ('work', 'analysis'):
            cand = os.path.join(here, sub, 'win16_imports.json')
            if os.path.exists(cand):
                return cand
        parent = os.path.dirname(here)
        if parent == here:
            return None
        here = parent


@dataclass
class Win16Import:
    module: str         # KERNEL, USER, GDI, SOSLIB03, WING, MMSYSTEM, TOOLHELP, WIN87EM
    ordinal: int        # export ordinal in that module
    name: str           # C shim name, e.g. 'KERNEL_GlobalAlloc'
    api: str            # bare API name, e.g. 'GlobalAlloc' (or 'Ord15' if unknown)
    category: str       # 'mem','file','gdi','user','sound','blit','fpu','sys','unknown'
    known: bool = False # True if resolved from IDA map or built-in seed


# Modules whose imports are floating-point emulation trampolines. CATZ uses real
# x87 instructions in the code stream (only ~6 WIN87EM refs), so unlike El-Fish
# there is no inline FPU-trampoline skipping to do; WIN87EM calls are real calls.
_FPU_MODULES = {'WIN87EM'}

_CATEGORY_BY_MODULE = {
    'KERNEL': 'sys', 'USER': 'user', 'GDI': 'gdi', 'SOSLIB03': 'sound',
    'WING': 'blit', 'MMSYSTEM': 'sound', 'TOOLHELP': 'sys', 'WIN87EM': 'fpu',
}

# High-confidence built-in seed of Win16 system ordinals (Windows 3.1).
# Used only as a fallback before the IDA-derived map is available. Names that
# matter most for bring-up (memory, module, file, basic GDI/USER) are covered;
# everything else resolves to MODULE_OrdN until IDA fills it in.
_SEED = {
    'KERNEL': {
        5: 'LocalAlloc', 6: 'LocalLock', 7: 'LocalFree', 8: 'LocalUnlock',
        15: 'GlobalAlloc', 16: 'GlobalFree', 17: 'GlobalReAlloc', 18: 'GlobalLock',
        19: 'GlobalUnlock', 20: 'GlobalSize', 23: 'LockSegment', 24: 'UnlockSegment',
        30: 'WaitEvent', 47: 'GetModuleHandle', 49: 'GetModuleFileName',
        50: 'GetProcAddress', 51: 'MakeProcInstance', 52: 'FreeProcInstance',
        74: 'OpenFile', 81: '_lclose', 82: '_lread', 83: '_lcreat', 84: '_llseek',
        85: '_lopen', 86: '_lwrite', 88: 'lstrcpy', 89: 'lstrcat', 90: 'lstrlen',
        91: 'InitTask', 95: 'LoadLibrary', 96: 'FreeLibrary', 97: 'GetTempDrive',
        127: 'GetPrivateProfileInt', 128: 'GetPrivateProfileString',
        129: 'WritePrivateProfileString', 130: 'GetProfileInt', 131: 'GetProfileString',
    },
    'GDI': {
        27: 'CreateCompatibleDC', 31: 'SetPixel', 34: 'BitBlt', 35: 'StretchBlt',
        45: 'SelectObject', 53: 'CreateBitmap', 54: 'CreateBitmapIndirect',
        62: 'CreateCompatibleBitmap', 68: 'DeleteDC', 69: 'DeleteObject',
        80: 'GetDeviceCaps', 65: 'RealizePalette', 66: 'GetPaletteEntries',
        360: 'CreatePalette', 361: 'GetPaletteEntries', 363: 'SetPaletteEntries',
        370: 'CreateDIBitmap', 371: 'SetDIBits', 372: 'GetDIBits',
        439: 'SetDIBitsToDevice', 489: 'StretchDIBits',
    },
    'USER': {
        1: 'MessageBox', 10: 'SetTimer', 12: 'KillTimer', 39: 'BeginPaint',
        40: 'EndPaint', 41: 'CreateWindow', 42: 'ShowWindow', 57: 'RegisterClass',
        66: 'GetDC', 68: 'ReleaseDC', 107: 'DefWindowProc', 108: 'GetMessage',
        110: 'PostMessage', 111: 'SendMessage', 113: 'TranslateMessage',
        114: 'DispatchMessage', 124: 'UpdateWindow', 125: 'InvalidateRect',
        173: 'LoadCursor', 174: 'LoadIcon', 420: 'wsprintf',
    },
}

# Win16 PASCAL stack-purge bytes per call (callee pops args). WORD/UINT/HANDLE/
# BOOL/int = 2; DWORD/LONG/COLORREF/far pointer = 4. Each shim must do
# `cpu->sp += 4 (far retaddr) + purge`, or `retf` boundaries corrupt. Keyed by
# (MODULE, API). Functions not listed default to 0 with a runtime warning.
PURGE = {
    # ---- argument sizes that were missing ----
    # A stub with no entry here pops only the far return address and leaves its
    # arguments on the stack. Win16 is PASCAL: the callee pops them. Every such
    # call shifted the caller's frame, so its epilogue restored DS from the wrong
    # slot -- GetCursorPos alone left the WAD's frame loop running with DS=0,
    # which stored a null-segment PetParams and made the pet's colour ramp
    # unreadable, so every ball plotted as colour 0 (a black cat on black).
    # HMI Sound Operating System: PASCAL too -- the call sites push and never
    # 'add sp' afterwards.
    ('SOSLIB03', 'SOSDIGIDETECTINIT'): 4, ('SOSLIB03', 'SOSDIGIUSERSERVICE'): 2,
    ('USER', 'GETCURSORPOS'): 4,        ('USER', 'BRINGWINDOWTOTOP'): 2,
    ('USER', 'CHECKDLGBUTTON'): 6,      ('USER', 'DESTROYICON'): 2,
    ('USER', 'ENABLEWINDOW'): 4,        ('USER', 'GETACTIVEWINDOW'): 0,
    ('USER', 'GETCLASSNAME'): 8,        ('USER', 'GETWINDOWPLACEMENT'): 6,
    ('USER', 'GETWINDOWWORD'): 4,       ('USER', 'INFLATERECT'): 8,
    ('USER', 'ISDIALOGMESSAGE'): 6,     ('USER', 'ISDLGBUTTONCHECKED'): 4,
    ('USER', 'ISICONIC'): 2,            ('USER', 'ISWINDOWVISIBLE'): 2,
    ('USER', 'SENDDLGITEMMESSAGE'): 12, ('USER', 'SETCAPTURE'): 2,
    ('USER', 'SWAPMOUSEBUTTON'): 2,     ('USER', 'SYSTEMPARAMETERSINFO'): 10,
    ('USER', 'WINHELP'): 12,            ('USER', 'SETWINDOWWORD'): 6,
    ('USER', 'SETWINDOWLONG'): 8,       ('USER', 'GETSYSTEMMETRICS'): 2,
    ('USER', 'SETSYSMODALWINDOW'): 2,   ('USER', 'GETNEXTWINDOW'): 4,
    ('KERNEL', 'GETPROFILEINT'): 10,    ('KERNEL', 'GETSYSTEMDIRECTORY'): 6,
    ('KERNEL', 'GLOBALDOSALLOC'): 4,    ('KERNEL', 'GLOBALDOSFREE'): 2,
    ('KERNEL', 'WINEXEC'): 6,           ('KERNEL', 'WRITEPROFILESTRING'): 12,
    # ---- KERNEL ----
    ('KERNEL', 'GLOBALALLOC'): 6, ('KERNEL', 'GLOBALREALLOC'): 8,
    ('KERNEL', 'GLOBALFREE'): 2, ('KERNEL', 'GLOBALLOCK'): 2,
    ('KERNEL', 'GLOBALUNLOCK'): 2, ('KERNEL', 'GLOBALSIZE'): 2,
    ('KERNEL', 'GLOBALHANDLE'): 2, ('KERNEL', 'GLOBALFLAGS'): 2,
    ('KERNEL', 'LOCALINIT'): 6, ('KERNEL', 'GETWINFLAGS'): 0,
    ('KERNEL', 'INITTASK'): 0, ('KERNEL', 'WAITEVENT'): 2, ('KERNEL', 'INITAPP'): 2,
    ('KERNEL', 'GETVERSION'): 0, ('KERNEL', 'GETCURRENTTASK'): 0,
    ('KERNEL', 'GETMODULEUSAGE'): 2, ('KERNEL', 'GETMODULEFILENAME'): 8,
    ('KERNEL', 'GETMODULEHANDLE'): 4, ('KERNEL', 'FINDRESOURCE'): 10,
    ('KERNEL', 'LOADRESOURCE'): 4, ('KERNEL', 'LOCKRESOURCE'): 2,
    ('KERNEL', 'FREERESOURCE'): 2, ('KERNEL', 'SIZEOFRESOURCE'): 4,
    ('KERNEL', 'OPENFILE'): 10, ('KERNEL', '_LCLOSE'): 2, ('KERNEL', '_LREAD'): 8,
    ('KERNEL', '_LLSEEK'): 8, ('KERNEL', '_LOPEN'): 6, ('KERNEL', '_LWRITE'): 8,
    ('KERNEL', '_HREAD'): 10, ('KERNEL', '_LCREAT'): 6,
    ('KERNEL', 'LOADLIBRARY'): 4, ('KERNEL', 'FREELIBRARY'): 2,
    ('KERNEL', 'OUTPUTDEBUGSTRING'): 4, ('KERNEL', 'GETPRIVATEPROFILEINT'): 14,
    ('KERNEL', 'GETPRIVATEPROFILESTRING'): 22,
    ('KERNEL', 'WRITEPRIVATEPROFILESTRING'): 16, ('KERNEL', 'GETPROCADDRESS'): 6,
    ('KERNEL', 'LSTRLEN'): 4, ('KERNEL', 'LSTRCPY'): 8, ('KERNEL', 'LSTRCAT'): 8,
    # ---- USER ----
    ('USER', 'INITAPP'): 2, ('USER', 'SETMESSAGEQUEUE'): 2,
    ('USER', 'REGISTERCLASS'): 4, ('USER', 'CREATEWINDOW'): 30,
    ('USER', 'GETSYSTEMMENU'): 4, ('USER', 'APPENDMENU'): 10, ('USER', 'LOADICON'): 6,
    ('USER', 'DEFWINDOWPROC'): 10, ('USER', 'INVALIDATERECT'): 8, ('USER', 'INVALIDATERGN'): 6,
    ('USER', 'BEGINPAINT'): 6, ('USER', 'ENDPAINT'): 6, ('USER', 'GETUPDATERECT'): 8,
    ('USER', 'FILLRECT'): 8, ('USER', 'GETCLIENTRECT'): 6, ('USER', 'VALIDATERECT'): 6,
    ('USER', 'CHECKMENUITEM'): 6, ('USER', 'ENABLEMENUITEM'): 6, ('USER', 'GETMENU'): 2,
    ('USER', 'GETSUBMENU'): 4, ('USER', 'GETMENUITEMCOUNT'): 2, ('USER', 'GETMENUITEMID'): 4,
    ('USER', 'GETMENUSTATE'): 6, ('USER', 'MODIFYMENU'): 12, ('USER', 'DELETEMENU'): 6,
    ('USER', 'SETMENU'): 4, ('USER', 'DRAWMENUBAR'): 2, ('USER', 'CREATEMENU'): 0,
    ('USER', 'CREATEPOPUPMENU'): 0, ('USER', 'TRACKPOPUPMENU'): 14, ('USER', 'HILITEMENUITEM'): 8,
    ('USER', 'GETSYSTEMMETRICS'): 2, ('KERNEL', 'GETWINDOWSDIRECTORY'): 6,
    ('CTL3DV2', 'CTL3DREGISTER'): 2, ('CTL3DV2', 'CTL3DAUTOSUBCLASS'): 2,
    ('USER', 'MESSAGEBOX'): 12, ('USER', 'MESSAGEBEEP'): 2, ('USER', 'SETTIMER'): 10,
    ('USER', 'KILLTIMER'): 4, ('USER', 'GETTICKCOUNT'): 0, ('USER', 'PEEKMESSAGE'): 12,
    ('USER', 'SENDMESSAGE'): 10, ('USER', 'TRANSLATEMESSAGE'): 4,
    # PostMessage(HWND, UINT, WPARAM, LPARAM) = 2+2+2+4. Missing here it
    # purged 0 and corrupted the caller's stack on every engine frame tick.
    ('USER', 'POSTMESSAGE'): 10,
    # DialogBoxParam(HINSTANCE, LPCSTR, HWND, DLGPROC, LPARAM) = 2+4+2+4+4.
    ('USER', 'DIALOGBOXPARAM'): 16,
    ('USER', 'DISPATCHMESSAGE'): 4, ('USER', 'POSTQUITMESSAGE'): 2,
    ('USER', 'SETCLASSWORD'): 6, ('USER', 'GETWINDOWLONG'): 4,
    ('USER', 'SETWINDOWLONG'): 8, ('USER', 'CLIPCURSOR'): 4, ('USER', 'LOADCURSOR'): 6,
    ('USER', 'LOADSTRING'): 10, ('USER', 'GETSYSCOLOR'): 2, ('USER', 'RELEASECAPTURE'): 0,
    ('USER', 'LOADBITMAP'): 6,          # HINSTANCE + far LPCSTR
    ('USER', 'SETWINDOWPOS'): 14,       # hWnd, hWndInsertAfter, x, y, cx, cy, flags
    ('USER', 'ENUMTASKWINDOWS'): 10, ('USER', 'ENUMWINDOWS'): 8, ('USER', 'GETFOCUS'): 0,
    ('USER', 'CREATEDIALOGPARAM'): 16, ('USER', 'GETASYNCKEYSTATE'): 2,
    ('USER', 'SELECTPALETTE'): 6, ('USER', 'REALIZEPALETTE'): 2,
    ('USER', 'GETDESKTOPWINDOW'): 0, ('USER', 'REDRAWWINDOW'): 10,
    ('USER', 'GETWINDOWRECT'): 6, ('USER', 'GETCLIENTRECT'): 6,
    ('USER', 'SETWINDOWTEXT'): 6, ('USER', 'SHOWWINDOW'): 4, ('USER', 'DESTROYWINDOW'): 2,
    ('USER', 'MOVEWINDOW'): 12, ('USER', 'SETSCROLLPOS'): 8, ('USER', 'SETSCROLLRANGE'): 10,
    ('USER', 'GETDC'): 2, ('USER', 'RELEASEDC'): 4, ('USER', 'SETCURSOR'): 2,
    ('USER', 'SETCURSORPOS'): 4, ('USER', 'OFFSETRECT'): 8, ('USER', 'FRAMERECT'): 8,
    ('USER', 'DRAWTEXT'): 14, ('USER', 'DIALOGBOX'): 12, ('USER', 'ENDDIALOG'): 4,
    ('USER', 'CREATEDIALOG'): 12, ('USER', 'GETDLGITEM'): 4, ('USER', 'SETDLGITEMTEXT'): 8,
    ('USER', 'GETDLGITEMTEXT'): 10, ('USER', 'SETDLGITEMINT'): 8, ('USER', 'GETDLGITEMINT'): 10,
    ('USER', 'CLIENTTOSCREEN'): 6, ('USER', 'GETWINDOWRECT'): 6,
    # ---- GDI ----
    ('GDI', 'SETBKCOLOR'): 6, ('GDI', 'SETBKMODE'): 4, ('GDI', 'SETTEXTCOLOR'): 6,
    ('GDI', 'CREATEIC'): 16, ('GDI', 'LINETO'): 6, ('GDI', 'MOVETO'): 6,
    ('GDI', 'ELLIPSE'): 10, ('GDI', 'RECTANGLE'): 10, ('GDI', 'PATBLT'): 14,
    ('GDI', 'BITBLT'): 20, ('GDI', 'STRETCHBLT'): 24, ('GDI', 'POLYGON'): 8,
    ('GDI', 'CREATEPALETTE'): 4, ('GDI', 'GETSYSTEMPALETTEUSE'): 2,
    ('GDI', 'GETSYSTEMPALETTEENTRIES'): 10, ('GDI', 'GETPALETTEENTRIES'): 10,
    ('GDI', 'STRETCHDIBITS'): 32, ('GDI', 'GETDIBITS'): 18, ('GDI', 'CREATEDIBITMAP'): 20,
    ('GDI', 'SETDIBITSTODEVICE'): 28, ('GDI', 'SELECTOBJECT'): 4,
    ('GDI', 'SETVIEWPORTORGEX'): 10, ('GDI', 'CREATECOMPATIBLEBITMAP'): 6,
    ('GDI', 'CREATECOMPATIBLEDC'): 2, ('GDI', 'CREATEFONTINDIRECT'): 4,
    ('GDI', 'CREATEPEN'): 8, ('GDI', 'CREATESOLIDBRUSH'): 4, ('GDI', 'DELETEDC'): 2,
    ('GDI', 'DELETEOBJECT'): 2, ('GDI', 'GETDEVICECAPS'): 4, ('GDI', 'GETOBJECT'): 8,
    ('GDI', 'GETSTOCKOBJECT'): 2, ('GDI', 'GETTEXTEXTENT'): 8,
    # ---- MMSYSTEM ----
    ('MMSYSTEM', 'SNDPLAYSOUND'): 6, ('MMSYSTEM', 'TIMEGETDEVCAPS'): 6,
    ('MMSYSTEM', 'TIMEGETTIME'): 0,
    # ---- TOOLHELP ----
    ('TOOLHELP', 'GLOBALENTRYHANDLE'): 6, ('TOOLHELP', 'TIMERCOUNT'): 4,
    # ---- WIN87EM ---- (FP emulator hook; not a PASCAL call, no arg purge)
    ('WIN87EM', '__FPMATH'): 0,
}


# ---------------------------------------------------------------------------
# Absolute-value imports.
#
# A handful of KERNEL "imports" are not routines at all: the loader patches a
# VALUE into the code stream at every site, and they arrive as OFFSET16
# relocations rather than FAR_PTR ones. They are easy to miss, because nothing
# calls them and a stub for them is never reached - so the immediate keeps
# whatever was in the file, which for a chained (non-additive) fixup is the
# offset of the NEXT site in the chain. That is a plausible-looking small
# number, and the code using it does pointer arithmetic, so the damage is
# silent and lands only on data big enough to need it.
#
# __AHINCR is the one that matters: it is how a program walks a huge pointer
# past 64 KB. Real Win16 hands out selectors 8 apart, so __AHINCR is 8 and
# __AHSHIFT is 3. A recomp that hands out CONSECUTIVE selectors for the tiles
# of one allocation must report its own step instead, or every huge-pointer
# walk lands in the wrong tile.
SELECTOR_STEP = 1       # selector delta per 64 KB tile in the host model
WINFLAGS = 0x0403       # WF_ENHANCED | WF_PMODE | WF_80x87, as GetWinFlags reports


def get_value(module: str, api: str):
    """Value for an absolute-value import, or None if it is a real routine.

    Set win16.SELECTOR_STEP to the host memory model's selector step before
    lifting; the default of 1 matches a runtime that tiles one allocation
    across consecutive selectors.
    """
    key = (module or '').upper(), (api or '').upper()
    if key == ('KERNEL', '__AHINCR'):
        return SELECTOR_STEP
    if key == ('KERNEL', '__AHSHIFT'):
        return max(0, SELECTOR_STEP.bit_length() - 1)
    if key == ('KERNEL', '__WINFLAGS'):
        return WINFLAGS & 0xFFFF
    return None


def get_purge(module: str, api: str):
    """Return stack-purge bytes for a (module, api) Win16 call, or None if
    unknown (SOS/WinG and rare APIs - filled in as they are reached)."""
    return PURGE.get(((module or '').upper(), (api or '').upper()))


_loaded_map = None


def _load_map():
    """Load the IDA-derived import map (module -> {ordinal: api_name}), cached."""
    global _loaded_map
    if _loaded_map is not None:
        return _loaded_map
    _loaded_map = {}
    path = _find_map()
    if path:
        try:
            with open(path, encoding='utf-8') as f:
                raw = json.load(f)
            for mod, ords in raw.items():
                _loaded_map[mod.upper()] = {int(k): v for k, v in ords.items()}
        except Exception:
            _loaded_map = {}
    return _loaded_map


def _sanitize(api: str) -> str:
    out = []
    for ch in api:
        out.append(ch if (ch.isalnum() or ch == '_') else '_')
    return ''.join(out)


def get_import(module: str, ordinal: int) -> Win16Import:
    """Resolve a (module, ordinal) import to a Win16Import shim descriptor."""
    mod = (module or 'UNK').upper()
    cat = _CATEGORY_BY_MODULE.get(mod, 'unknown')

    api = None
    known = False
    idamap = _load_map().get(mod)
    if idamap and ordinal in idamap:
        api = idamap[ordinal]
        known = True
    elif mod in _SEED and ordinal in _SEED[mod]:
        api = _SEED[mod][ordinal]
        known = True

    if api:
        # Uppercase so names are consistent whether resolved from IDA (which
        # yields UPPERCASE) or the built-in seed (mixed case) -> shim impls and
        # call sites always agree.
        name = f'{mod}_{_sanitize(api).upper()}'
    else:
        api = f'Ord{ordinal}'
        name = f'{mod}_Ord{ordinal}'

    return Win16Import(module=mod, ordinal=ordinal, name=name, api=api,
                       category=cat, known=known)


def is_fpu_module(module: str) -> bool:
    return (module or '').upper() in _FPU_MODULES


def module_name(ne, module_idx: int) -> str:
    """Map a 1-based NE module_idx to its imported module name."""
    if 1 <= module_idx <= len(ne.module_names):
        return ne.module_names[module_idx - 1]
    return f'MOD{module_idx}'


# ---------------------------------------------------------------------------
# The multimedia surface, plus the KERNEL calls that go with reading samples off
# disc. Derived from the Win16 signatures, sizes being WORD/UINT/HANDLE/BOOL/
# int/BYTE = 2 and DWORD/LONG/far pointer = 4. Every Win16 title that makes a
# noise needs most of this list, so it lives here rather than in one project.
PURGE.update({
    # ---- KERNEL ----
    ('KERNEL', 'FATALEXIT'): 2,           # int nCode
    ('KERNEL', 'FATALAPPEXIT'): 6,        # UINT, LPCSTR
    ('KERNEL', 'LOCKSEGMENT'): 2,         # UINT uSegment
    ('KERNEL', 'UNLOCKSEGMENT'): 2,       # UINT uSegment
    ('KERNEL', 'GETTEMPFILENAME'): 12,    # BYTE, LPCSTR, UINT, LPSTR
    ('KERNEL', 'GETDOSENVIRONMENT'): 0,   # void
    ('KERNEL', 'GETDRIVETYPE'): 2,        # int nDrive
    ('KERNEL', 'GETFREESPACE'): 2,        # UINT wFlags
    ('KERNEL', 'HMEMCPY'): 12,            # void _huge*, const void _huge*, long
    ('KERNEL', '_HWRITE'): 10,            # HFILE, const void _huge*, long
    # DOS3CALL is an INT 21h passthrough, not a PASCAL call: everything is in
    # registers and nothing is pushed.
    ('KERNEL', 'DOS3CALL'): 0,
    # __AHSHIFT/__AHINCR/__WINFLAGS arrive as OFFSET16 relocations, not
    # FAR_PTR - they are absolute values the loader patches into the code
    # stream, never called. Purge 0 so a stray call site cannot corrupt.
    ('KERNEL', '__AHSHIFT'): 0,
    ('KERNEL', '__AHINCR'): 0,
    ('KERNEL', '__WINFLAGS'): 0,

    # ---- MMSYSTEM: master volume ----
    ('MMSYSTEM', 'AUXGETNUMDEVS'): 0,
    ('MMSYSTEM', 'AUXGETDEVCAPS'): 8,     # UINT, LPAUXCAPS, UINT
    ('MMSYSTEM', 'AUXGETVOLUME'): 6,      # UINT, LPDWORD
    ('MMSYSTEM', 'AUXSETVOLUME'): 6,      # UINT, DWORD

    # ---- MMSYSTEM: playback ----
    ('MMSYSTEM', 'WAVEOUTGETNUMDEVS'): 0,
    ('MMSYSTEM', 'WAVEOUTGETDEVCAPS'): 8,      # UINT, LPWAVEOUTCAPS, UINT
    ('MMSYSTEM', 'WAVEOUTOPEN'): 22,           # LPHWAVEOUT, UINT, LPCWAVEFORMAT,
                                               # DWORD cb, DWORD inst, DWORD flags
    ('MMSYSTEM', 'WAVEOUTCLOSE'): 2,           # HWAVEOUT
    ('MMSYSTEM', 'WAVEOUTPREPAREHEADER'): 8,   # HWAVEOUT, LPWAVEHDR, UINT
    ('MMSYSTEM', 'WAVEOUTUNPREPAREHEADER'): 8,
    ('MMSYSTEM', 'WAVEOUTWRITE'): 8,
    ('MMSYSTEM', 'WAVEOUTRESET'): 2,
    ('MMSYSTEM', 'WAVEOUTGETPOSITION'): 8,     # HWAVEOUT, LPMMTIME, UINT
    ('MMSYSTEM', 'WAVEOUTGETVOLUME'): 6,       # HWAVEOUT, LPDWORD
    ('MMSYSTEM', 'WAVEOUTSETVOLUME'): 6,       # HWAVEOUT, DWORD
    ('MMSYSTEM', 'WAVEOUTGETID'): 6,           # HWAVEOUT, LPUINT

    # ---- MMSYSTEM: recording ----
    ('MMSYSTEM', 'WAVEINOPEN'): 22,
    ('MMSYSTEM', 'WAVEINCLOSE'): 2,
    ('MMSYSTEM', 'WAVEINPREPAREHEADER'): 8,
    ('MMSYSTEM', 'WAVEINUNPREPAREHEADER'): 8,
    ('MMSYSTEM', 'WAVEINADDBUFFER'): 8,
    ('MMSYSTEM', 'WAVEINSTART'): 2,
    ('MMSYSTEM', 'WAVEINSTOP'): 2,
    ('MMSYSTEM', 'WAVEINRESET'): 2,

    # ---- MMSYSTEM: the sequencer clock ----
    ('MMSYSTEM', 'TIMESETEVENT'): 14,     # UINT, UINT, LPTIMECALLBACK, DWORD, UINT
    ('MMSYSTEM', 'TIMEKILLEVENT'): 2,     # UINT uTimerID
    ('MMSYSTEM', 'TIMEGETDEVCAPS'): 6,    # LPTIMECAPS, UINT
    ('MMSYSTEM', 'TIMEBEGINPERIOD'): 2,   # UINT uPeriod
    ('MMSYSTEM', 'TIMEENDPERIOD'): 2,     # UINT uPeriod

    # ---- USER ----
    ('USER', 'CALLNEXTHOOKEX'): 10,       # HHOOK, int, WPARAM(2), LPARAM(4)
})
