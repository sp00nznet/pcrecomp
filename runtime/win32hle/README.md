# runtime/win32hle — an implemented Win32, for running lifted PE code off Windows

`native32/` runs a lifted 32-bit Windows program by forwarding its imports to
the **real** Win32 API, so it only runs on Windows. `win32hle/` *answers those
imports itself*, on libc / POSIX / SDL2, so the same lifted program runs on
Linux (or anywhere SDL2 builds). It is the Win32 counterpart of `nextstep/`,
which already hosts recomp32 code on a non-Windows libsys HLE.

This is the portable path the OS-agnostic effort is built on; see
`../../../LINUX_PORT_PLAN.md` (out of tree).

## Why it needs no inline asm

It reuses native32's **shim ABI**, which runs entirely inside the lifted model:

> An import is a `recomp_func_t` (`void(void)`). When it is entered, `g_esp`
> points at `[ret][arg0][arg1]…`. The shim reads its stdcall arguments with
> `A32`/`APTR`/`ASTR`, does the work, returns with `RET`/`RETP`, and that macro
> pops `ret + argc*4` (stdcall, callee-cleans).

Because every import is our own C, a native → guest call (a `WndProc`, a thread
start) is made **explicitly** with `hle_call_guest()` — there is no
non-executable `.text` and no exec-fault trampoline. That is the single thing
that makes this portable where native32 is not: no inline asm, no OS exception
handler.

## Layout

| File | What |
|---|---|
| `win32hle.h` | the shim ABI (`A32`/`RET`/…), the registry, `hle_call_guest`, and every module's host-facing API |
| `host_lite.c` | the spine: register file, the machine lock (taken and given back with the registers saved: `hle_block_begin`/`_end`, `hle_yield`; every import and every loop back-edge is a hand-over point when another thread waits), per-thread simulated TIB (`g_fs_base`), dispatch lookups, shim registry, kernel object handles |
| `host.c` | the full host: `recomp_host_init`/`_boot`/`_run`/`_main` — register the shim modules, map+bind a PE, call its lifted entry |
| `pe_format.h`, `pe_loader.c` | the 32-bit PE structures; map an image at its base (or a DLL anywhere, relocated), bind its IAT by name or ordinal (`dll#N`) |
| `hle_path.c` | Windows paths on a POSIX disk: drive letters to host directories, either slash, components matched without case |
| `module.c` | modules and resources: `LoadLibraryA` (resource DLLs mapped, system DLLs as pseudo-modules), `GetProcAddress`, `FindResourceA`/`LoadResource`/`LoadStringA`, the current directory |
| `kernel32.c` | process, heap (sized blocks), virtual memory, time, critical sections, events, mutexes, waits, TLS, the console/serial calls a game links |
| `kernel32_ext.c` | files on descriptors, `FindFirstFileA`, attributes, file times, disks, `.ini` profiles |
| `kernel32_crt.c` | what an MSVC CRT asks on its way to `WinMain`: std handles, codepage 1252, locale (the wide calls answer `ERROR_CALL_NOT_IMPLEMENTED`, as on Windows 95), environment, threads |
| `user32.c` | a window manager without a display: windows, classes, the message queue with `WM_PAINT`/`WM_TIMER` generated, focus/capture/activation, dialogs from templates (modal and not), and the standard controls (button, static, edit, list and combo boxes with owner-draw, trackbar, progress, hotkey) |
| `gdi32.c`, `gdidc.c` | DIBs and `StretchDIBits` into a framebuffer; device contexts, fonts (TrueType through SDL2_ttf, Liberation for Arial/MS Sans Serif) and `TextOutA` into a surface |
| `ddraw.c` | DirectDraw in software: `IDirectDraw`/`2`, surfaces 1–3 (lock, blit with colour fill, colour key and stretch, flip), palettes, clippers, a virtual display mode |
| `dsound.c` | DirectSound on SDL2 audio: buffers mixed in software at their rate, volume and pan, with play cursors in real time |
| `screen.c` | the SDL2 window for a DirectDraw game: the primary surface scaled (sharp, smooth, CRT, nearest, integer; F12, F11), SDL input turned into the messages a mouse and keyboard give |
| `winmm.c` | timers (`timeSetEvent` on threads, `timeKillEvent` waiting for a callback under way), joystick, waveOut, MCI |
| `wsock32.c` | Winsock 1.1 on BSD sockets, by name and ordinal; `WSAAsyncSelect` through the pump; IPX as IPXEmu carries it on UDP |
| `ole32.c` | COM: class factories a host serves and ones the guest registers itself, GUID strings, BSTRs |
| `storage.c` | structured storage on compound files in Windows' format (`StgCreateDocfile`, `IStorage`, `IStream`, `OleSaveToStream`) |
| `advapi32.c` | an in-memory registry (seeded by the host, optionally saved to a file); COMCTL32, VERSION, SHELL32 |
| `present.c` | the plain SDL2 layer for a GDI game: the gdi32 framebuffer in a window |
| `*_selftest.c` | synthetic lifted guests driving the spine, the loader, the host, the pump and present, headless; `build_selftests.sh` builds and runs them |

## State (what's real, what's next)

Two titles run on it: Fury³ (its CRT and `WinMain`, the first census), and
Tiberian Sun, which boots, plays its movies and music, runs its menus (the
game's own and the Win32 dialogs behind them) and plays a skirmish on Linux,
with no Windows and no Wine (tiberiansun-recomp, `src/linux`).

What a title still brings:

- its own **lift** (the generated C — per game, never in this repo);
- the **breadth** of the API it happens to call, filled in as it hits a gap:
  a permissive bind (`recomp_host_boot_permissive`, or `recomp_pe_bind` with
  `hle_resolve_or_stub`) turns each unanswered import into a stub that names
  itself when called;
- its own answers where Windows would have found a DLL's code (Tiberian Sun's
  Blowfish cipher, a COM server in the game folder), registered ahead of
  these with `win32hle_register` or `hle_com_register_class`.

Not here: guest SEH and C++ exceptions (`RaiseException` ends the run),
DirectX past DirectDraw 2 and DirectSound 1, and drawing anything through
GDI but text.

## Building the selftests

```
runtime/win32hle/build_selftests.sh
```

builds every `*_selftest.c` with the whole layer under gcc `-m32` and runs
it (SDL's dummy drivers: no display or sound card needed). Prereqs on
Debian/Ubuntu: `dpkg --add-architecture i386; apt install gcc-multilib
libsdl2-dev:i386 libsdl2-ttf-dev:i386`.
