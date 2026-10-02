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
| `win32hle.h` | the shim ABI (`A32`/`RET`/…), the registry, `hle_call_guest` |
| `host_lite.c` | the spine: register file, machine lock (pthread), per-thread simulated TIB (`g_fs_base`), dispatch lookups, shim registry. "lite" = no PE loader |
| `kernel32.c` | process/module, heap, `VirtualAlloc`, time, error, `lstr*` — on libc/POSIX |
| `gdi32.c` | the software-renderer seam: `CreateDIBSection` + `StretchDIBits` blit into a host framebuffer (32bpp, nearest-neighbour). No SDL — pure pixels |
| `user32.c` | the message core, SDL-free: class/window registries, the message queue, `GetMessage`/`PeekMessage`/`DispatchMessage` (calls the `WndProc` via `hle_call_guest`) |
| `pe_format.h` | the 32-bit PE structures, portably (no windows.h) |
| `pe_loader.c` | `recomp_pe_map` (mmap sections at their VAs, zero `.bss`), `recomp_pe_bind` (IAT → shims), `recomp_pe_relocate` (HIGHLOW) |
| `host.c` | the full host: `recomp_host_init`/`_boot`/`_run`/`_main` — register the shim modules, map+bind a PE, call its lifted entry |
| `win32hle_selftest.c` | a synthetic lifted guest driving the shims + a callback, headless |
| `pe_loader_selftest.c` | builds a minimal PE (2 imports, a reloc), maps/binds/relocates it, headless |
| `host_selftest.c` | a full boot: a synthetic lifted GUI app (entry → class → window → message loop → `WndProc` paints) driven through the host, headless |

## State (what's real, what's next)

Implemented and tested headless, under gcc `-m32`:

- the guest ↔ native ↔ guest spine, the machine lock, the simulated TIB
- a kernel32 startup/heap/time subset
- the gdi32 DIB-and-blit frame path into a framebuffer
- the PE loader: map an image at its VAs, bind its IAT to the shims, relocate
- the full host: map + bind + call the lifted entry, with a real Win32 message
  loop (`GetMessage`/`DispatchMessage` → `WndProc` via `hle_call_guest`) and the
  gdi32 paint path, driven end to end by a synthetic lifted GUI app

Deferred (tracked in the port plan / ROADMAP):

- **SDL2 present** — the one thing still missing to run a *real* windowed game:
  copy the gdi32 framebuffer to a texture, show a window, and feed SDL input
  back as `WM_*` messages. The message core and paint path are already here and
  headless; this bolts a display onto them. Needs 32-bit SDL2 (`libsdl2-dev:i386`).
- 8/16/24bpp DIBs and the palette-animation emulator (generalised from SC2K).
- the breadth of kernel32/user32/gdi32 a given title needs, filled in as titles
  hit the gaps (the shim registry makes each one a few lines).

## Building the selftest

```
gcc -m32 -O1 -Wall -Wno-unused-but-set-variable \
    -Iruntime/recomp32 -Iruntime/win32hle \
    runtime/win32hle/host_lite.c runtime/win32hle/kernel32.c \
    runtime/win32hle/gdi32.c runtime/win32hle/win32hle_selftest.c \
    -lpthread -lm -o /tmp/win32hle_selftest && /tmp/win32hle_selftest
```

Expected: `win32hle_selftest: all checks passed`. Prereq: `gcc-multilib`.
