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
| `win32hle_selftest.c` | a synthetic lifted guest that drives all of the above headless |

## State (what's real, what's next)

Implemented and tested headless, under gcc `-m32`:

- the guest ↔ native ↔ guest spine, the machine lock, the simulated TIB
- a kernel32 startup/heap/time subset
- the gdi32 DIB-and-blit frame path into a framebuffer

Deferred (tracked in the port plan / ROADMAP):

- **user32 + SDL2 present** — window, message pump, input, and copying the
  framebuffer to a texture. Needs 32-bit SDL2 (`libsdl2-dev:i386`).
- **A PE loader** — map a real image's data/resources at their VAs and bind its
  IAT to these shims. The spine drives lifted code without it (the selftest
  proves that); a real game needs it. Lives in the eventual full host.
- 8/16/24bpp DIBs and the palette-animation emulator (generalised from SC2K).

## Building the selftest

```
gcc -m32 -O1 -Wall -Wno-unused-but-set-variable \
    -Iruntime/recomp32 -Iruntime/win32hle \
    runtime/win32hle/host_lite.c runtime/win32hle/kernel32.c \
    runtime/win32hle/gdi32.c runtime/win32hle/win32hle_selftest.c \
    -lpthread -lm -o /tmp/win32hle_selftest && /tmp/win32hle_selftest
```

Expected: `win32hle_selftest: all checks passed`. Prereq: `gcc-multilib`.
