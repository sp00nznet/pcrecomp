/*
 * win32hle: a portable, *implemented* Win32-subset for recomp32 (global-register
 * model) lifted code. Where native32/ forwards a guest's imports to the real
 * Win32 API (and so only runs on Windows), win32hle answers them itself, on top
 * of libc / POSIX / SDL2, so a lifted Win32 program runs on Linux (or anywhere
 * SDL2 builds). It is the Win32 counterpart of runtime/nextstep/, which already
 * hosts recomp32 code on a non-Windows libsys HLE.
 *
 * The whole layer rests on native32's shim ABI, which needs no inline asm:
 *
 *   An import is a `recomp_func_t` (void(void)) run *inside* the lifted model.
 *   When it is entered, `g_esp` points at [ret][arg0][arg1]...; the shim reads
 *   its stdcall arguments with A32/APTR/ASTR, does the work against libc/SDL2,
 *   returns a value with RET/RETP, and that macro pops `ret + argc*4` (stdcall).
 *
 * Because every import is our own C, native -> guest calls (a WndProc, a thread
 * start) are made explicitly with hle_call_guest(); there is no non-executable
 * .text and no exec-fault trampoline. That is the one thing that makes this
 * portable where native32 is not.
 *
 * The host (host_lite.c) owns the register file, the machine lock, the per-thread
 * TIB (g_fs_base), and recomp_lookup_import(); win32hle registers its shims with
 * it. A real game additionally needs a PE loader to map the image's data and
 * resources at their VAs; that is separate (see ROADMAP) and not needed to
 * exercise the shim layer.  MSVC x86 and gcc/clang -m32 both build this.
 */
#ifndef WIN32HLE_H
#define WIN32HLE_H

#include <stdint.h>
#include "recomp_types.h"   /* g_eax, g_esp, MEM*, recomp_func_t, the dispatch contract */

/* ---- the Win32 ABI, portably ----
 * Win32 is 32-bit stdcall. On a 32-bit host a guest pointer is a host pointer,
 * so HANDLE/HWND/HDC are just uint32_t the host casts as needed. */
typedef uint32_t win_handle;   /* HANDLE/HWND/HDC/HMODULE/HBITMAP... */

/* Stdcall argument access from inside a shim. g_esp -> [ret][arg0][arg1]...,
 * so argument i (0-based) is at g_esp + 4 + 4*i. */
static inline uint32_t hle_a32(int i) {
    return *(uint32_t *)(uintptr_t)(g_esp + 4u + 4u * (uint32_t)i);
}
#define A32(i)   hle_a32(i)                       /* arg i as uint32_t */
#define APTR(i)  ((void *)(uintptr_t)hle_a32(i))  /* arg i as a pointer */
#define ASTR(i)  ((char *)(uintptr_t)hle_a32(i))  /* arg i as a char*  */

/* Return from a stdcall shim: set eax and pop ret + argc args. Every shim ends
 * in exactly one of these; the argc is the callee's own purge. */
#define RET(eax, argc)   do { g_eax = (uint32_t)(eax); g_esp += 4u + 4u * (uint32_t)(argc); return; } while (0)
#define RETV(argc)       RET(0, argc)                       /* void-returning (eax undefined) */
#define RETP(ptr, argc)  RET((uint32_t)(uintptr_t)(ptr), argc)

/* ---- shim registry ----
 * A shim is named by the Win32 symbol it answers. The host assigns each a
 * synthetic VA at registration and resolves that VA in recomp_lookup_import.
 * A real bind walks the guest IAT and writes these VAs into it; the selftest
 * (and any direct caller) uses hle_resolve() to get one by name. */
typedef struct { const char *name; recomp_func_t fn; } win32hle_shim;

/* Register a NULL-terminated array of shims. Called once per module at startup
 * (kernel32, user32, gdi32, ... each export one). Returns the count added. */
int  win32hle_register(const win32hle_shim *shims);

/* Synthetic VA for a registered shim, or 0 if unknown. */
uint32_t hle_resolve(const char *name);

/* Human name for a synthetic shim VA (for traces/faults), or NULL. */
const char *hle_name(uint32_t va);

/* ---- native -> guest ----
 * Run a lifted function (window proc, dialog proc, thread start, timer) from
 * HLE C, pushing `nargs` stdcall args. Returns the guest's eax. Takes the
 * machine lock around the call; nests, so a shim may call it while itself
 * running inside the lifted model. */
uint32_t hle_call_guest(uint32_t va, int nargs, const uint32_t *args);

/* ---- the machine lock ----
 * One recursive lock serialises the global register file. A thread holds it
 * while running lifted code; hle_call_guest takes it, and a host driving lifted
 * code from its own thread must bracket that with these. Nests. */
void  mach_enter(void);
void  mach_leave(void);

/* ---- user32 message queue, host-callable ----
 * So the optional SDL present/input layer can inject translated events, and a
 * host can drive the queue, without user32 depending on SDL. */
void     hle_post_message(uint32_t hwnd, uint32_t message, uint32_t wParam, uint32_t lParam);
int      hle_msg_pop(uint32_t *message, uint32_t *wParam, uint32_t *lParam);  /* 1 if one popped */
uint32_t hle_first_hwnd(void);           /* the first created window, or 0 */
void     hle_set_pump_hook(void (*fn)(void)); /* called when the queue is empty (present layer) */

/* ---- gdi32 framebuffer, host-callable ---- */
void            hle_gdi_set_target(uint32_t *pixels, int w, int h); /* the blit destination */
const uint32_t *hle_gdi_framebuffer(int *w, int *h);                /* what present shows */

/* ---- optional SDL2 present/input layer (present.c) ----
 * Shows the gdi32 framebuffer in a window and turns SDL input into WM_*
 * messages. Separate from everything above so the core stays headless and
 * SDL-free; link it only when you want a visible window. */
int   hle_present_open(const char *title, int w, int h);   /* 0 on success */
void  hle_present_frame(const uint32_t *fb);                /* blit a w*h ARGB frame */
void  hle_present_pump(void);                               /* SDL events -> WM_* */
void  hle_present_step(void);                               /* pump + show one frame + yield */
void  hle_present_enable(void);                             /* wire present_step as the pump hook */
void  hle_present_close(void);

/* ---- host services a shim may need ---- */
void  hle_fatal(const char *fmt, ...);   /* print + abort: an unimplemented path */
extern int win32hle_trace;               /* env SC2K/HLE trace: one line per shim call */

/* Each module's shim table (defined in its .c, registered by the host). */
extern const win32hle_shim win32hle_kernel32[];
extern const win32hle_shim win32hle_kernel32_ext[];   /* file I/O, Global*, .ini */
extern const win32hle_shim win32hle_gdi32[];
extern const win32hle_shim win32hle_user32[];

#endif /* WIN32HLE_H */
