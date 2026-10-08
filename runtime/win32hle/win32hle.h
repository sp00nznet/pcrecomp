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
#include <stddef.h>
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

/* Like hle_resolve, but registers a self-naming "unimplemented" stub for an
 * unknown name and returns its VA (used as the resolver for a permissive bind,
 * so an unresolved import aborts with its name when first called, not at bind). */
uint32_t hle_resolve_or_stub(const char *name);

/* Human name for a synthetic shim VA (for traces/faults), or NULL. */
const char *hle_name(uint32_t va);

/* ---- native -> guest ----
 * Run a lifted function (window proc, dialog proc, thread start, timer) from
 * HLE C, pushing `nargs` stdcall args. Returns the guest's eax. Takes the
 * machine lock around the call; nests, so a shim may call it while itself
 * running inside the lifted model. */
uint32_t hle_call_guest(uint32_t va, int nargs, const uint32_t *args);

/* ---- the machine lock ----
 * One lock serialises the global register file. A thread holds it while
 * running lifted code; hle_call_guest takes it, and a host driving lifted
 * code from its own thread must bracket that with these. Nests per thread. */
void  mach_enter(void);
void  mach_leave(void);
/* Inside a shim: give the machine up around a blocking wait, registers saved
 * (begin), and take it back (end). Between them, touch no guest state. */
void  hle_block_begin(void);
void  hle_block_end(void);
/* Inside a shim: hand the machine to a waiting thread, if any. */
void  hle_yield(void);

/* ---- user32 message queue, host-callable ----
 * So the optional SDL present/input layer can inject translated events, and a
 * host can drive the queue, without user32 depending on SDL. */
void     hle_post_message(uint32_t hwnd, uint32_t message, uint32_t wParam, uint32_t lParam);
int      hle_msg_pop(uint32_t *message, uint32_t *wParam, uint32_t *lParam);  /* 1 if one popped */
uint32_t hle_first_hwnd(void);           /* the first created window, or 0 */
void     hle_set_pump_hook(void (*fn)(void)); /* called when the queue is empty (present layer) */
/* The window manager's host side (user32.c): the screen size (the display
 * mode), input as a mouse and keyboard would give it, and what is where. */
void     hle_set_screen_size(int w, int h);
void     hle_input_mouse(uint32_t message, int screen_x, int screen_y);   /* WM_MOUSEMOVE, WM_LBUTTONDOWN, ... */
void     hle_input_key(int down, uint32_t vk, uint32_t scan);
void     hle_input_cursor(int screen_x, int screen_y);                    /* GetCursorPos, without a message */
void     hle_input_key_state(uint32_t vk, int down);                      /* GetKeyState, without a message */
uint32_t hle_window_at(int screen_x, int screen_y, int *client_x, int *client_y);
uint32_t hle_focus_window(void);
uint32_t hle_send(uint32_t hwnd, uint32_t msg, uint32_t wParam, uint32_t lParam);   /* SendMessageA */
extern void (*hle_dialog_hook)(uint32_t hwnd, uint32_t resource_id);   /* a dialog made from a resource */
extern void (*hle_cursor_hook)(int x, int y);                          /* the guest moved the cursor */
extern void (*hle_proc_hook)(uint32_t hwnd, uint32_t msg, uint32_t wParam, uint32_t lParam);   /* every message delivered */
extern volatile int hle_lbutton_reads;   /* GetKeyState/GetAsyncKeyState(VK_LBUTTON) calls so far */
int         hle_is_window(uint32_t h);
int         hle_window_screen_rect(uint32_t h, int *l, int *t, int *r, int *b);
const char *hle_window_class(uint32_t h);
uint32_t    hle_window_parent(uint32_t h);
uint32_t    hle_window_style(uint32_t h);
uint32_t    hle_dialog_item(uint32_t dlg, uint32_t id);
void        hle_queue_dump(void);              /* the queue, to stderr */

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

/* ---- kernel object handles (host_lite.c) ----
 * Typed: hle_handle_obj(h, type) is NULL for a handle of another type (type 0
 * takes any). CloseHandle calls the type's closer. */
enum { HLE_H_FILE = 1, HLE_H_FIND, HLE_H_EVENT, HLE_H_MUTEX, HLE_H_THREAD, HLE_H_SEMAPHORE,
       HLE_H_REGKEY, HLE_H_SOCKET, HLE_H_OTHER };
uint32_t hle_handle_alloc(int type, void *obj);       /* 0 when the table is full */
void    *hle_handle_obj(uint32_t h, int type);
int      hle_handle_type(uint32_t h);
int      hle_handle_close(uint32_t h);                /* 1 if it was a handle */
void     hle_handle_set_closer(int type, void (*fn)(void *));

/* ---- paths (hle_path.c) ----
 * Guest (Windows) paths to host paths: drive letters map to host directories
 * (Z: is /), either slash separates, and components match without case.
 * hle_host_path returns 1 when the path exists. */
void hle_set_drive(char letter, const char *host_root);
int  hle_host_path(const char *guest, char *out, size_t n);
void hle_guest_path(const char *host, char *out, size_t n);

/* ---- host services a shim may need (kernel32.c) ---- */
void  hle_set_last_error(uint32_t code);           /* what GetLastError answers next */
uint32_t hle_get_last_error(void);
void  hle_set_command_line(const char *cmdline);   /* what GetCommandLineA answers */
extern void (*hle_on_exit)(int code);              /* run by ExitProcess before the process goes */
void  hle_exit(int code);                          /* flush and leave, once */
uint32_t hle_thread_id(void);                      /* GetCurrentThreadId's answer for this thread */
uint32_t hle_ticks_ms(void);                       /* GetTickCount */
void *hle_alloc(uint32_t n);                       /* a zeroed heap block (HeapFree-able) */
void  hle_free(void *p);
void  hle_enter_cs(uint32_t cs);                   /* a guest CRITICAL_SECTION */
void  hle_leave_cs(uint32_t cs);
uint32_t hle_wait(int n, const uint32_t *handles, int all, uint32_t timeout_ms);  /* WaitForMultipleObjects */
extern int (*hle_wait_hook)(uint32_t h);           /* a host's own waitable: 1 ready, 0 not, -1 not mine */
void  hle_set_event(uint32_t h);                    /* SetEvent, under the machine */
int   hle_filetrace(void);                         /* HLE_FILETRACE=1: log file opens */
void  hle_set_module_path(const char *real_path);  /* real image path -> GetModuleFileNameA */

/* ---- modules and resources (module.c) ----
 * The host adds its main image (main_image 1); LoadLibraryA adds DLLs. A
 * NULL module is the main image. */
int      hle_module_add(const char *guest_path, uint32_t base, uint32_t rsrc_rva, uint32_t rsrc_size, int main_image);
uint32_t hle_find_resource(uint32_t hmod, uint32_t name, uint32_t type);   /* HRSRC, or 0 */
uint32_t hle_resource_data(uint32_t hmod, uint32_t hrsrc, uint32_t *size); /* its bytes' VA */
int      hle_load_string(uint32_t hmod, uint32_t id, char *buf, int n);
uint32_t hle_dialog_resource_id(uint32_t tmpl);   /* the RT_DIALOG id a template came from, or 0 */
void  hle_fatal(const char *fmt, ...);   /* print + abort: an unimplemented path */
extern int win32hle_trace;
extern const char *g_cur_import;          /* the last import entered (fault reports) */               /* env SC2K/HLE trace: one line per shim call */

/* Each module's shim table (defined in its .c, registered by the host). */
extern const win32hle_shim win32hle_kernel32[];
extern const win32hle_shim win32hle_kernel32_ext[];   /* file I/O, Global*, .ini */
extern const win32hle_shim win32hle_kernel32_crt[];   /* CRT startup -> WinMain */
extern const win32hle_shim win32hle_module[];         /* modules, resources, current directory */
extern const win32hle_shim win32hle_gdi32[];
extern const win32hle_shim win32hle_gdidc[];          /* DCs, fonts, text (SDL2_ttf) */
uint32_t hle_gdi_surface_dc(uint8_t *px, int w, int h, int pitch, int bpp);   /* a DC drawing into those pixels */
void     hle_gdi_release_dc(uint32_t hdc);
extern const win32hle_shim win32hle_user32[];
extern const win32hle_shim win32hle_winmm[];
extern const win32hle_shim win32hle_wsock32[];        /* by name and by ordinal */
void hle_ws_poll(void);                                /* the pump: WSAAsyncSelect notifications */
extern const win32hle_shim win32hle_ole32[];          /* OLE32 + OLEAUT32 */
extern const win32hle_shim win32hle_storage[];        /* structured storage: compound files */
extern const win32hle_shim win32hle_dsound[];         /* DirectSound on SDL audio (dsound.c) */
extern const win32hle_shim win32hle_ddraw[];          /* DirectDraw in software (ddraw.c) */
/* The primary surface, for a presenter: 0 until there is one. seq changes
 * when its pixels or palette may have. */
int  hle_dd_frame(const uint8_t **px, int *w, int *h, int *pitch, int *bpp, const uint32_t **palette, unsigned *seq);
void hle_dd_mode(int *w, int *h, int *bpp);
int  hle_dd_surface_pixels(uint32_t obj, uint8_t **px, int *w, int *h, int *pitch, int *bpp);   /* 0: not a surface */
void hle_dsound_set_master(float gain);              /* 0 mutes */
/* A host's own sound (a movie's), mixed with the game's buffers: interleaved
 * s16 pushed at its own rate. */
int  hle_audio_stream_open(int rate, int channels);   /* an id, or -1 with no audio */
void hle_audio_stream_push(int id, const int16_t *pcm, int frames);
int  hle_audio_stream_queued(int id);                 /* frames pushed and not yet played */
void hle_audio_stream_gain(int id, float gain);
void hle_audio_stream_close(int id);
int  hle_file_fd(uint32_t handle);                    /* a file HANDLE's descriptor, or -1 */
extern const win32hle_shim win32hle_bink[];           /* binkw32 on ffmpeg (bink.c; stubs without HLE_WITH_FFMPEG) */
/* The SDL2 display and input for a DirectDraw game (screen.c): installs
 * itself as the pump hook. headless: no window (a script drives input). */
int  hle_screen_open(const char *title, int fullscreen, int headless);
void hle_screen_pump(void);
extern void (*hle_screen_frame_hook)(const uint8_t *px, int w, int h, int pitch, int bpp);   /* each shown frame */
extern int (*hle_screen_compose_hook)(const uint8_t *px16, int pitch, int w, int h, uint32_t *out);   /* a 2x picture */
int  hle_screen_scale(const char *name);   /* sharp, smooth, crt, nearest, integer: 0 if unknown */
void hle_screen_bars(int blur);            /* the bars beside the picture: a blur of it, or black */
extern void (*hle_screen_settings_hook)(const char *scale, int bars, int fullscreen);   /* F11/F12 changed them */
extern const win32hle_shim win32hle_advapi32[];       /* the registry; COMCTL32, VERSION, SHELL32 */
/* The registry (advapi32.c), in memory: seeded by the host, optionally saved
 * to a file on every write. Roots are the HKEY_ values (HKLM 0x80000002). */
void hle_reg_set_string(uint32_t root, const char *path, const char *name, const char *value);
void hle_reg_set_dword(uint32_t root, const char *path, const char *name, uint32_t value);
void hle_reg_load(const char *file);

/* ---- COM objects served by the host (ole32.c) ----
 * A vtable is built from a shim table (each method a stdcall shim whose arg 0
 * is `this`); an object is its vtable pointer, a count at +4, then host state.
 * hle_com_QueryInterface/AddRef/Release are an IUnknown for such objects. */
uint32_t hle_com_vtable(const win32hle_shim *methods);
uint32_t hle_com_new(uint32_t vtable, uint32_t size);
void     hle_com_register_class(const uint8_t *clsid, uint32_t (*create)(const uint8_t *iid, uint32_t *out));
void     hle_com_QueryInterface(void);
void     hle_com_AddRef(void);
void     hle_com_Release(void);
void     hle_guid_string(const uint8_t *guid, char *out);   /* 39 bytes: {...} */

#endif /* WIN32HLE_H */
