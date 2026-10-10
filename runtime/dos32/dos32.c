/*
 * dos32.c - the DOS/4GW host for lifted LE programs (see dos32.h).
 *
 * Guest memory is one 4 GB reservation; a guest linear address is an offset
 * into it (g_mem_base), so the host may be 64-bit and nothing from the host's
 * own address space leaks into the guest. Committed on start:
 *
 *   0x00000000  environment block (see "Low memory" below)
 *   0x00000080  copy of the command tail
 *   0x00000100  PSP (selector SEL_PSP)
 *   0x00000400  BIOS data area: tick count at 0x46C, shift flags at 0x417
 *   0x00001000  conventional memory for DPMI 0100h, up to 0x9F000
 *   0x000A0000  VGA window
 *   image_base  the LE objects (0x400000 by convention)
 *   HEAP_LO     DPMI 0501h / int 21h 48h blocks
 *   LFB_VA      the VESA linear frame buffer
 *
 * Low memory: Watcom's startup reads the command tail with `repe scasb` and
 * the environment through ds, and the lifter treats both as flat (base 0),
 * while the PSP's own fields are read through es: with a real base. So the
 * environment sits at linear 0 under a base-0 selector, a copy of the tail
 * sits at 0x80 where the flat reads land, and the PSP proper sits at 0x100.
 * ponytail: the environment must fit in 0x80 bytes; a program that wants a
 * real one needs ds tracked by the lifter.
 *
 * Interrupts: the guest runs on one thread, and an IRQ is delivered only at a
 * point where the lifted code calls in (a loop back-edge, an int, a port
 * read), with every register and flag saved around the handler. That is a
 * coarser grain than the hardware's, and it is what makes delivery safe.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <mmsystem.h>
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <ctype.h>
#include <errno.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "recomp_types.h"
#include "dos32.h"

/* ---- CPU state the lifted code links against --------------------------- */
uint32_t g_eax, g_ecx, g_edx, g_esp, g_ebx, g_esi, g_edi, g_ebp;
double   g_st[8];
int      g_fp_top;
uint16_t g_fpu_cw = 0x037F;
uint64_t g_mm[8];
uint16_t g_seg_cs, g_seg_ds, g_seg_es, g_seg_fs, g_seg_gs, g_seg_ss;
uint32_t g_fs_base, g_gs_base, g_es_base;
ptrdiff_t g_mem_base;
uint32_t g_cur_func;
uint32_t g_icall_trace[ICALL_TRACE_SIZE], g_icall_from[ICALL_TRACE_SIZE];
uint32_t g_icall_trace_idx, g_icall_count;

double dos32_speed = 1.0;
volatile int dos32_quit;
void (*dos32_on_retrace)(void);

/* ---- layout ------------------------------------------------------------- */
#define COMMIT_SIZE  0x10000000u   /* 256 MB, demand-zero */
#define HEAP_LO      0x01000000u
#define HEAP_HI      0x05000000u   /* 64 MB: more than any DOS game expects */
#define CONV_LO      0x00001000u
#define CONV_HI      0x0009F000u
#define LFB_VA       0xE0000000u
#define VRAM_SIZE    0x00400000u   /* 4 MB, 1024x768x8 with room */
#define HOSTVEC_VA   0xFFF00000u   /* default interrupt handlers live here */

#define SEL_CODE 0x0170
#define SEL_DATA 0x0178
#define SEL_PSP  0x0024
#define SEL_ENV  0x002C
#define SEL_FIRST_FREE 0x40        /* descriptor index */
#define NSEL 1024

static uint8_t* M;
static const dos32_config* C;
static jmp_buf exit_jmp;
static int exit_code;

#define LIN(a)    (M + (uint32_t)(a))
#define R8(a)     (*(uint8_t*)LIN(a))
#define R16(a)    (*(uint16_t*)LIN(a))
#define R32(a)    (*(uint32_t*)LIN(a))

uint8_t* dos32_mem(uint32_t va) { return LIN(va); }

static void logf_(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}
#define LOG(...) do { if (C->log) logf_(__VA_ARGS__); } while (0)

/* Unhandled things are reported once each, always: they are the to-do list. */
static void once(const char* what, uint32_t a, uint32_t b) {
    static uint32_t seen[512];
    static int n;
    uint32_t key = ((uint32_t)(uintptr_t)what * 2654435761u) ^ (a << 16) ^ b;
    for (int i = 0; i < n; i++) if (seen[i] == key) return;
    if (n < 512) seen[n++] = key;
    fprintf(stderr, "dos32: unhandled %s %#x %#x (from 0x%08X)\n", what, a, b, g_cur_func);
}

/* ---- selectors ---------------------------------------------------------- */
static struct { uint32_t base, limit; uint8_t used; } sel[NSEL];

static uint32_t sel_base(uint32_t s) { return sel[(s >> 3) & (NSEL - 1)].base; }

static void sel_set(uint32_t s, uint32_t base, uint32_t limit) {
    s = (s >> 3) & (NSEL - 1);
    sel[s].base = base; sel[s].limit = limit; sel[s].used = 1;
}

static uint32_t sel_alloc(uint32_t base, uint32_t limit) {
    for (int i = SEL_FIRST_FREE; i < NSEL; i++)
        if (!sel[i].used) { sel[i].used = 1; sel[i].base = base; sel[i].limit = limit; return (i << 3) | 7; }
    return 0;
}

void recomp_set_seg(int sreg, uint32_t s) {
    s &= 0xFFFF;
    switch (sreg) {
    case 0: g_seg_es = (uint16_t)s; g_es_base = sel_base(s); break;
    case 4: g_seg_fs = (uint16_t)s; g_fs_base = sel_base(s); break;
    case 5: g_seg_gs = (uint16_t)s; g_gs_base = sel_base(s); break;
    }
}

/* ---- dispatch ----------------------------------------------------------- */
recomp_func_t recomp_lookup(uint32_t va) {
    uint32_t lo = 0, hi = recomp_dispatch_count;
    while (lo < hi) {
        uint32_t mid = (lo + hi) / 2;
        uint32_t a = recomp_dispatch_table[mid].address;
        if (a == va) return recomp_dispatch_table[mid].func;
        if (a < va) lo = mid + 1; else hi = mid;
    }
    return NULL;
}

static int hostvec_n, stub_n;
static void hostvec_default(void);

/* `int N; ret`, reached by a computed jump (Watcom's int386x keeps a table of
 * them) and too small for the catalog to list: run it from its bytes. */
static void int_stub(void) { recomp_int(stub_n); g_esp += 4; }

recomp_func_t recomp_lookup_manual(uint32_t va) {
    if (va - HOSTVEC_VA < 256 * 16) { hostvec_n = (va - HOSTVEC_VA) / 16; return hostvec_default; }
    if (va - 0x1000u < 0x0F000000u && R8(va) == 0xCD && R8(va + 2) == 0xC3) { stub_n = R8(va + 1); return int_stub; }
    return NULL;
}
recomp_func_t recomp_lookup_import(uint32_t va) { (void)va; return NULL; }

/* ---- heap: first fit over a sorted block list --------------------------- */
typedef struct { uint32_t base, size; } block_t;
typedef struct { block_t b[4096]; int n; uint32_t lo, hi; } arena_t;
static arena_t heap = { .lo = HEAP_LO, .hi = HEAP_HI };
static arena_t conv = { .lo = CONV_LO, .hi = CONV_HI };

static uint32_t arena_alloc(arena_t* a, uint32_t size, uint32_t align) {
    uint32_t at = a->lo;
    size = (size + align - 1) & ~(align - 1);
    if (!size) size = align;
    int i = 0;
    for (; i <= a->n; i++) {
        uint32_t end = i < a->n ? a->b[i].base : a->hi;
        at = (at + align - 1) & ~(align - 1);
        if (end >= at && end - at >= size) break;
        if (i < a->n) at = a->b[i].base + a->b[i].size;
    }
    if (i > a->n || a->n >= 4096) return 0;
    memmove(&a->b[i + 1], &a->b[i], (a->n - i) * sizeof(block_t));
    a->b[i].base = at; a->b[i].size = size; a->n++;
    memset(LIN(at), 0, size);
    return at;
}

static int arena_find(arena_t* a, uint32_t base) {
    for (int i = 0; i < a->n; i++) if (a->b[i].base == base) return i;
    return -1;
}

static int arena_free(arena_t* a, uint32_t base) {
    int i = arena_find(a, base);
    if (i < 0) return 0;
    memmove(&a->b[i], &a->b[i + 1], (a->n - i - 1) * sizeof(block_t));
    a->n--;
    return 1;
}

static uint32_t arena_resize(arena_t* a, uint32_t base, uint32_t size, uint32_t align) {
    int i = arena_find(a, base);
    if (i < 0) return 0;
    size = (size + align - 1) & ~(align - 1);
    uint32_t limit = i + 1 < a->n ? a->b[i + 1].base : a->hi;
    if (base + size <= limit) {
        if (size > a->b[i].size) memset(LIN(base + a->b[i].size), 0, size - a->b[i].size);
        a->b[i].size = size;
        return base;
    }
    uint32_t old = a->b[i].size, nb = arena_alloc(a, size, align);
    if (!nb) return 0;
    memcpy(LIN(nb), LIN(base), old);
    arena_free(a, base);
    return nb;
}

static uint32_t arena_free_bytes(arena_t* a) {
    uint32_t used = 0;
    for (int i = 0; i < a->n; i++) used += a->b[i].size;
    return a->hi - a->lo - used;
}

uint32_t dos32_heap_alloc(uint32_t bytes) { return arena_alloc(&heap, bytes, 4096); }
void dos32_heap_free(uint32_t va) { arena_free(&heap, va); }

/* ---- interrupt state ---------------------------------------------------- */
static struct { uint16_t sel; uint32_t off; } pmvec[256];
static uint32_t rmvec[256];
static volatile int g_if = 1;
static int in_irq;
static uint8_t pic_mask[2];

static int vec_hooked(int v) { return pmvec[v].off - HOSTVEC_VA >= 256 * 16; }

typedef struct {
    uint32_t eax, ebx, ecx, edx, esi, edi, ebp, esp;
    uint32_t fk, fa, fb, fcf;
    uint16_t ds, es, fs, gs;
    uint32_t es_base, fs_base, gs_base, cur;
    double st[8]; int top; uint16_t cw;
} saved_t;

static void save(saved_t* s) {
    s->eax = g_eax; s->ebx = g_ebx; s->ecx = g_ecx; s->edx = g_edx;
    s->esi = g_esi; s->edi = g_edi; s->ebp = g_ebp; s->esp = g_esp;
    s->fk = g_flag_k; s->fa = g_flag_a; s->fb = g_flag_b; s->fcf = g_flag_cf;
    s->ds = g_seg_ds; s->es = g_seg_es; s->fs = g_seg_fs; s->gs = g_seg_gs;
    s->es_base = g_es_base; s->fs_base = g_fs_base; s->gs_base = g_gs_base;
    s->cur = g_cur_func;
    memcpy(s->st, g_st, sizeof g_st); s->top = g_fp_top; s->cw = g_fpu_cw;
}

static void restore(const saved_t* s) {
    g_eax = s->eax; g_ebx = s->ebx; g_ecx = s->ecx; g_edx = s->edx;
    g_esi = s->esi; g_edi = s->edi; g_ebp = s->ebp; g_esp = s->esp;
    g_flag_k = s->fk; g_flag_a = s->fa; g_flag_b = s->fb; g_flag_cf = s->fcf;
    g_seg_ds = s->ds; g_seg_es = s->es; g_seg_fs = s->fs; g_seg_gs = s->gs;
    g_es_base = s->es_base; g_fs_base = s->fs_base; g_gs_base = s->gs_base;
    g_cur_func = s->cur;
    memcpy(g_st, s->st, sizeof g_st); g_fp_top = s->top; g_fpu_cw = s->cw;
}

static void push32(uint32_t v) { g_esp -= 4; R32(g_esp) = v; }

/* Run a guest function as an interrupt handler would be run: EFLAGS, CS and
 * a return address on the stack, the program's own data selectors loaded. */
static void call_guest(uint32_t va, int as_irq) {
    recomp_func_t fn = recomp_lookup(va);
    if (!fn) { once("guest handler not lifted", va, 0); return; }
    if (as_irq) push32(0x202);
    push32(SEL_CODE);
    push32(RECOMP_RETADDR);
    recomp_set_seg(0, SEL_DATA);
    recomp_set_seg(4, 0);
    recomp_set_seg(5, 0);
    g_seg_ds = SEL_DATA;
    g_flag_k = FK_EFLAGS; g_flag_a = 0x202; g_flag_b = 0; g_flag_cf = 0;
    fn();
}

static void irq(int v) {
    saved_t s;
    save(&s);
    in_irq++;
    call_guest(pmvec[v].off, 1);
    in_irq--;
    restore(&s);
}

/* ---- timer -------------------------------------------------------------- */
static LARGE_INTEGER qpf, t0;
static double now_s(void) {
    LARGE_INTEGER t;
    QueryPerformanceCounter(&t);
    return (double)(t.QuadPart - t0.QuadPart) / (double)qpf.QuadPart;
}
static uint32_t pit_div = 65536;
static int pit_latch, pit_lohi, pit_mode_byte;
static double pit_next, bios_next;
static double guest_time, last_real;

/* Guest time runs at dos32_speed times real time; everything the program can
 * measure (PIT IRQs, the BIOS tick, retrace) is derived from it. */
int dos32_virtual_clock;

/* With dos32_virtual_clock, guest time is not read from the host at all: the
 * host advances it (dos32_advance), and every read adds a fixed sliver so a
 * program that spins on the tick count still sees it move. A run is then the
 * same run every time, at whatever speed the host manages. */
static double gtime(void) {
    if (dos32_virtual_clock) return guest_time += 1e-6;
    double r = now_s();
    guest_time += (r - last_real) * dos32_speed;
    last_real = r;
    return guest_time;
}

/* ---- keyboard ----------------------------------------------------------- */
static CRITICAL_SECTION input_lock;
static uint16_t scq[256];
static int scq_r, scq_w;
static uint8_t port60;
static uint16_t kbbuf[64];
static int kb_r, kb_w;
static uint8_t shift_flags;

static const char sc_ascii[2][0x3A] = {
    { 0, 27, '1','2','3','4','5','6','7','8','9','0','-','=', 8, 9,
      'q','w','e','r','t','y','u','i','o','p','[',']', 13, 0, 'a','s',
      'd','f','g','h','j','k','l',';','\'','`', 0,'\\','z','x','c','v',
      'b','n','m',',','.','/', 0,'*', 0,' ' },
    { 0, 27, '!','@','#','$','%','^','&','*','(',')','_','+', 8, 9,
      'Q','W','E','R','T','Y','U','I','O','P','{','}', 13, 0, 'A','S',
      'D','F','G','H','J','K','L',':','"','~', 0,'|','Z','X','C','V',
      'B','N','M','<','>','?', 0,'*', 0,' ' },
};

static void bios_key(uint8_t sc) {
    int up = sc & 0x80;
    uint8_t k = sc & 0x7F;
    if (k == 0x2A || k == 0x36) { shift_flags = up ? shift_flags & ~3 : shift_flags | (k == 0x2A ? 2 : 1); }
    else if (k == 0x1D) { shift_flags = up ? shift_flags & ~4 : shift_flags | 4; }
    else if (k == 0x38) { shift_flags = up ? shift_flags & ~8 : shift_flags | 8; }
    else if (!up) {
        uint8_t ch = k < 0x3A ? (uint8_t)sc_ascii[(shift_flags & 3) ? 1 : 0][k] : 0;
        if (((kb_w + 1) & 63) != kb_r) { kbbuf[kb_w] = (uint16_t)(k << 8 | ch); kb_w = (kb_w + 1) & 63; }
    }
    R8(0x417) = shift_flags;
}

void dos32_key(int scancode, int down) {
    EnterCriticalSection(&input_lock);
    if (scancode & 0xE000) { scq[scq_w++ & 255] = 0xE0; }
    scq[scq_w++ & 255] = (uint16_t)((scancode & 0x7F) | (down ? 0 : 0x80));
    LeaveCriticalSection(&input_lock);
}

/* ---- mouse -------------------------------------------------------------- */
static struct {
    int x, y, buttons;                /* virtual coordinates */
    int minx, maxx, miny, maxy;
    int mick_x, mick_y;
    int shown;
    uint32_t handler, mask;           /* int 33h AX=0Ch */
    int pending;                      /* event bits not yet delivered */
    int px, py, pbuttons;             /* last raw input, screen pixels */
    int rel;                          /* 1: the last input was dos32_mouse_move */
    double rdx, rdy;                  /* motion not yet taken, screen pixels */
    double fx, fy;                    /* fractions of a virtual unit carried over */
    int scr_w, scr_h;
} mouse;
static volatile LONG mouse_dirty;

void dos32_mouse(int x, int y, int buttons) {
    EnterCriticalSection(&input_lock);
    mouse.px = x; mouse.py = y; mouse.pbuttons = buttons; mouse.rel = 0;
    LeaveCriticalSection(&input_lock);
    InterlockedExchange(&mouse_dirty, 1);
}

void dos32_mouse_move(double dx, double dy, int buttons) {
    EnterCriticalSection(&input_lock);
    mouse.rdx += dx; mouse.rdy += dy; mouse.pbuttons = buttons; mouse.rel = 1;
    LeaveCriticalSection(&input_lock);
    InterlockedExchange(&mouse_dirty, 1);
}

/* ---- video -------------------------------------------------------------- */
static int vmode = 3;
static int vw = 80, vh = 25, vpitch = 80;
static int vesa_lfb;
static uint32_t vbank;                /* current 64 KB bank in banked modes */
static uint8_t* vram;                 /* host copy of video memory past the window */
static uint8_t dac[256][3];
static int dac_w, dac_r, dac_c, dac_rc;
static uint8_t seq_idx, seq[8], crtc_idx, crtc[32], gc_idx, gc[16];
static CRITICAL_SECTION video_lock;

int dos32_video_mode(void) { return vmode; }

static const struct { uint16_t mode; uint16_t w, h; } vesa_modes[] = {
    { 0x100, 640, 400 }, { 0x101, 640, 480 }, { 0x103, 800, 600 }, { 0x105, 1024, 768 },
};

static void set_mode(int mode, int clear) {
    EnterCriticalSection(&video_lock);
    vmode = mode; vbank = 0; vesa_lfb = 0;
    if (mode == 0x13) { vw = 320; vh = 200; vpitch = 320; }
    else if (mode < 0x100) { vw = 80; vh = 25; vpitch = 80; }
    else {
        for (int i = 0; i < 4; i++)
            if (vesa_modes[i].mode == (mode & 0x1FF)) { vw = vesa_modes[i].w; vh = vesa_modes[i].h; }
        vpitch = vw;
        vesa_lfb = (mode & 0x4000) != 0;
        vmode = mode & 0x1FF;
    }
    if (clear) { memset(LIN(0xA0000), 0, 0x10000); memset(vram, 0, VRAM_SIZE); memset(LIN(LFB_VA), 0, VRAM_SIZE); }
    LeaveCriticalSection(&video_lock);
    LOG("dos32: video mode %#x %dx%d%s\n", mode, vw, vh, vesa_lfb ? " (LFB)" : "");
}

/* Banked VESA: the 64 KB window at A0000 is guest memory; the rest of video
 * memory lives in vram. Switching banks swaps the window out and back in. */
static void set_bank(uint32_t bank) {
    if (bank == vbank) return;
    EnterCriticalSection(&video_lock);
    memcpy(vram + vbank * 0x10000u, LIN(0xA0000), 0x10000);
    vbank = bank & 63;
    memcpy(LIN(0xA0000), vram + vbank * 0x10000u, 0x10000);
    LeaveCriticalSection(&video_lock);
}

int dos32_frame(uint32_t* out, int maxw, int maxh, int* w, int* h) {
    if (vmode < 0x13) return 0;
    uint32_t pal[256];
    for (int i = 0; i < 256; i++) {
        uint32_t r = dac[i][0] & 63, g = dac[i][1] & 63, b = dac[i][2] & 63;
        pal[i] = (r << 18 | (r >> 4) << 16) | (g << 10 | (g >> 4) << 8) | (b << 2 | b >> 4);
    }
    int fw = vw < maxw ? vw : maxw, fh = vh < maxh ? vh : maxh;
    EnterCriticalSection(&video_lock);
    for (int y = 0; y < fh; y++) {
        uint32_t off = (uint32_t)y * vpitch;
        for (int x = 0; x < fw; x++, off++) {
            uint8_t p;
            if (vmode == 0x13) p = R8(0xA0000 + off);
            else if (vesa_lfb) p = R8(LFB_VA + off);
            else p = (off >> 16) == vbank ? R8(0xA0000 + (off & 0xFFFF)) : vram[off];
            out[y * fw + x] = pal[p];
        }
    }
    LeaveCriticalSection(&video_lock);
    *w = fw; *h = fh;
    return 1;
}

/* Retrace: 70 Hz in guest time, in retrace for the first ~5% of each frame. */
static int spin;
static long long last_frame;

/* The 70 Hz frame clock: dos32_on_retrace runs once per frame of guest time,
 * from the poll, whether or not the program ever looks at port 3DAh. */
static void frame_clock(double t) {
    long long f = (long long)(t * 70.0);
    if (f != last_frame) {
        last_frame = f;
        if (dos32_on_retrace) dos32_on_retrace();
    }
}

static int retrace(void) {
    double t = gtime();
    frame_clock(t);
    t *= 70.0;
    return t - (double)(long long)t < 0.05;
}

/* ---- polling: deliver what is due --------------------------------------- */
static void poll_input(void) {
    uint16_t q[64];
    int n = 0;
    EnterCriticalSection(&input_lock);
    while (scq_r != scq_w && n < 64) q[n++] = scq[scq_r++ & 255];
    int px = mouse.px, py = mouse.py, pb = mouse.pbuttons, rel = mouse.rel;
    double rdx = mouse.rdx, rdy = mouse.rdy;
    mouse.rdx = mouse.rdy = 0;
    LeaveCriticalSection(&input_lock);
    for (int i = 0; i < n; i++) {
        port60 = (uint8_t)q[i];
        if (vec_hooked(9) && g_if) irq(9);
        else bios_key(port60);
    }
    if (InterlockedExchange(&mouse_dirty, 0)) {
        /* An absolute pointer: the screen maps onto whatever range the
         * program set with int 33h 7/8 (Theme Park asks for 640x400 in mode
         * 13h and halves it), which is where a real driver's mickeys would
         * have taken the cursor. */
        int sw = vmode <= 0x13 ? 320 : vw, sh = vmode <= 0x13 ? 200 : vh;
        int vx = mouse.minx + px * (mouse.maxx - mouse.minx + 1) / sw;
        int vy = mouse.miny + py * (mouse.maxy - mouse.miny + 1) / sh;
        int mx = vx - mouse.x, my = vy - mouse.y;
        if (rel) {
            /* A relative pointer, as a real driver moves: from wherever the
             * cursor is, including where the program put it with AX=04h.
             * Mickeys count the whole motion, clamped at the edge or not. */
            mouse.fx += rdx * (mouse.maxx - mouse.minx + 1) / sw;
            mouse.fy += rdy * (mouse.maxy - mouse.miny + 1) / sh;
            mx = (int)mouse.fx; my = (int)mouse.fy;
            mouse.fx -= mx; mouse.fy -= my;
            vx = mouse.x + mx; vy = mouse.y + my;
        }
        if (vx < mouse.minx) vx = mouse.minx;
        if (vx > mouse.maxx) vx = mouse.maxx;
        if (vy < mouse.miny) vy = mouse.miny;
        if (vy > mouse.maxy) vy = mouse.maxy;
        int ev = 0;
        if (vx != mouse.x || vy != mouse.y) ev |= 1;
        int chg = pb ^ mouse.buttons;
        if (chg & 1) ev |= (pb & 1) ? 2 : 4;
        if (chg & 2) ev |= (pb & 2) ? 8 : 16;
        if (chg & 4) ev |= (pb & 4) ? 32 : 64;
        mouse.mick_x += mx;
        mouse.mick_y += my * 2;
        mouse.x = vx; mouse.y = vy; mouse.buttons = pb;
        mouse.pending |= ev;
    }
    if (mouse.pending && mouse.handler && g_if) {
        int ev = mouse.pending & mouse.mask;
        mouse.pending = 0;
        if (ev) {
            saved_t s;
            save(&s);
            LOG("dos32: mouse event %x (%d,%d) b%d, interrupting sub_%08X\n", ev, mouse.x, mouse.y, mouse.buttons, g_cur_func);
            g_eax = ev; g_ebx = mouse.buttons; g_ecx = mouse.x; g_edx = mouse.y;
            g_esi = mouse.mick_x; g_edi = mouse.mick_y;
            in_irq++;
            call_guest(mouse.handler, 0);
            in_irq--;
            restore(&s);
        }
    }
}

static void dos32_poll(void) {
    if (dos32_quit) { exit_code = 0; longjmp(exit_jmp, 1); }
    if (in_irq) return;
    double t = gtime();
    double period = pit_div / 1193182.0;
    frame_clock(t);
    if (t >= bios_next) {
        int k = 0;
        while (t >= bios_next && k++ < 8) { bios_next += 65536 / 1193182.0; R32(0x46C)++; }
        if (t >= bios_next) bios_next = t;
    }
    if (t >= pit_next) {
        int k = 0;
        while (t >= pit_next && k++ < 4) {
            pit_next += period;
            if (g_if && !(pic_mask[0] & 1)) {
                if (vec_hooked(8)) irq(8);
                else if (vec_hooked(0x1C)) irq(0x1C);
            }
        }
        if (t >= pit_next) pit_next = t + period;   /* fell behind: drop, don't storm */
    }
    poll_input();
}

static void yield_hook(void) { dos32_poll(); }

void dos32_advance(double seconds) {
    guest_time += seconds;
    dos32_poll();
}

void dos32_idle(double seconds) {
    if (dos32_virtual_clock) { dos32_advance(seconds); return; }
    double end = now_s() + seconds;
    for (;;) {
        dos32_poll();
        double left = end - now_s();
        if (left <= 0) break;
        if (left > 0.002) Sleep(1); else SwitchToThread();
    }
}

/* The default for every vector the program did not hook, and what a hooked
 * handler chains to. Both chain styles land here: `jmp far` (nothing to pop:
 * the host restores esp after the handler) and `pushfd; call far` (the flags
 * and our dummy return address: pop both). */
static void hostvec_default(void) {
    int n = hostvec_n;
    if (n == 9) bios_key(port60);
    g_esp += 8;
}

/* ---- files -------------------------------------------------------------- */
#define NFILES 64
static int fh[NFILES];        /* host fd, -1 = closed; 0-4 are the DOS std handles */
static char cwd[260];
static uint32_t dta = 0x180;  /* default DTA: PSP:80h */

static void host_path(const char* dos, char* out, size_t n) {
    char tmp[512];
    const char* p = dos;
    if (p[0] && p[1] == ':') p += 2;
    if (*p == '\\' || *p == '/') snprintf(tmp, sizeof tmp, "%s", p);
    else snprintf(tmp, sizeof tmp, "%s\\%s", cwd, p);
    snprintf(out, n, "%s%s", C->root, tmp);
    for (char* q = out; *q; q++) if (*q == '/') *q = '\\';
}

static void guest_str(uint32_t va, char* out, size_t n) {
    size_t i = 0;
    for (; i + 1 < n && R8(va + i); i++) out[i] = (char)R8(va + i);
    out[i] = 0;
}

static int alloc_handle(int fd) {
    for (int i = 5; i < NFILES; i++) if (fh[i] < 0) { fh[i] = fd; return i; }
    _close(fd);
    return -1;
}

/* ---- registers for int handlers ---------------------------------------- */
typedef struct {
    uint32_t eax, ebx, ecx, edx, esi, edi, ebp, flags;
    uint16_t ds, es;
    int rm;     /* a real-mode call from DPMI 0300h: pointers are seg:off */
} regs_t;

#define AL(r) ((uint8_t)(r)->eax)
#define AH(r) ((uint8_t)((r)->eax >> 8))
#define AX(r) ((uint16_t)(r)->eax)
#define BL(r) ((uint8_t)(r)->ebx)
#define BH(r) ((uint8_t)((r)->ebx >> 8))
#define BX(r) ((uint16_t)(r)->ebx)
#define CX(r) ((uint16_t)(r)->ecx)
#define DX(r) ((uint16_t)(r)->edx)
#define DL(r) ((uint8_t)(r)->edx)
#define DH(r) ((uint8_t)((r)->edx >> 8))
#define CL(r) ((uint8_t)(r)->ecx)
#define CH(r) ((uint8_t)((r)->ecx >> 8))
#define SET16(f, v) ((f) = ((f) & 0xFFFF0000u) | (uint16_t)(v))
#define SET8L(f, v) ((f) = ((f) & 0xFFFFFF00u) | (uint8_t)(v))
#define SET8H(f, v) ((f) = ((f) & 0xFFFF00FFu) | ((uint32_t)(uint8_t)(v) << 8))
#define CF 1u
#define ZF 0x40u
#define OK(r)      ((r)->flags &= ~CF)
#define FAIL(r, e) ((r)->flags |= CF, SET16((r)->eax, (e)))

/* ds/es:off as a linear address. Protected mode: ds is flat (the lifter does
 * not track it); es has a real base. Real mode: segment * 16. */
static uint32_t ds_ptr(regs_t* r, uint32_t off) { return r->rm ? r->ds * 16u + (off & 0xFFFF) : off; }
static uint32_t es_ptr(regs_t* r, uint32_t off) { return r->rm ? r->es * 16u + (off & 0xFFFF) : sel_base(r->es) + off; }
static uint32_t dsdx(regs_t* r) { return ds_ptr(r, r->rm ? DX(r) : r->edx); }

/* The DOS clock: the host's time at start, plus guest time since. A program
 * that times itself by the DOS clock then keeps pace with everything else
 * (the speed control, the virtual clock of a headless run). */
static FILETIME start_ft;
static void guest_clock(SYSTEMTIME* t) {
    ULARGE_INTEGER u;
    if (!start_ft.dwLowDateTime && !start_ft.dwHighDateTime) {
        SYSTEMTIME now; GetLocalTime(&now); SystemTimeToFileTime(&now, &start_ft);
    }
    u.LowPart = start_ft.dwLowDateTime; u.HighPart = start_ft.dwHighDateTime;
    u.QuadPart += (ULONGLONG)(gtime() * 1e7);
    FILETIME ft = { u.LowPart, u.HighPart };
    FileTimeToSystemTime(&ft, t);
}

/* ---- int 21h ------------------------------------------------------------ */
static void int21(regs_t* r) {
    char name[260], path[600];
    switch (AH(r)) {
    case 0x02: putchar(DL(r)); break;
    case 0x06: if (DL(r) != 0xFF) putchar(DL(r)); else { r->flags |= ZF; SET8L(r->eax, 0); } break;
    case 0x07: case 0x08: {
        while (kb_r == kb_w) { dos32_poll(); Sleep(1); }
        SET8L(r->eax, kbbuf[kb_r] & 0xFF); kb_r = (kb_r + 1) & 63;
        break; }
    case 0x09: { uint32_t p = dsdx(r); while (R8(p) != '$') putchar(R8(p++)); break; }
    case 0x0B: SET8L(r->eax, kb_r != kb_w ? 0xFF : 0); break;
    case 0x0E: SET8L(r->eax, 26); break;
    case 0x19: SET8L(r->eax, 2); break;                     /* C: */
    case 0x1A: dta = dsdx(r); break;
    case 0x2F: if (r->rm) { r->es = 0; SET16(r->ebx, dta); } else { r->es = SEL_DATA; r->ebx = dta; } break;
    case 0x25: pmvec[AL(r)].sel = r->ds; pmvec[AL(r)].off = r->edx;
               LOG("dos32: int 21h set vector %02X -> %08X\n", AL(r), r->edx); break;
    case 0x35: r->es = pmvec[AL(r)].sel; r->ebx = pmvec[AL(r)].off; break;
    case 0x2A: { SYSTEMTIME t; guest_clock(&t);
        SET16(r->ecx, t.wYear); SET8H(r->edx, t.wMonth); SET8L(r->edx, t.wDay); SET8L(r->eax, t.wDayOfWeek); break; }
    case 0x2C: { SYSTEMTIME t; guest_clock(&t);
        SET8H(r->ecx, t.wHour); SET8L(r->ecx, t.wMinute); SET8H(r->edx, t.wSecond);
        SET8L(r->edx, t.wMilliseconds / 10); break; }
    case 0x30: SET16(r->eax, 0x0006); r->ebx &= 0xFFFF0000u; r->ecx &= 0xFFFF0000u; break;  /* DOS 6.0 */
    case 0x33: SET8L(r->edx, 0); break;
    case 0x36: SET16(r->eax, 64); SET16(r->ebx, 0x7FFF); SET16(r->ecx, 512); SET16(r->edx, 0xFFFF); break;
    case 0x3B: guest_str(dsdx(r), name, sizeof name);
        if (name[0] && name[1] == ':') memmove(name, name + 2, strlen(name + 2) + 1);
        if (name[0] == '\\' || name[0] == '/') snprintf(cwd, sizeof cwd, "%s", name);
        else { size_t l = strlen(cwd); snprintf(cwd + l, sizeof cwd - l, "\\%s", name); }
        for (char* q = cwd; *q; q++) if (*q == '/') *q = '\\';
        { size_t l = strlen(cwd); if (l > 1 && cwd[l - 1] == '\\') cwd[l - 1] = 0; }
        OK(r); break;
    case 0x3C: case 0x3D: case 0x5B: {
        guest_str(dsdx(r), name, sizeof name);
        host_path(name, path, sizeof path);
        int fl = AH(r) == 0x3D ? ((AL(r) & 3) == 0 ? _O_RDONLY : (AL(r) & 3) == 1 ? _O_WRONLY : _O_RDWR)
                              : (_O_RDWR | _O_CREAT | (AH(r) == 0x5B ? _O_EXCL : _O_TRUNC));
        int fd = -1;
        if (C->overlay && fl == _O_RDONLY) {   /* a mod's copy of the file wins, for reading */
            char opath[600];
            snprintf(opath, sizeof opath, "%s%s", C->overlay, path + strlen(C->root));
            fd = _open(opath, fl | _O_BINARY);
            if (fd >= 0) LOG("dos32: open %s (overlay) -> %d\n", opath, fd);
        }
        if (fd < 0) fd = _open(path, fl | _O_BINARY, _S_IREAD | _S_IWRITE);
        LOG("dos32: open %s -> %d\n", path, fd);
        if (fd < 0) { FAIL(r, errno == ENOENT ? 2 : 5); break; }
        int h = alloc_handle(fd);
        if (h < 0) { FAIL(r, 4); break; }
        SET16(r->eax, h); OK(r); break; }
    case 0x3E: { int h = BX(r);
        if (h < NFILES && fh[h] >= 0 && h > 4) { _close(fh[h]); fh[h] = -1; }
        OK(r); break; }
    case 0x3F: { int h = BX(r);
        uint32_t n = r->rm ? CX(r) : r->ecx, p = dsdx(r);
        if (h == 0) { SET16(r->eax, 0); OK(r); break; }
        if (h >= NFILES || fh[h] < 0) { FAIL(r, 6); break; }
        int got = _read(fh[h], LIN(p), n);
        if (got < 0) { FAIL(r, 5); break; }
        r->eax = r->rm ? (r->eax & 0xFFFF0000u) | (uint16_t)got : (uint32_t)got; OK(r); break; }
    case 0x40: { int h = BX(r);
        uint32_t n = r->rm ? CX(r) : r->ecx, p = dsdx(r);
        if (h == 1 || h == 2) { fwrite(LIN(p), 1, n, h == 1 ? stdout : stderr); r->eax = n; OK(r); break; }
        if (h >= NFILES || fh[h] < 0) { FAIL(r, 6); break; }
        int put = n ? _write(fh[h], LIN(p), n) : (_chsize(fh[h], _lseek(fh[h], 0, SEEK_CUR)), 0);
        if (put < 0) { FAIL(r, 5); break; }
        r->eax = r->rm ? (r->eax & 0xFFFF0000u) | (uint16_t)put : (uint32_t)put; OK(r); break; }
    case 0x41: guest_str(dsdx(r), name, sizeof name); host_path(name, path, sizeof path);
        if (_unlink(path)) FAIL(r, 2); else OK(r); break;
    case 0x42: { int h = BX(r);
        if (h >= NFILES || fh[h] < 0) { FAIL(r, 6); break; }
        long off = (long)((uint32_t)CX(r) << 16 | DX(r));
        long pos = _lseek(fh[h], off, AL(r));
        if (pos < 0) { FAIL(r, 25); break; }
        SET16(r->eax, pos & 0xFFFF); SET16(r->edx, (uint32_t)pos >> 16); OK(r); break; }
    case 0x43: guest_str(dsdx(r), name, sizeof name); host_path(name, path, sizeof path);
        if (AL(r) == 0) { DWORD a = GetFileAttributesA(path);
            if (a == INVALID_FILE_ATTRIBUTES) { FAIL(r, 2); break; }
            SET16(r->ecx, (a & FILE_ATTRIBUTE_DIRECTORY) ? 0x10 : 0x20); }
        OK(r); break;
    case 0x44:
        if (AL(r) == 0x00) { int h = BX(r);
            SET16(r->edx, h <= 4 ? 0x80D3 : 0x0002); OK(r); }
        else if (AL(r) == 0x08) { SET16(r->eax, 1); OK(r); }
        else { once("int 21h 44h", AL(r), 0); OK(r); }
        break;
    case 0x47: { uint32_t p = ds_ptr(r, r->rm ? (uint16_t)r->esi : r->esi);
        const char* c = cwd[0] == '\\' ? cwd + 1 : cwd;
        size_t i = 0; for (; c[i] && i < 63; i++) R8(p + i) = (uint8_t)c[i];
        R8(p + i) = 0; OK(r); break; }
    case 0x48: {   /* DOS/4GW: a block above 1 MB, BX paragraphs, AX = selector */
        uint32_t size = (uint32_t)BX(r) << 4;
        uint32_t a = arena_alloc(&heap, size, 16);
        if (!a) { FAIL(r, 8); SET16(r->ebx, 0); break; }
        SET16(r->eax, sel_alloc(a, size - 1)); OK(r); break; }
    case 0x49: arena_free(&heap, sel_base(r->es)); OK(r); break;
    case 0x4A: OK(r); break;
    case 0x4C: exit_code = AL(r); longjmp(exit_jmp, 1);
    case 0x4E: case 0x4F: {
        static intptr_t fhandle = -1;
        static uint16_t fattr;
        struct _finddata_t fd;
        int rc;
        if (AH(r) == 0x4E) {
            guest_str(dsdx(r), name, sizeof name); host_path(name, path, sizeof path);
            if (fhandle != -1) _findclose(fhandle);
            fattr = CX(r);
            fhandle = _findfirst(path, &fd);
            rc = fhandle == -1 ? -1 : 0;
        } else rc = fhandle == -1 ? -1 : _findnext(fhandle, &fd);
        while (rc == 0 && (((fd.attrib & _A_SUBDIR) && !(fattr & 0x10)) || !strcmp(fd.name, ".")))
            rc = _findnext(fhandle, &fd);
        if (rc) { FAIL(r, 18); break; }
        R8(dta + 0x15) = (fd.attrib & _A_SUBDIR) ? 0x10 : 0x20;
        { struct tm* tm = localtime(&fd.time_write);
          R16(dta + 0x16) = tm ? (uint16_t)(tm->tm_hour << 11 | tm->tm_min << 5 | tm->tm_sec / 2) : 0;
          R16(dta + 0x18) = tm ? (uint16_t)((tm->tm_year - 80) << 9 | (tm->tm_mon + 1) << 5 | tm->tm_mday) : 0; }
        R32(dta + 0x1A) = (uint32_t)fd.size;
        { size_t i = 0; for (; fd.name[i] && i < 12; i++) R8(dta + 0x1E + i) = (uint8_t)toupper((uint8_t)fd.name[i]);
          R8(dta + 0x1E + i) = 0; }
        OK(r); break; }
    case 0x56: { char n2[260], p2[600];
        guest_str(dsdx(r), name, sizeof name); host_path(name, path, sizeof path);
        guest_str(es_ptr(r, r->rm ? (uint16_t)r->edi : r->edi), n2, sizeof n2); host_path(n2, p2, sizeof p2);
        if (rename(path, p2)) FAIL(r, 5); else OK(r); break; }
    case 0x57: { int h = BX(r);
        if (h >= NFILES || fh[h] < 0) { FAIL(r, 6); break; }
        if (AL(r) == 0) { SET16(r->ecx, 0); SET16(r->edx, (14 << 9) | (1 << 5) | 1); }
        OK(r); break; }
    case 0x62: SET16(r->ebx, r->rm ? 0x10 : SEL_PSP); break;
    case 0xFF: if (AL(r) == 0 && DX(r) == 0x78) { SET8L(r->eax, 1); g_seg_gs = 0; g_gs_base = 0; } break;
    default: once("int 21h", AH(r), AL(r)); FAIL(r, 1); break;
    }
}

/* ---- int 10h ------------------------------------------------------------ */
static void int10(regs_t* r) {
    switch (AH(r)) {
    case 0x00: set_mode(AL(r) & 0x7F, !(AL(r) & 0x80)); break;
    case 0x01: case 0x02: case 0x05: case 0x06: case 0x07: case 0x0B: break;
    case 0x03: SET16(r->edx, 0); SET16(r->ecx, 0x0607); break;
    case 0x08: SET16(r->eax, 0x0720); break;
    case 0x09: case 0x0A: case 0x0E: if (vmode < 4) putchar(AL(r)); break;
    case 0x0F: SET8L(r->eax, vmode < 0x100 ? vmode : 0x13); SET8H(r->eax, 80); SET8H(r->ebx, 0); break;
    case 0x10:
        if (AL(r) == 0x10) { int i = BX(r) & 255; dac[i][0] = DH(r); dac[i][1] = CH(r); dac[i][2] = CL(r); }
        else if (AL(r) == 0x12 || AL(r) == 0x17) {
            uint32_t p = es_ptr(r, r->rm ? DX(r) : r->edx);
            for (int i = 0; i < CX(r); i++)
                for (int c = 0; c < 3; c++) {
                    int k = (BX(r) + i) & 255;
                    if (AL(r) == 0x12) dac[k][c] = R8(p + i * 3 + c) & 63; else R8(p + i * 3 + c) = dac[k][c];
                }
        } else if (AL(r) == 0x15) { int i = BL(r); SET8H(r->edx, dac[i][0]); SET8H(r->ecx, dac[i][1]); SET8L(r->ecx, dac[i][2]); }
        break;
    case 0x11: break;
    case 0x12: if (BL(r) == 0x10) { SET16(r->ebx, 0x0003); SET16(r->ecx, 0x0009); } break;
    case 0x1A: if (AL(r) == 0) { SET8L(r->eax, 0x1A); SET16(r->ebx, 0x0008); } break;
    case 0x4F: {
        uint32_t p = es_ptr(r, r->rm ? (uint16_t)r->edi : r->edi);
        switch (AL(r)) {
        case 0x00: {
            int v2 = R32(p) == 0x32454256;  /* 'VBE2' */
            memset(LIN(p), 0, v2 ? 512 : 256);
            memcpy(LIN(p), "VESA", 4);
            R16(p + 4) = v2 ? 0x0200 : 0x0102;
            /* OEM string and mode list inside the caller's buffer, as far pointers */
            uint32_t seg = r->rm ? r->es : (p >> 4), base = r->rm ? r->es * 16u : (p & ~15u);
            uint32_t oem = p + 0xE0, list = p + 0xC0;
            memcpy(LIN(oem), "dos32", 6);
            R32(p + 6) = (seg << 16) | (oem - base);
            R32(p + 10) = 1;
            R32(p + 14) = (seg << 16) | (list - base);
            R16(p + 18) = VRAM_SIZE >> 16;
            for (int i = 0; i < 4; i++) R16(list + i * 2) = vesa_modes[i].mode;
            R16(list + 8) = 0xFFFF;
            SET16(r->eax, 0x004F); break; }
        case 0x01: {
            int m = -1;
            for (int i = 0; i < 4; i++) if (vesa_modes[i].mode == (CX(r) & 0x1FF)) m = i;
            if (m < 0) { SET16(r->eax, 0x014F); break; }
            memset(LIN(p), 0, 256);
            R16(p + 0) = 0x009B;          /* supported, color, graphics, LFB available */
            R8(p + 2) = 7; R8(p + 3) = 0;
            R16(p + 4) = 64; R16(p + 6) = 64;
            R16(p + 8) = 0xA000; R16(p + 10) = 0;
            R16(p + 16) = vesa_modes[m].w;
            R16(p + 18) = vesa_modes[m].w; R16(p + 20) = vesa_modes[m].h;
            R8(p + 22) = 8; R8(p + 23) = 16; R8(p + 24) = 1; R8(p + 25) = 8;
            R8(p + 26) = 1; R8(p + 27) = 4; R8(p + 29) = 1;
            R32(p + 40) = LFB_VA;
            SET16(r->eax, 0x004F); break; }
        case 0x02: set_mode(BX(r) < 0x100 ? BX(r) & 0x7F : BX(r) & 0x41FF, !(BX(r) & 0x8000)); SET16(r->eax, 0x004F); break;
        case 0x03: SET16(r->ebx, vmode | (vesa_lfb ? 0x4000 : 0)); SET16(r->eax, 0x004F); break;
        case 0x05: if (BH(r) == 0) set_bank(DX(r)); else SET16(r->edx, vbank);
            SET16(r->eax, 0x004F); break;
        case 0x06: if (BL(r) == 1 || BL(r) == 0) {} SET16(r->ebx, vpitch); SET16(r->ecx, vw);
            SET16(r->edx, VRAM_SIZE / vpitch); SET16(r->eax, 0x004F); break;
        case 0x07: SET16(r->eax, 0x004F); SET16(r->ecx, 0); SET16(r->edx, 0); break;
        default: once("int 10h 4Fh", AL(r), 0); SET16(r->eax, 0x014F); break;
        }
        break; }
    default: once("int 10h", AH(r), AL(r)); break;
    }
}

/* ---- int 16h ------------------------------------------------------------ */
static void int16(regs_t* r) {
    switch (AH(r)) {
    case 0x00: case 0x10:
        while (kb_r == kb_w) { dos32_poll(); Sleep(1); }
        SET16(r->eax, kbbuf[kb_r]); kb_r = (kb_r + 1) & 63;
        LOG("dos32: int 16h key %04X\n", AX(r)); break;
    case 0x01: case 0x11:
        dos32_poll();
        if (kb_r == kb_w) r->flags |= ZF; else { r->flags &= ~ZF; SET16(r->eax, kbbuf[kb_r]); }
        break;
    case 0x02: case 0x12: SET8L(r->eax, shift_flags); break;
    case 0x03: break;
    default: once("int 16h", AH(r), 0); break;
    }
}

/* ---- int 33h ------------------------------------------------------------ */
static void mouse_ranges(void) {
    mouse.minx = 0; mouse.miny = 0;
    mouse.maxx = vmode == 0x13 || vmode < 0x13 ? 639 : vw - 1;
    mouse.maxy = vmode == 0x13 ? 199 : vmode < 0x13 ? 199 : vh - 1;
}

static void int33(regs_t* r) {
    static uint32_t seen[64];
    if (C->log && AX(r) < 64 && !seen[AX(r)]++) LOG("dos32: int 33h ax=%04X first use (0x%08X)\n", AX(r), g_cur_func);
    switch (AX(r)) {
    case 0x00: case 0x21:
        mouse_ranges(); mouse.x = (mouse.maxx + 1) / 2; mouse.y = (mouse.maxy + 1) / 2;
        mouse.shown = 0; mouse.handler = 0;
        SET16(r->eax, 0xFFFF); SET16(r->ebx, 3); break;
    case 0x01: mouse.shown++; break;
    case 0x02: mouse.shown--; break;
    case 0x03: dos32_poll(); SET16(r->ebx, mouse.buttons); SET16(r->ecx, mouse.x); SET16(r->edx, mouse.y); break;
    case 0x04: mouse.x = CX(r); mouse.y = DX(r); break;
    case 0x05: case 0x06: SET16(r->eax, mouse.buttons); SET16(r->ebx, 0);
        SET16(r->ecx, mouse.x); SET16(r->edx, mouse.y); break;
    case 0x07: mouse.minx = (int16_t)CX(r); mouse.maxx = (int16_t)DX(r);
        if (mouse.minx > mouse.maxx) { int t = mouse.minx; mouse.minx = mouse.maxx; mouse.maxx = t; } break;
    case 0x08: mouse.miny = (int16_t)CX(r); mouse.maxy = (int16_t)DX(r);
        if (mouse.miny > mouse.maxy) { int t = mouse.miny; mouse.miny = mouse.maxy; mouse.maxy = t; } break;
    case 0x0B: dos32_poll(); SET16(r->ecx, mouse.mick_x); SET16(r->edx, mouse.mick_y);
        mouse.mick_x = mouse.mick_y = 0; break;
    case 0x0C: case 0x14:
        mouse.handler = r->edx; mouse.mask = CX(r);
        LOG("dos32: mouse handler %08X mask %x\n", r->edx, CX(r)); break;
    case 0x0A: case 0x0F: case 0x10: case 0x13: case 0x1A: case 0x1D: break;
    case 0x1B: SET16(r->ebx, 50); SET16(r->ecx, 50); SET16(r->edx, 50); break;
    case 0x24: SET16(r->ebx, 0x0626); SET16(r->ecx, 0x0400); break;
    default: once("int 33h", AX(r), 0); break;
    }
}

/* ---- int 31h (DPMI) ----------------------------------------------------- */
static void run_int(int n, regs_t* r);

static void int31(regs_t* r) {
    uint32_t edi = r->edi;
    switch (AX(r)) {
    case 0x0000: {
        uint32_t first = 0;
        for (int i = 0; i < CX(r); i++) { uint32_t s = sel_alloc(0, 0); if (!i) first = s; }
        if (!first) { FAIL(r, 0x8011); break; }
        SET16(r->eax, first); OK(r); break; }
    case 0x0001: sel[(BX(r) >> 3) & (NSEL - 1)].used = 0; OK(r); break;
    case 0x0002: SET16(r->eax, sel_alloc((uint32_t)BX(r) << 4, 0xFFFF)); OK(r); break;
    case 0x0003: SET16(r->eax, 8); OK(r); break;
    case 0x0006: { uint32_t b = sel_base(BX(r)); SET16(r->ecx, b >> 16); SET16(r->edx, b); OK(r); break; }
    case 0x0007: sel_set(BX(r), (uint32_t)CX(r) << 16 | DX(r), sel[(BX(r) >> 3) & (NSEL - 1)].limit);
        if ((BX(r) | 7) == (g_seg_es | 7)) g_es_base = sel_base(BX(r));
        if ((BX(r) | 7) == (g_seg_fs | 7)) g_fs_base = sel_base(BX(r));
        if ((BX(r) | 7) == (g_seg_gs | 7)) g_gs_base = sel_base(BX(r));
        OK(r); break;
    case 0x0008: sel[(BX(r) >> 3) & (NSEL - 1)].limit = (uint32_t)CX(r) << 16 | DX(r); OK(r); break;
    case 0x0009: OK(r); break;
    case 0x000A: { uint32_t s = sel_alloc(sel_base(BX(r)), sel[(BX(r) >> 3) & (NSEL - 1)].limit);
        SET16(r->eax, s); OK(r); break; }
    case 0x000B: { uint32_t p = es_ptr(r, edi), s = BX(r), b = sel_base(s), l = sel[(s >> 3) & (NSEL - 1)].limit;
        int g = l > 0xFFFFF; if (g) l >>= 12;
        R16(p) = (uint16_t)l; R16(p + 2) = (uint16_t)b; R8(p + 4) = (uint8_t)(b >> 16);
        R8(p + 5) = 0xF2; R8(p + 6) = (uint8_t)((l >> 16) & 15) | 0x40 | (g ? 0x80 : 0); R8(p + 7) = (uint8_t)(b >> 24);
        OK(r); break; }
    case 0x000C: { uint32_t p = es_ptr(r, edi);
        uint32_t b = R16(p + 2) | (uint32_t)R8(p + 4) << 16 | (uint32_t)R8(p + 7) << 24;
        uint32_t l = R16(p) | (uint32_t)(R8(p + 6) & 15) << 16;
        if (R8(p + 6) & 0x80) l = l << 12 | 0xFFF;
        sel_set(BX(r), b, l); OK(r); break; }
    case 0x0100: {
        uint32_t a = arena_alloc(&conv, (uint32_t)BX(r) << 4, 16);
        if (!a) { FAIL(r, 8); SET16(r->ebx, (uint16_t)(arena_free_bytes(&conv) >> 4)); break; }
        SET16(r->eax, a >> 4); SET16(r->edx, sel_alloc(a, ((uint32_t)BX(r) << 4) - 1)); OK(r); break; }
    case 0x0101: arena_free(&conv, sel_base(DX(r))); sel[(DX(r) >> 3) & (NSEL - 1)].used = 0; OK(r); break;
    case 0x0102: if (arena_resize(&conv, sel_base(DX(r)), (uint32_t)BX(r) << 4, 16) == sel_base(DX(r))) OK(r);
        else FAIL(r, 8); break;
    case 0x0200: SET16(r->ecx, rmvec[BL(r)] >> 16); SET16(r->edx, rmvec[BL(r)]); OK(r); break;
    case 0x0201: rmvec[BL(r)] = (uint32_t)CX(r) << 16 | DX(r); OK(r); break;
    case 0x0202: SET16(r->ecx, SEL_CODE); r->edx = HOSTVEC_VA; OK(r); break;
    case 0x0203: OK(r); break;
    case 0x0204: SET16(r->ecx, pmvec[BL(r)].sel); r->edx = pmvec[BL(r)].off; OK(r); break;
    case 0x0205: pmvec[BL(r)].sel = CX(r); pmvec[BL(r)].off = r->edx;
        LOG("dos32: DPMI set vector %02X -> %08X\n", BL(r), r->edx); OK(r); break;
    case 0x0300: case 0x0301: case 0x0302: {
        uint32_t p = es_ptr(r, edi);
        regs_t rr = { 0 };
        rr.edi = R32(p); rr.esi = R32(p + 4); rr.ebp = R32(p + 8); rr.ebx = R32(p + 16);
        rr.edx = R32(p + 20); rr.ecx = R32(p + 24); rr.eax = R32(p + 28); rr.flags = R16(p + 32);
        rr.es = R16(p + 34); rr.ds = R16(p + 36); rr.rm = 1;
        if (AX(r) == 0x0300) run_int(BL(r), &rr);
        else once("DPMI real-mode far call", AX(r), R32(p + 44));
        R32(p) = rr.edi; R32(p + 4) = rr.esi; R32(p + 8) = rr.ebp; R32(p + 16) = rr.ebx;
        R32(p + 20) = rr.edx; R32(p + 24) = rr.ecx; R32(p + 28) = rr.eax; R16(p + 32) = (uint16_t)rr.flags;
        R16(p + 34) = rr.es; R16(p + 36) = rr.ds;
        OK(r); break; }
    case 0x0303: SET16(r->ecx, 0xF000); SET16(r->edx, 0x0100); OK(r); break;
    case 0x0304: OK(r); break;
    case 0x0400: SET16(r->eax, 0x005A); SET16(r->ebx, 0x0005); SET8L(r->ecx, 5); SET16(r->edx, 0x0870); OK(r); break;
    case 0x0500: { uint32_t p = es_ptr(r, edi), fb = arena_free_bytes(&heap);
        for (int i = 0; i < 12; i++) R32(p + i * 4) = 0xFFFFFFFFu;
        R32(p) = fb; R32(p + 4) = fb >> 12; R32(p + 8) = fb >> 12; R32(p + 0xC) = (HEAP_HI - HEAP_LO) >> 12;
        R32(p + 0x10) = fb >> 12; R32(p + 0x14) = fb >> 12; R32(p + 0x18) = (HEAP_HI - HEAP_LO) >> 12;
        R32(p + 0x1C) = fb >> 12; R32(p + 0x20) = 0;
        OK(r); break; }
    case 0x0501: {
        uint32_t size = (uint32_t)BX(r) << 16 | CX(r), a = arena_alloc(&heap, size, 4096);
        LOG("dos32: DPMI alloc %#x -> %08X\n", size, a);
        if (!a) { FAIL(r, 0x8013); break; }
        SET16(r->ebx, a >> 16); SET16(r->ecx, a); SET16(r->esi, a >> 16); SET16(r->edi, a);
        OK(r); break; }
    case 0x0502: arena_free(&heap, (uint32_t)(uint16_t)r->esi << 16 | (uint16_t)r->edi); OK(r); break;
    case 0x0503: {
        uint32_t a = arena_resize(&heap, (uint32_t)(uint16_t)r->esi << 16 | (uint16_t)r->edi,
                                  (uint32_t)BX(r) << 16 | CX(r), 4096);
        if (!a) { FAIL(r, 0x8013); break; }
        SET16(r->ebx, a >> 16); SET16(r->ecx, a); SET16(r->esi, a >> 16); SET16(r->edi, a); OK(r); break; }
    case 0x0600: case 0x0601: case 0x0602: case 0x0603: case 0x0702: case 0x0703: OK(r); break;
    case 0x0604: SET16(r->ebx, 0); SET16(r->ecx, 4096); OK(r); break;
    case 0x0800: {
        uint32_t phys = (uint32_t)BX(r) << 16 | CX(r);
        uint32_t lin = phys == LFB_VA ? LFB_VA : phys < 0x100000 ? phys : 0;
        if (!lin) { once("DPMI map physical", phys, 0); FAIL(r, 0x8021); break; }
        SET16(r->ebx, lin >> 16); SET16(r->ecx, lin); OK(r); break; }
    case 0x0801: OK(r); break;
    case 0x0900: SET8L(r->eax, g_if); g_if = 0; OK(r); break;
    case 0x0901: SET8L(r->eax, g_if); g_if = 1; OK(r); break;
    case 0x0902: SET8L(r->eax, g_if); OK(r); break;
    case 0x0E00: case 0x0E01: SET16(r->eax, 0); OK(r); break;
    default: once("int 31h", AX(r), 0); FAIL(r, 0x8001); break;
    }
}

static void int2f(regs_t* r) {
    switch (AX(r)) {
    case 0x1680: Sleep(0); SET8L(r->eax, 0); break;
    case 0x1600: SET8L(r->eax, 0); break;
    case 0x1687: SET16(r->eax, 0); SET16(r->ebx, 1); SET8L(r->ecx, 4); SET16(r->edx, 0x005A); break;
    default: once("int 2Fh", AX(r), 0); break;
    }
}

static void run_int(int n, regs_t* r) {
    if (C->log && n != 0x33 && n != 0x16 && !(n == 0x21 && (AH(r) == 0x2C || AH(r) == 0x2A))) LOG("dos32: int %02Xh ax=%04X bx=%04X cx=%04X dx=%04X (0x%08X)\n",
                                             n, AX(r), BX(r), CX(r), DX(r), g_cur_func);
    switch (n) {
    case 0x21: int21(r); break;
    case 0x10: int10(r); break;
    case 0x16: int16(r); break;
    case 0x31: int31(r); break;
    case 0x33: int33(r); break;
    case 0x2F: int2f(r); break;
    case 0x1A: if (AH(r) == 0) { uint32_t t = R32(0x46C); SET16(r->ecx, t >> 16); SET16(r->edx, t); SET8L(r->eax, 0); } break;
    case 0x11: SET16(r->eax, 0x4026); break;
    case 0x12: SET16(r->eax, 640); break;
    case 0x15: r->flags |= CF; SET8H(r->eax, 0x86); break;
    case 0x4B: r->flags |= CF; break;
    case 0x20: exit_code = 0; longjmp(exit_jmp, 1);
    default: once("int", n, AX(r)); break;
    }
}

void recomp_int(int n) {
    /* An int the program hooked itself (some games call their own handlers
     * with int) runs the guest handler. */
    if (vec_hooked(n) && n != 0x21 && n != 0x31 && n != 0x10 && n != 0x33 && n != 0x16) {
        saved_t s; save(&s);
        call_guest(pmvec[n].off, 1);
        uint32_t keep_eax = g_eax, keep_ebx = g_ebx, keep_ecx = g_ecx, keep_edx = g_edx;
        restore(&s);
        g_eax = keep_eax; g_ebx = keep_ebx; g_ecx = keep_ecx; g_edx = keep_edx;
        return;
    }
    regs_t r;
    r.eax = g_eax; r.ebx = g_ebx; r.ecx = g_ecx; r.edx = g_edx;
    r.esi = g_esi; r.edi = g_edi; r.ebp = g_ebp;
    r.flags = recomp_eflags(g_flag_k, g_flag_a, g_flag_b, g_flag_cf, 1);
    r.ds = g_seg_ds; r.es = g_seg_es; r.rm = 0;
    run_int(n, &r);
    g_eax = r.eax; g_ebx = r.ebx; g_ecx = r.ecx; g_edx = r.edx;
    g_esi = r.esi; g_edi = r.edi; g_ebp = r.ebp;
    if (r.es != g_seg_es) recomp_set_seg(0, r.es);
    g_flag_k = FK_EFLAGS; g_flag_a = r.flags; g_flag_b = 0; g_flag_cf = r.flags & 1;
    dos32_poll();
}

/* ---- ports -------------------------------------------------------------- */
static uint32_t port_reads[0x400];
static uint8_t in8(uint32_t port) {
    port_reads[port & 0x3FF]++;
    switch (port) {
    case 0x20: case 0xA0: return 0;
    case 0x21: return pic_mask[0];
    case 0xA1: return pic_mask[1];
    case 0x40: {
        uint32_t c = (uint32_t)(pit_div - (uint32_t)(gtime() * 1193182.0) % pit_div);
        if (pit_latch) { pit_latch = 0; return (uint8_t)c; }
        pit_latch = 1; return (uint8_t)(c >> 8); }
    case 0x60: return port60;
    case 0x61: return 0x20;
    case 0x64: return scq_r != scq_w ? 0x1D : 0x1C;
    case 0x201: return 0xF0;
    case 0x3C7: return 3;
    case 0x3C8: return (uint8_t)dac_w;
    case 0x3C9: { uint8_t v = dac[dac_r][dac_rc]; if (++dac_rc == 3) { dac_rc = 0; dac_r = (dac_r + 1) & 255; } return v; }
    case 0x3C5: return seq[seq_idx & 7];
    case 0x3CF: return gc[gc_idx & 15];
    case 0x3D5: return crtc[crtc_idx & 31];
    case 0x3DA: case 0x3BA: {
        int v = retrace();
        if (++spin > 200) { spin = 0; dos32_poll(); SwitchToThread(); }
        return v ? 0x09 : 0x00; }
    }
    if ((port >= 0x220 && port <= 0x22F) || (port >= 0x330 && port <= 0x331) || (port >= 0x388 && port <= 0x38B))
        return 0xFF;    /* no sound card on the bus */
    once("in", port, 0);
    return 0xFF;
}

static void out8(uint32_t port, uint8_t v) {
    switch (port) {
    case 0x20: case 0xA0: return;
    case 0x21: pic_mask[0] = v; return;
    case 0xA1: pic_mask[1] = v; return;
    case 0x43: pit_mode_byte = v; pit_lohi = 0;
        if ((v & 0x30) == 0) pit_latch = 0;
        return;
    case 0x40:
        if (!pit_lohi) { pit_div = (pit_div & 0xFF00) | v; pit_lohi = 1; }
        else {
            pit_div = (pit_div & 0xFF) | (uint32_t)v << 8; pit_lohi = 0;
            if (!pit_div) pit_div = 65536;
            pit_next = gtime() + pit_div / 1193182.0;
            LOG("dos32: PIT %.1f Hz\n", 1193182.0 / pit_div);
        }
        return;
    case 0x61: case 0x64: case 0x80: return;
    case 0x3C6: return;
    case 0x3C7: dac_r = v; dac_rc = 0; return;
    case 0x3C8: dac_w = v; dac_c = 0; return;
    case 0x3C9: dac[dac_w][dac_c] = v & 63; if (++dac_c == 3) { dac_c = 0; dac_w = (dac_w + 1) & 255; } return;
    case 0x3C4: seq_idx = v; return;
    case 0x3C5: seq[seq_idx & 7] = v;
        if ((seq_idx & 7) == 4 && !(v & 8) && vmode == 0x13) once("unchained VGA (mode X)", v, 0);
        return;
    case 0x3CE: gc_idx = v; return;
    case 0x3CF: gc[gc_idx & 15] = v; return;
    case 0x3D4: crtc_idx = v; return;
    case 0x3D5: crtc[crtc_idx & 31] = v; return;
    case 0x3C0: case 0x3C2: case 0x3B4: case 0x3B5: return;
    }
    if ((port >= 0x220 && port <= 0x22F) || (port >= 0x330 && port <= 0x331) || (port >= 0x388 && port <= 0x38B))
        return;
    once("out", port, v);
}

uint8_t  recomp_in8(uint32_t port) { return in8(port); }
uint16_t recomp_in16(uint32_t port) { return (uint16_t)(in8(port) | in8(port + 1) << 8); }
uint32_t recomp_in32(uint32_t port) { return recomp_in16(port) | (uint32_t)recomp_in16(port + 2) << 16; }
void recomp_out8(uint32_t port, uint8_t v) { out8(port, v); }
/* A 16-bit out to a VGA index port writes the index and then its data. */
void recomp_out16(uint32_t port, uint16_t v) { out8(port, (uint8_t)v); out8(port + 1, (uint8_t)(v >> 8)); }
void recomp_out32(uint32_t port, uint32_t v) { recomp_out16(port, (uint16_t)v); recomp_out16(port + 2, (uint16_t)(v >> 16)); }

void recomp_ins(uint32_t port, uint32_t va, int size, uint32_t count, int dir) {
    for (uint32_t i = 0; i < count; i++, va += dir * size)
        for (int b = 0; b < size; b++) R8(va + b) = in8(port);
}
void recomp_outs(uint32_t port, uint32_t va, int size, uint32_t count, int dir) {
    for (uint32_t i = 0; i < count; i++, va += dir * size)
        for (int b = 0; b < size; b++) out8(port + (size == 2 ? b : 0), R8(va + b));
}

void recomp_cli(void) { g_if = 0; }
void recomp_sti(void) { g_if = 1; dos32_poll(); }
void recomp_hlt(void) { Sleep(1); dos32_poll(); }

/* ---- crashes ------------------------------------------------------------ */
/* A fault in lifted code is a guest fault: name the guest address, the lifted
 * function and the indirect calls that led there, then stop. */
/* DOS32_BREAK=addr[,len]: a hardware write watchpoint on guest memory. Each
 * write logs the lifted function that made it and the new value. The guest
 * thread cannot set its own debug registers, so a helper thread suspends it
 * and sets them. */
static uint32_t brk_va;
static HANDLE brk_thread;
static DWORD WINAPI set_watchpoint(LPVOID p) {
    (void)p;
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    SuspendThread(brk_thread);
    GetThreadContext(brk_thread, &ctx);
    ctx.Dr0 = (DWORD_PTR)LIN(brk_va);
    ctx.Dr7 = 1 | (1u << 16) | (1u << 18);   /* L0, break on write, 2 bytes */
    SetThreadContext(brk_thread, &ctx);
    ResumeThread(brk_thread);
    return 0;
}

static LONG CALLBACK on_fault(EXCEPTION_POINTERS* ep) {
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    if (code == EXCEPTION_SINGLE_STEP && brk_va) {
        fprintf(stderr, "dos32: write %08X = %04X in sub_%08X (esp %08X, ret %08X)\n", brk_va, R16(brk_va),
                g_cur_func, g_esp, R32(g_esp));
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (code != EXCEPTION_ACCESS_VIOLATION && code != EXCEPTION_INT_DIVIDE_BY_ZERO &&
        code != EXCEPTION_ILLEGAL_INSTRUCTION && code != EXCEPTION_STACK_OVERFLOW &&
        code != EXCEPTION_INT_OVERFLOW)
        return EXCEPTION_CONTINUE_SEARCH;
    uintptr_t a = code == EXCEPTION_ACCESS_VIOLATION ? (uintptr_t)ep->ExceptionRecord->ExceptionInformation[1] : 0;
    fprintf(stderr, "\ndos32: guest fault %08lX in sub_%08X", code, g_cur_func);
    if (code == EXCEPTION_ACCESS_VIOLATION) {
        if (a - (uintptr_t)M < 0x100000000ull) fprintf(stderr, " at guest %08X", (uint32_t)(a - (uintptr_t)M));
        else fprintf(stderr, " at host %p", (void*)a);
        fprintf(stderr, " (%s)", ep->ExceptionRecord->ExceptionInformation[0] ? "write" : "read");
    }
    fprintf(stderr, "\n  eax=%08X ebx=%08X ecx=%08X edx=%08X esi=%08X edi=%08X ebp=%08X esp=%08X\n",
            g_eax, g_ebx, g_ecx, g_edx, g_esi, g_edi, g_ebp, g_esp);
    fprintf(stderr, "  last indirect calls (newest first):\n");
    for (int i = 1; i <= 12 && i <= (int)g_icall_trace_idx; i++) {
        uint32_t k = (g_icall_trace_idx - i) & (ICALL_TRACE_SIZE - 1);
        fprintf(stderr, "    %08X from %08X\n", g_icall_trace[k], g_icall_from[k]);
    }
    fprintf(stderr, "  guest stack:");
    for (int i = 0; i < 16; i++) {
        uint32_t v = g_esp + i * 4;
        if (v - 0x1000u < 0x0F000000u) fprintf(stderr, "%s%08X", i % 8 ? " " : "\n    ", R32(v));
    }
    fprintf(stderr, "\n");
    fflush(stderr);
    TerminateProcess(GetCurrentProcess(), 3);
    return EXCEPTION_CONTINUE_SEARCH;
}

/* ---- start -------------------------------------------------------------- */
static void put_str(uint32_t at, const char* s) { while (*s) R8(at++) = (uint8_t)*s++; R8(at) = 0; }

int dos32_run(const dos32_config* cfg) {
    C = cfg;
    InitializeCriticalSection(&input_lock);
    InitializeCriticalSection(&video_lock);
    QueryPerformanceFrequency(&qpf);
    QueryPerformanceCounter(&t0);
    timeBeginPeriod(1);
    AddVectoredExceptionHandler(1, on_fault);

    /* 4 GB of address space, so every 32-bit guest address is ours; only what
     * is used is committed. */
    M = VirtualAlloc(NULL, 0x100000000ull, MEM_RESERVE, PAGE_NOACCESS);
    if (!M || !VirtualAlloc(M, COMMIT_SIZE, MEM_COMMIT, PAGE_READWRITE) ||
        !VirtualAlloc(M + LFB_VA, VRAM_SIZE, MEM_COMMIT, PAGE_READWRITE) ||
        !VirtualAlloc(M + HOSTVEC_VA, 0x10000, MEM_COMMIT, PAGE_READWRITE)) {
        fprintf(stderr, "dos32: cannot reserve guest memory (%lu)\n", GetLastError());
        return 255;
    }
    g_mem_base = (ptrdiff_t)M;
    vram = calloc(1, VRAM_SIZE);
    memcpy(LIN(cfg->image_base), cfg->image, cfg->image_size);

    /* Selectors: flat code and data, the PSP and the environment. */
    sel_set(SEL_CODE, 0, 0xFFFFFFFFu);
    sel_set(SEL_DATA, 0, 0xFFFFFFFFu);
    sel_set(SEL_PSP, 0x100, 0xFF);
    sel_set(SEL_ENV, 0, 0x7F);
    for (int i = 0; i < 256; i++) { pmvec[i].sel = SEL_CODE; pmvec[i].off = HOSTVEC_VA + i * 16; }

    /* Low memory (see the top of this file). */
    uint32_t e = 0;
    put_str(e, "PATH=C:\\"); e += 9;
    put_str(e, "DOS4G=QUIET"); e += 12;
    R8(e++) = 0;
    R16(e) = 1; e += 2;
    put_str(e, cfg->progname); e += (uint32_t)strlen(cfg->progname) + 1;
    if (e > 0x80) { fprintf(stderr, "dos32: environment longer than 128 bytes\n"); return 255; }
    R16(0x100) = 0x20CD;
    R16(0x100 + 0x2C) = SEL_ENV;
    {
        size_t n = strlen(cfg->args);
        if (n > 126) n = 126;
        for (uint32_t base = 0x80; base <= 0x180; base += 0x100) {
            R8(base) = (uint8_t)(n + 1);
            R8(base + 1) = ' ';
            memcpy(LIN(base + 2), cfg->args, n);
            R8(base + 2 + n) = 13;
            R8(base) = (uint8_t)(n + 1);
        }
    }
    R16(0x463) = 0x3D4;     /* BIOS: CRTC base */
    R8(0x449) = 3;          /* BIOS: video mode */

    for (int i = 0; i < NFILES; i++) fh[i] = i <= 4 ? i : -1;
    snprintf(cwd, sizeof cwd, "%s", cfg->cwd);
    mouse_ranges();
    pit_next = bios_next = 65536 / 1193182.0;
    last_real = now_s();
    recomp_yield_hook = yield_hook;

    g_esp = cfg->stack;
    g_seg_cs = SEL_CODE; g_seg_ds = g_seg_ss = SEL_DATA;
    recomp_set_seg(0, SEL_PSP);
    recomp_set_seg(4, 0);
    recomp_set_seg(5, 0);
    g_flag_k = FK_EFLAGS; g_flag_a = 0x202;
    push32(RECOMP_RETADDR);

    if (getenv("DOS32_BREAK")) {
        brk_va = strtoul(getenv("DOS32_BREAK"), NULL, 16);
        DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &brk_thread, 0, FALSE,
                        DUPLICATE_SAME_ACCESS);
        WaitForSingleObject(CreateThread(NULL, 0, set_watchpoint, NULL, 0, NULL), INFINITE);
    }
    recomp_func_t entry = recomp_lookup(cfg->entry);
    if (!entry) { fprintf(stderr, "dos32: entry 0x%08X not lifted\n", cfg->entry); return 255; }
    if (!setjmp(exit_jmp)) {
        entry();
        fprintf(stderr, "dos32: program returned from its entry point\n");
    }
    if (C->log)
        for (int i = 0; i < 0x400; i++)
            if (port_reads[i]) fprintf(stderr, "dos32: port %03X read %u times%c", i, port_reads[i], 10);
    fflush(stdout);
    return exit_code;
}
