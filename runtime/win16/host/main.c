/*
 * main.c - Win16 host entry: load the image, start every module, run the game.
 *
 * Loads the flat memory image (segments + applied internal relocations) that
 * tools/ne/ne_link.py built, maps selector n to SEG_SEGMENT_BASE[n], then does
 * what the Windows 3.1 loader did: run each DLL's LibMain in load order, and
 * finally the host EXE's startup code, which reaches WinMain and the message
 * loop. RECOMP_MODULES[] (mem_layout.h) says where each one's entry and DGROUP
 * are; nothing here names a particular game.
 *
 * Also home to the diagnostics every lifted body can reach (the call ring,
 * crash/stack-overflow reports, the watch hooks) and the indirect-call miss
 * policy. Grown in catz, where each of these found a real bug.
 */
#include "cpu.h"
#include "segments.h"
#include "mem_layout.h"
#include "recomp_game.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>

static void fnc_report(void);
extern int g_fncount;

/* Watchdog: if the engine hangs in lifted code, dump the recent call ring so we
 * can see the spinning loop, then exit. Enable with -DRECOMP_WATCHDOG;
 * RECOMP_WATCHDOG_SECS overrides the default 5 s. */
static DWORD WINAPI watchdog_thread(LPVOID p) {
    (void)p;
    const char *w = getenv("RECOMP_WATCHDOG_SECS");
    Sleep(w ? (DWORD)atoi(w) * 1000u : 5000u);
    fprintf(stderr, "\n[watchdog] time up - recent call ring (hang loop?):\n");
    dump_fn_ring(60);
    /* _exit skips atexit, so the RECOMP_FN_COUNT report has to be asked for
       here or a hang never gets one -- and a hang is when it is wanted. */
    if (g_fncount) fnc_report();
    fflush(stderr);
    _exit(99);
    return 0;
}

#ifndef RECOMP_IMAGE_PATH
#define RECOMP_IMAGE_PATH "build_data/mem_image.bin"
#endif

/* Function-entry ring buffer (declared in cpu.h, filled by TRACE_FN). */
const char *g_fn_ring[RECOMP_FN_RING_SIZE];
unsigned g_fn_ring_pos = 0;

/* Global CPU pointer so the Win32 backend / WndProc bridge can invoke guest
 * code (the registered window procedure) on delivered messages. */
CPU *g_cpu = NULL;

/* Where the current run of ds==0 began — for the null-selector hunt. */
const char *g_ds_zero_from = "?";
unsigned g_ds_run = 0;

#ifdef RECOMP_WATCH_SP
/* See cpu.h: the guest stack is one 64 KB segment and it drains. Report the
 * call chain each time sp crosses a new low-water mark — if the chain repeats
 * at every threshold the stack is leaking (a callee not balancing its frame);
 * if it keeps growing it is honest recursion. */
void recomp_sp_check(const char *nm)
{
    static const uint16_t floors[] = { 0xC000, 0x8000, 0x4000, 0x2000, 0x1000, 0x0800, 0x0400 };
    static unsigned next_floor = 0;
    uint16_t sp = g_cpu ? g_cpu->sp : 0xFFFE;

    /* A null DS is legitimate for a moment after `lds` loads a NULL far pointer
     * (seg001_5A45 is that branch and reloads DS immediately), so entry-time
     * ds==0 on its own means nothing. What is NOT legitimate is DS *staying*
     * null across many calls — that is a lost DGROUP, and any far pointer built
     * as `push ds` from then on carries a null selector. Discriminate on run
     * length and report where the run began. */
    if (g_cpu) {
        if (g_cpu->ds == 0) {
            if (g_ds_run++ == 0) g_ds_zero_from = nm;   /* first call of this run */
        } else {
            g_ds_run = 0;
        }
    }
    /* A single-step plunge is a stack switch or a bogus `sub sp`, not ordinary
       frame growth; report the pair of calls it happened between. */
    {   static uint16_t prev_sp = 0xFFFE; static const char *prev_nm = "?";
        static int shown = 0;
        if (shown < 8 && prev_sp > sp && (uint16_t)(prev_sp - sp) > 0x400) {
            shown++;
            fprintf(stderr, "[SP-DROP] %04X -> %04X (-%u) between %s and %s\n",
                    prev_sp, sp, (unsigned)(prev_sp - sp), prev_nm, nm);
            fprintf(stderr, "  last 40 labels:");
            for (int i = 40; i > 0; i--) {
                const char *r = g_fn_ring[(g_fn_ring_pos - (unsigned)i) & (RECOMP_FN_RING_SIZE - 1)];
                if (r) fprintf(stderr, " %s", r);
            }
            fprintf(stderr, "\n");
        }
        prev_sp = sp; prev_nm = nm;
    }
    if (next_floor >= sizeof floors / sizeof floors[0]) return;
    if (sp > floors[next_floor]) return;
    fprintf(stderr, "\n[SP-LOW] guest sp=%04X (below %04X) at %s\n", sp, floors[next_floor], nm);
    next_floor++;
    dump_guest_stack(g_cpu, 48);
}
#endif

/*
 * Guest call stack. Win16 far functions open with `inc bp; push bp; mov bp,sp`
 * and close with `pop bp; dec bp; retf`, so the saved bp at [bp] carries a
 * mark bit: odd means THIS frame belongs to a far function and its return
 * address at [bp+2] is 4 bytes (offset then segment); even means near, 2 bytes,
 * returning into the same segment as the frame we came from.
 *
 * Far more useful than the flat call ring, which only shows what ran recently,
 * not who is waiting on what.
 */
void dump_guest_stack(CPU *cpu, int max)
{
    /* The guest stack can't be walked: the lifter pushes a literal 0 as the
     * far-return offset (control actually returns through the host C stack), so
     * every return address on it is fake. The HOST stack is the guest call
     * stack — one C frame per lifted function still executing. Print raw
     * addresses as file VAs; `addr2line -f -e <exe>` names them.
     * ponytail: no dbghelp/PDB plumbing to symbolize in-process, the two-step
     * is fine for a debug dump. Note -O2 tail-merges the innermost chain, so
     * the deepest few lifted labels appear as their sibling-call parent. */
    (void)cpu;
    void *frames[128];
    USHORT n = CaptureStackBackTrace(0, (ULONG)(max > 128 ? 128 : max), frames, NULL);
    fprintf(stderr, "--- guest call stack (%u host frames, innermost first) ---\n"
                    "    symbolize: addr2line -f -e <this exe> \\\n     ", n);
    for (USHORT i = 0; i < n; i++)
        fprintf(stderr, " %p", frames[i]);
    fprintf(stderr, "\n");
    fflush(stderr);
}

/* Runaway recursion in lifted code kills the host with STATUS_STACK_OVERFLOW and
 * no clue where. Dump the tail of the call ring in order — a recursion shows up
 * as a repeating cycle. SetThreadStackGuarantee (in main) leaves us enough stack
 * to actually run this handler. */
static LONG CALLBACK stack_overflow_veh(EXCEPTION_POINTERS *ep)
{
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    if (code != EXCEPTION_STACK_OVERFLOW) {
        /* Any other fatal exception kills the host with no output at all --
           the process just returns a shell-level status and the run looks like
           it "stopped" wherever stderr happened to end. Name it, and print the
           same guest evidence, before letting the OS take it. Non-fatal codes
           (breakpoints, C++ EH, debugger notifications) pass straight through. */
        if (code != EXCEPTION_ACCESS_VIOLATION &&
            code != EXCEPTION_ILLEGAL_INSTRUCTION &&
            code != EXCEPTION_INT_DIVIDE_BY_ZERO &&
            code != EXCEPTION_PRIV_INSTRUCTION &&
            code != EXCEPTION_IN_PAGE_ERROR &&
            code != EXCEPTION_ARRAY_BOUNDS_EXCEEDED)
            return EXCEPTION_CONTINUE_SEARCH;
        fprintf(stderr, "\n[CRASH] exception %08lX at %p; last 40 guest calls:\n",
                (unsigned long)code, ep->ExceptionRecord->ExceptionAddress);
        for (int i = 40; i > 0; i--) {
            const char *nm = g_fn_ring[(g_fn_ring_pos - (unsigned)i) & (RECOMP_FN_RING_SIZE - 1)];
            if (nm) fprintf(stderr, " %s", nm);
        }
        fprintf(stderr, "\n");
        if (g_cpu) dump_guest_stack(g_cpu, 40);
        fflush(stderr);
        _exit(96);
    }
    fprintf(stderr, "\n[STACK-OVERFLOW] host stack exhausted; last 64 calls "
                    "(oldest first), total=%u:\n", g_fn_ring_pos);
    for (int i = 64; i > 0; i--) {
        const char *nm = g_fn_ring[(g_fn_ring_pos - (unsigned)i) & (RECOMP_FN_RING_SIZE - 1)];
        if (nm) fprintf(stderr, "  %s\n", nm);
    }
    if (g_cpu) dump_guest_stack(g_cpu, 40);
    fflush(stderr);
    _exit(98);
    return EXCEPTION_CONTINUE_SEARCH;
}

/* sp on return from a call must be the pre-call sp plus the callee's purge.
   Below it means leaked guest stack; far above it means the callee unwound
   a frame it did not own. Either way the 64 KB guest stack is being eaten. */
void recomp_div0(const char *kind)
{
    static int fired = 0;
    if (fired++ >= 6) return;
    fprintf(stderr, "[DIV0] guest %s by zero; registers left unchanged\n", kind);
    if (fired == 1) { dump_fn_ring(24); if (g_cpu) dump_guest_stack(g_cpu, 24); }
    fflush(stderr);
}

void recomp_sp_broke(const char *callee, uint16_t sp0, uint16_t sp1)
{
    static int fired = 0;
    if (fired++ >= 8) return;
    fprintf(stderr, "[SP-BROKE] %s returned sp %04X->%04X\n", callee, sp0, sp1);
    fprintf(stderr, "  last 24 labels:");
    for (int i = 24; i > 0; i--) {
        const char *r = g_fn_ring[(g_fn_ring_pos - (unsigned)i) & (RECOMP_FN_RING_SIZE - 1)];
        if (r) fprintf(stderr, " %s", r);
    }
    fprintf(stderr, "\n");
    fflush(stderr);
}

void recomp_bp_broke(const char *callee, uint16_t bp0, uint16_t bp1, uint16_t sp0, uint16_t sp1)
{
    static int fired = 0;
    if (fired++ >= 8) return;
    fprintf(stderr, "[BP-BROKE] %s returned bp %04X->%04X  sp %04X->%04X\n",
            callee, bp0, bp1, sp0, sp1);
    /* The ring shows which labels actually ran inside the callee, i.e. which
     * edge it left through — for an early return that is far more informative
     * than the call stack, which only says who was waiting. */
    fprintf(stderr, "  last 24 labels:");
    for (int i = 24; i > 0; i--) {
        const char *r = g_fn_ring[(g_fn_ring_pos - (unsigned)i) & (RECOMP_FN_RING_SIZE - 1)];
        if (r) fprintf(stderr, " %s", r + 3);
    }
    fprintf(stderr, "\n");
    fflush(stderr);
}

void dump_fn_ring(int n)
{
    if (n <= 0 || n > (int)RECOMP_FN_RING_SIZE) n = (int)RECOMP_FN_RING_SIZE;
    /* Histogram: tally occurrences of each distinct name pointer across the full
     * ring (same lifted fn => same literal pointer). The most frequent names are
     * the spin loop. */
    const char *names[256]; int counts[256]; int nd = 0;
    for (unsigned i = 0; i < RECOMP_FN_RING_SIZE; i++) {
        const char *nm = g_fn_ring[i];
        if (!nm) continue;
        int j = 0; for (; j < nd; j++) if (names[j] == nm) break;
        if (j == nd && nd < 256) { names[nd] = nm; counts[nd] = 0; nd++; }
        if (j < 256) counts[j]++;
    }
    fprintf(stderr, "--- ring histogram (top spin functions) ---\n");
    for (int top = 0; top < 15; top++) {
        int best = -1;
        for (int j = 0; j < nd; j++) if (counts[j] >= 0 && (best < 0 || counts[j] > counts[best])) best = j;
        if (best < 0 || counts[best] <= 0) break;
        fprintf(stderr, "  %5d  %s\n", counts[best], names[best]);
        counts[best] = -1;
    }
    /* The histogram names the spin, but not the order. The tail in call
       order is what shows which branch a per-frame handler actually takes. */
    fprintf(stderr, "--- last %d calls, oldest first ---\n", n);
    for (int i = n; i > 0; i--) {
        const char *nm = g_fn_ring[(g_fn_ring_pos - (unsigned)i) & (RECOMP_FN_RING_SIZE - 1)];
        if (nm) fprintf(stderr, " %s", nm);
    }
    fprintf(stderr, "\n");
    fprintf(stderr, "--- end (total calls=%u) ---\n", g_fn_ring_pos);
}

/* Call a far-exported lifted function. argw holds arg words in PASCAL push
 * order (left-to-right); a far return frame is pushed so the callee's RETF
 * balances. Returns AX (DX:AX for 32-bit/far results — read cpu->dx for hi). */
static uint16_t call_export(CPU *cpu, void (*fn)(CPU *), const uint16_t *argw, int nwords)
{
    for (int i = 0; i < nwords; i++) push16(cpu, argw[i]);
    push16(cpu, cpu->cs);
    push16(cpu, 0);
    fn(cpu);
    return cpu->ax;
}

static int load_image(CPU *cpu, const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "cannot open image: %s\n", path); return 0; }
    size_t n = fread(cpu->mem, 1, RECOMP_IMAGE_SIZE, f);
    fclose(f);
    if (n != RECOMP_IMAGE_SIZE) {
        fprintf(stderr, "short read: %zu of %u\n", n, (unsigned)RECOMP_IMAGE_SIZE);
        return 0;
    }
    return 1;
}

#ifdef RECOMP_WATCH_MEM
static void recomp_watch_init(void);
#endif

int g_fncount;
static struct { const char *n; unsigned long c; } g_fnc[8192];
int g_watch_ds;
/* RECOMP_WATCH_DS: the WAD is an EXE, so its own code runs with DS pinned to
   DGROUP for the whole program. Anything else means a callee clobbered it --
   which is how a Win16 stub that forgets to pop its arguments shows up, since
   the caller then restores DS from the wrong stack slot. Also tracks the low
   water mark of the guest stack. */
void recomp_fn_hit(const char *n) {
    if (g_watch_ds && g_cpu) {
        static unsigned long ncall; static uint16_t lo = 0xFFFF; static int shown;
        if (g_cpu->sp < lo) lo = g_cpu->sp;
        if (++ncall % 200000 == 0)
            fprintf(stderr, "[sp] after %lu calls: sp=%04X ss=%04X min=%04X\n",
                    ncall, g_cpu->sp, g_cpu->ss, lo);
        if (n && recomp_dgroup_of_seg((uint16_t)atoi(n + 3)) == RECOMP_AUTO_DATA_SEG
            && g_cpu->ds != RECOMP_AUTO_DATA_SEG && shown++ < 12)
            fprintf(stderr, "[dsbad] %s ds=%04X\n", n, g_cpu->ds);
        if (!g_fncount) return;
    }
    uintptr_t h = ((uintptr_t)n >> 3) * 2654435761u;
    for (unsigned k = 0; k < 8192; k++) {
        unsigned x = (unsigned)((h + k) & 8191u);
        if (!g_fnc[x].n) { g_fnc[x].n = n; g_fnc[x].c = 1; return; }
        if (g_fnc[x].n == n) { g_fnc[x].c++; return; }
    }
}
static void fnc_report(void) {
    for (int i = 0; i < 8192; i++)
        if (g_fnc[i].n) fprintf(stderr, "[fnc] %s %lu\n", g_fnc[i].n, g_fnc[i].c);
}
/* Stub-hit recorder: which unimplemented Win16 APIs did this session reach? */
static const char *g_stubs[256];
static int g_nstubs;
void recomp_stub_hit(const char *n) {
    if (g_nstubs < 256) g_stubs[g_nstubs++] = n;
}
static void stub_report(void) {
    fprintf(stderr, "[stubs] %d unimplemented APIs reached:\n", g_nstubs);
    for (int i = 0; i < g_nstubs; i++) fprintf(stderr, "[stubs]   %s\n", g_stubs[i]);
}
uint16_t g_wsel;
static struct { const char *n; uint16_t s; unsigned long c; } g_selw[4096];
static int g_nselw;
void recomp_sel_write(uint16_t seg, uint16_t off, uint16_t val) {
    {   static int inited; static long lo = -1, hi = -1;
        if (!inited) { inited = 1;
            const char *a = getenv("RECOMP_WATCH_LO"), *b = getenv("RECOMP_WATCH_HI");
            if (a) lo = strtol(a, NULL, 16);
            if (b) hi = strtol(b, NULL, 16); }
        if (lo >= 0 && off >= lo && off <= hi) {
            static int nn;
            const char *fn = g_fn_ring[(g_fn_ring_pos - 1) & (RECOMP_FN_RING_SIZE - 1)];
            if (nn++ < 4000)
                fprintf(stderr, "[w] %04X:%04X = %04X by %s\n", seg, off, val, fn ? fn : "?");
            /* first hit only: shows who is writing here */
            if (nn == 8)
                for (int q = 1; q <= 44; q++) {
                    const char *r = g_fn_ring[(g_fn_ring_pos - (unsigned)q) & (RECOMP_FN_RING_SIZE - 1)];
                    fprintf(stderr, "[wring] %2d %s\n", q, r ? r : "?");
                }
        } }
    if (g_wsel != 0xFFFFu) {
        static int shown;
        if (!shown) { shown = 1;
            fprintf(stderr, "[selw] first write to %04X, ring tail (newest first):\n", seg);
            for (int k = 1; k <= 60; k++) {
                const char *r = g_fn_ring[(g_fn_ring_pos - (unsigned)k) & (RECOMP_FN_RING_SIZE - 1)];
                fprintf(stderr, "   %2d %s\n", k, r ? r : "?");
            }
        }
    }
    const char *n = g_fn_ring[(g_fn_ring_pos - 1) & (RECOMP_FN_RING_SIZE - 1)];
    if (!n) n = "?";
    if (g_wsel != 0xFFFFu) seg = 0;
    uintptr_t h = ((uintptr_t)n >> 3) * 31u + seg * 2654435761u;
    for (unsigned k = 0; k < 8192; k++) {
        unsigned x = (unsigned)((h + k) & 4095u);
        if (!g_selw[x].n) { g_selw[x].n = n; g_selw[x].s = seg; g_selw[x].c = 1; return; }
        if (g_selw[x].n == n && g_selw[x].s == seg) { g_selw[x].c++; return; }
    }
}
static void selw_report(void) {
    for (int r = 0; r < 300; r++) {
        int b = -1;
        for (int i = 0; i < 4096; i++)
            if (g_selw[i].n && g_selw[i].c && (b < 0 || g_selw[i].c > g_selw[b].c)) b = i;
        if (b < 0) break;
        fprintf(stderr, "[selw] %04X %-20s %lu\n", g_selw[b].s, g_selw[b].n, g_selw[b].c);
        g_selw[b].c = 0;
    }
}

int main(int argc, char *argv[])
{
    { const char *ws = getenv("RECOMP_WATCH_SEL");
      if (ws) { g_wsel = (uint16_t)strtoul(ws, NULL, 16); atexit(selw_report); } }
    if (getenv("RECOMP_FN_COUNT")) { g_fncount = 1; atexit(fnc_report); }
    if (getenv("RECOMP_WATCH_DS")) g_watch_ds = 1;
    if (getenv("RECOMP_STUB_HITS")) atexit(stub_report);
    const char *img = (argc > 1) ? argv[1] : RECOMP_IMAGE_PATH;

    /* Unbuffered: the engine dies by crash/abort often enough that a lost
     * stdout buffer hides exactly the lines that say where it got to. */
    setvbuf(stdout, NULL, _IONBF, 0);

    ULONG guarantee = 64 * 1024;
    SetThreadStackGuarantee(&guarantee);
    AddVectoredExceptionHandler(1, stack_overflow_veh);
#ifdef RECOMP_WATCH_MEM
    recomp_watch_init();
#endif

    CPU cpu;
    cpu_init(&cpu);
    if (recomp_game.selector_step > 1) cpu.sel_step = (uint16_t)recomp_game.selector_step;
    g_cpu = &cpu;

    /* Flat image + a heap for dynamically allocated selectors (past the image).
     * 24 MB is period-appropriate (Catz targeted ~8 MB machines): it bounds the
     * engine's free-memory probe (GlobalAlloc-until-fail) to a realistic count
     * instead of the tens of thousands a huge heap would report. */
    uint32_t total = RECOMP_IMAGE_SIZE + (24u << 20);  /* +24 MB heap */
    if (!cpu_alloc_mem(&cpu, total)) {
        fprintf(stderr, "Failed to allocate %u bytes\n", total);
        return 1;
    }
    if (!load_image(&cpu, img)) { cpu_free(&cpu); return 1; }

    /* selector -> flat base: NE segment index n maps to SEG_SEGMENT_BASE[n];
     * any other selector falls back to the guard region. */
    for (uint32_t s = 0; s < 0x10000; ++s)
        cpu.sel_base[s] = RECOMP_GUARD_BASE;
    for (uint32_t n = 0; n <= RECOMP_NUM_SEG; ++n)
        cpu.sel_base[n] = SEG_SEGMENT_BASE[n];

    if (recomp_game.start) recomp_game.start(&cpu);

    printf("%s recomp - starting\n", recomp_game.title);
    printf("  image: %s (%.2f MB), %d modules\n", img, RECOMP_IMAGE_SIZE / 1048576.0,
           RECOMP_NUM_MODULES);
    fflush(stdout);

    /* 1) Each DLL's LibMain, in load order, the way the Win16 loader ran them.
     *    Entry contract: DS = DGROUP, DI = hInstance, CX = the local heap size
     *    from the NE header, ES:SI = command line. CX left at 0 makes Borland's
     *    startup take its `jcxz` path and skip LocalInit, so the DLL runs with
     *    no local heap at all. A DLL with no entry (cs 0) has no LibMain. */
    for (int i = 0; i < RECOMP_NUM_MODULES; i++) {
        const RecompModule *m = &RECOMP_MODULES[i];
        if (!m->is_dll || !m->cs) continue;
        cpu.ds = cpu.es = m->dgroup;
        cpu.ss = RECOMP_STACK_SEG;
        cpu.sp = RECOMP_STACK_SP ? RECOMP_STACK_SP : 0xFFFE;
        cpu.cs = m->cs;
        cpu.di = m->dgroup;                 /* hInstance == DGROUP selector */
        cpu.cx = m->heap;
        cpu.si = 0;
        if (!recomp_dispatch_lookup(&cpu, m->cs, m->ip)) {
            fprintf(stderr, "%s: LibMain seg%u:%04X was never lifted\n", m->name, m->cs, m->ip);
            return 1;
        }
        printf("%s init returned (ax=%04X)\n", m->name, cpu.ax);
    }

#ifdef RECOMP_WATCHDOG
    CreateThread(NULL, 0, watchdog_thread, NULL, 0, NULL);
#else
    (void)watchdog_thread;
#endif

    /* 2) The host EXE's startup (Borland C0 -> InitTask -> WinMain): window and
     *    message loop, calling into the DLLs through the cross-module calls the
     *    lifter already resolved. It has its own DGROUP and the stack. */
    const RecompModule *host = &RECOMP_MODULES[RECOMP_NUM_MODULES - 1];
    cpu.ds = cpu.es = host->dgroup;
    cpu.ss = RECOMP_STACK_SEG;
    cpu.sp = RECOMP_STACK_SP ? RECOMP_STACK_SP : 0xFFFE;
    cpu.cs = host->cs;
    if (!recomp_dispatch_lookup(&cpu, host->cs, host->ip)) {
        fprintf(stderr, "%s: entry seg%u:%04X was never lifted\n", host->name, host->cs, host->ip);
        return 1;
    }
    printf("%s returned (ax=%04X)\n", host->name, cpu.ax);

    cpu_free(&cpu);
    return 0;
}

/* A branch whose target the decoder never resolved (see ne_lift). Reaching one
 * means we are executing a path the static recompile does not cover — say so
 * with a stack rather than wandering off. */
void recomp_unreachable(const char *seg, unsigned off)
{
    fprintf(stderr, "\n[UNLIFTED] branch into seg%s:%04X has no lifted code\n", seg, off);
    dump_guest_stack(g_cpu, 40);
    _exit(97);
}

#ifdef RECOMP_WATCH_MEM
uint16_t g_watch_seg = 0xFFFF, g_watch_off = 0xFFFF;

int g_watch_armed = 0;               /* gate: only report while a frame is live */

void recomp_watch_hit(uint16_t seg, uint16_t off, uint16_t val)
{
    static int n = 0;
    if (!g_watch_armed) return;
    if (n++ >= 12) return;
    fprintf(stderr, "\n[WATCH] write %04X:%04X = %04X\n", seg, off, val);
    dump_guest_stack(g_cpu, 24);
}

void recomp_watch_frame(uint16_t seg, uint16_t off, int on)
{
    if (on) { g_watch_seg = seg; g_watch_off = off; }
    g_watch_armed = on;
}

static void recomp_watch_init(void)
{
    const char *w = getenv("RECOMP_WATCH");
    unsigned s, o;
    if (w && sscanf(w, "%x:%x", &s, &o) == 2) {
        g_watch_seg = (uint16_t)s; g_watch_off = (uint16_t)o;
        /* Arming from the env var has to actually arm: the frame gate
           (recomp_watch_frame) is for narrowing a stack slot to one frame, not a
           precondition for watching a heap address. */
        g_watch_armed = 1;
        fprintf(stderr, "[WATCH] armed on %04X:%04X\n", g_watch_seg, g_watch_off);
    }
}
#endif

/* DS is callee-saved in Win16 (a function that reloads DGROUP restores the
 * caller's DS with `pop ds`). A callee that returns with DS changed leaves the
 * caller building far pointers from a wrong — often null — selector. */
void recomp_ds_broke(const char *callee, uint16_t ds0, uint16_t ds1)
{
    static int fired = 0;
    if (fired++ >= 6) return;
    fprintf(stderr, "[DS-BROKE] %s returned ds %04X->%04X\n", callee, ds0, ds1);
    if (fired == 1) dump_guest_stack(g_cpu, 30);
    fflush(stderr);
}

/* The DGROUP of whichever module owns code segment `seg`. A window or dialog
 * procedure is entered from the host with no DS of its own, and Win16 gave it
 * its module's DGROUP (MakeProcInstance thunks, or the `mov ax, ds` prologue
 * the loader patched). Picking the wrong module's is how a DLL's wndproc ends
 * up reading the EXE's statics. */
uint16_t recomp_dgroup_of_seg(uint16_t seg)
{
    for (int i = 0; i < RECOMP_NUM_MODULES; i++)
        if (seg >= RECOMP_MODULES[i].first_seg && seg <= RECOMP_MODULES[i].last_seg)
            return RECOMP_MODULES[i].dgroup;
    return RECOMP_AUTO_DATA_SEG;
}

/* The module a handle names: Win16 hInstance == its DGROUP selector. NULL for
 * a handle this image did not load (a resource-only DLL, say). */
const RecompModule *recomp_module_of_hinst(uint16_t hinst)
{
    hinst = recomp_hinst_unalias(hinst);
    for (int i = 0; i < RECOMP_NUM_MODULES; i++)
        if (RECOMP_MODULES[i].dgroup == hinst)
            return &RECOMP_MODULES[i];
    return NULL;
}

/* Indirect call/jump through a far or near pointer. tools/ne/gen_dispatch.py
 * generates the lookup. A MISS is reported and the frame the call pushed is
 * dropped, so the caller resumes; on Catz that was enough to run the whole game
 * while the last misses were chased down. RECOMP_DISPATCH_STRICT=1 aborts
 * instead, which is what you want while bringing a new title up. */
/* A program that builds or loads machine code at run time (compiled sprites,
 * say) calls into memory nothing was lifted from. A project can run such code
 * itself -- an interpreter for the few instructions it uses -- by defining this;
 * 1 = handled, the call's frame already popped. */
__attribute__((weak)) int recomp_dispatch_miss_hook(CPU *cpu, uint16_t seg, uint16_t off, int far_call)
{ (void)cpu; (void)seg; (void)off; (void)far_call; return 0; }

static void dispatch_miss(CPU *cpu, uint16_t seg, uint16_t off, int far_call)
{
    static int told, strict = -1;
    if (recomp_dispatch_miss_hook(cpu, seg, off, far_call)) return;
    if (strict < 0) strict = getenv("RECOMP_DISPATCH_STRICT") != NULL;
    if (told++ < 32 || strict)
        fprintf(stderr, "[dispatch] %s MISS seg=%u off=%04X\n", far_call ? "far" : "near", seg, off);
    if (strict) {
        dump_fn_ring(40);
        dump_guest_stack(cpu, 40);
        _exit(95);
    }
    cpu->sp = (uint16_t)(cpu->sp + (far_call ? 4 : 2));
}

/* Host thunks: native functions behind guest far pointers. Segment 0xFFF0 is
 * past any lifted numbering and never a real selector the runtime hands out. */
#define RECOMP_HOST_SEG 0xFFF0u
static struct { void (*fn)(CPU *, uint16_t); uint16_t arg; } g_thunks[256];
static int g_nthunks;

uint32_t recomp_host_thunk(void (*fn)(CPU *cpu, uint16_t arg), uint16_t arg)
{
    for (int i = 0; i < g_nthunks; i++)          /* the same (fn, arg) is one pointer */
        if (g_thunks[i].fn == fn && g_thunks[i].arg == arg)
            return (RECOMP_HOST_SEG << 16) | (uint32_t)i;
    if (g_nthunks == 256) return 0;
    g_thunks[g_nthunks].fn = fn;
    g_thunks[g_nthunks].arg = arg;
    return (RECOMP_HOST_SEG << 16) | (uint32_t)g_nthunks++;
}

void dispatch_far(CPU *cpu, uint16_t seg, uint16_t off)
{
    if (seg == RECOMP_HOST_SEG && off < g_nthunks) {
        g_thunks[off].fn(cpu, g_thunks[off].arg);
        return;
    }
    if (!recomp_dispatch_lookup(cpu, seg, off)) dispatch_miss(cpu, seg, off, 1);
}

void dispatch_near(CPU *cpu, uint16_t seg, uint16_t off)
{
    if (!recomp_dispatch_lookup(cpu, seg, off)) dispatch_miss(cpu, seg, off, 0);
}
