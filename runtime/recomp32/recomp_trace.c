/*
 * Bring-up diagnostics hung off RECOMP_ENTER. See recomp_trace.h.
 *
 * Every one of these earned its place on a real target, and the notes say
 * which question each was written to answer -- the shape of the answer is what
 * makes a diagnostic worth keeping.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "recomp_types.h"
#include "recomp_trace.h"

void (*recomp_trace_extra)(uint32_t va) = NULL;
const char* g_cur_import = "(none)";

#ifdef RECOMP_TRACE

uint32_t g_enter_trace[RECOMP_ENTER_SIZE] = {0};
uint32_t g_enter_idx = 0;

/*
 * --calltrace FILE: every lifted-function entry, tagged with the thread.
 *
 * The entry ring holds only the last RECOMP_ENTER_SIZE, and when a startup
 * path loops, the interesting call -- the one that failed -- has already
 * rolled out of it. The file has no such limit.
 *
 * BUFFERED, and that matters more than it looks. Unbuffered, on the theory
 * that a crash must not take the tail with it, a nine-million-call run took
 * long enough that the trace was never actually taken; with 4 MB of buffer the
 * same run costs ten seconds. recomp_trace_flush() from the fault handler, and
 * the flush every exit(3) does, keep the tail anyway.
 */
static FILE* g_calltrace;

/*
 * --firsthit LO HI: the first entry to each distinct function in [LO,HI),
 * printed in order with the thread that got there.
 *
 * A full calltrace answers "what ran" and then asks you to read a hundred
 * megabytes. The bring-up question is almost always narrower: did execution
 * ever reach THIS subsystem, and in what order. One bit per 4-byte-aligned
 * address over the chosen window costs a range check and a bit test per call,
 * so it can be left on for a whole run.
 */
static uint32_t g_fh_lo, g_fh_hi;
static uint8_t* g_fh_seen;

/*
 * --argtrace VA: one line per entry to VA with its first three stack
 * arguments.
 *
 * A --watch line is seven lines of registers and object dump, which is the
 * wrong shape when the question is "what sequence of ids went through this one
 * dispatcher". Pointed at a script-function lookup it is a script trace.
 */
#define TRACE_AT_MAX 4
static uint32_t g_at[TRACE_AT_MAX];
static unsigned g_at_n;

/*
 * --watch VA: the machine state and the object under ecx, every entry.
 *
 * Reading the generated C tells you which member a function dereferences; only
 * a run tells you what is in it. --watchspan LO HI moves or narrows the window
 * so a member at +0x234 can be read without a recompile.
 */
/*
 * --argobj VA N: at every entry to VA, dump the object ARGUMENT N points at.
 *
 * --watch dumps the object under ecx, which is the right thing for a method and
 * the wrong thing about half the time: the object a function is really deciding
 * about arrives as an argument. Reading it needed a recompile until this
 * existed. N is zero-based and counts the stack arguments only, so for a
 * thiscall the `this` is ecx and N=0 is the first declared parameter.
 */
/*
 * --chase VA OFFSETS: follow a pointer chain from ecx, every entry to VA.
 *
 * The field that matters is rarely in the object a method is called on. It is
 * two or three hops away -- `this->device->batch->buffer` -- and each hop's
 * address is different every run, so --watch and --poison cannot get there:
 * --watch dumps one object, and --poison needs an address you do not have
 * until the run is already past the point you wanted to look at.
 *
 * OFFSETS is a comma-separated list, and each hop prints its value and the
 * word at that value, which is the vtable for anything with one -- so
 * rtti.json names every object on the way down.
 *
 *   --chase 0x0071E850 0xC,0x98
 *   [chase] 0x0071E850 ecx=11EABFD0 [007D39A4]  +0C=11EAC020 [007CF138]
 *                                               +98=00000000
 */
#define TRACE_CHASE_MAX 4
#define TRACE_CHASE_HOPS 6
static struct { uint32_t va; unsigned n; uint32_t off[TRACE_CHASE_HOPS]; }
    g_chase[TRACE_CHASE_MAX];
static unsigned g_chase_n;

#define TRACE_ARGOBJ_MAX 4
static struct { uint32_t va; unsigned n; } g_argobj[TRACE_ARGOBJ_MAX];
static unsigned g_argobj_n;

#define TRACE_WATCH_MAX 8
static uint32_t g_watch[TRACE_WATCH_MAX];
static unsigned g_watch_n;
static int g_wlo = 0, g_whi = 0xA0;

/*
 * --poison ADDR [--poisonval V]: report every change of one target dword.
 *
 * Written to catch a 64-bit host pointer being stored into target memory by a
 * shim that left a struct uninitialised: the value turns into 0x00007FFx and
 * the program dies much later somewhere else. Pairing the report with the
 * import the machine was last inside names the shim that did it.
 */
static uint32_t g_poison, g_poison_last, g_poison_val;
static int g_poison_hit;

/*
 * --poke ADDR VAL VA: write one byte the first time VA is entered.
 *
 * Programs turn their own diagnostics off. A retail build can still carry live
 * assertion and logging machinery gated on a byte that startup clears from an
 * absent setting; poking the byte back once execution is past the code that
 * cleared it turns the original diagnostics back on. "Force this flag, but not
 * until here" is the general shape.
 *
 * ponytail: one byte, one site, no restore. Widen it when something needs a
 * dword or a second poke.
 */
static uint32_t g_poke_addr, g_poke_at;
static uint8_t g_poke_val;
static int g_poke_done;

void recomp_trace_enter(uint32_t va) {
    if (g_poke_at && !g_poke_done && va == g_poke_at) {
        g_poke_done = 1;
        MEM8(g_poke_addr) = g_poke_val;
        fprintf(stderr, "[poke] MEM8(0x%08X) = %u on entry to 0x%08X\n",
                g_poke_addr, g_poke_val, va);
    }
    /* The ring first, and unconditionally: recomp_dump_trace is what prints a
     * call path after a fault, and a backtrace that has quietly stopped
     * recording is worse than none. */
    g_enter_trace[g_enter_idx++ & (RECOMP_ENTER_SIZE - 1)] = va;

    if (g_fh_seen && va >= g_fh_lo && va < g_fh_hi) {
        uint32_t i = (va - g_fh_lo) >> 2;
        if (!(g_fh_seen[i >> 3] & (1u << (i & 7)))) {
            g_fh_seen[i >> 3] |= (uint8_t)(1u << (i & 7));
            fprintf(stderr, "[first] t%lu 0x%08X\n", GetCurrentThreadId(), va);
        }
    }
    for (unsigned t = 0; t < g_at_n; t++)
        if (g_at[t] == va) {
            /* and the 16 bytes the first argument points at, when it does
             * (a CLSID, a string): the pointer alone answers little */
            uint32_t p = MEM32(g_esp + 4);
            fprintf(stderr, "[args] t%lu %08X %08X %08X %08X", GetCurrentThreadId(), va,
                    p, MEM32(g_esp + 8), MEM32(g_esp + 12));
            if (p >= 0x10000 && !IsBadReadPtr((void*)(uintptr_t)p, 16))
                fprintf(stderr, "  *%08X %08X %08X %08X", MEM32(p), MEM32(p + 4), MEM32(p + 8), MEM32(p + 12));
            fputc('\n', stderr);
        }
    /* Thread-tagged, because the trace interleaves the target's own worker
     * threads with the main one and a flat sequence cannot be read. */
    if (g_calltrace)
        fprintf(g_calltrace, "%lu %08X\n", GetCurrentThreadId(), va);

    if (g_poison) {
        uint32_t v = MEM32(g_poison);
        if (v != g_poison_last && g_poison_hit < 400
            && (!g_poison_val || v == g_poison_val)) {
            g_poison_hit++;
            fprintf(stderr, "[poison] 0x%08X: 0x%08X -> 0x%08X on entry to"
                            " 0x%08X (last import %s)\n",
                    g_poison, g_poison_last, v, va, g_cur_import);
            g_poison_last = v;
        }
    }
    for (unsigned w = 0; w < g_watch_n; w++) {
        if (g_watch[w] != va) continue;
        fprintf(stderr, "[watch] 0x%08X ecx=%08X ebx=%08X eax=%08X esi=%08X"
                        " edi=%08X esp=%08X args:", va, g_ecx, g_ebx, g_eax,
                g_esi, g_edi, g_esp);
        for (int k = 4; k <= 0x20; k += 4)
            fprintf(stderr, " %08X", MEM32(g_esp + k));
        fprintf(stderr, "\n");
        if (g_ecx >= 0x00200000u)
            for (int row = g_wlo; row < g_whi; row += 0x20) {
                fprintf(stderr, "[watch]   [ecx+%02X]:", row);
                for (int k = 0; k < 0x20; k += 4)
                    fprintf(stderr, " %08X", MEM32(g_ecx + row + k));
                fprintf(stderr, "\n");
            }
    }
    for (unsigned w = 0; w < g_argobj_n; w++) {
        if (g_argobj[w].va != va) continue;
        uint32_t o = MEM32(g_esp + 4 + 4 * g_argobj[w].n);
        fprintf(stderr, "[argobj] 0x%08X arg%u=%08X", va, g_argobj[w].n, o);
        if (o < 0x00200000u) { fprintf(stderr, " (not a pointer)\n"); continue; }
        fprintf(stderr, " vtable=%08X\n", MEM32(o));
        for (int row = 0; row < 0x40; row += 0x20) {
            fprintf(stderr, "[argobj]   [+%02X]:", row);
            for (int k = 0; k < 0x20; k += 4)
                fprintf(stderr, " %08X", MEM32(o + row + k));
            fprintf(stderr, "\n");
        }
    }
    for (unsigned w = 0; w < g_chase_n; w++) {
        if (g_chase[w].va != va) continue;
        uint32_t p = g_ecx;
        fprintf(stderr, "[chase] 0x%08X ecx=%08X", va, p);
        if (p >= 0x00200000u) fprintf(stderr, " [%08X]", MEM32(p));
        for (unsigned k = 0; k < g_chase[w].n; k++) {
            if (p < 0x00200000u) { fprintf(stderr, "  +%02X=?", g_chase[w].off[k]); break; }
            p = MEM32(p + g_chase[w].off[k]);
            fprintf(stderr, "  +%02X=%08X", g_chase[w].off[k], p);
            if (p >= 0x00200000u) fprintf(stderr, " [%08X]", MEM32(p));
        }
        fprintf(stderr, "\n");
    }
    if (recomp_trace_extra) recomp_trace_extra(va);
}

void recomp_dump_trace(const char* why) {
    fprintf(stderr, "=== entry trace (%s) ===\n", why ? why : "");
    int depth = (g_enter_idx < RECOMP_ENTER_SIZE) ? (int)g_enter_idx
                                                  : RECOMP_ENTER_SIZE;
    for (int i = depth; i > 0; i--) {
        uint32_t idx = (g_enter_idx - i) & (RECOMP_ENTER_SIZE - 1);
        if (g_enter_trace[idx])
            fprintf(stderr, "  0x%08X\n", g_enter_trace[idx]);
    }
}

void recomp_trace_flush(void) { if (g_calltrace) fflush(g_calltrace); }

#define TRACE_U32(x) ((uint32_t)strtoul((x), NULL, 0))

int recomp_trace_arg(int argc, char** argv, int i) {
    const char* a = argv[i];
    if (!strcmp(a, "--calltrace") && i + 1 < argc) {
        g_calltrace = fopen(argv[i + 1], "w");
        /* 64 KB: a run ended by TerminateProcess (hiddenrun) loses at most that */
        if (g_calltrace) setvbuf(g_calltrace, NULL, _IOFBF, 64u << 10);
        else fprintf(stderr, "[trace] cannot write %s\n", argv[i + 1]);
        return 2;
    }
    if (!strcmp(a, "--firsthit") && i + 2 < argc) {
        g_fh_lo = TRACE_U32(argv[i + 1]);
        g_fh_hi = TRACE_U32(argv[i + 2]);
        if (g_fh_hi > g_fh_lo)
            g_fh_seen = (uint8_t*)calloc(((g_fh_hi - g_fh_lo) >> 5) + 1, 1);
        return 3;
    }
    if (!strcmp(a, "--argtrace") && i + 1 < argc && g_at_n < TRACE_AT_MAX) {
        g_at[g_at_n++] = TRACE_U32(argv[i + 1]);
        return 2;
    }
    if (!strcmp(a, "--watch") && i + 1 < argc && g_watch_n < TRACE_WATCH_MAX) {
        g_watch[g_watch_n++] = TRACE_U32(argv[i + 1]);
        return 2;
    }
    if (!strcmp(a, "--chase") && i + 2 < argc && g_chase_n < TRACE_CHASE_MAX) {
        g_chase[g_chase_n].va = TRACE_U32(argv[i + 1]);
        const char* q = argv[i + 2];
        unsigned n = 0;
        while (*q && n < TRACE_CHASE_HOPS) {
            g_chase[g_chase_n].off[n++] = (uint32_t)strtoul(q, NULL, 0);
            const char* comma = strchr(q, ',');
            if (!comma) break;
            q = comma + 1;
        }
        g_chase[g_chase_n].n = n;
        g_chase_n++;
        return 3;
    }
    if (!strcmp(a, "--argobj") && i + 2 < argc
            && g_argobj_n < TRACE_ARGOBJ_MAX) {
        g_argobj[g_argobj_n].va = TRACE_U32(argv[i + 1]);
        g_argobj[g_argobj_n].n = (unsigned)TRACE_U32(argv[i + 2]);
        g_argobj_n++;
        return 3;
    }
    if (!strcmp(a, "--watchspan") && i + 2 < argc) {
        g_wlo = (int)(TRACE_U32(argv[i + 1]) & ~0x1Fu);
        g_whi = (int)TRACE_U32(argv[i + 2]);
        return 3;
    }
    if (!strcmp(a, "--poison") && i + 1 < argc) {
        g_poison = TRACE_U32(argv[i + 1]);
        return 2;
    }
    if (!strcmp(a, "--poisonval") && i + 1 < argc) {
        g_poison_val = TRACE_U32(argv[i + 1]);
        return 2;
    }
    if (!strcmp(a, "--poke") && i + 3 < argc) {
        g_poke_addr = TRACE_U32(argv[i + 1]);
        g_poke_val = (uint8_t)TRACE_U32(argv[i + 2]);
        g_poke_at = TRACE_U32(argv[i + 3]);
        return 4;
    }
    return 0;
}

#else  /* built without -DRECOMP_TRACE: the options parse but do nothing */

void recomp_dump_trace(const char* why) { (void)why; }
void recomp_trace_flush(void) { }

int recomp_trace_arg(int argc, char** argv, int i) {
    static const struct { const char* name; int takes; } opts[] = {
        {"--calltrace", 2}, {"--firsthit", 3}, {"--argtrace", 2},
        {"--watch", 2}, {"--watchspan", 3}, {"--argobj", 3}, {"--chase", 3},
        {"--poison", 2},
        {"--poisonval", 2}, {"--poke", 4},
    };
    for (unsigned k = 0; k < sizeof opts / sizeof opts[0]; k++)
        if (!strcmp(argv[i], opts[k].name)) {
            fprintf(stderr, "[trace] %s needs a build with -DRECOMP_TRACE\n",
                    argv[i]);
            return (i + opts[k].takes - 1 < argc) ? opts[k].takes : 1;
        }
    return 0;
}

#endif

void recomp_trace_help(void) {
    fprintf(stderr,
        "  --calltrace FILE      every lifted-function entry, thread-tagged\n"
        "  --firsthit LO HI      first entry to each function in [LO,HI)\n"
        "  --argtrace VA         one line per entry to VA, with 3 arguments\n"
        "  --watch VA            registers, arguments and the object at ecx\n"
        "  --watchspan LO HI     move the [ecx+..] window --watch dumps\n"
        "  --argobj VA N         vtable and first 0x40 bytes of argument N\n"
        "  --chase VA OFFSETS    follow a pointer chain from ecx (0xC,0x98)\n"
        "  --poison ADDR         report every change of a target dword\n"
        "  --poisonval V         ...only when it becomes V\n"
        "  --poke ADDR VAL VA    write one byte on first entry to VA\n");
}
