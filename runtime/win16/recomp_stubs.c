/* recomp_stubs.c - the minimum a freshly lifted Win16 NE target needs to LINK.
 *
 * cpu.h declares a diagnostic and dispatch surface that lifted code references
 * from the first compile: the entry ring, the selector-write watch, indirect
 * call dispatch, and the loud-abort helpers. None of it is optional at link
 * time -- every lifted translation unit refers to it -- but almost none of it
 * needs a real implementation before the program first runs.
 *
 * So this file exists to get a project from "compiles" to "links" on day one,
 * and to make sure that the moment execution reaches something unimplemented it
 * STOPS. Nothing here returns a plausible-looking wrong answer.
 *
 * Replace these one at a time as the project comes up. A project that has its
 * own implementation simply drops this file from its build.
 */
#include "cpu.h"

#include <stdio.h>
#include <stdlib.h>

/* ---- Entry trace ring (see RECOMP_ENTER / TRACE_FN in cpu.h) ---- */
const char *g_fn_ring[RECOMP_FN_RING_SIZE];
unsigned    g_fn_ring_pos = 0;
int         g_fncount = 0;      /* set non-zero to count lifted entries */
int         g_watch_ds = 0;     /* set non-zero to trap DS changes */
uint16_t    g_wsel = 0;         /* selector to watch writes to, 0 = none */

void recomp_fn_hit(const char *n)
{
    (void)n;   /* counting/DS-watch hook; inert until a project wants it */
}

void recomp_sel_write(uint16_t seg, uint16_t off, uint16_t val)
{
    (void)seg; (void)off; (void)val;   /* arm by setting g_wsel */
}

/* ---- Loud failures ----
 *
 * Both of these abort. A lifted guest has no exception model: returning from
 * here would hand the caller registers and a frame that are wrong from this
 * point on, and the crash would land somewhere else entirely, in code that is
 * fine. Dying at the actual site is the whole value. */
static void die(const char *what, const char *detail)
{
    fflush(stdout);
    fprintf(stderr, "\n[recomp] %s: %s\n", what, detail);
    fprintf(stderr, "[recomp] last %u lifted entries (newest first):\n",
            (unsigned)(g_fn_ring_pos < 16 ? g_fn_ring_pos : 16));
    for (unsigned i = 0; i < 16 && i < g_fn_ring_pos; i++) {
        const char *fn = g_fn_ring[(g_fn_ring_pos - 1 - i) & (RECOMP_FN_RING_SIZE - 1)];
        if (fn) fprintf(stderr, "[recomp]   %s\n", fn);
    }
    abort();
}

void recomp_unreachable(const char *seg, unsigned off)
{
    char buf[96];
    snprintf(buf, sizeof buf, "seg%s:%04X was never lifted (data-in-code desync)",
             seg, off);
    die("unreachable", buf);
}

void recomp_div0(const char *kind)
{
    die("divide by zero", kind ? kind : "?");
}

/* ---- Indirect dispatch ----
 *
 * `call bx` and `call far [bp-4]` land here with a guest address that has to be
 * mapped back to a lifted function. That needs a (segment, offset) -> function
 * table, which gen_dispatch-style tooling builds from the lifted sources. Until
 * a project generates one, an indirect call is a stop, not a guess. */
void dispatch_near(CPU *cpu, uint16_t seg, uint16_t off)
{
    char buf[96];
    (void)cpu;
    snprintf(buf, sizeof buf, "near call to %u:%04X, no dispatch table built",
             (unsigned)seg, (unsigned)off);
    die("indirect dispatch", buf);
}

void dispatch_far(CPU *cpu, uint16_t seg, uint16_t off)
{
    char buf[96];
    (void)cpu;
    snprintf(buf, sizeof buf, "far call to %04X:%04X, no dispatch table built",
             (unsigned)seg, (unsigned)off);
    die("indirect dispatch", buf);
}

/* ---- Software interrupts ----
 *
 * A Win16 binary should not be issuing these, so reaching one usually means the
 * disassembler decoded data as code rather than that the guest wants DOS. Stop
 * and say which vector, so it can be told apart. */
void int_handler(CPU *cpu, uint8_t vec)
{
    char buf[64];
    (void)cpu;
    snprintf(buf, sizeof buf, "INT 0x%02X in a Win16 target", (unsigned)vec);
    die("software interrupt", buf);
}

void dos_int21(CPU *cpu)
{
    char buf[64];
    snprintf(buf, sizeof buf, "INT 21h AH=0x%02X", (unsigned)cpu->ah);
    die("DOS call", buf);
}
