/*
 * crash_report.c - crash diagnostics for recompiled 32-bit programs.
 * See crash_report.h.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

#include "recomp_types.h"
#include "crash_report.h"

static recomp_region_fn g_region = NULL;

void recomp_set_region_describer(recomp_region_fn fn) { g_region = fn; }

static const char* region_of(uint32_t va) {
    return g_region ? g_region(va) : "";
}

static void dump_registers(void) {
    fprintf(stderr, "  eax=%08X ecx=%08X edx=%08X ebx=%08X\n",
            g_eax, g_ecx, g_edx, g_ebx);
    fprintf(stderr, "  esp=%08X ebp=%08X esi=%08X edi=%08X\n",
            g_esp, g_ebp, g_esi, g_edi);
}

/* Most recent last: the tail is where you start reading. */
static void dump_icall_trace(void) {
    unsigned shown = 0;
    fprintf(stderr, "  recent indirect calls (oldest first):\n");
    for (int i = 0; i < ICALL_TRACE_SIZE; i++) {
        uint32_t idx = (g_icall_trace_idx - ICALL_TRACE_SIZE + i)
                       & (ICALL_TRACE_SIZE - 1);
        uint32_t va = g_icall_trace[idx];
        if (!va) continue;
        fprintf(stderr, "    %08X %s\n", va, region_of(va));
        shown++;
    }
    if (!shown) fprintf(stderr, "    (none)\n");
    fprintf(stderr, "  total indirect calls: %u\n", g_icall_count);
}

void recomp_report_state(const char* why) {
    fprintf(stderr, "\n=== recomp: %s ===\n", why ? why : "state");
    /* The single most useful line: which lifted function was executing. Every
     * lifted body sets this on entry, with or without RECOMP_TRACE. */
    fprintf(stderr, "  current lifted function: sub_%08X\n", g_cur_func);
    dump_registers();
    dump_icall_trace();
    recomp_dump_trace(why);   /* no-op unless built with RECOMP_TRACE */
    fflush(stderr);
}

static LONG WINAPI veh_handler(EXCEPTION_POINTERS* ep) {
    DWORD code = ep->ExceptionRecord->ExceptionCode;

    const char* name;
    switch (code) {
    case EXCEPTION_ACCESS_VIOLATION:      name = "access violation"; break;
    case EXCEPTION_STACK_OVERFLOW:        name = "stack overflow"; break;
    case EXCEPTION_INT_DIVIDE_BY_ZERO:    name = "integer divide by zero"; break;
    case EXCEPTION_ILLEGAL_INSTRUCTION:   name = "illegal instruction"; break;
    case EXCEPTION_IN_PAGE_ERROR:         name = "in-page error"; break;
    default:
        /* Not ours -- and in particular not a C++/SEH exception being used for
         * control flow, which we must not narrate. */
        return EXCEPTION_CONTINUE_SEARCH;
    }

    fprintf(stderr, "\n=== recomp: CRASH (%s) ===\n", name);
    fprintf(stderr, "  host address: %p\n",
            (void*)ep->ExceptionRecord->ExceptionAddress);
    if (code == EXCEPTION_ACCESS_VIOLATION &&
        ep->ExceptionRecord->NumberParameters >= 2) {
        uintptr_t bad = (uintptr_t)ep->ExceptionRecord->ExceptionInformation[1];
        const char* op = ep->ExceptionRecord->ExceptionInformation[0]
                       ? "write" : "read";
        fprintf(stderr, "  bad %s of %p %s\n", op, (void*)bad,
                region_of((uint32_t)bad));
    }
    recomp_report_state("state at fault");

    /* Report, then let it die: swallowing the fault would turn a crash into an
     * infinite loop of the same crash. */
    return EXCEPTION_CONTINUE_SEARCH;
}

void recomp_install_crash_handler(void) {
    static int installed = 0;
    if (installed) return;
    AddVectoredExceptionHandler(1, veh_handler);
    installed = 1;
}
