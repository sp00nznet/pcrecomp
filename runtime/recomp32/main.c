/*
 * X-Wing Alliance Static Recompilation - Entry Point
 *
 * Sets up the memory layout, initializes the register model,
 * installs the VEH crash handler, and launches the recompiled game.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <dbghelp.h>
#include "recomp/recomp_types.h"

/* ============================================================
 * Global Register Definitions
 * ============================================================ */

uint32_t g_eax = 0, g_ecx = 0, g_edx = 0, g_esp = 0;
uint32_t g_ebx = 0, g_esi = 0, g_edi = 0;
uint16_t g_seg_cs = 0, g_seg_ds = 0, g_seg_es = 0;
uint16_t g_seg_fs = 0, g_seg_gs = 0, g_seg_ss = 0;

/* Memory base offset (0 for fixed-base mapping) */
ptrdiff_t g_mem_base = 0;

/* ICALL trace */
uint32_t g_icall_trace[ICALL_TRACE_SIZE] = {0};
uint32_t g_icall_trace_idx = 0;
uint32_t g_icall_count = 0;

/* ============================================================
 * Memory Layout Constants (from PE analysis)
 *
 * .text:  0x00401000 - 0x005A8B20  (code, not mapped - we ARE the code)
 * .rdata: 0x005A9000 - 0x005ADA24  (read-only data)
 * .data:  0x005AE000 - 0x00B0F974  (read/write data)
 * ============================================================ */

#define XWA_IMAGE_BASE    0x00400000
#define XWA_DATA_START    0x005A9000  /* .rdata start */
#define XWA_DATA_END      0x00B10000  /* end of .data (rounded up) */
#define XWA_DATA_SIZE     (XWA_DATA_END - XWA_DATA_START)

/* Stack: 4MB at a fixed location below the data sections */
#define XWA_STACK_BASE    0x00300000
#define XWA_STACK_SIZE    0x00100000  /* 1 MB stack */
#define XWA_STACK_TOP     (XWA_STACK_BASE + XWA_STACK_SIZE)

static HANDLE g_data_mapping = NULL;
static void*  g_data_view = NULL;
static void*  g_stack_alloc = NULL;

/* ============================================================
 * VEH Crash Handler
 * ============================================================ */

static uint32_t g_seh_skip_count = 0;

static void dump_icall_trace(void) {
    fprintf(stderr, "\n=== ICALL Trace (last %d calls) ===\n", ICALL_TRACE_SIZE);
    for (int i = 0; i < ICALL_TRACE_SIZE; i++) {
        uint32_t idx = (g_icall_trace_idx - ICALL_TRACE_SIZE + i) & (ICALL_TRACE_SIZE - 1);
        if (g_icall_trace[idx]) {
            fprintf(stderr, "  [%2d] 0x%08X\n", i, g_icall_trace[idx]);
        }
    }
    fprintf(stderr, "Total indirect calls: %u\n", g_icall_count);
}

static void dump_registers(void) {
    fprintf(stderr, "\n=== Recomp Register State ===\n");
    fprintf(stderr, "  EAX=0x%08X  ECX=0x%08X  EDX=0x%08X  EBX=0x%08X\n",
            g_eax, g_ecx, g_edx, g_ebx);
    fprintf(stderr, "  ESP=0x%08X  ESI=0x%08X  EDI=0x%08X\n",
            g_esp, g_esi, g_edi);
}

static LONG WINAPI veh_handler(EXCEPTION_POINTERS* ep) {
    DWORD code = ep->ExceptionRecord->ExceptionCode;

    /* Only handle access violations */
    if (code != EXCEPTION_ACCESS_VIOLATION) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    fprintf(stderr, "\n=== CRASH: Access Violation ===\n");
    fprintf(stderr, "  Faulting address: 0x%p\n", (void*)ep->ExceptionRecord->ExceptionAddress);
    if (ep->ExceptionRecord->NumberParameters >= 2) {
        fprintf(stderr, "  %s at 0x%p\n",
                ep->ExceptionRecord->ExceptionInformation[0] ? "WRITE" : "READ",
                (void*)ep->ExceptionRecord->ExceptionInformation[1]);
    }

    dump_registers();
    dump_icall_trace();

    return EXCEPTION_CONTINUE_SEARCH;
}

/* ============================================================
 * Dispatch Table Lookup (binary search)
 * ============================================================ */

recomp_func_t recomp_lookup(uint32_t va) {
    int lo = 0;
    int hi = (int)recomp_dispatch_count - 1;

    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        uint32_t mid_va = recomp_dispatch_table[mid].address;
        if (mid_va == va) {
            return recomp_dispatch_table[mid].func;
        } else if (mid_va < va) {
            lo = mid + 1;
        } else {
            hi = mid - 1;
        }
    }
    return NULL;
}

/* Manual override table (populated as needed) */
static recomp_dispatch_entry_t g_manual_overrides[] = {
    { 0, NULL }  /* sentinel */
};
static const int g_manual_override_count = 0;

recomp_func_t recomp_lookup_manual(uint32_t va) {
    for (int i = 0; i < g_manual_override_count; i++) {
        if (g_manual_overrides[i].address == va) {
            return g_manual_overrides[i].func;
        }
    }
    return NULL;
}

/* Import bridge table (populated during init) */
#define MAX_IMPORT_BRIDGES 256
static recomp_dispatch_entry_t g_import_bridges[MAX_IMPORT_BRIDGES];
static int g_import_bridge_count = 0;

recomp_func_t recomp_lookup_import(uint32_t va) {
    for (int i = 0; i < g_import_bridge_count; i++) {
        if (g_import_bridges[i].address == va) {
            return g_import_bridges[i].func;
        }
    }
    return NULL;
}

/* ============================================================
 * Memory Setup
 * ============================================================ */

static int setup_memory(const char* data_file) {
    /*
     * Map the original data sections at their original VAs.
     * We use VirtualAlloc at fixed addresses since the binary
     * has no ASLR and uses a fixed image base.
     */

    /* Allocate the simulated stack */
    g_stack_alloc = VirtualAlloc(
        (void*)XWA_STACK_BASE,
        XWA_STACK_SIZE,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE
    );
    if (!g_stack_alloc) {
        /* Try without fixed address */
        g_stack_alloc = VirtualAlloc(NULL, XWA_STACK_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!g_stack_alloc) {
            fprintf(stderr, "ERROR: Failed to allocate stack\n");
            return 0;
        }
        fprintf(stderr, "WARNING: Stack allocated at %p (wanted 0x%08X)\n",
                g_stack_alloc, XWA_STACK_BASE);
    }

    /* Set initial stack pointer to top of stack (minus some alignment) */
    g_esp = (uint32_t)((uintptr_t)g_stack_alloc + XWA_STACK_SIZE - 16);

    /* Allocate the data region */
    g_data_view = VirtualAlloc(
        (void*)(uintptr_t)XWA_DATA_START,
        XWA_DATA_SIZE,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE
    );
    if (!g_data_view) {
        /* Try without fixed address */
        g_data_view = VirtualAlloc(NULL, XWA_DATA_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!g_data_view) {
            fprintf(stderr, "ERROR: Failed to allocate data region\n");
            return 0;
        }
        /* Calculate offset for non-fixed mapping */
        g_mem_base = (ptrdiff_t)((uintptr_t)g_data_view - XWA_DATA_START);
        fprintf(stderr, "WARNING: Data mapped at %p (wanted 0x%08X), offset=%lld\n",
                g_data_view, XWA_DATA_START, (long long)g_mem_base);
    }

    /* Load .rdata and .data sections from the original binary */
    if (data_file) {
        FILE* f = fopen(data_file, "rb");
        if (f) {
            /*
             * .rdata: file offset 0x001A8200, VA 0x005A9000, size 0x4A24
             * .data:  file offset 0x001AC800, VA 0x005AE000, size 0x561974
             */
            /* Read .rdata */
            fseek(f, 0x001A8200, SEEK_SET);
            fread((void*)ADDR(0x005A9000), 1, 0x4A24, f);

            /* Read .data */
            fseek(f, 0x001AC800, SEEK_SET);
            fread((void*)ADDR(0x005AE000), 1, 0x561974, f);

            fclose(f);
            printf("[*] Loaded data sections from %s\n", data_file);
        } else {
            fprintf(stderr, "WARNING: Could not open %s for data loading\n", data_file);
        }
    }

    return 1;
}

static void cleanup_memory(void) {
    if (g_data_view) {
        VirtualFree(g_data_view, 0, MEM_RELEASE);
        g_data_view = NULL;
    }
    if (g_stack_alloc) {
        VirtualFree(g_stack_alloc, 0, MEM_RELEASE);
        g_stack_alloc = NULL;
    }
}

/* ============================================================
 * Entry Point
 * ============================================================ */

/* Forward declaration of the recompiled WinMain / game entry */
extern void sub_004D7810(void);  /* Placeholder - real entry point TBD from analysis */

int main(int argc, char* argv[]) {
    printf("=== X-Wing Alliance Static Recompilation ===\n");
    printf("=== Phase 2: Recompilation Infrastructure  ===\n\n");

    /* Default path to original binary for data loading */
    const char* data_file = NULL;
    if (argc > 1) {
        data_file = argv[1];
    }

    /* Install VEH crash handler */
    AddVectoredExceptionHandler(1, veh_handler);
    printf("[*] VEH crash handler installed\n");

    /* Set up memory layout */
    if (!setup_memory(data_file)) {
        fprintf(stderr, "FATAL: Memory setup failed\n");
        return 1;
    }
    printf("[*] Memory layout initialized\n");
    printf("    Stack:  %p - %p (ESP = 0x%08X)\n",
           g_stack_alloc, (char*)g_stack_alloc + XWA_STACK_SIZE, g_esp);
    printf("    Data:   %p (0x%08X - 0x%08X)\n",
           g_data_view, XWA_DATA_START, XWA_DATA_END);
    printf("    Offset: %lld\n", (long long)g_mem_base);

    printf("\n[*] XWA recomp infrastructure ready.\n");
    printf("[*] Dispatch table: %u functions\n", recomp_dispatch_count);
    printf("[*] To run game: pass path to xwingalliance.exe as argument\n");

    /* TODO: Once imports are bridged and entry point identified:
     *   sub_XXXXXXXX();  // Call recompiled WinMain
     */

    cleanup_memory();
    return 0;
}
