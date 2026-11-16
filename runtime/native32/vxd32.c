/*
 * vxd32: the Windows 9x kernel boundary, for lifted Windows 98 kernel32.
 *
 * Windows 98's kernel32 imports nothing. It leaves ring 3 by one far call
 * through a call gate to VMM (kernel32's VxDCall0..8, ordinals 1-9:
 * `mov eax,[esp+4]; pop [esp]; call fword cs:[gate]`). lift32 turns that
 * `call m16:32` into recomp_farcall32(); this file answers it by service id
 * (VxD id << 16 | service), the way VWIN32 and VMM's Win32 services would,
 * with the host underneath.
 *
 * At the gate the stack is: [esp] the VxDCall caller's return address, then
 * the service's arguments. The gate returns straight to that caller and pops
 * the arguments, so a handler names its argument count.
 *
 * NATIVE32_VXD=1 traces every call. An unknown service stops the process
 * (exit 5) with its id and arguments: nothing is guessed.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#include "native32.h"

typedef struct { uint32_t id; int nargs; uint32_t (*fn)(const uint32_t* a); const char* name; } vxd_service_t;

/* VWIN32 3: kernel32's boot hands VWIN32 its code and data selectors (args
 * 1, 2) before reading the boot block; nothing for a flat host to keep. */
static uint32_t vwin32_boot_sels(const uint32_t* a) { (void)a; return 0; }

/* VWIN32 4A (crit, level): the kernel side of a critical section kernel32
 * just initialised (its type-4 object). Returns VWIN32's own object for it;
 * kernel32 keeps it in the section. A zeroed block of our own stands in. */
static uint32_t vwin32_crst_create(const uint32_t* a) { (void)a; return (uint32_t)(uintptr_t)calloc(1, 0x40); }

/* VMM's Win32 memory services (DDK _PageReserve/_PageCommit/_PageDecommit),
 * in pages. page: a page number, or PR_PRIVATE 0x80000400 / PR_SHARED
 * 0x80060000 / PR_SYSTEM 0x80080000 for "anywhere in that arena".
 * ponytail: every arena is "anywhere" in the host; place PR_SHARED above 2 GB
 * if kernel32 turns out to test addresses for sharedness. */
#define PR_ANY(p) (((p) & 0xFFF00000u) == 0x80000000u)
static uint32_t vmm_page_reserve(const uint32_t* a) {
    void* want = PR_ANY(a[0]) ? NULL : (void*)(uintptr_t)(a[0] << 12);
    void* p = VirtualAlloc(want, a[1] << 12, MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    return p ? (uint32_t)(uintptr_t)p : 0xFFFFFFFFu;
}
/* (page, npages, hpd, pagerdata, flags) */
static uint32_t vmm_page_commit(const uint32_t* a) {
    return VirtualAlloc((void*)(uintptr_t)(a[0] << 12), a[1] << 12, MEM_COMMIT, PAGE_EXECUTE_READWRITE) != NULL;
}
/* (page, npages, flags) */
static uint32_t vmm_page_decommit(const uint32_t* a) {
    return VirtualFree((void*)(uintptr_t)(a[0] << 12), a[1] << 12, MEM_DECOMMIT);
}

/* VWIN32 6 (data, entry1, entry2): kernel32 registers where VWIN32 calls
 * back into it (two code entries and a block). Kept for when a callback
 * has to be delivered (APCs, exceptions). */
uint32_t g_vwin32_callbacks[3];
static uint32_t vwin32_set_callbacks(const uint32_t* a) {
    for (int i = 0; i < 3; i++) g_vwin32_callbacks[i] = a[i];
    return 1;
}

/* VWIN32 47 (env): kernel32 tells VWIN32 where the first process's
 * environment now lives (it copied it out of the DOS VM). Nothing to keep. */
static uint32_t vwin32_set_env(const uint32_t* a) { (void)a; return 0; }

/* VMM's ring-0 heap (DDK _HeapAllocate/_HeapFree/_HeapReAllocate/
 * _HeapGetSize order, services 5-8). flags bit 0 = HEAPZEROINIT. */
static HANDLE vmm_heap(void) { static HANDLE h; if (!h) h = HeapCreate(0, 0, 0); return h; }
static uint32_t vmm_heap_alloc(const uint32_t* a) {
    return (uint32_t)(uintptr_t)HeapAlloc(vmm_heap(), (a[1] & 1) ? HEAP_ZERO_MEMORY : 0, a[0] ? a[0] : 1);
}
static uint32_t vmm_heap_free(const uint32_t* a) { return a[0] ? HeapFree(vmm_heap(), 0, (void*)(uintptr_t)a[0]) : 0; }
static uint32_t vmm_heap_realloc(const uint32_t* a) {
    return (uint32_t)(uintptr_t)HeapReAlloc(vmm_heap(), (a[2] & 1) ? HEAP_ZERO_MEMORY : 0, (void*)(uintptr_t)a[0], a[1] ? a[1] : 1);
}
static uint32_t vmm_heap_size(const uint32_t* a) { return (uint32_t)HeapSize(vmm_heap(), 0, (void*)(uintptr_t)a[0]); }

/* VWIN32 4F (fn, handle): 33h registers a kernel32 object (a process) with
 * VWIN32's ring-0 side, 34h drops it. The host keeps no ring-0 twin. */
static uint32_t vwin32_obj_fn(const uint32_t* a) { return a[0] == 0x33 || a[0] == 0x34; }

static const vxd_service_t g_services[] = {
    { 0x002A004F, 2, vwin32_obj_fn, "VWIN32_ObjectFn" },
    { 0x00010005, 2, vmm_heap_alloc, "VMM_HeapAllocate" },
    { 0x00010006, 2, vmm_heap_free, "VMM_HeapFree" },
    { 0x00010007, 3, vmm_heap_realloc, "VMM_HeapReAllocate" },
    { 0x00010008, 2, vmm_heap_size, "VMM_HeapGetSize" },
    { 0x002A0047, 1, vwin32_set_env, "VWIN32_SetEnvironment" },
    { 0x002A0006, 3, vwin32_set_callbacks, "VWIN32_SetCallbacks" },
    { 0x00010000, 3, vmm_page_reserve, "VMM_PageReserve" },
    { 0x00010001, 5, vmm_page_commit, "VMM_PageCommit" },
    { 0x00010002, 3, vmm_page_decommit, "VMM_PageDecommit" },
    { 0x002A004A, 2, vwin32_crst_create, "VWIN32_CreateCrst" },
    { 0x002A0003, 8, vwin32_boot_sels, "VWIN32_BootSelectors" },
    { 0, 0, NULL, NULL },
};

static int g_trace = -1;

/* VWIN32's ring-0 entry table: the KEXP header's second dword is where
 * VWIN32 stores its address; kernel32 enters an entry by a retf (lifted as
 * recomp_retf32). Entries are tagged 0xFEED0000 + their offset. */
#define R0_TAG 0xFEED0000u
static uint32_t g_r0_table[0x40];
static uint16_t g_next_sel = 0x0087;   /* LDT, RPL 3: what a flat host hands out */

uint32_t native32_vwin32_r0_table(void) {
    for (int i = 0; i < 0x40; i++) g_r0_table[i] = R0_TAG + 4u * i;
    return (uint32_t)(uintptr_t)g_r0_table;
}

/* The LDT. kernel32 writes descriptors itself, through an alias selector
 * whose base is the LDT (the boot block's +10h); the host owns the array and
 * every LDT selector's base is read from what kernel32 wrote there. GDT
 * selectors (the host's own flat ones) are base 0. */
static uint8_t g_ldt[0x10000];
static uint16_t g_ldt_alias;
uint32_t g_es_base, g_cs_base, g_ds_base;

void native32_w9x_ldt(uint16_t alias_sel, uint32_t* ldt_base) { g_ldt_alias = alias_sel & ~7; *ldt_base = (uint32_t)(uintptr_t)g_ldt; }

uint32_t recomp_sel_base(uint32_t sel) {
    sel &= 0xFFFF;
    if ((sel & ~7u) == g_ldt_alias) return (uint32_t)(uintptr_t)g_ldt;
    if (!(sel & 4)) return 0;
    const uint8_t* d = g_ldt + (sel & ~7u);
    return d[2] | d[3] << 8 | d[4] << 16 | (uint32_t)d[7] << 24;
}

/* A data selector on [base, base+limit] in the host's LDT: what VWIN32 or
 * KRNL386 would have allocated. */
uint16_t native32_w9x_alloc_sel(uint32_t base, uint32_t limit) {
    uint16_t sel = g_next_sel;
    uint8_t* d = g_ldt + (sel & ~7u);
    g_next_sel += 8;
    d[0] = (uint8_t)limit; d[1] = (uint8_t)(limit >> 8);
    d[2] = (uint8_t)base; d[3] = (uint8_t)(base >> 8); d[4] = (uint8_t)(base >> 16); d[7] = (uint8_t)(base >> 24);
    d[5] = 0xF2;                            /* present, DPL 3, data, writable */
    d[6] = (uint8_t)((limit >> 16) & 0x0F) | 0x40;
    return sel;
}

static const uint8_t* ldt_desc(uint16_t sel) {
    if (!(sel & 4) || (sel & ~7u) == g_ldt_alias) return NULL;
    const uint8_t* d = g_ldt + (sel & ~7u);
    return (d[5] & 0x80) ? d : NULL;           /* present */
}

int recomp_lsl32(uint16_t sel, uint32_t* limit) {
    if ((sel & ~7u) == g_ldt_alias) { *limit = sizeof g_ldt - 1; return 1; }
    const uint8_t* d = ldt_desc(sel);
    if (!d) return 0;
    uint32_t l = d[0] | d[1] << 8 | (uint32_t)(d[6] & 0x0F) << 16;
    *limit = (d[6] & 0x80) ? (l << 12) | 0xFFF : l;
    return 1;
}

int recomp_lar32(uint16_t sel, uint32_t* rights) {
    if ((sel & ~7u) == g_ldt_alias) { *rights = 0x00C0F200u; return 1; }
    const uint8_t* d = ldt_desc(sel);
    if (!d) return 0;
    *rights = ((uint32_t)d[5] << 8 | (uint32_t)(d[6] & 0xF0) << 16);
    return 1;
}

void recomp_set_seg(int sreg, uint32_t sel) {
    if (sreg == 0) { g_seg_es = (uint16_t)sel; g_es_base = recomp_sel_base(sel); }
    if (sreg == 5) { g_seg_gs = (uint16_t)sel; g_gs_base = recomp_sel_base(sel); }
    if (sreg == 3) { g_seg_ds = (uint16_t)sel; g_ds_base = recomp_sel_base(sel); }
}

int recomp_retf32(uint32_t target) {
    if ((target & 0xFFFF0000u) != R0_TAG) return 0;
    uint32_t off = target & 0xFFFF;
    if (g_trace < 0) g_trace = getenv("NATIVE32_VXD") != NULL;
    switch (off) {
    case 0x28:   /* allocate ecx LDT selectors: ax = the first. ponytail: a counter; no descriptors yet */
        g_eax = (g_eax & 0xFFFF0000u) | g_next_sel;
        g_next_sel += (uint16_t)(8 * (g_ecx ? g_ecx : 1));
        break;
    default:
        fprintf(stderr, "\n[vwin32-r0] unknown ring-0 entry +%02X from sub_%08X: eax=%08X ecx=%08X edx=%08X ebx=%08X\n",
                off, g_cur_func, g_eax, g_ecx, g_edx, g_ebx);
        fflush(stderr);
        TerminateProcess(GetCurrentProcess(), 5);
    }
    if (g_trace) fprintf(stderr, "[vwin32-r0] +%02X -> eax=%08X (from sub_%08X)\n", off, g_eax, g_cur_func);
    return 1;
}

int recomp_farcall32(uint32_t ptr) {
    uint32_t id = g_eax, *a = (uint32_t*)(uintptr_t)(g_esp + 4);
    (void)ptr;
    if (g_trace < 0) g_trace = getenv("NATIVE32_VXD") != NULL;
    for (const vxd_service_t* s = g_services; s->fn; s++) {
        if (s->id != id) continue;
        uint32_t r = s->fn(a);
        if (g_trace)
            fprintf(stderr, "[vxd] %08X %s(%08X %08X %08X %08X) = %08X  (from sub_%08X)\n",
                    id, s->name, a[0], a[1], a[2], a[3], r, g_cur_func);
        g_eax = r;
        g_esp += 4 + 4u * s->nargs;
        return 1;
    }
    fprintf(stderr, "\n[vxd] unknown service %08X (VxD %04X, service %04X) from sub_%08X\n"
                    "      stack: ret %08X, args %08X %08X %08X %08X %08X %08X\n",
            id, id >> 16, id & 0xFFFF, g_cur_func, MEM32(g_esp), a[0], a[1], a[2], a[3], a[4], a[5]);
    native32_dump_icalls(8);
    fflush(stderr);
    TerminateProcess(GetCurrentProcess(), 5);
    return 1;
}
