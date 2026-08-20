/*
 * hybrid.c - lifted <-> real boundary. See hybrid.h and docs/HYBRID.md.
 *
 * 32-bit x86, MSVC (uses __asm). The three rules that make it correct are
 * marked RULE 1/2/3 below; each one cost a long debugging session to find.
 */
#include "hybrid.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string.h>

/* ============================================================
 * lifted -> real
 * ============================================================ */

/* MSVC inline asm cannot address locals once esp/ebp are switched, so the
 * marshalling slots are file-scope. They are saved and restored around each
 * call, which is what makes this reentrant (RULE 2). */
static uint32_t T_eax, T_ecx, T_edx, T_ebx, T_esi, T_edi, T_ebp, T_espp4,
                T_tgt, T_fesp, T_sesp;

#pragma warning(disable:4731)   /* we clobber ebp deliberately; push/pop restores it */
void hybrid_call_machine(hybrid_regs *r, uint32_t target)
{
    /* RULE 2: BE REENTRANT.
     * The real code we are about to call can call back into lifted code (that
     * is the whole point of routing vtables), which dispatches an import, which
     * lands here again. If the saved host esp lived in a plain global, the
     * inner call would overwrite the outer's copy and the outer would restore a
     * bogus esp and return into hyperspace - long after the real mistake, in a
     * frame that looks unrelated. Save and restore the whole block. */
    uint32_t sv_eax = T_eax, sv_ecx = T_ecx, sv_edx = T_edx, sv_ebx = T_ebx,
             sv_esi = T_esi, sv_edi = T_edi, sv_ebp = T_ebp, sv_espp4 = T_espp4,
             sv_tgt = T_tgt, sv_fesp = T_fesp, sv_sesp = T_sesp;

    T_eax = r->eax; T_ecx = r->ecx; T_edx = r->edx; T_ebx = r->ebx;
    T_esi = r->esi; T_edi = r->edi;

    /* RULE 1: SEED ebp.
     * MSVC emits frameless funclets for SEH unwind and local-object destruction
     * that address the CALLER's frame:
     *     lea ecx, [ebp-0x10]
     *     jmp CString::~CString
     * If such a funclet is not in your lifted set, dispatch falls back to the
     * real original - which then runs against the HOST's ebp and destructs a
     * garbage pointer. That reads as heap corruption a long way from the cause. */
    T_ebp = r->ebp;

    T_espp4 = r->esp + 4;   /* skip the fake return slot; `call` writes a real one there */
    T_tgt = target;

    __asm {
        push ebx
        push esi
        push edi
        push ebp
        mov T_sesp, esp
        mov eax, T_eax
        mov ecx, T_ecx
        mov edx, T_edx
        mov ebx, T_ebx
        mov esi, T_esi
        mov edi, T_edi
        mov ebp, T_ebp
        mov esp, T_espp4
        call dword ptr [T_tgt]
        mov T_fesp, esp
        mov T_eax, eax
        /* RULE 3: CAPTURE edx.
         * A 64-bit return comes back in edx:eax. Dropping edx silently
         * truncates every one of them, and compilers of this era pass such
         * pairs around constantly (`mov [ebp-8],eax; mov [ebp-4],edx`). */
        mov T_edx, edx
        mov esp, T_sesp
        pop ebp
        pop edi
        pop esi
        pop ebx
    }

    r->eax = T_eax; r->edx = T_edx; r->esp = T_fesp;

    T_eax = sv_eax; T_ecx = sv_ecx; T_edx = sv_edx; T_ebx = sv_ebx;
    T_esi = sv_esi; T_edi = sv_edi; T_ebp = sv_ebp; T_espp4 = sv_espp4;
    T_tgt = sv_tgt; T_fesp = sv_fesp; T_sesp = sv_sesp;
}

/* ============================================================
 * real -> lifted
 * ============================================================
 *
 * A per-target stub `mov eax, <ova>; jmp r2l_common` is what goes in the vtable
 * slot. It lands in r2l_common with eax = the target's original VA, ecx = this,
 * [esp] = the real return address and arguments above it. r2l_helper copies the
 * arguments onto a private emulated frame, calls the host's invoke, and reports
 * how many argument bytes the callee's `ret N` cleaned so we can return
 * __thiscall-correctly.
 */

static hybrid_invoke_fn g_invoke;
static uint8_t  *g_arena;
static uint32_t  g_arena_top, g_frame;
static uint8_t  *g_pool;
static size_t    g_pool_off, g_pool_size;
static unsigned long g_r2l_calls;

#define R2L_STUB_BYTES 16
#define R2L_ARGS_COPIED 16      /* enough for any sane calling convention */

static uint64_t __cdecl r2l_helper(uint32_t ova, uint32_t this_, uint32_t *real_args,
                                   uint32_t ebx, uint32_t esi, uint32_t edi, uint32_t ebp)
{
    uint32_t save = g_arena_top;
    uint32_t argsp;
    hybrid_regs r;
    uint64_t ret;
    int i;

    /* The frame goes on a private arena, NOT on the real stack: the host's own
     * C frames (dispatch, the lifted function bodies) keep descending on the
     * real stack while the lifted code runs, and the two would interleave. */
    g_arena_top -= g_frame;
    argsp = g_arena_top + g_frame - 0x100;

    for (i = 0; i < R2L_ARGS_COPIED; i++)
        *(uint32_t *)(uintptr_t)(argsp + 4 + i * 4) = real_args[i];
    *(uint32_t *)(uintptr_t)argsp = 0xDEADBEEFu;    /* fake return slot */

    memset(&r, 0, sizeof r);
    /* Seed every callee-saved register from the real caller, not just `this`:
     * some routed targets are thunks that use the caller's ebp (RULE 1 again,
     * from the other side of the boundary). */
    r.ecx = this_; r.ebx = ebx; r.esi = esi; r.edi = edi; r.ebp = ebp;
    r.esp = argsp;

    g_r2l_calls++;
    ret = g_invoke(ova, &r, real_args);

    g_arena_top = save;
    return ret;
}

__declspec(naked) static void r2l_common(void)
{
    __asm {
        push ebp
        mov  ebp, esp                  /* [ebp+4]=retaddr, [ebp+8]=arg0, [ebp]=caller ebp */
        push dword ptr [ebp]           /* caller's ebp, for ebp-relative thunks */
        push edi
        push esi
        push ebx
        lea  edx, [ebp+8]
        push edx                       /* real_args */
        push ecx                       /* this */
        push eax                       /* ova */
        call r2l_helper                /* edx:eax = pop:result */
        add  esp, 28                   /* clean 7 cdecl args */
        mov  ecx, edx                  /* ecx = arg bytes the callee cleaned */
        mov  edx, [ebp+4]              /* retaddr */
        mov  esp, ebp
        pop  ebp
        add  esp, 4                    /* pop retaddr */
        add  esp, ecx                  /* callee-cleans convention */
        jmp  edx                       /* return, eax = result */
    }
}

int hybrid_init(hybrid_invoke_fn invoke, uint32_t frame_bytes, uint32_t arena_bytes)
{
    if (!invoke) return 0;
    if (!frame_bytes) frame_bytes = 0x8000u;
    if (!arena_bytes) arena_bytes = 8u << 20;
    g_invoke = invoke;
    g_frame  = frame_bytes;
    g_arena  = (uint8_t *)VirtualAlloc(NULL, arena_bytes, MEM_RESERVE | MEM_COMMIT,
                                       PAGE_READWRITE);
    if (!g_arena) return 0;
    g_arena_top = (uint32_t)(uintptr_t)(g_arena + arena_bytes);
    g_pool_size = 0x200000u;
    g_pool = (uint8_t *)VirtualAlloc(NULL, g_pool_size, MEM_RESERVE | MEM_COMMIT,
                                     PAGE_EXECUTE_READWRITE);
    return g_pool != NULL;
}

uint32_t hybrid_thunk(uint32_t ova)
{
    uint8_t *s;
    if (!g_pool || g_pool_off + R2L_STUB_BYTES > g_pool_size) return 0;
    s = g_pool + g_pool_off;
    g_pool_off += R2L_STUB_BYTES;
    s[0] = 0xB8; *(uint32_t *)(s + 1) = ova;                          /* mov eax, ova */
    s[5] = 0xE9; *(int32_t *)(s + 6) =
        (int32_t)((uint8_t *)r2l_common - (s + 10));                  /* jmp r2l_common */
    return (uint32_t)(uintptr_t)s;
}

int hybrid_thunk_target(uint32_t addr, uint32_t *out_ova)
{
    if (!g_pool) return 0;
    if (addr < (uint32_t)(uintptr_t)g_pool ||
        addr >= (uint32_t)(uintptr_t)g_pool + g_pool_off) return 0;
    if (out_ova) *out_ova = *(uint32_t *)(uintptr_t)(addr + 1);
    return 1;
}

unsigned long hybrid_r2l_calls(void) { return g_r2l_calls; }

/* ============================================================
 * vtable / function-pointer routing
 * ============================================================ */

#define HYBRID_MAX_SLOTS 65536
static uint32_t g_slot_ova[HYBRID_MAX_SLOTS];
static int      g_nslots;

uint32_t hybrid_slot_target(int slot_index)
{
    if (slot_index < 0 || slot_index >= g_nslots) return (uint32_t)-1;
    return g_slot_ova[slot_index];
}

int hybrid_route_fnptr_slots(void *image_base, int32_t image_delta,
                             hybrid_is_fn_start is_fn_start, int min_run,
                             int slot_lo, int slot_hi, int *out_total)
{
    uint8_t *base = (uint8_t *)image_base;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    uint32_t b = (uint32_t)(uintptr_t)base, tlo = 0, thi = 0;
    int i, n = 0, routed = 0;

    if (min_run < 1) min_run = 3;

    for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
        if (!memcmp(sec[i].Name, ".text", 5)) {
            tlo = b + sec[i].VirtualAddress;
            thi = tlo + sec[i].Misc.VirtualSize;
        }

    #define IS_FNPTR(v) ((v) >= tlo && (v) < thi && is_fn_start((v) - image_delta))

    for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        uint32_t p, e;
        if (memcmp(sec[i].Name, ".rdata", 6) && memcmp(sec[i].Name, ".data", 5))
            continue;
        p = b + sec[i].VirtualAddress;
        e = p + sec[i].Misc.VirtualSize;
        while (p + 4 <= e) {
            uint32_t v = *(uint32_t *)(uintptr_t)p;
            if (IS_FNPTR(v)) {
                uint32_t q = p, r;
                int run = 0;
                while (q + 4 <= e && IS_FNPTR(*(uint32_t *)(uintptr_t)q)) { run++; q += 4; }
                if (run >= min_run) {
                    for (r = p; r < q; r += 4) {
                        uint32_t ova = *(uint32_t *)(uintptr_t)r - image_delta;
                        if (n < HYBRID_MAX_SLOTS) g_slot_ova[n] = ova;
                        if (n >= slot_lo && n < slot_hi) {
                            uint32_t t = hybrid_thunk(ova);
                            if (t) { *(uint32_t *)(uintptr_t)r = t; routed++; }
                        }
                        n++;
                    }
                }
                p = q;
            } else {
                p += 4;
            }
        }
    }
    #undef IS_FNPTR

    g_nslots = n;
    if (out_total) *out_total = n;
    FlushInstructionCache(GetCurrentProcess(), NULL, 0);
    return routed;
}
