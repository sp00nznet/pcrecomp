/*
 * seh32: guest structured exceptions, dispatched over the guest's own chain.
 *
 * A guest that raises with RaiseException expects Windows to walk fs:[0] and
 * ask each registered handler. The guest's chain is in its own TIB (make_tib),
 * which Windows never sees, so the real RaiseException found no handler and
 * ended the process. Borland's runtimes raise this way for every exception:
 * Delphi's `raise` (0x0EEDFADE), C++Builder's `throw` (0x0EEFFACE), and both
 * use the same chain for try/finally.
 *
 * So shim_RaiseException walks the chain here: each handler is called as
 * guest code with (EXCEPTION_RECORD*, registration, CONTEXT*, 0), in guest
 * memory below the raiser's stack. ExceptionContinueExecution returns from
 * RaiseException; ExceptionContinueSearch goes on to the next frame. A handler
 * that takes the exception calls RtlUnwind (shim_RtlUnwind: every frame above
 * its own is called again with EXCEPTION_UNWINDING, then popped), and then
 * continues inside the function that registered the frame, at its except
 * block, by a jump with that function's ebp. Lifted, that function's body is
 * further up the host stack: the host makes the jump with native32_seh_continue
 * (a patch at the runtime's jump), which longjmps into that body's landing pad
 * (RECOMP_EH_ENTER, eh32.c), found by the registration RtlUnwind stopped at.
 *
 * An MSVC guest's _except_handler3 enters its __except block by calling an
 * address inside the function that registered the frame, with that
 * function's ebp. The call misses the dispatch table and lands in the body's
 * landing pad (RECOMP_EH_FRAME, recomp_eh_jump in eh32.c), so no patch is
 * needed when the lift gives __try functions their frames
 * (tools/lift/eh32.py).
 *
 * Off unless the host sets native32_guest_seh: a lift made before eh32.py
 * knew __try frames has no landing pads, and it is better to crash at the
 * raise than to resume wrong. Included by native32.c.
 *
 * ponytail: hardware faults in guest code are not offered to the guest's
 * handlers (an access violation stays a crash), and the CONTEXT a handler gets
 * has the integer registers only.
 */

int native32_guest_seh;

#define SEH_UNWINDING   2u
#define SEH_EXIT_UNWIND 4u

/* The registration the last RtlUnwind stopped at, for native32_seh_continue. */
static __declspec(thread) uint32_t t_unwind_target;
static int seh_trace = -1;

/* A guest handler: cdecl, four arguments. Every register but eax is kept. */
static uint32_t seh_call(uint32_t handler, uint32_t er, uint32_t reg, uint32_t ctx) {
    recomp_func_t fn = recomp_lookup(handler);
    if (!fn) {
        fprintf(stderr, "[seh32] handler 0x%08X of frame 0x%08X is not lifted\n", handler, reg);
        return 1;    /* ExceptionContinueSearch */
    }
    uint32_t esp = g_esp, ebp = g_ebp, ebx = g_ebx, esi = g_esi, edi = g_edi, cur = g_cur_func;
    /* The frame of ntdll's ExecuteHandler2, which makes the call: its ebp
     * frame holds the same four arguments, and C++Builder's handler stub
     * reads them there ([ebp+8]..[ebp+14h]), not from its own stack. */
    for (int pass = 0; pass < 2; pass++) {
        PUSH32(g_esp, 0);
        PUSH32(g_esp, ctx);
        PUSH32(g_esp, reg);
        PUSH32(g_esp, er);
        if (pass == 0) {
            PUSH32(g_esp, 0);            /* its return address */
            PUSH32(g_esp, g_ebp);
            g_ebp = g_esp;
        }
    }
    PUSH32(g_esp, RECOMP_RETADDR);
    fn();
    uint32_t eax = g_eax;
    if (seh_trace > 0)
        fprintf(stderr, "[seh32]   handler 0x%08X of frame 0x%08X%s -> %u\n", handler, reg,
                MEM32(er + 4) & SEH_UNWINDING ? " (unwinding)" : "", eax);
    g_esp = esp, g_ebp = ebp, g_ebx = ebx, g_esi = esi, g_edi = edi, g_cur_func = cur;
    return eax;
}

/* An EXCEPTION_RECORD and a CONTEXT below the current guest esp, which is
 * lowered past them: the handlers run beneath. */
static uint32_t seh_records(uint32_t code, uint32_t flags, uint32_t n, uint32_t args, uint32_t* ctx) {
    g_esp = (g_esp - (sizeof(EXCEPTION_RECORD) + sizeof(CONTEXT) + 64)) & ~15u;
    EXCEPTION_RECORD* er = (EXCEPTION_RECORD*)(uintptr_t)g_esp;
    CONTEXT* c = (CONTEXT*)(er + 1);
    memset(er, 0, sizeof *er + sizeof *c);
    er->ExceptionCode = code;
    er->ExceptionFlags = flags;
    er->NumberParameters = n > EXCEPTION_MAXIMUM_PARAMETERS ? EXCEPTION_MAXIMUM_PARAMETERS : n;
    for (DWORD i = 0; args && i < er->NumberParameters; i++)
        er->ExceptionInformation[i] = MEM32(args + 4 * i);
    c->ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
    c->Eax = g_eax, c->Ecx = g_ecx, c->Edx = g_edx, c->Ebx = g_ebx;
    c->Esi = g_esi, c->Edi = g_edi, c->Ebp = g_ebp, c->Esp = g_esp;
    *ctx = (uint32_t)(uintptr_t)c;
    return (uint32_t)(uintptr_t)er;
}

/* 1 if a guest handler took the exception and asked to continue. A handler
 * that unwinds and jumps does not come back here at all. */
static int seh_dispatch(uint32_t code, uint32_t flags, uint32_t n, uint32_t args) {
    if (seh_trace < 0) seh_trace = getenv("NATIVE32_TRACE_EH") != NULL;
    uint32_t reg = MEM32(g_fs_base);
    if (!reg || reg == 0xFFFFFFFFu) return 0;
    uint32_t esp = g_esp, ctx;
    uint32_t er = seh_records(code, flags, n, args, &ctx);
    if (seh_trace) {
        fprintf(stderr, "[seh32] raise 0x%08X from sub_%08X, first frame 0x%08X, esp 0x%08X (stack 0x%08X-0x%08X)\n",
                code, g_cur_func, reg, g_esp, MEM32(g_fs_base + 8), MEM32(g_fs_base + 4));
        /* Delphi's: [0] the raising address, [1] the object: its class name
         * (a ShortString at VMT-44) and its message (an AnsiString at +4). */
        uint32_t obj = n >= 2 && args ? MEM32(args + 4) : 0, vmt = obj ? MEM32(obj) : 0;
        if (code == 0x0EEDFADEu && vmt > 0x10000u) {
            const uint8_t* cn = (const uint8_t*)(uintptr_t)MEM32(vmt - 44);
            const char* msg = (const char*)(uintptr_t)MEM32(obj + 4);
            fprintf(stderr, "[seh32]   %.*s at 0x%08X: %.200s\n", cn ? cn[0] : 0, cn ? (const char*)cn + 1 : "",
                    MEM32(args), msg && !IsBadStringPtrA(msg, 200) ? msg : "");
        }
        for (uint32_t r = reg; r && r != 0xFFFFFFFFu; r = MEM32(r))
            fprintf(stderr, "[seh32]   frame 0x%08X: handler 0x%08X, %08X %08X\n", r, MEM32(r + 4),
                    MEM32(r + 8), MEM32(r + 12));
    }
    for (; reg && reg != 0xFFFFFFFFu; reg = MEM32(reg)) {
        uint32_t disp = seh_call(MEM32(reg + 4), er, reg, ctx);
        if (disp == 0) {             /* ExceptionContinueExecution */
            g_esp = esp;
            return 1;
        }
    }
    g_esp = esp;
    if (seh_trace) fprintf(stderr, "[seh32] 0x%08X: no guest frame took it\n", code);
    return 0;
}

/* RtlUnwind(TargetFrame, TargetIp, ExceptionRecord, ReturnValue), stdcall.
 * Returns to its caller: TargetIp is where the caller goes on anyway. */
static void shim_RtlUnwind(void) {
    uint32_t target = MEM32(g_esp + 4), er = MEM32(g_esp + 12), ret = MEM32(g_esp + 16);
    if (!native32_guest_seh) {   /* as before: the real one */
        RtlUnwind((PVOID)(uintptr_t)target, (PVOID)(uintptr_t)MEM32(g_esp + 8),
                  (PEXCEPTION_RECORD)(uintptr_t)er, (PVOID)(uintptr_t)ret);
        g_esp += 4 + 4 * 4;
        return;
    }
    uint32_t esp = g_esp, ctx;
    uint32_t mine = seh_records(0xC0000027u /* STATUS_UNWIND */, 0, 0, 0, &ctx);
    if (!er) er = mine;
    MEM32(er + 4) |= SEH_UNWINDING | (target ? 0 : SEH_EXIT_UNWIND);
    for (uint32_t reg = MEM32(g_fs_base); reg && reg != 0xFFFFFFFFu && reg != target; ) {
        seh_call(MEM32(reg + 4), er, reg, ctx);
        reg = MEM32(reg);
        MEM32(g_fs_base) = reg;
    }
    t_unwind_target = target;
    if (seh_trace > 0) fprintf(stderr, "[seh32] RtlUnwind to frame 0x%08X done\n", target);
    g_esp = esp + 4 + 4 * 4;
    g_eax = ret;
}

/* The jump into the except block of the frame RtlUnwind stopped at, with the
 * guest registers as they are (the runtime has set that function's ebp). */
void native32_seh_continue(uint32_t va) {
    recomp_ehframe_t* f = t_unwind_target ? recomp_eh_owner(t_unwind_target) : NULL;
    if (seh_trace)
        fprintf(stderr, "[seh32] continue at 0x%08X in the frame at 0x%08X (body sub_%08X)\n",
                va, t_unwind_target, f ? f->func : 0);
    if (!f) {
        fprintf(stderr, "[seh32] no lifted body owns frame 0x%08X (continue at 0x%08X)\n",
                t_unwind_target, va);
        return;
    }
    recomp_eh_resume(f, va);
}
