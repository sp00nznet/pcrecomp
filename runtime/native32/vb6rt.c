/*
 * vb6rt: a Visual Basic 5/6 guest on the real MSVBVM60.DLL (or MSVBVM50).
 *
 * A native-compiled VB program is mostly calls into its runtime, and the
 * runtime is not the C ABI: its helpers take arguments in ecx and edx
 * (__vbaStrCopy, __vbaFreeStr, __vbaVarMove), __vbaChkstk moves esp and
 * zeroes the new locals, and its error handling reads the caller's frame
 * through ebp and fs:[0]. So:
 *
 *   0. the runtime is a guest-ABI range (native32_add_guest_abi): entered
 *      with the guest's registers, on the guest's stack, and calls back with
 *      them (its error handler calls a procedure's cleanup with that
 *      procedure's ebp);
 *   1. it finds the procedure it is in through fs:[0] (__vbaOnError writes
 *      the mode into the frame; __vbaExitProc and the error raise read it),
 *      so a call into it runs with the guest's SEH chain on the real fs:[0]
 *      (gen_bridge, native32_fs_mirror_lo/hi);
 *   2. a runtime error (a failed late-bound call, Err.Raise, a type
 *      mismatch) is a real RaiseException inside it, code 0xC000008F. A
 *      vectored handler moves off the guest stack (the runtime's own frames
 *      are on it) to the host stack below the bridge's anchor and offers the
 *      error to the guest's chain (seh32's dispatch): __vbaExceptHandler runs
 *      through the procedure's frame, as Windows would have called it;
 *   3. a procedure with `On Error` takes it, and the runtime continues
 *      inside it (its handler label, or the next statement for Resume Next)
 *      through one small helper, `push ebp; mov ebp, esp; mov ecx, [ebp+14h];
 *      mov ebx, [ebp+8]; mov esp, [ebp+10h]; mov ebp, [ebp+0Ch]; call ecx;
 *      jmp ebx`. That helper is patched to jump to vb_resume here (when the
 *      address is in a lifted body: a VB OCX's own continue as before), which puts
 *      back what the bridges it skips would have (gen_unwind), sets the
 *      guest's ebp and esp and longjmps into the lifted body at that address
 *      (eh32's landing pad: the body was lifted with RECOMP_EH_FRAME and the
 *      procedure's resume points, tools/pe/vb6.py error_resumes);
 *   4. nothing takes it: reported, and the process ends (VB's own unhandled
 *      error box is never reached this way).
 *
 * Patterns, not addresses: nothing here depends on one MSVBVM60 build.
 * ponytail: one guest thread (a VB6 exe has one); the helper's stack-limit
 * callback (ecx) is not run, it only re-arms a stack-overflow guard; a
 * handler answering "continue execution" is not supported (VB's never does).
 * Included by native32.c after seh32.c.
 */
#define VB_ERROR_CODE 0xC000008Fu

recomp_ehframe_t* recomp_eh_find(uint32_t va, uint32_t ebp);   /* eh32.c */

static const uint8_t vb_resume_helper[] = {
    0x55, 0x8B, 0xEC, 0x8B, 0x4D, 0x14, 0x8B, 0x5D, 0x08, 0x8B, 0x65, 0x10,
    0x8B, 0x6D, 0x0C, 0xFF, 0xD1, 0xFF, 0xE3 };

/* Put back what every gen_bridge entered below the frame at guest esp
 * `entry_esp` would have on return: the TEB's stack bounds, its widening
 * count and the anchor, newest first. Bridges entered from that body or
 * deeper were called with a lower guest esp. */
static void gen_unwind(uint32_t entry_esp) {
    NT_TIB* tib = (NT_TIB*)NtCurrentTeb();
    while (t_gen_n > 0 && (t_gen_n > MAX_GEN_NEST || t_gen[t_gen_n - 1].gesp < entry_esp)) {
        t_gen_n--;
        if (t_gen_n >= MAX_GEN_NEST) continue;
        gen_saved_t* g = &t_gen[t_gen_n];
        tib->StackBase = (PVOID)(uintptr_t)g->lim0;
        tib->StackLimit = (PVOID)(uintptr_t)g->lim1;
        if (g->widened) g_teb_widened--;
        __writefsdword(0x14, g->anchor);
    }
}

static void __cdecl vb_resume(uint32_t target, uint32_t ebp, uint32_t esp, uint32_t cb);
static int __cdecl vb_lifted(uint32_t target, uint32_t ebp) { return recomp_eh_find(target, ebp) != NULL; }

/* The patched helper jumps here with (target, ebp, esp, callback) on the
 * stack. A continuation in a lifted body goes to vb_resume; anything else (a
 * VB OCX's own procedure, run natively) is the helper's own four lines. */
static __declspec(naked) void vb_resume_stub(void) {
    __asm {
        push dword ptr [esp + 8]     ; ebp
        push dword ptr [esp + 8]     ; target (moved up by the push)
        call vb_lifted
        add  esp, 8
        test eax, eax
        jnz  lifted
        push ebp
        mov  ebp, esp
        mov  ecx, [ebp + 14h]
        mov  ebx, [ebp + 8]
        mov  esp, [ebp + 10h]
        mov  ebp, [ebp + 0Ch]
        call ecx
        jmp  ebx
    lifted:
        jmp  vb_resume
    }
}

static void __cdecl vb_resume(uint32_t target, uint32_t ebp, uint32_t esp, uint32_t cb) {
    (void)cb;
    if (seh_trace > 0)
        fprintf(stderr, "[vb6rt] continue at 0x%08X, ebp 0x%08X esp 0x%08X\n", target, ebp, esp);
    recomp_ehframe_t* f = recomp_eh_find(target, ebp);
    if (f) {
        /* The guest keeps the chain the runtime left on the real fs:[0], from
         * its first frame on the guest's stack; the host gets back the
         * registration the landing pad's setjmp saw, so longjmp has nothing
         * of the host's to unwind. */
        uint32_t lo = MEM32(g_fs_base + 8), hi = MEM32(g_fs_base + 4), r = __readfsdword(0);
        while (r != 0xFFFFFFFFu && r && (r < lo || r >= hi)) r = *(uint32_t*)(uintptr_t)r;
        MEM32(g_fs_base) = r ? r : 0xFFFFFFFFu;
        gen_unwind(f->entry_esp);
        __writefsdword(0, (DWORD)((_JUMP_BUFFER*)f->jb)->Registration);
        g_ebp = ebp;
        g_esp = esp;
        recomp_eh_resume(f, target);
    }
    fprintf(stderr, "[vb6rt] no lifted body continues at 0x%08X (ebp 0x%08X): lift it with "
                    "its procedure's error_resumes\n", target, ebp);
    TerminateProcess(GetCurrentProcess(), 3);
}

/* The raise, on the host stack: offered to the guest's chain. */
static __declspec(thread) EXCEPTION_RECORD t_vb_er;
static __declspec(thread) uint32_t t_vb_esp;

static void __cdecl vb_dispatch(void) {
    /* Below the runtime's frames on the guest stack: they are not returned
     * to (the handler resumes by longjmp, or the process ends). */
    g_esp = (t_vb_esp - 0x200) & ~15u;
    if (seh_trace > 0) {
        uint32_t reg = MEM32(g_fs_base), desc = MEM32(reg + 12), tbl = desc ? MEM32(desc + 0x14) : 0;
        uint32_t line = MEM32(reg + 0x1C);
        fprintf(stderr, "[vb6rt] in the procedure of frame %08X, statement %u at 0x%08X\n", reg, line,
                tbl && line < MEM32(tbl) ? MEM32(tbl + 4 + 4 * line) : 0);
    }
    seh_dispatch(t_vb_er.ExceptionCode, t_vb_er.ExceptionFlags, t_vb_er.NumberParameters,
                 (uint32_t)(uintptr_t)t_vb_er.ExceptionInformation);
    fprintf(stderr, "[vb6rt] Visual Basic runtime error 0x%08X: no procedure's On Error took it "
                    "(in sub_%08X)\n", (uint32_t)t_vb_er.ExceptionInformation[0], g_cur_func);
    recomp_trace_flush();
    TerminateProcess(GetCurrentProcess(), 3);
}

static __declspec(naked) void vb_dispatch_tramp(void) {
    __asm {
        mov  esp, fs:[0x14]      ; the innermost bridge's anchor: free below
        sub  esp, 64
        and  esp, 0FFFFFFF0h
        call vb_dispatch
        int  3
    }
}

static LONG CALLBACK vb_veh(EXCEPTION_POINTERS* ep) {
    EXCEPTION_RECORD* er = ep->ExceptionRecord;
    if (er->ExceptionCode != VB_ERROR_CODE || !t_gen_n || !g_teb_widened)
        return EXCEPTION_CONTINUE_SEARCH;
    /* Frames above the guest's on the real chain are native code's own: a VB
     * OCX's procedures, the runtime's internal ones. They are asked first,
     * here, as Windows would (one that takes the error unwinds and jumps,
     * natively, and never comes back); Windows cannot be left to do it,
     * because it would then reach the guest's frames, whose handler is an
     * address in the guest image it will not call. */
    typedef EXCEPTION_DISPOSITION (__cdecl *handler_t)(EXCEPTION_RECORD*, void*, CONTEXT*, void*);
    uint32_t head = MEM32(g_fs_base), r = __readfsdword(0);
    for (; r != head && r && r != 0xFFFFFFFFu; r = MEM32(r))
        if (((handler_t)(uintptr_t)MEM32(r + 4))(er, (void*)(uintptr_t)r, ep->ContextRecord, NULL)
                == ExceptionContinueExecution)
            return EXCEPTION_CONTINUE_EXECUTION;
    if (r != head) return EXCEPTION_CONTINUE_SEARCH;
    t_vb_er = *er;
    t_vb_esp = ep->ContextRecord->Esp;
    if (seh_trace > 0) {
        fprintf(stderr, "[vb6rt] error %08X raised at %p (x87 sw %04lX tags %04lX cw %04lX); callers:",
                (uint32_t)er->ExceptionInformation[0], er->ExceptionAddress,
                ep->ContextRecord->FloatSave.StatusWord & 0xFFFF, ep->ContextRecord->FloatSave.TagWord & 0xFFFF,
                ep->ContextRecord->FloatSave.ControlWord & 0xFFFF);
        for (uint32_t bp = ep->ContextRecord->Ebp, k = 0; k < 12 && bp >= t_vb_esp &&
             bp < MEM32(g_fs_base + 4); bp = MEM32(bp), k++)
            fprintf(stderr, " %08X", MEM32(bp + 4));
        fprintf(stderr, "\n");
    }
    ep->ContextRecord->Eip = (DWORD)(uintptr_t)vb_dispatch_tramp;
    return EXCEPTION_CONTINUE_EXECUTION;
}

int native32_vb6_runtime(void) {
    if (seh_trace < 0) seh_trace = getenv("NATIVE32_TRACE_EH") != NULL;
    HMODULE m = GetModuleHandleA("msvbvm60.dll");
    if (!m) m = GetModuleHandleA("msvbvm50.dll");
    if (!m) return 0;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((uint8_t*)m + ((IMAGE_DOS_HEADER*)m)->e_lfanew);
    uint8_t* b = (uint8_t*)m;
    uint32_t size = nt->OptionalHeader.SizeOfImage, n = size - sizeof vb_resume_helper;
    native32_add_guest_abi((uint32_t)(uintptr_t)m, size);
    native32_fs_mirror_lo = (uint32_t)(uintptr_t)m;
    native32_fs_mirror_hi = native32_fs_mirror_lo + size;
    for (uint32_t i = 0x1000; i < n; i++) {
        if (memcmp(b + i, vb_resume_helper, sizeof vb_resume_helper)) continue;
        DWORD old;
        if (!VirtualProtect(b + i, 5, PAGE_EXECUTE_READWRITE, &old)) break;
        b[i] = 0xE9;
        *(int32_t*)(b + i + 1) = (int32_t)((uint8_t*)vb_resume_stub - (b + i + 5));
        VirtualProtect(b + i, 5, old, &old);
        FlushInstructionCache(GetCurrentProcess(), b + i, 5);
        AddVectoredExceptionHandler(1, vb_veh);
        if (seh_trace > 0) fprintf(stderr, "[vb6rt] resume helper at %p patched\n", b + i);
        return 1;
    }
    fprintf(stderr, "[vb6rt] the runtime's resume helper was not found: VB errors will not be handled\n");
    return 0;
}
