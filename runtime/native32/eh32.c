/*
 * eh32: guest C++ exceptions for lifted x86-32 code (MSVC's frame-based EH).
 *
 * A guest `throw` reaches _CxxThrowException, which would RaiseException on
 * the host and walk the host's SEH chain: it has never heard of the guest's
 * frames, so a throw the guest would catch one frame up kills the process.
 * That is not an edge case. Unreal signals recoverable failures by throwing
 * (UObject::StaticLoadObject catches its own "can't resolve package name"),
 * and every `guard`/`unguard` is a try/catch.
 *
 * x86 MSVC registers its handlers on the stack, so the guest describes its own
 * frames: fs:[0] heads a chain of {next, handler} records that the lifted
 * prologues build in guest memory exactly as the original did. A C++ frame's
 * handler is a stub `mov eax, FuncInfo; jmp __CxxFrameHandler`, and FuncInfo
 * holds the unwind map (state -> destructor funclet) and the try blocks. The
 * frame's state index is at record+8 and its ebp is record+12. So the throw is
 * dispatched here, entirely from guest data, the way __CxxFrameHandler would:
 *
 *   1. walk the chain for a try block that covers its frame's state and has a
 *      catch matching a type in the ThrowInfo (by decorated name, since the
 *      thrower and the catcher can be different modules);
 *   2. run every unwind funclet between the throw and that frame, and the
 *      catching frame's own down to the try block;
 *   3. store the exception object in the catch's variable, run the catch
 *      funclet as guest code (ebp = the frame's), which returns where the
 *      function continues;
 *   4. longjmp into the lifted body that owns the frame. generate.py gives
 *      every function that installs a handler a setjmp landing pad at entry
 *      (RECOMP_EH_ENTER) and a label at each continuation (tools/lift/eh32.py).
 *
 * A throw nothing in the guest catches goes to the real _CxxThrowException,
 * so the host's crash report sees it as before.
 *
 * Included at the end of native32.c, so hosts need no change to their build.
 *
 * ponytail: C++ frames only. A __try/__except (SEH, _except_handler3) frame
 * is skipped, not asked: its filter could catch a C++ throw, and its __finally
 * blocks do not run on the way past. Add when a title catches that way.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "recomp_types.h"

#define EH_MAGIC_VC6   0x19930520u
#define EH_MAGIC_VC7   0x19930521u
#define EH_MAGIC_VC8   0x19930522u

static __declspec(thread) recomp_ehframe_t* t_frames;   /* newest first */
/* The exception a running catch funclet holds, for a bare `throw;`. */
static __declspec(thread) uint32_t t_cur_obj, t_cur_info;

void recomp_eh_push(recomp_ehframe_t* f) { f->prev = t_frames; t_frames = f; }

void recomp_eh_pop(recomp_ehframe_t* f) {
    /* A longjmp past this frame already dropped it. */
    for (recomp_ehframe_t* p = t_frames; p; p = p->prev)
        if (p == f) { t_frames = f->prev; return; }
}

/* The FuncInfo a C++ frame's handler stub names, or 0 if it is not one. */
static uint32_t funcinfo(uint32_t handler) {
    const uint8_t* h = (const uint8_t*)(uintptr_t)handler;
    if (handler < 0x10000u || IsBadReadPtr(h, 11) || h[0] != 0xB8) return 0;
    if (h[5] != 0xE9 && !(h[5] == 0xFF && h[6] == 0x25)) return 0;
    uint32_t fi = *(const uint32_t*)(h + 1);
    if (IsBadReadPtr((void*)(uintptr_t)fi, 20)) return 0;
    uint32_t magic = MEM32(fi);
    return magic == EH_MAGIC_VC6 || magic == EH_MAGIC_VC7 || magic == EH_MAGIC_VC8 ? fi : 0;
}

/* Run guest code at va as MSVC's _CallSettingFrame does: ebp = the frame's,
 * on the current guest stack. Returns eax; every other register is kept. */
static uint32_t call_funclet(uint32_t va, uint32_t frame_ebp) {
    recomp_func_t fn = recomp_lookup(va);
    if (!fn) {
        fprintf(stderr, "[eh32] funclet 0x%08X is not lifted\n", va);
        return 0;
    }
    uint32_t esp = g_esp, ebp = g_ebp, ebx = g_ebx, esi = g_esi, edi = g_edi, cur = g_cur_func;
    g_ebp = frame_ebp;
    g_esp -= 4;
    MEM32(g_esp) = 0;                   /* return address: the funclet's ret pops it */
    fn();
    uint32_t eax = g_eax;
    g_esp = esp, g_ebp = ebp, g_ebx = ebx, g_esi = esi, g_edi = edi, g_cur_func = cur;
    return eax;
}

/* Destroy a C++ frame's locals from its current state down to `to`. */
static void unwind_to(uint32_t rec, uint32_t fi, int to) {
    int s = (int)MEM32(rec + 8);
    uint32_t map = MEM32(fi + 8);
    int max = (int)MEM32(fi + 4);
    while (s != to && s >= 0 && s < max) {
        int next = (int)MEM32(map + 8 * s);
        uint32_t action = MEM32(map + 8 * s + 4);
        MEM32(rec + 8) = (uint32_t)next;
        if (action) call_funclet(action, rec + 12);
        s = next;
    }
}

/* The ThrowInfo's CatchableType that a catch of `type` takes, or 0. */
static uint32_t catchable(uint32_t info, uint32_t type) {
    uint32_t arr = MEM32(info + 12);
    int n = (int)MEM32(arr);
    for (int i = 0; i < n; i++) {
        uint32_t ct = MEM32(arr + 4 + 4 * i);
        uint32_t td = MEM32(ct + 4);
        if (td == type || !strcmp((const char*)(uintptr_t)(td + 8), (const char*)(uintptr_t)(type + 8)))
            return ct;
    }
    return 0;
}

/* Store the thrown object into the catch's variable. */
static void bind_catch_object(uint32_t handler, uint32_t ct, uint32_t obj, uint32_t frame_ebp) {
    uint32_t adj = MEM32(handler), disp = MEM32(handler + 8);
    if (!MEM32(handler + 4) || !disp || !ct) return;       /* catch(...) or no variable */
    uint32_t dst = frame_ebp + disp;
    uint32_t src = obj + MEM32(ct + 8);                     /* this-displacement (mdisp) */
    uint32_t size = MEM32(ct + 20), copy = MEM32(ct + 24);
    if (adj & 8) MEM32(dst) = src;                          /* by reference */
    else if (MEM32(ct) & 1 || !copy) memcpy((void*)(uintptr_t)dst, (void*)(uintptr_t)src, size);
    else {                                                  /* copy constructor, thiscall */
        uint32_t ecx = g_ecx;
        g_ecx = dst;
        g_esp -= 4;
        MEM32(g_esp) = src;
        call_funclet(copy, g_ebp);   /* ret 4 pops the argument */
        g_ecx = ecx;
    }
}

static int dispatch(uint32_t obj, uint32_t info) {
    uint32_t top = MEM32(g_fs_base);
    for (uint32_t rec = top; rec && rec != 0xFFFFFFFFu; rec = MEM32(rec)) {
        uint32_t fi = funcinfo(MEM32(rec + 4));
        if (!fi) continue;
        int state = (int)MEM32(rec + 8);
        uint32_t tries = MEM32(fi + 16);
        int ntry = (int)MEM32(fi + 12);
        for (int t = 0; t < ntry; t++) {
            uint32_t tb = tries + 20 * t;
            int lo = (int)MEM32(tb), hi = (int)MEM32(tb + 4), ncatch = (int)MEM32(tb + 12);
            if (state < lo || state > hi) continue;
            for (int c = 0; c < ncatch; c++) {
                uint32_t h = MEM32(tb + 16) + 16 * c;
                uint32_t type = MEM32(h + 4);
                uint32_t ct = type ? catchable(info, type) : 0;
                if (type && !ct) continue;
                /* Caught: unwind everything above, then this frame to the try. */
                for (uint32_t r = top; r != rec; r = MEM32(r)) {
                    uint32_t f = funcinfo(MEM32(r + 4));
                    if (f) unwind_to(r, f, -1);
                }
                unwind_to(rec, fi, lo);
                MEM32(g_fs_base) = rec;
                MEM32(rec + 8) = (uint32_t)(hi + 1);
                uint32_t ebp = rec + 12;
                bind_catch_object(h, ct, obj, ebp);
                uint32_t prev_obj = t_cur_obj, prev_info = t_cur_info;
                t_cur_obj = obj, t_cur_info = info;
                uint32_t resume = call_funclet(MEM32(h + 12), ebp);
                t_cur_obj = prev_obj, t_cur_info = prev_info;
                /* The catch returned: continue in the frame's own function,
                 * on its stack as its prologue left it ([ebp-0x10]). */
                for (recomp_ehframe_t* f = t_frames; f; f = f->prev) {
                    if (f->entry_esp != ebp + 4) continue;
                    t_frames = f;
                    g_ebp = ebp;
                    g_esp = MEM32(ebp - 0x10);
                    g_eax = resume;
                    f->resume = resume;
                    longjmp(f->jb, 1);
                }
                fprintf(stderr, "[eh32] frame 0x%08X caught, but no lifted body owns it (resume 0x%08X)\n",
                        ebp, resume);
                return 0;
            }
        }
    }
    return 0;
}

typedef void (__stdcall *cxx_throw_t)(void*, void*);

/* _CxxThrowException(object, ThrowInfo), stdcall, in the lifted model. */
void native32_shim_CxxThrowException(void) {
    uint32_t obj = MEM32(g_esp + 4), info = MEM32(g_esp + 8);
    if (!info) obj = t_cur_obj, info = t_cur_info;          /* `throw;` */
    g_esp += 4;                                             /* the call's return address */
    if (info) dispatch(obj, info);
    /* Nothing in the guest catches it: the host's crash report does. */
    static cxx_throw_t real;
    if (!real) real = (cxx_throw_t)GetProcAddress(LoadLibraryA("msvcrt.dll"), "_CxxThrowException");
    real((void*)(uintptr_t)obj, (void*)(uintptr_t)info);
}
