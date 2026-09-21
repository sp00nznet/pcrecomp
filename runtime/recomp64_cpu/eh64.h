/*
 * eh64.h - guest C++ exception handling for a lifted Win64 PE.
 *
 * A recompiled function is an ordinary C function, and the host unwinder knows
 * nothing about the try/catch blocks the ORIGINAL function had: its .xdata
 * describes machine code that is no longer being executed. So a guest `throw`
 * walks the host stack, finds no guest handler, and kills the process - even
 * when the guest would have caught it one frame up and carried on.
 *
 * That is not an edge case. UE3 signals recoverable failures by throwing:
 *
 *     UObject* UObject::StaticLoadObject(...)
 *     {
 *         try { ... }
 *         catch (TCHAR* Error) { SafeLoadError(...); return NULL; }
 *     }
 *
 * so every "failed to find object" in a shipping build is a throw that the
 * game swallows. Without this, the first one is fatal and reads convincingly
 * as missing content.
 *
 * The scheme:
 *
 *   * the guest STACK is faithful - the lifter pushes real return addresses
 *     and the prologues it executes build the original frames - so the
 *     original .pdata/.xdata still describes it exactly, and an ordinary x64
 *     virtual unwind over guest state works;
 *   * each lifted function that had a handler calls setjmp on entry, so there
 *     is a host landing pad for every guest frame that can catch;
 *   * the throw is caught where the guest raises it (RaiseException), not in a
 *     vectored handler, so the longjmp happens on a normal call stack.
 */
#ifndef ES3_EH64_H
#define ES3_EH64_H

#include <stdint.h>
#include <setjmp.h>

/* cpu64.h includes this header after the CPU typedef. */

typedef struct es3_ehframe {
    struct es3_ehframe *prev;
    jmp_buf         *jb;
    uint64_t         func;      /* guest VA of the function this frame runs */
    uint64_t         resume;    /* guest VA to continue at, set on a catch */
    int              cs_depth;  /* shadow call stack depth at entry */
} es3_ehframe_t;

void es3_eh_push(es3_ehframe_t *f, uint64_t func, jmp_buf *jb);
void es3_eh_pop(es3_ehframe_t *f);

/* Called from the runtime's _CxxThrowException interception, with the guest
 * state as the throwing function left it: ret_pc is where that function would
 * have resumed, c->rsp is its stack with the return address already consumed.
 *
 * Returns 0 when no guest frame catches, and the caller then lets the throw
 * take its normal course. Never returns when one does: it longjmps into the
 * catching frame's lifted body. */
int es3_eh_throw(CPU *c, uint64_t ret_pc, uint64_t obj, uint64_t throw_info);

/* The lifter emits these. _ind and _ljump belong to the generated body. */
#define ES3_EH_ENTER(va)                                                      \
    jmp_buf _ehjb;                                                            \
    es3_ehframe_t _ehf;                                                       \
    es3_eh_push(&_ehf, (va), &_ehjb);                                         \
    if (setjmp(_ehjb)) { _ind = _ehf.resume; goto _ljump; }

#define ES3_EH_LEAVE() es3_eh_pop(&_ehf)

#endif /* ES3_EH64_H */
