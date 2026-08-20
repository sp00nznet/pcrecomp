/*
 * hybrid.h - the lifted <-> real boundary for a partially recompiled program.
 *
 * A static recompilation is rarely all-or-nothing. You lift the application and
 * leave its libraries (MFC, the CRT, the OS) as real machine code, which means
 * control crosses the boundary in BOTH directions:
 *
 *     lifted -> real    an import call, or a function you have not lifted yet
 *     real   -> lifted  a library calling back into application code: a vtable
 *                       slot, a window procedure, a qsort comparator, an
 *                       _initterm initializer table
 *
 * The first direction is obvious and everyone builds it. The second is what
 * lets the *application body* run recompiled while its framework stays real,
 * and it is where the subtle bugs live. This header is both directions, model
 * agnostic: it talks in a plain register block, so it works whether your lifted
 * code uses a CPU struct (`c->eax`) or global registers (`g_eax`).
 *
 * Proven on Microsoft Encarta 97 (MFC 4.0): 10,432 routed function-pointer
 * slots, 10,242 real MFC virtual dispatches per session landing in lifted code.
 *
 * See docs/HYBRID.md for the three correctness rules and the bisect method for
 * finding which slot or which function is the broken one.
 */
#ifndef PCRECOMP_HYBRID_H
#define PCRECOMP_HYBRID_H

#include <stdint.h>
#include <stddef.h>

/* The registers that cross the boundary. Marshal to/from your own CPU model. */
typedef struct {
    uint32_t eax, ecx, edx, ebx, esp, ebp, esi, edi;
} hybrid_regs;

/* ---------------- lifted -> real ----------------
 *
 * Run real machine code at `target` with `r`'s registers loaded and esp set to
 * the emulated stack, then read the results back into `r`.
 *
 * Convention: on entry r->esp points at the (fake) return-address slot your
 * lifted `call` pushed, with arguments above it - exactly the x86 layout. On
 * return r->eax / r->edx hold the result and r->esp reflects any stdcall
 * callee cleanup.
 *
 * It is reentrant: the real code you call may call back into lifted code, which
 * may call real code again. See docs/HYBRID.md rule 2.
 */
void hybrid_call_machine(hybrid_regs *r, uint32_t target);

/* ---------------- real -> lifted ----------------
 *
 * The host supplies this: run the lifted function whose ORIGINAL va is `ova`
 * with the given registers, and return
 *
 *     (uint64_t)result | ((uint64_t)arg_bytes_cleaned << 32)
 *
 * `arg_bytes_cleaned` is what the callee's `ret N` popped, so the trampoline can
 * return __thiscall/__stdcall-correctly. With the usual "caller pushes a return
 * slot" lifting convention that is `final_esp - initial_esp - 4`.
 *
 * `real_args` points at the real caller's first argument; real_args[-1] is its
 * return address. `r->esp` is the emulated frame the trampoline set up, with
 * the arguments already copied there.
 */
typedef uint64_t (*hybrid_invoke_fn)(uint32_t ova, hybrid_regs *r, uint32_t *real_args);

/* Call once before making any thunks. `frame_bytes` is how much emulated stack
 * each nested real->lifted call gets (0x8000 is a sane default); `arena_bytes`
 * bounds total nesting (8 MB is plenty). Returns 0 on failure. */
int hybrid_init(hybrid_invoke_fn invoke, uint32_t frame_bytes, uint32_t arena_bytes);

/* An address real code can CALL (or store in a vtable) that lands in the lifted
 * function whose original VA is `ova`. Stable for the life of the process. */
uint32_t hybrid_thunk(uint32_t ova);

/* Is `addr` one of our thunks? If so, *out_ova gets the target's original VA.
 * Your dispatch should check this first: lifted code that reads a routed slot
 * and calls through it hands you a thunk address, not a function VA. */
int hybrid_thunk_target(uint32_t addr, uint32_t *out_ova);

/* Number of real->lifted calls made so far (a progress signal worth printing:
 * it is how much of the application body is actually running recompiled). */
unsigned long hybrid_r2l_calls(void);

/* ---------------- vtable / function-pointer routing ----------------
 *
 * Rewrite every .rdata/.data slot that points at a lifted function start into a
 * thunk, so real virtual dispatch lands in lifted code.
 *
 * `is_fn_start(ova)` must answer "is this the entry of a function I lifted?".
 * IMPORTANT: it must NOT be filtered by whatever range you are bisecting with -
 * see docs/HYBRID.md, "the bisect that lied".
 *
 * Only runs of >= min_run consecutive valid function pointers are rewritten,
 * which keeps jump tables (whose entries are mid-function) and data that merely
 * looks pointer-ish out of it. 3 is a good value.
 *
 * slot_lo/slot_hi bound WHICH slots get routed, in scan order, so you can
 * binary-search a slot that breaks the program. Pass 0 / INT_MAX for all.
 * *out_total, if non-NULL, gets the number of candidate slots seen (the bisect
 * upper bound). Returns the number actually routed.
 */
typedef int (*hybrid_is_fn_start)(uint32_t ova);
int hybrid_route_fnptr_slots(void *image_base, int32_t image_delta,
                             hybrid_is_fn_start is_fn_start, int min_run,
                             int slot_lo, int slot_hi, int *out_total);

/* The original VA a routed slot pointed at, by scan index - so a bisect that
 * narrows to one slot can say which function it is. -1 if out of range. */
uint32_t hybrid_slot_target(int slot_index);

#endif /* PCRECOMP_HYBRID_H */
