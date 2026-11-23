# XRC and pcrecomp's 32-bit lifter

[XRC](https://github.com/ps4star/XRC) is a static recompiler from 32-bit x86 (PE, ELF, Mach-O, raw) to portable C,
written in Odin. WhiteRecomp's FINAL FANTASY XIII port uses it to translate all 55,770 functions of that game. It is
public domain (The Unlicense). We owe it nothing, but we learned from it, so here is the credit. Thanks to its
author for a careful, well-documented piece of work. Its README explains every optimization with the numbers it
measured, which made this comparison easy.

This note compares the two lifters (pcrecomp's `tools/lift/lift32.py` + `generate.py` with `runtime/recomp32` and
`runtime/native32`, as of origin/main on 2026-11-23), says which of XRC's ideas are worth taking, and records the
first one taken.

## How the two are built

| | XRC | pcrecomp (lift32 / native32) |
|---|---|---|
| Decoder | Odin `core:rexcode` (patched), its own fast path | Capstone |
| Between decode and C | no IR for the C path (per-function plans: flags, x87, sync, stack, slots); an experimental LLVM-IR backend (SSA) | none: each instruction becomes C text directly, with a small amount of state (`_flag_state`) |
| Function discovery | a function map (Ghidra export, or symbols), plus targets of direct calls, `push offset`, jump tables and data | `disasm32.py` catalog, `generate.true_extent` walk, RTTI/vtable seeds, `seed_from_log` from runs |
| Translator speed | 55k functions in about 6 s (12 threads) | Red Alert 2: 25k functions in 377-650 s (Python, one thread) |
| Output | one C file per 64 KB guest page, only changed pages rewritten | one C file per N functions (ra2: 63 files, 5.9 M lines, 286 MB) |
| Verification | `XRC_INGAME`: the translation linked into the retail exe and checked against the original code as it runs; `XRC_FL_VERIFY` / `XRC_STACK_VERIFY` checking builds | `difftest.py` against hardware for single instructions; title playtests and goldens on the lifted build only. The house rule is never to run original executables, so we do not adopt `XRC_INGAME`. It is noted here only. |

## Technique by technique

"Today" is pcrecomp origin/main. The wins quoted for XRC are its own FF13 numbers.

| Technique | XRC | pcrecomp today | Expected win here | Effort / risk |
|---|---|---|---|---|
| Registers in C locals | always (`r_eax`…), synced to `XCtx` at calls / returns | **have it**: `RECOMP_LOCAL_REGS` (locals, written out before every call and return, all 8 reloaded after) | - | - |
| Reload only what a callee may change (callee-saved plan) | `x_abi_plan`: 49k of 55k functions keep ebx/esi/edi/ebp | none: every call reloads all 8 | **taken, see below** | low: one prepass, one macro, a run-time checker |
| Trim stores/loads by liveness (`xrc_sync`) | stores only dirty registers and loads only live ones: 46% of stores, 59% of loads go | none | speed, a little C size | medium: needs a per-function liveness over the C each instruction becomes. A good next step on top of the callee-saved plan |
| Lazy flags, computed only where read | per-function plan, setters store nothing when no reader | **mostly have it**: operand snapshot (`_flag_a/_b/_k`) in locals that the C compiler drops when dead; compare-branch fusion when the setter is textually before the reader. What remains: `RECOMP_FLAGS_OUT` (4 global stores) at every call and return, and `RECOMP_ENTER` reloads them, because flags deliberately cross calls (see the comment at `RECOMP_FLAGS_OUT`) | small speed | medium: the cross-call rule exists for real bugs (CRT `cos`, `_CIcos`), so dropping it needs a flow-exact proof that a callee never reads entry flags. `entry_reads_flags` is a 32-instruction heuristic, not a proof |
| Fusion across labels | fuses when one setter reaches the reader on every path | resets at every branch target and falls back to `recomp_cond(_flag_k, …)` at run time | small speed | medium |
| x87 at static depths, as doubles | `x87_flow`: depth fixed per instruction, slot k is a C double | **have it as an option**: `RECOMP_X87_RING` + `RECOMP_X87_LOCAL` (constant `_xk`, which the compiler folds). ra2 does not turn it on (ra2-integ does) | speed in float code | config only, per title |
| SSE as host intrinsics | `emmintrin.h`, vector extensions off x86; real rcp/rsqrt for bit-identical results | union lanes in plain C (`lift32_sse.py`), checked against hardware by difftest | speed in SSE-heavy titles | medium; bit-identity is already covered by difftest, so this is purely speed |
| Stack-balance analysis | `ret N` known per function, so esp after a call is `esp + N` (51k of 55k) | esp reloaded from `g_esp` after every call | speed: the compiler keeps `[esp+k]` addressing across calls | low-medium; the same prepass as the callee-saved plan. **Next candidate** |
| Read-only constant folding | `M32(0x25a3c20)` becomes `0x3f800000u` for non-writable sections: -1.8% battle, -3.7% more with 128-bit loads | none | small speed, smaller C | low; needs the section table in the lifter and a "patched" exclusion list (ra2's remaster patches, `patch_sites`) |
| Flat EA (64-bit `base + disp`) | -5% code, -3-4% time on x86-64 | 32-bit hosts mostly (`RECOMP_FLAT_MEMORY`: no base at all); 64-bit ports use `RECOMP_MEM_BASE` | 64-bit ports only | low |
| Stack slot promotion | `[ebp-k]` as C locals; measured no faster and riskier, so FF13 turns it off | none | - | skip |
| Inlining small functions | up to 24 instructions (64 hot) pasted at direct calls | none in the lifter. MSVC/clang can inline within one chunk file, but every call goes through the protocol | speed | medium-high (labels, flags, the return check) |
| Devirtualization from a profile | guarded fast path at sites where at least 90% of calls go to one target | `RECOMP_ICALL_SITE_CACHE` (last target, one compare) and `RECOMP_RESOLVE_CACHE`, both opt-in. ra2 uses neither (ra2-integ does) | the cache gets most of it with no profile | config only. A profile adds little over the cache unless it also inlines |
| Profile-guided layout (`layout_hot`) | hot functions moved into hot pages (C3 clustering): -3.5% to -8% | none: functions in address order | speed in large titles | medium: needs a call-count build and a profile per title |
| Translator cost | 6 s, multithreaded, only changed pages rewritten | minutes in Python; every chunk rewritten | developer time | separate project |

## Taken: the callee-saved register plan (`LIFT32_ABI`)

`generate.py` scans every body that `lift_function_linear` lifts. A body *keeps* a register when two things hold:

- On every path from its entry, it pushes the register before writing it, and does not write it again after the
  pop. This is a must-analysis over the body's own CFG, so an early exit that writes esi before the prologue's
  `push esi` counts against it. XRC's scan is linear and would miss that.
- Every direct callee and tail target keeps the register too. This is a greatest fixpoint over the call graph.

Indirect calls and switch jumps are trusted, as in XRC. Unlike XRC, a push around a call does not excuse its callee,
because an argument push looks the same. A target that nothing scanned keeps nothing, which covers hooks, stubs and
imports.

A direct call to a callee that keeps registers is lifted as `RECOMP_CALL_K(func, mask)`. It reloads eax, ecx, edx
and esp, and leaves the kept registers in the caller's locals. `RECOMP_ABI_CHECK` builds reload everything anyway and
report any claim that turns out false (`recomp_abi_violation`, native32).

How to use it:

- Set `LIFT32_ABI=<file>` and lift twice. The first lift writes the scans; the second uses them, and warns if a body
  changed since the plan was made.
- No driver changes are needed, since every lift32 driver goes through `lift_function_linear`.
- It is off when the variable is unset, so origin/main's output is unchanged.

Red Alert 2 (gamemd.exe, `--all`): 24,953 bodies scanned; 17,309 keep at least one register. 152,279 direct call
sites became `RECOMP_CALL_K`. Windows 2000 (calc with its 29 lifted DLLs): 58,940 bodies, 29,041 keep one.

| ra2, MSVC /O2, 12 threads | baseline | LIFT32_ABI |
|---|---|---|
| generated C | 285.8 MB | 287.0 MB (+0.4%) |
| ra2.exe | 135.5 MB | 131.4 MB (-3.0%) |
| clean build (two each, alternating) | 497 s, 532 s | 423 s, 418 s (**-18%**) |
| lift (Python) | 377 s | the same, run twice (the plan needs a first pass) |
| process CPU, skirmish-start, 180 s, 5 runs each, alternating | 55.7 s (50.6-61.7) | 56.9 s (54.4-60.0): no difference outside the noise |
| playtest suite (36 cases) | 36/36 (3 timing flakes on the first run, passing on rerun) | 36/36 |
| `RECOMP_ABI_CHECK` build, skirmish-start | - | 0 violations, in game |

Windows 2000 accessories (`tools/interact.py winmine notepad calc`, baseline and `LIFT32_ABI` builds from the same
tree, run back to back): identical rows on stage 1 and golden, 0 `RECOMP_ABI_CHECK` violations. The golden column
failed on both alike: the session's display changed between runs.

The check build earned its keep. The first plan trusted every indirect jump, and calc's `jmp [__imp__EH_prolog]`
thunk then counted as keeping ebp, although `_EH_prolog` sets the caller's ebp. calc faulted on its first button,
and the check build named the four callers. Now `jmp [absolute]` is an unknown tail, so an import thunk keeps
nothing.

The result in short: the run-time win is too small to measure on a speed-capped game, where most of the time is
host-side. The C compiler does visibly less work, though: 18% less compile time and 3% less code, because the
callee-saved locals no longer die at every call. The larger XRC wins need the same prepass: store/load trimming
(`xrc_sync`) and the stack-balance esp. Read-only folding and the existing `RECOMP_X87_LOCAL` /
`RECOMP_ICALL_SITE_CACHE` switches are the cheap ones to try per title.
