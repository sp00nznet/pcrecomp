# Hybrid recompilation: running lifted code inside a real program

A static recompilation of a real application is never all-or-nothing. You lift
the application; its framework (MFC, the CRT, the OS) stays as real machine
code. So control crosses the boundary in both directions:

```
lifted -> real     an import call, or a function you have not lifted yet
real   -> lifted   the framework calling back into application code:
                   a vtable slot, a window procedure, a qsort comparator,
                   an _initterm initializer table
```

Everyone builds the first direction. **The second is the one that matters**, and
the one nobody warns you about. Without it, "the recompiled app runs" means the
entry point runs and the framework does everything else. With it, the
application *body* is your code while its framework stays real — and you can
delete the framework later, at your leisure, instead of up front.

`runtime/hybrid/` is both directions. This document is what it cost to get
right, because none of it is guessable and all of it fails far from the cause.

---

## Part 1: the three rules

Each of these produced a crash that looked like something else entirely.

### Rule 1 — seed `ebp` when calling real code

MSVC emits **frameless funclets** for SEH unwind and local-object destruction:

```asm
00405350:  lea ecx, [ebp-0x10]     ; the CString in the CALLER's frame
00405353:  jmp CString::~CString
```

That function has no prologue. It addresses *its caller's* frame. If it is not
in your lifted set, your dispatcher falls back to the real original — which then
runs against the **host's** `ebp` and destructs a garbage pointer.

The symptom is heap corruption (`STATUS_HEAP_CORRUPTION`) detected later, in
unrelated code, on a thread that looks innocent. The cause is one missing
register in your trampoline.

Load `ebp` from the emulated CPU like every other register.

### Rule 2 — the trampoline must be reentrant

The natural implementation stashes the host's `esp` somewhere before switching
to the emulated stack, because MSVC inline asm cannot address locals once you
have moved `esp`. If "somewhere" is a plain global, you have a bomb:

```
lifted entry
  -> call_machine(AfxWinMain)          saves host esp  -> T_sesp
       real MFC calls a routed vtable slot
         -> real->lifted trampoline
              lifted callee dispatches an import
                -> call_machine(...)   OVERWRITES T_sesp
                <- restores fine
       AfxWinMain returns
  <- call_machine restores esp from T_sesp   *** now the inner call's value ***
```

The outer restores a stale `esp`, pops garbage into the callee-saved registers,
and returns into hyperspace. The crash lands thousands of instructions later
with a wrecked stack and no trail.

Save and restore the whole marshalling block around each call. It is four lines
and it is not optional the moment you route a single vtable slot.

### Rule 3 — capture `edx`, not just `eax`

A 64-bit return comes back in `edx:eax`. Compilers of the mid-90s pass such
pairs around constantly:

```asm
call  sub_514AD0
mov   dword ptr [ebp-8], eax
mov   dword ptr [ebp-4], edx
```

Capture only `eax` and every 64-bit value silently loses its high half. Nothing
crashes; results are just quietly wrong, which is worse.

---

## Part 2: routing the vtables

`hybrid_route_fnptr_slots()` walks `.rdata`/`.data` and rewrites every slot that
points at a lifted function start into a thunk, so real virtual dispatch lands
in lifted code.

Two heuristics keep it honest:

- **Runs of >= 3.** Three consecutive valid function-start pointers is a vtable,
  not a coincidence. This keeps out data that merely looks pointer-ish.
- **Function *starts* only.** Jump-table entries point mid-function, so requiring
  an exact match against your function map excludes them.

Your dispatcher must recognise thunk addresses: lifted code that reads a routed
slot and calls through it hands you a thunk, not a function VA. That is what
`hybrid_thunk_target()` is for.

Worth printing every run: the count of real->lifted calls. It is the honest
measure of how much of the application is actually running recompiled. (Encarta
97: 10,242 per session, against 10,432 routed slots.)

---

## Part 3: bisecting, when it breaks

It will break, at 30,000 dispatched calls, in a function you have never heard
of. Do not read the disassembly. Bisect.

The trick is that a hybrid build has two independent dials, and each can be
binary-searched against a pass/fail signal (does the app reach its main window?):

| Dial | Question it answers |
|---|---|
| `R2L_LO` / `R2L_HI` — route only slots `[LO,HI)` | *which routed slot* breaks it |
| `LIFT_LO` / `LIFT_HI` — only functions `[LO,HI)` run lifted, rest run real | *which lifted function* is wrong |

~14 runs each over ten thousand candidates. In Encarta both bisects landed on
exactly one item, and the second landed on the very function containing the
faulting instruction.

### The isolation ladder

Once a bisect names a slot, the failure is still ambiguous: bad lift? bad slot
rewrite? bad calling convention? bad stack switch? Peel one layer at a time:

| Mode | What it does | If it PASSES, you have excluded |
|---|---|---|
| `PASSTHRU` | slot rewritten, thunk jumps straight at the original | the slot rewrite itself |
| `STUB` | trampoline returns 0 without running the callee | the return convention |
| `REAL=1` | run the ORIGINAL body through the trampoline | the lift — it is the harness |
| `REAL=2` | ...and without the esp switch | everything but the stack switch |

Reading it: `STUB` and `PASSTHRU` pass but `REAL=1` fails ⇒ the harness, not the
lift. `REAL=1` passes but lifted fails ⇒ the lift, and now go read that one
function.

### The bisect that lied

A warning worth the paragraph. The first `LIFT_LO/HI` bisect confidently blamed
a six-byte import thunk — which the trace showed was **never called**.

The slot-routing scanner decided "is this a function start?" using the same
`lookup()` that `LIFT_LO/HI` filters. So restricting the lifted set silently
changed which slots got routed, and the bisect was measuring two variables at
once.

**A bisect dial must not perturb anything else.** `hybrid_route_fnptr_slots()`
takes a separate `is_fn_start` callback for exactly this reason — keep it
unfiltered.

---

## Part 4: diagnostics that paid for themselves

- **Return address as call site.** When an indirect call goes through a null,
  the lifted call site has already pushed its return address, so `[esp]` names
  the faulting instruction exactly. One line, and it beats any stack walk.
- **Trail, not "last".** A single `g_last` variable is the last target
  *dispatched*, not the current frame — after a callee returns it names the
  callee, and you will chase the wrong function. Keep a small ring buffer.
- **`HeapValidate` after every dispatched call.** Expensive, but it converts
  "heap corruption somewhere" into "heap corruption after call #1052 to X".
- **Log the app's message boxes and answer OK.** A modal dialog under a watchdog
  tells you nothing; its text tells you exactly what the program thinks is
  wrong. This is what turned "unknown error" into "the command line is
  improperly formatted".
- **Log the config it reads.** Registry keys, INI lookups — an old application
  that will not start is usually looking for something its installer wrote.
  Answering those lookups from a table is far cheaper than running Setup, and
  leaves the machine untouched.

---

## Part 5: two lifter bugs this shape of program will find

Both are in `tools/lift/lift32_cpu.py` now; check your own lifter for them.

**Absolute displacements need relocating too.** It is easy to relocate address
*immediates* (`push offset table`) and forget the displacement inside a memory
operand when the operand also has a base register:

```asm
mov dl, byte ptr [ecx + 0x56d902]     ; a table lookup at an ABSOLUTE address
```

`0x56d902` is as much an address as `[0x58d428]` is. The base register says
nothing. The `.reloc` table marks exactly the ones that need it — use it as the
authority rather than guessing by range.

**An indirect call must resolve its target before pushing the return address.**

```asm
mov  dword ptr [esp + 0x18], eax   ; stash a function pointer
call dword ptr [esp + 0x18]        ; and call through it
```

A real `call` reads its target using the **pre-push** `esp`. Emit
`push(ret); dispatch(read(esp+0x18))` and you read one slot off — in Encarta,
a zero, and a jump to address 0. Resolve into a temporary first:

```c
{ uint32_t _ct = rd32(c->esp + 0x18u); push32(c, ret); dispatch(c, _ct); }
```

12,703 call sites in one 1.3 MB binary had this shape.

---

## Provenance

Everything here was found the hard way while making Microsoft Encarta 97
(MFC 4.0, MSVC 4.x, 7,326 functions) run as recompiled code on Windows 11.
See [sp00nznet/encarta](https://github.com/sp00nznet/encarta).
