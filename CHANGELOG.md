# Changelog

All notable changes to pcrecomp. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [SemVer](https://semver.org/).

## [Unreleased]

### Fixed
- `disasm32.py`'s callback harvest (`push offset` / `mov r, offset` into code)
  no longer skips a target that an earlier body already covers: that body fell
  into it after a call it did not know was noreturn, and the target becomes an
  alias entry, as a jump into a body already does. The Movies: CRT
  `__endthreadex` ends in `ExitThread` and runs on into `__threadstartex`,
  whose only reference is the `push offset` ahead of `CreateThread`; the
  game's first worker thread faulted. POD and Hellbender catalogs unchanged.
  (#13)

### Fixed
- `disasm32.py`'s prologue scan starts a hot-patchable function at its
  `mov edi, edi` (8B FF), not two bytes in at `push ebp`. MSVC /hotpatch code
  (D3DX, the CRT, most Microsoft libraries) was split two bytes into every
  such function. The Movies: 2,048 of 3,083 framed functions; split entries
  6,582 -> 4,536, exact function ends 87.7% -> 91.2%. (#12)

### Added
- `generate.py`: `true_extent()` and `closure()`, the lift-driver helpers that
  forcecommander, prey and The Movies each carried a copy of. `true_extent`
  walks a body's branches for its real end, capped by reach instead of the
  catalog's clamp: MSVC calls a function's own __finally block mid-body, so
  the clamp cut CRT calloc off before its epilogue. On The Movies' startup
  closure, undefined-label ITAIL fallbacks 76 -> 44 and bodies with no
  terminator 7 -> 0. Selftest models the calloc shape.
- `true_extent` follows `jmp [reg*4 + table]` switches through their tables
  and can hand back the exact instruction set it reached;
  `linear_disassemble_function(reached=...)` then lifts only those, so the
  table bytes between a switch and its arms are never lifted as `pushal`
  (The Movies: CRT memcpy's tail copies were unresolved ITAILs). The sweep
  also decodes through `disasm32.decode`.
- `find_splits()`: entries that are really the middle of the entry before
  them (a walk from them branches backward into it). Dropping them from
  `true_extent`'s `entries` stops the parent being cut at a loop head. 366 on
  The Movies. (#11)

### Changed
- `disasm32.py` is 7-18x faster with byte-identical output. capstone's Python
  `disasm()` is a generator over one `cs_disasm(count=0)` call, so it decodes
  its whole buffer, with detail, before yielding the first instruction; every
  early-exit caller paid for a full window. `decode()` decodes in doubling
  batches instead. Fury3 3:35 -> 0:18, Hellbender 5:19 -> 0:42; The Movies'
  whole catalog went from 143 minutes to 8. (#10)

From #9. Found bringing Nocturne (Terminal Reality, Watcom C/C++32) in game.

### Fixed
- `lift32`: `push`/`pop` of a segment register moves esp by 4 in 32-bit code
  (2 only with a 66h prefix); `add` publishes CF, so `add`/`adc` chains carry
  right; `fild`/`fistp qword` are exact, the x87 stack shadowing an int64 per
  slot (`g_st_i64`).
- `generate`: static flag state no longer crosses a branch target.
- `recomp_types.h`: an unresolved `RECOMP_ICALL` no longer pops a return
  address it never pushed (Nocturne's CRT init lost its saved registers and
  skipped ~90 static constructors).
  difftest: 186/197 match, 11 known divergences, 0 failures.

### Added
- `drm/emu_unpack.py`: unpack a compressed PE32 by running its stub under
  Unicorn to the OEP, then rebuild the import directory around the IAT the code
  calls through. Handles PECompact 2.x and Valve's Steam2 wrapper on top of it
  (`SteamStartup`/`SteamIsAppSubscribed` answered). Headless, deterministic,
  `--selftest` for the IAT picker. Found on The Movies (2005), whose Steam
  build packs all three executables this way. (#5)

From #6. Found running SimCity 2000
(Windows 95, MSVC 2.x) recompiled: its simulation faulted after `div cl`.

### Fixed
- `lift32`: one-operand `mul`, `imul`, `div` and `idiv` at 8 and 16 bits use AX
  and DX:AX. Every width was lifted as the 32-bit EDX:EAX form, so `div cl`
  overwrote EDX. One-operand `mul`/`imul` now set CF and OF; signed
  `INT_MIN / -1` takes the divide-by-zero path instead of C undefined behaviour.
  (`lift32_cpu` already had this right.) Eight difftest cases: 183/195 match,
  12 known divergences, 0 failures.

From #8. Found running SimCity 2000
recompiled: its simulation hung in the CRT's `strstr`.

### Fixed
- `lift32`: a `rep`/`repe`/`repne` `cmps` or `scas` with ECX = 0 leaves the flags
  as they were. It set them to "equal", so `strstr` never saw the end of its
  haystack and looped forever. The jcc after a rep compare now reads the lazy
  flag state instead of assuming a compare wrote it. Two difftest cases:
  177/189 match, 12 known divergences, 0 failures.

From #4. Found running Gunman Chronicles (MSVC 6 CRT, Quake-lineage software renderer)
fully recompiled; each is generic x86 semantics or code generation. Each fix
has a difftest case against Unicorn: 175/187 match, 12 known divergences,
0 failures.

### Fixed
- `sahf` loads SF ZF AF PF CF from `ah` (it was a comment), and `fprem` reports
  C2 clear: the CRT `fmod` loop `fprem; fnstsw ax; sahf; jp` spun forever.
- `fxam` and `xlatb` lifted; the CRT math functions classify with them.
- `frndint` rounds by the control word (it truncated, so `floor`/`ceil` did).
- `fld`/`fstp` of 80-bit operands convert for real (they pushed 0.0 / dropped
  the value); `fsin`/`fcos`/`fsincos`/`fptan` clear C2.
- Flags survive `ret`: every `ret` publishes the lazy flag state and every call
  reloads it (`RECOMP_FLAGS_OUT/IN`), so a caller's `je` after a helper that
  returns ZF reads the helper's flags. Weak globals in `recomp_types.h`, so no
  project runtime needs a change.
- `inc`/`dec` keep CF; `bt; jae` no longer inverted; memory `bt*` address the
  bit string; `lock`-prefixed forms lift; `fist`/`fistp` round by the control
  word; patched immediates/displacements apply on every read.
- x87 compares report unordered (NaN) as C3=C2=C0; `repe cmps; sbb` reads the
  real CF; PF of narrow results is taken from the low byte.
- `generate.py`: a body can hold code below its entry (a `goto` to the entry
  comes first); `push label; jmp func` lifts as a call returning to `label`;
  a body that runs off its end falls through as a tail call.

### Added
- `Lifter(precise_carry=True)`: `adc`/`sbb` take CF from the `add`/`sub`/`cmp`
  before them instead of the `_cf` variable. Opt-in: Fury3 depends on the old
  behaviour.
- `Lifter(reloc=fn)`: rewrite every absolute displacement and immediate that
  points into a moved block of static data (growing fixed-size tables).
- `RECOMP_LOCAL_REGS` (opt-in): lifted bodies keep the eight registers in
  locals, written back around calls and returns, so the optimiser can hold
  them in host registers. `RECOMP_FLAT_MEMORY` (opt-in): no base added per
  guest access. Together about 2x on Gunman's renderer.
- `lift_function_linear(indirect_targets=...)`: when the caller knows every
  local target of a body's indirect jumps, only those get labels and switch
  cases, so a function with a `switch` optimises (default unchanged).
