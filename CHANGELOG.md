# Changelog

All notable changes to pcrecomp. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [SemVer](https://semver.org/).

## [Unreleased]

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
