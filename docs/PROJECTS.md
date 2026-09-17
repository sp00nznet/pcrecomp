# Project Index

**Why each tool in here exists, and which project bled to produce it.**

This is a provenance ledger, not a status board. Statuses and function counts
move every week and rot in a document; they live in the
[README table](../README.md#the-projects-that-built-this) and nowhere else.
What does not rot is *why* a tool works the way it does, and that is what is
written down here.

Read it when a tool surprises you. Nearly every strange-looking branch in this
repo is a scar from one specific binary, and the entry below names it.

---

## Tool -> origin, at a glance

| Tool | Came from | Because |
|------|-----------|---------|
| `disasm/disasm32.py` | X-Wing Alliance | Capstone recursive descent over a whole PE |
| `disasm32.find_branch_targets` E9 seeding | Trespasser | A linker map proved 7,331 real functions were reached only by `jmp rel32` |
| `disasm/decode16.py`, `disasm/analyze.py` | Civilization | No 16-bit decoder existed that understood MSC 5.x overlays |
| `disasm/largemodel16.py` | DinoPark Tycoon | Borland large model: 3,609 of 3,611 far calls resolved |
| `disasm/fpu_decode.py` | El-Fish | x87 in a 16-bit NE image, mixed into the code stream |
| `disasm/callgraph.py` | Soldier of Fortune | "Who calls this" without booting Ghidra |
| `disasm/score_recovery.py` | Trespasser | A recovered catalog is worthless until scored against symbols |
| `lift/lift32.py` | X-Wing Alliance | The core x86-32 -> C lifter |
| `lift/lift32_cpu.py` | Encarta 97 | A reentrant CPU struct, because MFC re-enters lifted code |
| `lift/lift16.py` | Civilization | 16-bit segmented lifting with a DOS runtime under it |
| `lift/recover.py` | Crimson Skies, Trespasser | Alternate entry points and jmp-thunk chains IDA never lists |
| `lift/difftest.py`, `difftest16.py` | Fury³ | A wrong carry flag broke a menu transition deterministically |
| `lift/translator.py`, `generate.py` | X-Wing Alliance | Pipeline orchestration and a fast linear-sweep fallback |
| `pe/pe_analyze.py` | Soldier of Fortune + Heavy Metal | Two half-analysers merged into one |
| `pe/pe_analyze.py` VirtualSize=0 path | Nocturne | Watcom linker 2.18 writes 0 in every section header |
| `pe/stdcall_argc.py` | Fury³ / Hellbender | Hand-typed stack-purge tables drift; derive them from the SDK |
| `pe/extract_imports.py` | Soldier of Fortune | Six modules, one shared Win32 surface to shim |
| `pe/catalog.py` | Black & White | Cataloguing a whole install tree before picking a target |
| `ne/*` | El-Fish, Microsoft Bob, Catz | The 16-bit New Executable front end and Win16 PASCAL purge table |
| `classify/*` | Gunman Chronicles | 78% of a GoldSrc game is the SDK; find the other 13% |
| `cpp/*` | Black & White | Mangling, demangling and vtable parsing across MSVC and Metrowerks |
| `drm/safedisc_dump.py`, `inject_and_run.c` | X-Wing Alliance, Black & White | SafeDisc v1 and v2+ |
| `assets/isextract.py` | Soldier of Fortune | InstallShield, including multi-volume |
| `assets/isextract.py` v6+ layout | One Must Fall: Battlegrounds | v7 and v9 discs; the flat 0x57 descriptor array |
| `pe/catalog.py` MZ sniffing | One Must Fall: Battlegrounds | The engine ships its modules as `.ModuleDLL` |
| `pe/analyze_sections.py` evidence ranking | One Must Fall: Battlegrounds | A 4-byte marker inside a mangled C++ name is not DRM |
| `assets/extract_wise.py` | Operation Neptune | Wise installer overlays |
| `assets/bin2iso.js`, `extract_cab.sh` | Black & White | BIN/CUE and InstallShield CAB |
| `formats/*` | Encarta 97 | FIF, FTC, M20/MVB, SPAM, DAT, string tables |
| `ghidra/*` | Gunman Chronicles, Black & White | Headless decompile, bounds, stats, xrefs |
| `ida/*` | Crimson Skies, Recoil, MechWarrior 3, POD | IDA follows vtables; the call-graph scan does not |
| `runtime/recomp16/` | Civilization, DinoPark | A whole DOS machine: CPU, INTs, VGA, SDL2 |
| `runtime/recomp32/` | X-Wing Alliance | Global-register model, dispatch, VEH |
| `runtime/recomp32/image_loader.c` | Fury³, Nocturne | Map the original image at its real VA; clamp the section copy |
| `runtime/recomp32/crash_report.c` | Crimson Skies | Every project was writing the same reporter |
| `runtime/recomp32_cpu/`, `runtime/hybrid/` | Encarta 97 | The lifted <-> real boundary |
| `runtime/compat/win32_compat.h` | Soldier of Fortune | 275 Win32 APIs sorted into keep/shim/SDL2/stub |

---

## Sid Meier's Civilization (1991)

**Repo**: [sp00nznet/civ](https://github.com/sp00nznet/civ) ·
**Original**: `CIV.EXE` (305 KB, 16-bit MZ) + 23 overlay modules, Microsoft C 5.x

The oldest binary in the collection, and the reason the entire 16-bit half of
this repo exists: `decode16.py`, `analyze.py`, `lift16.py` and the whole of
`runtime/recomp16/`.

**Notable**: 16-bit segmented memory with overlay loading through INT 3Fh.
Required simulating a complete DOS environment including a Mode 13h
framebuffer. Nothing about this is reusable from a 32-bit toolchain, which is
why the 16-bit path is a parallel pipeline rather than a special case of the
32-bit one.

---

## Operation Neptune (1991, Win32 re-release 1998)

**Repo**: [sp00nznet/operationneptune](https://github.com/sp00nznet/operationneptune) ·
**Original**: `ONWIN32.EXE`, Borland-compiled PE32, unpacked

**Contributed**: `assets/extract_wise.py`.

**Notable**: The re-release **ships its own linker map**. That is the rarest
thing in this line of work -- real ground truth for function starts, names and
sizes -- and it is why this project is the calibration target for
`disasm/score_recovery.py`. If a change to function recovery does not hold up
here, it does not hold up. Also the only Borland CRT in the collection, which
starts up nothing like MSVC's.

---

## DinoPark Tycoon (1993)

**Repo**: [sp00nznet/dinopark](https://github.com/sp00nznet/dinopark) ·
**Original**: 16-bit DOS, Borland large model

**Contributed**: `disasm/largemodel16.py`.

**Notable**: Large model means far calls everywhere and no clean code/data
boundary. `largemodel16.py` completes the call graph across segments and finds
that boundary; measured 3,609 of 3,611 far calls resolved. `tools/lift_full.py`
in that repo is the reference driver for `lift16.Lifter` -- start there rather
than from scratch.

---

## El-Fish (1993)

**Repo**: [sp00nznet/elfish](https://github.com/sp00nznet/elfish) ·
**Original**: 16-bit NE + TSXLIB DOS extender

**Contributed**: the first version of the `ne/` front end, `disasm/fpu_decode.py`.

**Notable**: 121 segments, and x87 mixed directly into the instruction stream,
which is what forced a separate FPU decoder rather than a few extra table
entries. `tools/ne_lift.py` there is the reference driver for lifting a
segmented NE image.

---

## Fury³ (1995) and Hellbender (1996)

**Repos**: [sp00nznet/fury3](https://github.com/sp00nznet/fury3), hellbender (private) ·
**Engine**: Terminal Reality voxel engine, Win32/MSVC

**Contributed**: `pe/stdcall_argc.py`, `runtime/recomp32/image_loader.c`, the
carry-flag model in `lift32.py`, and the case list in `lift/difftest.py`.

**Notable**: The same engine twice is the cheapest possible regression test for
a lifter -- anything that works on Fury³ and fails on Hellbender is a tool bug,
not a game quirk. The `sbb r, r` note in `difftest.py` is from here: the
"precise" carry variant *deterministically* broke the new-game -> briefing
transition, which is how the CF model got settled by measurement rather than
argument.

---

## Catz (1996)

**Repo**: [sp00nznet/catz-recomp](https://github.com/sp00nznet/catz-recomp) ·
**Original**: 16-bit NE engine DLL (PF Magic)

**Notable**: Lifting a *DLL* rather than an EXE, in NE format, where the host
process is real and only the engine is recompiled. Forced `lift16.py` to
support a per-project symbol prefix, because the generated names collided with
the previous project's.

---

## Microsoft Encarta 97 Encyclopedia (1996)

**Repo**: [sp00nznet/encarta](https://github.com/sp00nznet/encarta) ·
**Original**: `ENC97.EXE` + 5 DLLs + 6 legacy 16-bit components + 14 `.M20` files, MFC 4.0 / MSVC 4.x

**Contributed**: all of `formats/`, `runtime/hybrid/`,
`runtime/recomp32_cpu/`, `lift/lift32_cpu.py`, and `docs/HYBRID.md`.

**Notable**: Not a game, which is the point -- the approach works on any kind
of application. It is also the project that forced the **real -> lifted**
direction of the hybrid boundary to exist. An MFC app is mostly framework
calling back into application code; without that direction, "the recompiled app
runs" would have meant the entry point runs and MFC does everything else.
`DECO_32.DLL` is a third-party Iterated Systems fractal codec, fully recompiled
and byte-exact with no DLL present.

---

## Grand Theft Auto (1997)

**Repo**: [sp00nznet/gta](https://github.com/sp00nznet/gta) ·
**Engine**: DMA "Race'n'Chase"

**Notable**: The handler table starts at `0x4B4AD1` -- an *odd* address, inside
a packed struct array. That single fact is why
`disasm32.find_data_code_pointers` scans every byte offset instead of only
aligned ones. An aligned-only scan misses the table entirely and the functions
in it surface at runtime as unresolved indirect calls.

---

## POD Gold (1997)

**Repo**: [sp00nznet/pod-recomp](https://github.com/sp00nznet/pod-recomp) ·
**Engine**: Ubi Soft MMX software rasteriser

**Contributed**: the MMX instruction coverage in `lift32.py`, the MMX register
aliasing in `runtime/recomp32/recomp_types.h`, and the self-modified-immediate
handling.

**Notable**: A hand-written MMX inner loop that rewrites its own immediates at
runtime. The lifter cannot treat an immediate as a constant when the code
writes to it, and `recomp_types.h` documents exactly where MMX and x87 alias --
POD never interleaves them, which is the only reason the simple model holds.

---

## X-Wing Alliance (1999)

**Repo**: [sp00nznet/xwa](https://github.com/sp00nznet/xwa) ·
**Original**: `xwingalliance.exe`, MSVC, SafeDisc v1, fixed base `0x00400000`

**Contributed**: `disasm/disasm32.py`, `lift/lift32.py`, `lift/translator.py`,
`lift/generate.py`, `drm/safedisc_dump.py`, `runtime/recomp32/`, both
`templates/`.

**Notable**: This project produced the core automated pipeline; most of the
32-bit toolchain is its descendant. SafeDisc decryption needed a custom memory
dumper because static unwrapping was not viable.

---

## Zipper GOS: Recoil (1999), MechWarrior 3 (1999), Crimson Skies (2000)

**Repos**: [sp00nznet/crimsonskies](https://github.com/sp00nznet/crimsonskies);
recoil and mw3 private ·
**Engine**: Zipper Interactive GOS, three generations

**Contributed**: `tools/ida/`, `lift/recover.py`,
`runtime/recomp32/crash_report.c`.

**Notable**: Function discovery here was bootstrapped with **IDA Pro** rather
than a call-graph scan, because GOS is vtable-heavy and a scan that only
follows CALLs never reaches a virtual method. That is what `tools/ida/` is for.
Three games on one engine also made it obvious that every project was
hand-rolling the same crash reporter, so it moved into `runtime/`.

---

## Soldier of Fortune (2000)

**Repo**: [sp00nznet/sof](https://github.com/sp00nznet/sof) ·
**Engine**: Quake II (heavily modified) + GHOUL ·
**Original**: `SoF.exe` + `gamex86.dll` + `ref_gl.dll` + `player.dll` + 3 sound DLLs, MSVC 6.0

**Contributed**: `pe/pe_analyze.py` (merged with Heavy Metal's),
`pe/extract_imports.py`, `assets/isextract.py`, `runtime/compat/win32_compat.h`.

**Notable**: Non-standard image bases (0x20M, 0x30M, 0x40M, 0x50M), Winsock
imported **by ordinal**, and a `GetRefAPI` calling convention that differs from
stock Quake II. Seven modules sharing one Win32 surface is why
`extract_imports.py` prints a cross-module summary rather than one table per
file.

---

## Gunman Chronicles (2000)

**Repo**: [sp00nznet/gunman](https://github.com/sp00nznet/gunman) ·
**Engine**: GoldSrc

**Contributed**: all of `classify/`, `ghidra/DecompileAll.java`,
`ghidra/ExportFunctions.java`.

**Notable**: 78% of the binary is the Half-Life SDK. Only 499 of 3,990
functions need real RE work -- but you have to *prove* which 499, which is the
entire job of the four-pass classifier: names, string references, call-graph
propagation, then address clustering (functions from one source file compile
adjacent).

---

## Heavy Metal: FAKK2 (2000)

**Repo**: [sp00nznet/heavymetal](https://github.com/sp00nznet/heavymetal) ·
**Engine**: id Tech 3 + Ritual UberTools

**Contributed**: `pe/pe_analyze.py` (merged), `assets/pk3_inspect.py`.

**Notable**: A copy-on-write `str` class exported by all three binaries, 50
symbols -- the critical ABI bridge, and the kind of thing that has to be found
before anything links.

---

## Black & White (2001)

**Repo**: [sp00nznet/bw](https://github.com/sp00nznet/bw) ·
**Engine**: Lionhead custom, MSVC 6.0, SafeDisc

**Contributed**: all of `cpp/`, `ghidra/GhidraStats.java`,
`drm/inject_and_run.c`, `assets/bin2iso.js`, `assets/extract_cab.sh`,
`pe/catalog.py`.

**Notable**: The most C++-heavy project here. Seven-level class hierarchy
(`Base` -> `GameThing` -> `Object` -> `Mobile` -> `Living`...), and a
`CreatureMental` struct of 135 KB. Required a full mangling/demangling
toolchain in both directions and across two compilers.

---

## Jurassic Park: Trespasser (1998)

**Repo**: private ·
**Original**: `setup\tpassp6.exe`, the Pentium Pro/II build. Plain MSVC 6.0 PE32, no DRM.

**Contributed**: `disasm/score_recovery.py`, the E9 tail-call seeding in
`disasm32.find_branch_targets`, and [CONSOLIDATION.md](CONSOLIDATION.md).

**Notable**: This project's only contribution so far is *measurement*, and it
has been worth more than most features. Scoring `disasm32.py` against a linker
map found it missing **7,331 functions** that IDA found -- 89% of them reached
by `jmp rel32` and nothing else, 95% C++ mangled names, 61% eight bytes or
smaller: optimised `__thiscall` accessors with no recognisable prologue. Four
lines of fix recovered 6,550 of them. Nobody had scored the disassembler
before, so nobody knew.

---

## Nocturne (1999)

**Repo**: private ·
**Engine**: Terminal Reality, Watcom C/C++32

**Contributed**: the `VirtualSize == 0` tolerance in `pe/pe_analyze.py`, and
the clamped section copy in `runtime/recomp32/image_loader.c`.

**Notable**: Watcom linker 2.18 writes `VirtualSize = 0` in **every** section
header. Every PE tool that trusts that field silently produces empty sections.
Watcom also gives the loader a 42 MB image, which is where the unclamped
section copy was found -- it had been reading past the end of the file on
anything large enough to notice.

---

## Rise of Legends (2006)

**Repo**: private ·
**Engine**: Big Huge Games rts2, MSVC 7.1

**Notable**: The stress test. 13.25 MB, 19.2 million instructions, **25,513
functions reachable only through vtables**, and no RTTI to lean on. Everything
else the toolchain has been proven on is smaller, older, or both. It is the
strongest argument for porting a real vtable scanner from xboxrecomp: a
function recovery pass that cannot follow a vtable misses most of this binary.

---

## One Must Fall: Battlegrounds (2003)

**Repo**: [sp00nznet/omfbg](https://github.com/sp00nznet/omfbg) (private) *
**Engine**: Diversions Entertainment, modular -- `OMFBG.exe` + 9 `.ModuleDLL`

**Contributed**: the v6+ file-descriptor layout in `assets/isextract.py`, the
`MZ` sniffing in `pe/catalog.py`, and the strong/weak split in
`pe/analyze_sections.py`.

**Notable**: the best-instrumented binary in the collection. **10,374 exports,
every one an MSVC-mangled C++ name** -- `Core.ModuleDLL` alone publishes 8,320
named functions with their class, parameter types and calling convention. That
is better ground truth than Operation Neptune's linker map, and it is why this
should become the calibration target for C++ recovery the way Neptune is for
Borland C. Also: the disc carries every SafeDisc marker, and SafeDisc covers
only the 53 KB launcher -- 4.51 MB of the 4.56 MB total is unprotected. The
triage lesson is that disc-level DRM markers say nothing about which *binaries*
are wrapped.

All three tool fixes were prerequisites rather than improvements. `isextract`
crashed on the disc; `catalog.py` reported the install as two binaries and hid
the other nine; `analyze_sections.py` called four clean modules SecuROM on the
strength of `AddD` matches that were all inside
`?AddData@DE_CChecksumMD5@@`-style export names.

---

## Monster Truck Madness 1 & 2 (1996, 1998)

**Repo**: [sp00nznet/mtm](https://github.com/sp00nznet/mtm) (private) *
**Engine**: Terminal Reality, third generation

**Notable**: the Fury3/Hellbender pair is the collection's cheapest regression
test, and this is the same engine a third time -- except MTM2 ships the renderer
as `VOXRT24.DLL` (248 KB, 8 exports) and `TRID3D.DLL` instead of linking it in.
The code Fury3 forced the lifter to get right is here as a standalone DLL. With
Nocturne (1999) that makes four Terminal Reality generations: 1995, 1996, 1998,
1999. No DRM. Statically linked CRT, so `classify/` runs before anything else.

---

## Star Wars: Force Commander (2000)

**Repo**: [sp00nznet/forcecommander](https://github.com/sp00nznet/forcecommander) (private) *
**Original**: `Focom.exe`, MSVC 6.0 + MSVCP60, no DRM

**Notable**: the clean version of the X-Wing Alliance problem. Same publisher,
one year later, 3.94 MB of `.text` -- 1.5x XWA -- and no SafeDisc, no packer,
nothing to dump. Second-largest target in the collection behind Rise of Legends.
Everything XWA learned about LucasArts binaries applies without repeating XWA's
first week.

---

## Terminal Velocity (1995)

**Repo**: [sp00nznet/tv](https://github.com/sp00nznet/tv) (private) *
**Original**: `GAME.EXE`, Watcom C/C++, DOS/4GW

**Notable**: the argument for an **LE/LX front end**. `catalog.py` names LE/LX
images correctly and routes them nowhere, because nothing reads them. DOS/4GW is
what the entire 32-bit DOS era shipped on, and OS/2's 32-bit format is LX -- the
same work unlocks both, which makes this the highest-leverage missing front end.
Also Terminal Reality again, contemporary with Fury3, so a Watcom DOS build and
an MSVC Windows build of related code become comparable: the sharpest available
test of whether the lifter is compiler-independent.

---

## Black & White 2 (2005)

**Repo**: [sp00nznet/bw2](https://github.com/sp00nznet/bw2) (private) *
**Engine**: Lionhead, four years on from `bw`

**Notable**: `white.exe` is **21,739,061 bytes** -- larger than Rise of Legends
(13.25 MB), which is currently the stress test rather than a project. The size
is read from the InstallShield 9 header; the binary itself is on disc 2, 3 or 4
and has not been extracted. Black & White's 569 hand-recovered types become 569
hypotheses to test here. Needs the vtable scanner ported from `xboxrecomp`
first -- same prerequisite as Rise of Legends, and on a bigger binary.

Incidentally the proof that the `isextract.py` v6+ work generalises: the layout
that fixed an InstallShield 7 disc reads an InstallShield 9 one unchanged.

---

## The Magic School Bus Explores the Human Body (1994)

**Repo**: [sp00nznet/msbus](https://github.com/sp00nznet/msbus) (private) *
**Original**: Win16 NE, Microsoft "band" engine

**Notable**: roughly **60 KB of machine code driving 190 MB of content** --
three `BD*.EXE` of 7-23 KB (`FEEDER`, `MSBSNOOP`, `GOBAND`) plus a 5 KB
`BANDDLL.DLL`. The inverse of Microsoft Bob, which is the same publisher, same
year, same format, and where the code *is* the product. Lifting is short; the
project is `.MSF`, `.PAG` and `.PFL`.

---

## The Even More Incredible Machine (1993)

**Repo**: [sp00nznet/tim](https://github.com/sp00nznet/tim) (private) *
**Original**: `TEMIM.EXE`, Borland C++, NE, 27 code segments

**Notable**: imports KERNEL, USER and GDI and **nothing else** -- the entire
shim surface is the one `ne/` already generates. Its NE entry table names its own
Windows callbacks (`TIMWINDOWPROC`, `CONFIRMDLGPROC`, `STATUSDLGPROC`,
`DESTROYALLMONSTERS`), so the message loop is identified before disassembly.
Third Borland project after Operation Neptune and Gizmos & Gadgets.

---

## Missile Attack! (1992)

**Repo**: [sp00nznet/missileattack](https://github.com/sp00nznet/missileattack) (private) *
**Original**: `MISSILE.EXE`, 87 KB NE shareware, **one code segment**

**Notable**: the fixture for the 16-bit pipeline. 21 KB in a single segment, so
segmentation -- the first-class problem in every other NE project here -- is
absent, and a change to `ne_parse.py`/`ne_decode.py`/`lift16.py` can be checked
end to end in the time it takes to read the diff. Five named entry points across
21 KB. Imports `win87em`, which puts an x87 surface in a 16-bit NE image: the
El-Fish problem at 1/100th the size.

---

## The Electronic Whole Earth Catalog (1988)

**Repo**: [sp00nznet/wholeearth](https://github.com/sp00nznet/wholeearth) (private)

**Notable**: not a PC title at all. The disc has an Apple Partition Map and an
HFS volume and no ISO 9660 descriptor -- Macintosh, Broderbund, the same shelf as
Shufflepuck Cafe. Probably HyperCard, in which case there is no 68k binary to
recompile and it is a format project. Staged pending a mount; it likely belongs
to `macrecomp`.

---

## World Empire (1994)

**Repo**: sp00nznet/worldempire (private) - P0

**Notable**: the first target where the x86 lives in a different file than the
game. `EMPIRE.EXE` imports `VBRUN300.DLL` and nothing else and carries 14
relocations across 114 KB of "code" -- Visual Basic 3 p-code, not machine code.
The entire program is nine bytes: `call VBRUN300.100` (THUNRTMAIN) and a far
pointer at the token stream. An x86 lifter produces confident garbage on it and
has no way to notice.

What it taught the toolbox: **VBRUN-only is a retarget signal, not a rejection.**
`VBRUN300.DLL` is an ordinary Win16 NE -- 99 code segments, 340 KB of real x86,
2,746 relocations, imports KERNEL/USER/GDI -- which `ne/` and `lift16` already
read. The interpreter is the target and the p-code is its input, the same shape
as `catz`, where the engine is a 16-bit NE DLL and the game is what it loads.
It also means the VB3 opcode semantics never need guessing: the dispatch table
and its handlers are x86 inside that DLL, so the interpreter is the spec.

`ne_parse.py` now prints the flag and names the retarget instead of leaving it
as folklore. It fires on the Visual Basic catalogue bundled with The Magic
School Bus too. Later VB (4/5/6) can compile native, so `MSVBVM*` warns rather
than concludes.

**Bring-up**: `VBRUN300.DLL` lifts -- 99/99 segments, 226,480 lines of C, 14,826
functions, 0 lift errors, 123 unhandled instructions (mostly data decoded as
code: `? di`, `into`, `outsd`), 2,106 Win16 import call sites all resolved by
name. It contributed three things to the toolbox:

* **`decode16.decode_one` raised on a truncated instruction.** A segment does
  not have to end on an instruction boundary, and reaching for operand bytes
  past the end raised `EndOfSegment` -- an exception raised in one place and
  caught in none, so it crashed the caller. `ne_decode` died on segment 1 of
  the first real binary pointed at it. It now returns `None`, which is what the
  `Optional[Instruction]` signature already promised and what every caller
  already handled.
* **`ne_lift.py` moved into `tools/lift/`.** It had been living in `catz/tools/`
  and World Empire had no business reaching into another project's directory
  for it. Parameterised (`PREFIX`) instead of hardcoding `catz_unreachable`.
  catz, elfish and bangbang each still carry forks of `ne_parse`, `ne_decode`,
  `win16` and `fpu_decode` as well; they should converge rather than drift.
* **The Win16 ordinal map is not per-project.** Four projects each carried a
  `win16_imports.json` and the widest was a strict superset of the other three.
  Without one, 237 of VBRUN300's 300 imports resolved to `MODULE_OrdN` and every
  purge lookup missed; with it, 300/300 resolve. `win16.py` now falls back to a
  toolbox-level copy.

**Builds and links.** 100 translation units compile with zero diagnostics, and
the whole tree links into a 21 MB binary that runs. Getting from "lifts" to
"links" cost four more toolbox fixes:

* **`runtime/win16/`** -- the Win16 CPU header, upstreamed from `catz/runtime/`
  with the project prefix neutralised to `RECOMP_`/`recomp_`, which is
  `ne_lift.PREFIX`'s default, so lifted code compiles against it unrenamed.
  catz's fork turned out to be a *stale* copy of `recomp16/cpu.h`: it was
  missing `flags_adc`, `flags_sbb`, `bcd_aaa/aas/aam/aad/daa/das` and
  `RECOMP_TICK`, all of which the lifter emits. Those are ported back from the
  canonical header rather than rewritten -- one source of truth for the
  semantics.
* **`runtime/win16/recomp_stubs.c`** -- the entry ring, selector watch,
  indirect dispatch and abort helpers that every lifted translation unit
  references. Without them a freshly lifted target cannot link at all; with
  them it links on day one and aborts loudly at anything unimplemented.
* **`tools/ne/gen_segments_h.py`** and **`tools/ne/gen_unresolved_stubs.py`**,
  both upstreamed from `catz/tools/` with the segment count and guard
  parameterised. The stub generator was changed in one important way: catz
  emitted `{ (void)cpu; }`, a silent return that lets the guest carry on with a
  frame that is wrong from that point on. It now calls `recomp_unreachable`
  and aborts, the same contract `gen_win16_stubs.py` already applies to an
  unimplemented import. 234 of 14,731 call targets are unresolved (1.59%).
* **A real lifter bug, found by the compiler.** `ne_lift.py` overrode the
  shared BCD lifting with an inline expansion, and for `aam 0` it emitted
  `_v / 0` verbatim -- undefined behaviour in C. The override dated from when
  `lift16.py` still dropped BCD as stubs; `lift16.py` has since grown real
  `bcd_*` helpers, and `bcd_aam` guards a zero divisor and leaves AX alone the
  way the hardware fault does. The fix was deleting the stale override.

**The purge gate is closed, and the guest runs.** The 133 missing purges were
derived from the documented prototypes: Win16 is PASCAL, so the purge is the
sum of the argument sizes, 2 bytes per handle/int/BOOL/UINT and 4 per
LONG/DWORD/COLORREF/far pointer. `win16.py` now carries the argument TYPES in
`_PROTO` and derives the byte count, so a wrong entry shows up as a wrong
prototype instead of an unfalsifiable integer.

The method was validated before it was trusted: applied to the 163 entries
already in `PURGE`, it reproduced 162. The one disagreement was
`USER.TRACKPOPUPMENU`, which the table gave as 14 -- **the table was wrong**.
It takes seven arguments, not six (the fifth, `nReserved`, was missing), so the
purge is 16; an independent scan of real call sites in VBRUN300 also read 16.
That is exactly the drift `stdcall_argc.py`'s docstring warns about, caught
this time because the derivation is checkable. `USER._WSPRINTF` is the one
exception to the PASCAL rule and is set explicitly: it is `cdecl` varargs, so
the caller cleans up and the purge is 0.

With that, `gen_win16_stubs.py` exits 0 on all 300 imports.

**Running it.** `gen_image.py` was upstreamed too (parameterised, and with a
`--stack` option, because a DLL has no stack of its own -- its NE `ss:sp` is
0:0 and the host has to map one). Note the NE header entry, seg 45:00A0, is
`mov ax, sp; retf` -- a 4-byte helper, not LibMain. The entry that matters is
ordinal 100, `THUNRTMAIN` at seg 45:0000, which is what EMPIRE.EXE's nine bytes
call. From there:

```
seg045_0000  (THUNRTMAIN)
  -> KERNEL.GLOBALHANDLE      unimplemented; stub purges, reports, returns AX=0
seg045_002A                   init check fails
seg045_009B
  -> INT 21h AH=4Ch           DOS terminate -- the runtime gives up deliberately
```

Lifted 16-bit code executing a real Win16 init path and taking the documented
failure branch because the stub told it memory setup failed. Both the trace and
the loud-abort contract are pinned as ctest cases, so a regression in the lift,
the image or the purge table shows up as a *different* trace rather than
passing quietly.

**Next**: a real Win16 memory manager. `GlobalAlloc`/`GlobalLock`/`GlobalHandle`
with actual selector-backed handles is what gets past init, and that is a phase,
not a patch -- catz's `win16_impl.c` is 106 KB for this reason.

**A correction worth recording.** The first attempt at upstreaming the Win16
runtime copied catz's `mem_layout.h` into `runtime/win16/`. That file is
*generated* -- it had CATZ.WAD's segment bases baked in, which is both wrong for
every other target and a section 3 violation, since it is a header reconstructed
from a proprietary binary. It was removed and `gen_image.py` upstreamed instead.
Generated output does not become runtime source by being copied.

*Negative result, recorded so it is not retried:* the purge cannot be inferred
from the caller's push run. Scanning back from each call site and summing
pushes agrees with the known-purge table only ~86% of the time, and taking the
minimum across call sites is worse (73%), not better. Contamination runs both
ways: a nested call inside an argument list hides the earlier arguments above
it (`call GetStockObject; push ax; call FillRect` reads as 2, not 8), while
scanning past the start of an argument list picks up an enclosing call's
pushes. Getting it right needs SP tracking through nested calls, which needs
the purges being solved for. `idt_to_json.py`'s docstring already said this --
".idt records a name per ordinal and almost never an argument size" -- and it
is right.

---

## Not targets, and why that is worth recording

**The OS/2 Arsenal and OS/2 Fever discs** are shareware compilations -- 10,000+
programs, not one target. Kept as a prospecting corpus: OS/2 16-bit is NE, which
`ne/` already reads (different shim table, not a different front end), and OS/2
32-bit is LX, which lands on the same missing decoder as Terminal Velocity.

---

## The Fallout forks (1997, 1998)

**Repos**: [fallout1-re](https://github.com/sp00nznet/fallout1-re),
[fallout2-re](https://github.com/sp00nznet/fallout2-re) ·
**Upstream**: alexbatalov's reverse-engineered source

Not recompilations -- forks of completed RE work, kept here because they answer
the "what is this *for*" question. Once the code exists, a 1997 DOS game gets a
web port, a multiplayer server and a Docker stack. That is the payoff the rest
of the repo is working towards.
