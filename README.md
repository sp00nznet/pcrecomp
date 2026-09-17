# pcrecomp

```
    ____  ______   ____  ________________  __  ___ ____
   / __ \/ ____/  / __ \/ ____/ ____/ __ \/  |/  // __ \
  / /_/ / /      / /_/ / __/ / /   / / / / /|_/ // /_/ /
 / ____/ /___   / _, _/ /___/ /___/ /_/ / /  / // ____/
/_/    \____/  /_/ |_/_____/\____/\____/_/  /_//_/

         "everything old is new again"
```

**The unified toolbox for tearing apart old PC software and putting it back together, better.**

This repo collects every tool, runtime, and hard-won trick from our PC static recompilation projects into one place. Next time we want to crack open a dusty `.exe` from 1995 and make it run on Windows 11, we start here.

---

## What's In The Box

```
pcrecomp/
  tools/           Reusable analysis & transformation tools
    pe/            PE analysis (imports, exports, sections, hashes, delay-imports,
                   protection/DRM detection, recursive binary catalog that
                   also names the non-PE binaries (NE/LE/MZ) instead of
                   calling them broken,
                   stdcall_argc.py derives each import's stack purge from the SDK)
    ne/            NE (16-bit New Executable) parse / disasm / call-graph,
                   gen_segments_h.py and gen_unresolved_stubs.py close the
                   lift -> compile -> link loop,
                   Win16 import resolution (ordinal -> API name + the PASCAL
                   stack-purge table) and C shim generation
    disasm/        Disassemblers (32-bit recursive descent, 16-bit table-driven,
                   x87 FPU decoder, direct call-graph scanner, large-model
                   far-call + code/data-boundary call-graph completion,
                   score_recovery.py scores a catalog against a reference and
                   splits false positives into "split" vs "invented")
    lift/          Code lifters (x86-32 and x86-16 to readable C; ne_lift.py is
                   the NE-aware 16-bit lifter -- far-call resolution, Win16
                   import shims, x87, segment-aware memory; lift32_cpu.py
                   is the reentrant CPU-struct model needed for hybrid builds;
                   recover.py finds alternate entry points a catalog missed;
                   difftest.py / difftest16.py run the lifted C against Unicorn
                   and name every register, flag and byte the two disagree on)
    classify/      Function classifiers (SDK vs custom, multi-signal, string refs)
    ghidra/        Ghidra headless scripts (decompile, export, stats, xrefs,
                   range disasm, function bounds)
    ida/           IDA headless scripts (code-map export, segment probe)
    drm/           DRM analysis (SafeDisc memory dumping, DLL injection)
    assets/        Asset extraction (InstallShield, Wise, PK3/ZIP, BIN/ISO, CAB)
    cpp/           C++ RE helpers (MSVC/MWerks name mangling, vtable parsing)
    formats/       Format decoders (FIF fractal images, M20/MVB, SPAM, DAT,
                   string tables)
  runtime/         Drop-in runtime support for recompiled code
    recomp32/      32-bit x86 runtime (global registers, memory model, dispatch,
                   image loader, crash reporter)
    recomp32_cpu/  32-bit x86 runtime, explicit CPU struct (reentrant; pairs
                   with lift32_cpu.py, required for hybrid builds)
    recomp16/      16-bit DOS runtime (CPU state, INT handlers, HAL, SDL2)
    win16/         16-bit Windows NE runtime: the CPU header lifted Win16 code
                   compiles against, plus recomp_stubs.c -- the entry ring,
                   indirect dispatch and loud-abort helpers every lifted unit
                   references, so a fresh target LINKS on day one and stops
                   dead at anything unimplemented
    compat/        Win32 API compatibility layers (Win32 -> SDL2 mapping)
    hybrid/        The lifted <-> real boundary: import trampoline, real->lifted
                   __thiscall trampoline, vtable routing. Lets a framework
                   (MFC, the CRT) stay real while the app body runs recompiled
  templates/       Starter files for new projects (CMake, .gitignore)
  docs/            Deep dives and philosophy
```

## The Projects That Built This

Every tool here was forged in the fires of an actual recompilation project.
These are the PC games and apps we've taken apart so far. Statuses are what the
project's own README claims; the numbers are function counts from its last
pipeline run.

| Project | What | Era | Engine/Tech | Status |
|---------|------|-----|-------------|--------|
| **[civ](https://github.com/sp00nznet/civ)** | Civilization | 1991 | 16-bit DOS / MSC 5.x | Runs! 672 functions, interactive boot/menu, 164K lines |
| **[operationneptune](https://github.com/sp00nznet/operationneptune)** | Operation Neptune | 1991 / Win32 1998 | Borland PE32, ships its own linker map | **Plays!** CRT -> WinMain -> opening -> in the submarine |
| **[skifree](https://github.com/sp00nznet/skifree)** | SkiFree | 1991 | Win16/Win32 (`ski32.exe`) | Playable rebuild from decompiled C, cross-platform + extras |
| **[dinopark](https://github.com/sp00nznet/dinopark)** | DinoPark Tycoon | 1993 | 16-bit DOS / Borland large model | Boots! Whole game lifted (~90K lines), renders .PIC screens + .ACT dinosaurs in colour |
| **[elfish](https://github.com/sp00nznet/elfish)** | El-Fish | 1993 | 16-bit NE + TSXLIB extender | Lifted & links - 2,236 functions, 121 segments, startup executes |
| **[hellbender](https://github.com/sp00nznet/hellbender)** | Hellbender | 1996 | Terminal Reality voxel engine (Win32/MSVC) | Bring-up - lifts clean (5,262 functions, 0 errors), 507 import bridges; same toolchain as Fury³ |
| **[fury3](https://github.com/sp00nznet/fury3)** | Fury³ | 1995 | Terminal Reality voxel engine (Win32/MSVC) | **Playable!** Flies the canyon - 1,945 functions, SDL2+imgui frontend, real joystick |
| **[catz](https://github.com/sp00nznet/catz-recomp)** | Catz | 1996 | 16-bit NE engine DLL (PF Magic) | Runs! Win32 window, original frame loop, toys and saving work |
| **[encarta](https://github.com/sp00nznet/encarta)** | Encarta 97 Encyclopedia | 1996 | MFC 4.0 + proprietary | **Runs!** Whole app lifted (7,326 fns); hybrid boundary puts the app body in recompiled code - 10,242 real MFC virtual dispatches land lifted per session |
| **[gta](https://github.com/sp00nznet/gta)** | Grand Theft Auto | 1997 | DMA "Race'n'Chase" | Builds & runs - 4,094 functions, 444K lines, runtime bringup |
| **[pod](https://github.com/sp00nznet/pod-recomp)** | POD Gold | 1997 | Ubi Soft MMX software rasteriser | Compiles & links - 3,405 functions, 0 lift errors, 422K lines |
| **[ejay](https://github.com/sp00nznet/ejay)** | Dance eJay 1 + 2 | 1997 | PXD Musicsoft audio engine behind a VB front end | **Plays and draws!** Decodes its intro, streams to a real sound card at 22,050 Hz and animates its cursor - out of recompiled 16-bit code |
| **[fallout1-re](https://github.com/sp00nznet/fallout1-re)** | Fallout | 1997 | Custom (Interplay) | Fork - native + HTML5 web port, multiplayer |
| **[fallout2-re](https://github.com/sp00nznet/fallout2-re)** | Fallout 2 | 1998 | Custom (Interplay) | Fork - decompilation ~complete (alexbatalov upstream) |
| **[trespasser](https://github.com/sp00nznet/trespasser)** | Jurassic Park: Trespasser | 1998 | DreamWorks Interactive rigid-body engine (MSVC 6.0) | P0 - reconnaissance. Ships a linker map, which makes it the calibration target for function recovery |
| **[nocturne](https://github.com/sp00nznet/nocturne)** | Nocturne | 1999 | Terminal Reality, Watcom C/C++32 | Phase 7 - 6,027 functions lift with 0 errors; real window, 42 MB image mapped, IAT dispatch, 95 of 171 imports live |
| **[xwa](https://github.com/sp00nznet/xwa)** | X-Wing Alliance | 1999 | Custom (LucasArts) | Active - D3D11 port, concourse UI runs, 2,702 functions |
| **[sof](https://github.com/sp00nznet/sof)** | Soldier of Fortune | 2000 | Quake II + GHOUL | Active - SDL2 port, 8 subsystems, full maps render |
| **[gunman](https://github.com/sp00nznet/gunman)** | Gunman Chronicles | 2000 | GoldSrc (Half-Life) | Phase 2 - 3,990 functions, weapons/entities rebuilt |
| **[heavymetal](https://github.com/sp00nznet/heavymetal)** | Heavy Metal: FAKK2 | 2000 | id Tech 3 + UberTools | Foundation - 57 source files, core systems scaffolded |
| **[crimsonskies](https://github.com/sp00nznet/crimsonskies)** | Crimson Skies | 2000 | Zipper GOS engine | Compiles & links - 6,232 functions, 826K lines, runtime bringup |
| **[bw](https://github.com/sp00nznet/bw)** | Black & White | 2001 | Lionhead custom | Active - all 569 types done, 10 Hz game loop runs |
| **[rol](https://github.com/sp00nznet/rol)** | Rise of Nations: Rise of Legends | 2006 | Big Huge Games rts2 (MSVC 7.1) | Phase 3 - the largest binary this toolchain has faced: 13.25 MB, 25,513 vtable-only functions, no RTTI |

Every row above links to a repo that is actually there. See
[docs/PROJECTS.md](docs/PROJECTS.md) for what each one taught the toolbox,
including the three fixes One Must Fall: Battlegrounds forced before its
disc would even open.

**Also not public** -- same toolbox, repos still private, listed because the
tools here carry their scars: **bolo** (Bolo Adventures III, 1993 -- shipped
`tools/unpklite.py`, a byte-exact static PKLITE 1.15 decompressor),
**coaster** (Roller Coaster Construction Set, 1993 -- ~560 functions, boots),
**bob** (Microsoft Bob, 1995 -- Win16 NE + Jet/WinG, `InitInstance` runs),
**mw3** (MechWarrior 3, 1999 -- 2,805 functions), **recoil** (1999 -- 3,490
functions) and **xvt** (X-Wing vs TIE Fighter, 1997).

The first three are held back by their own generated code rather than by
progress: lifted C is a derivative work of the binary it came from, and every
public repo here tracks none of it. See
[docs/PUBLISHING.md](docs/PUBLISHING.md) and `tools/audit_repo.py`.

Still at P0, so still private: **missileattack** (Missile Attack!, 1992),
**tim** (The Even More Incredible Machine, 1993), **msbus** (Magic School Bus:
Human Body, 1994), **tv** (Terminal Velocity, 1995), **mtm** (Monster Truck
Madness 1+2, 1996 / 1998), **forcecommander** (Star Wars: Force Commander,
2000), **omfbg** (One Must Fall: Battlegrounds, 2003) and **bw2** (Black &
White 2, 2005). Each is in [docs/PROJECTS.md](docs/PROJECTS.md) with what it
cost the toolbox.

### Sibling toolboxes

Same idea, different instruction set or platform. They are separate repos, not
submodules:

- **[xboxrecomp](https://github.com/sp00nznet/xboxrecomp)** -- original Xbox
  (XBE), and therefore **also x86-32**. It is the closest relative this repo
  has, and the two have been converging: see
  [docs/CONSOLIDATION.md](docs/CONSOLIDATION.md) for what has already been
  ported across and what is queued next.
- **[macrecomp](https://github.com/sp00nznet/macrecomp)** -- 68k Macintosh,
  A-trap dispatch and a QuickDraw/Toolbox HAL.

## Quick Start

### "I have a mystery .exe and I want to know what's inside"

```bash
# What are we dealing with? (prints a summary; --json names the output file)
python tools/pe/pe_analyze.py mystery.exe --json analysis.json

# What DLLs does it import? (including delay-loaded ones). Point
# extract_imports at the whole install folder to get the shared-API view
# across every module at once -- those are the shims to write first.
python tools/pe/extract_imports.py mystery.exe
python tools/pe/extract_imports.py /path/to/install
python tools/pe/delay_imports.py mystery.exe

# Is it packed or copy-protected? (SafeDisc/SecuROM/UPX/...)
python tools/pe/analyze_sections.py mystery.exe

# Catalog every binary in the install folder at once
python tools/pe/catalog.py /path/to/install --json > catalog.json

# Got Ghidra? Decompile everything in one shot
# (run in Ghidra's headless analyzer)
analyzeHeadless /path/to/project MyProject -import mystery.exe \
  -postScript tools/ghidra/DecompileAll.java output.c
```

### "I want to turn an old 32-bit exe into C code"

```bash
# Full automated pipeline: analyze -> disassemble -> lift -> compile
python -m tools game.exe --all --output src/recomp/gen/

# Or step by step:
python tools/pe/pe_analyze.py game.exe --json config/pe_analysis.json
python tools/disasm/disasm32.py game.exe --output functions.json --pe-json config/pe_analysis.json

# `python -m tools` is tools/lift/translator.py, and that is the only lifter
# CLI. lift32.py itself is a library: `from lift32 import Lifter`, one
# `Lifter` per function. Every project past the default pipeline drives it
# from its own run_lift.py -- that is where per-project relocation handling,
# import bridging and file splitting belong, not in a flag.
```

### "It's a 16-bit DOS game from 1991"

```bash
# Disassemble: the whole resident image, one overlay, or a byte range
python tools/disasm/decode16.py GAME.EXE --resident
python tools/disasm/decode16.py GAME.EXE --overlay 3
python tools/disasm/decode16.py GAME.EXE 0x1200 0x400

# Find function boundaries (MSC 5.x patterns) and write the symbol table
python tools/disasm/analyze.py GAME.EXE -symbols work/symbols.toml

# Large model (Borland/MSC): `largemodel16` is a library that extends the
# analyzer in place -- detect_code_end() clips the DGROUP data blob off the
# code, build_call_graph() resolves the far calls analyze.py leaves dangling.
#   from largemodel16 import detect_code_end, build_call_graph
#
# Lifting is a library too, same as the 32-bit side: `from lift16 import Lifter`.
# Copy a project's driver to start -- dinopark/tools/lift_full.py (DOS MZ,
# large model) or elfish/tools/ne_lift.py (NE, segmented).
```

### "Did the lifter get the semantics right?"

```bash
# Run the lifted C and a real x86 (Unicorn) over the same bytes and compare
# every register, flag and byte of memory. Needs unicorn + a C compiler.
python tools/lift/difftest.py -v

# The 16-bit CPU model's hand-written flag logic (BCD, ADC/SBB carry-in),
# against values taken from hardware
cc -Iruntime/recomp16 runtime/recomp16/cpu_selftest.c -o selftest && ./selftest
```

### "Did the disassembler find the real functions?"

```bash
# Score a recovered catalog against a reference -- a linker map, a PDB export,
# or another tool's analysis. Reports precision/recall on function starts.
python tools/disasm/score_recovery.py --reference ida_funcs.json \
                                      --candidate functions.json

# The reference can come from IDA, headless, in about a minute:
py -3.11 tools/ida/ida_funcs.py GAME.EXE ida_funcs.json
```

A false positive is two different defects wearing one name, so when the
reference carries function *ranges* (IDA, a PDB) the score separates them:
**split** means the address landed inside a known function, so one function
got entered twice -- it duplicates code in a lift. **invented** means it
landed outside every known function, so data was probably decoded as code --
that lifts to garbage. They need opposite fixes.

A reference is only ground truth if it came from symbols. Otherwise it is a
second opinion, and a disagreement means one of the two is wrong -- go look at
which before quoting the number.

### "It's a 16-bit Windows / OS-2 program (NE format)"

```bash
# Structure: segments, relocations, imports, entry points
python tools/ne/ne_parse.py GAME.EXE

# NE-aware disassembly (resolves cross-segment far calls + imports)
python tools/ne/ne_decode.py GAME.EXE --summary
python tools/ne/ne_decode.py GAME.EXE --seg 3

# Segment call graph / clusters / import usage
python tools/ne/ne_xref.py GAME.EXE --clusters
python tools/ne/ne_xref.py GAME.EXE --imports

# The import surface as C: prototypes + a correctly-purging stub for every
# import with no hand-written shim yet
python tools/ne/gen_win16_stubs.py GAME.DLL     --api runtime/runtime_api.h --stubs runtime/win16/win16_stubs.c     --shims runtime/win16 --guard MYGAME
```

Then lift it. `ne_lift.py` is a library, same as the other lifters -- set
`PREFIX` and call `lift_segment(ne, n)` per segment from your own driver:

```python
import ne_lift
ne_lift.PREFIX = 'mygame'
ne_lift.lift_segment(ne, seg.index)     # prints C to stdout
```

**The ordinal map is not per-project.** `KERNEL.90` is `lstrlen` in every Win16
binary, so `win16.py` now falls back to `tools/ne/win16_imports.json` when the
project has none of its own. Build it once with `idt_to_json.py` and every
Win16 target sees it. It stays gitignored -- it is IDA's data, not ours.

**Win16 is PASCAL, and that is the thing that bites.** The callee pops the
arguments, so a shim that pops the wrong number does not fail at the call - it
shifts the *caller's* frame, and the caller's epilogue then restores DS (or BP,
or a return address) from the wrong slot. The crash lands somewhere else
entirely, in code that is fine. `tools/ne/win16.py` carries the accumulated
purge table keyed by (MODULE, API); `gen_win16_stubs.py` fails rather than
generating a stub for an import that has no entry in it.

Names come from IDA, which ships the Win16 ordinal maps. Export them once with
`tools/ida/ida_export.py`-style extraction into `work/win16_imports.json` and
`win16.py` finds it by walking up from the project root; without it, imports
resolve to `MODULE_OrdN` and the purge lookups all miss.

### "The exe has SafeDisc DRM"

```bash
# Confirm it statically first (entry point inside a high-entropy section?)
python tools/pe/analyze_sections.py game.exe

# Dump decrypted code from a running process (Steam/CD version)
python tools/drm/safedisc_dump.py game.exe decrypted.exe
python tools/drm/safedisc_dump.py --pid 1234 game.exe decrypted.exe
```

### "It's a Wise installer and I want the files out"

```bash
# Find the overlay, inflate the install script, list embedded files
python tools/assets/extract_wise.py setup.exe out_dir/
```

### "Who calls this function? What does it call?"

```bash
# Direct callers (no Ghidra/IDA needed) + most-referenced functions
python tools/disasm/callgraph.py game.exe --callers 0x401D10
python tools/disasm/callgraph.py game.exe --hot 25

# Function-level graph + leaf detection (pair with DumpBounds.java output)
analyzeHeadless proj P -process game.exe -postScript tools/ghidra/DumpBounds.java bounds.csv
python tools/disasm/callgraph.py game.exe --bounds bounds.csv --leaves
```

### "I have IDA and want its analysis to drive the lifters"

```bash
# Export IDA's verified code map (functions + instruction heads), then feed it in
py -3 tools/ida/ida_export.py GAME.EXE code_map.json --key ne
python tools/ne/ne_decode.py GAME.EXE --ida-json code_map.json
```

## Requirements

**Python 3.10+** with:
- `capstone` - disassembly engine. Required.
- `pefile` - PE parsing. Optional; there is a pure-struct fallback.
- `lief` - advanced binary analysis. Optional.
- `unicorn` - the reference x86 that `lift/difftest.py` checks the lifted C
  against. Only needed to run the differential tests.

**For Ghidra scripts:** Ghidra 11.0+

**For IDA scripts:** IDA 7.4+ with its bundled Python (`ida_funcs.py` and
`ida_export.py` run headless under `idat -A -S`).

**For format tools:** C compiler (MSVC or GCC)

**For runtime:** CMake 3.20+, Visual Studio 2022 or compatible

```bash
pip install capstone pefile lief unicorn
```

## Starting a New Project

1. Copy `templates/CMakeLists.txt.template` and `templates/.gitignore.template`
2. Run `pe_analyze.py` on your target binary
3. Pick your pipeline:
   - **32-bit PE**: `python -m tools game.exe --all` (`disasm32` -> `lift32`,
     driven by `lift/translator.py`). Write your own `run_lift.py` when the
     defaults stop fitting.
   - **16-bit DOS**: `decode16` -> `analyze` -> `lift16` (with DOS compat runtime)
   - **16-bit Windows/OS-2 (NE)**: `ne/ne_parse` -> `ne/ne_decode` -> `lift16` (see `tools/ne/README.md`)
   - **GoldSrc/SDK game**: `DecompileAll.java` -> `combined_classify.py` (SDK separation)
   - **C++ heavy**: `GhidraStats.java` + `msvc_mangler.py` + `parse_vtables.js`
4. **Score the recovery before you lift it.** `disasm/score_recovery.py`
   against a linker map, a PDB or IDA. Lifting a catalog you have not scored
   means finding its gaps at runtime, 30,000 calls deep, instead of now.
5. Drop in the appropriate `runtime/` files
6. Build with CMake, fix, repeat

### Where the docs are

| Doc | What it covers |
|-----|----------------|
| [docs/PHILOSOPHY.md](docs/PHILOSOPHY.md) | Why static recompilation, and the approach end to end |
| [docs/PIPELINE.md](docs/PIPELINE.md) | Each phase, which tool, what it emits |
| [docs/HYBRID.md](docs/HYBRID.md) | Running lifted code *inside* a real program - the lifted/real boundary, its three non-obvious correctness rules, and how to bisect a hybrid build when it breaks 30,000 calls deep |
| [docs/PROJECTS.md](docs/PROJECTS.md) | Which project contributed which tool, and why it exists |
| [docs/CONSOLIDATION.md](docs/CONSOLIDATION.md) | What pcrecomp and [xboxrecomp](https://github.com/sp00nznet/xboxrecomp) should share, what has been ported, what is queued |

## Philosophy (the short version)

> Any PC application ever compiled can be systematically deconstructed and rebuilt for modern hardware. It's not magic, it's just work -- and with the right tools, it's *less* work every time.

We've proven this across DOS, Win16, Win32, MFC, Quake-family engines, GoldSrc, id Tech 3, and completely custom engines. The pattern is always the same: **Analyze -> Disassemble -> Classify -> Lift -> Shim -> Build -> Debug -> Ship.**

Read the full philosophy in [docs/PHILOSOPHY.md](docs/PHILOSOPHY.md).

## Credits

Built on other people's tools, and on published reverse-engineering work:

- **[capstone](https://www.capstone-engine.org/)** (BSD-3-Clause) — the
  disassembly engine under every lifter here.
- **[pefile](https://github.com/erocarrera/pefile)** (MIT) — PE parsing,
  including the `.reloc` walk the 32-bit lifters rely on.
- **[Ghidra](https://ghidra-sre.org/)** (Apache-2.0) and **IDA Pro** — hosts for
  the headless scripts in `tools/ghidra/` and `tools/ida/`; function boundaries
  and decompilation.
- **Kostya Shishkov** and **Alyssa Milburn** — their published work on the
  FVF/IFS fractal codec family underpins `tools/formats/ftcdecode/`.

All of the above are used as libraries or hosts under their own licences. None
of them are vendored here.

## License

**MIT** — see [LICENSE](LICENSE). Use these tools to bring back whatever
software you love.

One thing the licence cannot give you: rights to the software you point these
tools at. Lifting a binary produces a derivative work of that binary, so the
output carries whatever licence the original does. Own what you take apart.

---

*Built with stubbornness and too much coffee by [sp00nznet](https://github.com/sp00nznet)*
