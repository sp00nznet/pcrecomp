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
  tools/           Analysis & transformation tools (Python, a few C and Java)
    pe/            PE: headers, imports, resources, protection, symbol recovery
    ne/            NE (16-bit Windows / OS-2): parse, disassemble, Win16 imports,
                   and the generators that close lift -> compile -> link
    disasm/        Disassemblers, call graphs, and scoring a catalog
    lift/          Lifters for x86-16, x86-32 and x86-64, whole-image drivers,
                   and a differential tester for each
    cpp/           C++ recovery: RTTI, vtables, name (de)mangling
    classify/      Sorting functions: SDK vs custom, library vs game
    ghidra/ ida/   Headless scripts for both
    drm/           SafeDisc memory dumping
    assets/        Installers, archives and disc images
    formats/       Decoders for formats nobody else reads (C)
    audit_repo.py  Is this repo safe to make public?
  runtime/         What the lifted C compiles and links against
    recomp16/      16-bit DOS: CPU state, INT handlers, HAL, SDL2
    win16/         16-bit Windows NE: CPU header + link-on-day-one stubs
    recomp32/      32-bit, global registers: memory, dispatch, loader, crash report
    recomp32_cpu/  32-bit, explicit CPU struct (reentrant)
    recomp64_cpu/  64-bit, explicit CPU struct, plus guest C++ exception handling
    hybrid/        The lifted <-> real boundary, for keeping MFC or the CRT real
    compat/        Win32 -> SDL2 mapping
  templates/       Starter CMakeLists and .gitignore for a new project
  docs/            Pipeline, philosophy, the hybrid boundary, publishing
```

### The pipeline, by architecture

Every target goes **analyse -> find the functions -> lift -> generate the build
tree -> link against a runtime -> test the lift**. The tool at each step depends
on what the binary is:

| Stage | 16-bit DOS (MZ) | 16-bit Windows (NE) | 32-bit PE | 64-bit PE |
|-------|-----------------|---------------------|-----------|-----------|
| Analyse | `disasm/decode16` | `ne/ne_parse`, `ne/ne_xref` | `pe/pe_analyze`, `pe/catalog`, `pe/extract_imports` | same as 32-bit |
| Find functions | `disasm/analyze`, `disasm/largemodel16` | `ne/ne_decode` (or IDA via `ida/ida_export`) | `disasm/disasm32`, `cpp/rtti`, `cpp/vtable_scan`, `lift/recover`, `disasm/seed_from_log` | an IDA catalog, closed by `lift/generate64` |
| Lift | `lift/lift16` | `lift/ne_lift` | `lift/lift32` (global registers) or `lift/lift32_cpu` (CPU struct) | `lift/lift64_cpu` |
| Generate the build tree | the project's own driver | `ne/gen_segments_h`, `ne/gen_unresolved_stubs`, `ne/gen_win16_stubs`, `ne/gen_image` | `python -m tools` (`lift/translator`), `lift/generate` | `lift/generate64` |
| Runtime | `runtime/recomp16` | `runtime/win16` | `runtime/recomp32` or `recomp32_cpu`, plus `hybrid` | `runtime/recomp64_cpu` |
| Test the lift | `lift/difftest16`, `recomp16/cpu_selftest.c` | `lift/difftest16 --ne` | `lift/difftest` (Unicorn), `recomp32_cpu/cpu_selftest.c` | `lift/difftest64` (the host CPU) |

`disasm/score_recovery` scores any of the catalogs against a linker map, a PDB
or IDA, whatever the architecture.

### Every tool, one line each

**Reading the binary** (`tools/pe/`)

| Tool | What it does |
|------|--------------|
| `pe_analyze.py` | Headers, sections, imports, exports; `--json` feeds the rest of the pipeline |
| `extract_imports.py` | Imports of one module, or the shared API surface across a whole install folder |
| `delay_imports.py` | The delay-load table that the plain import table leaves out |
| `analyze_sections.py` | Packing and DRM detection (SafeDisc, SecuROM, UPX, ...) |
| `catalog.py` | Catalog every binary in a folder, naming NE/LE/MZ images rather than calling them broken |
| `stdcall_argc.py` | Each import's stdcall stack purge, from the SDK's `_Name@N` decorations instead of a hand-typed table |
| `rsrc.py` | List and extract `.rsrc` (bitmaps get their file header back, so they open) |
| `map_names.py` | Names from an MSVC linker MAP; `port` carries library names onto a binary that shipped without one |
| `debug_symbols.py` | Which source file each function came from, from surviving `__FILE__` strings |
| `merge_names.py` | Every name source (MAP > RTTI > `__FILE__` > anything else) merged into one C-safe name per address |

**Finding the functions** (`tools/disasm/`, `tools/cpp/`, `tools/lift/recover.py`)

| Tool | What it does |
|------|--------------|
| `disasm/disasm32.py` | 32-bit recursive descent from the entry point, exports and `--seed-functions` |
| `disasm/decode16.py` | Table-driven 16-bit decoder: resident image, one overlay, or a byte range |
| `disasm/analyze.py` | 16-bit function boundaries (MSC 5.x patterns) and a symbol table |
| `disasm/largemodel16.py` | Library: clips DGROUP off the code and resolves large-model far calls |
| `disasm/fpu_decode.py` | x87 decoding for the 16-bit side |
| `disasm/callgraph.py` | Direct callers/callees, hot functions and leaves, no Ghidra or IDA needed |
| `disasm/seed_from_log.py` | Feed the unresolved `ICALL`/`ITAIL` targets a run printed back into the next disassembly |
| `disasm/score_recovery.py` | Precision/recall of a catalog against a reference, false positives split into *split* and *invented* |
| `cpp/rtti.py` | Classes, vtables, virtual methods and inheritance from MSVC RTTI; every method is a proven entry point |
| `cpp/vtable_scan.py` | The same vtables without RTTI, found as runs of code pointers in data |
| `lift/recover.py` | Entries a catalog missed: jmp-thunk chains, stored function pointers, alternate entries inside merged functions |

**Lifting** (`tools/lift/`)

| Tool | What it does |
|------|--------------|
| `lift16.py` | x86-16 -> C for DOS MZ; a library (`from lift16 import Lifter`) |
| `ne_lift.py` | NE-aware x86-16 -> C: far calls through relocations, Win16 imports as `MODULE_API(cpu)`, x87, segment-aware memory |
| `lift32.py` | x86-32 -> C against global registers (`recomp32`); a library |
| `lift32_cpu.py` | x86-32 -> C against an explicit CPU struct, reentrant, needed for hybrid builds. x87 (80-bit operands, `fprem`, `fcmov`), MMX, packed SSE/SSE2, `lock`, bit-string ops, `bswap` |
| `lift64_cpu.py` | x86-64 -> C: 32-bit writes zero-extend, RIP-relative operands rebuilt, 16 GPRs + 16 XMM, SSE2 packed integer, quadword string ops, `cpuid` forwarded. x87 and MMX deliberately emit `RECOMP_TODO` |
| `translator.py` | `python -m tools`: the default 32-bit pipeline, analyse -> disassemble -> lift -> split into files |
| `generate.py` | Fast 32-bit generation: one linear sweep, split on known boundaries |
| `generate64.py` | Whole-PE x86-64 driver: chunked TUs, declarations, dispatch table, import map. It also finishes the catalog (below) |
| `difftest.py` | Lifted C vs Unicorn for x86-32, every register, flag and byte compared |
| `difftest16.py` | The same for x86-16, on raw bytes or a real NE segment (`--ne`) |
| `difftest64.py` | Lifted C vs the **host CPU** running the original bytes (`difftest64.asm`): registers, memory operands, `lock` atomics |

**Win16 NE** (`tools/ne/`, see [tools/ne/README.md](tools/ne/README.md))

| Tool | What it does |
|------|--------------|
| `ne_parse.py` | Segments, relocations, imports, entry points; flags a VBRUN-only import list as p-code |
| `ne_decode.py` | NE-aware disassembly with cross-segment far calls and imports resolved; `--ida-json` follows IDA's code map |
| `ne_xref.py` | Segment call graph, clusters, import usage, `--dot` |
| `win16.py` | Ordinal -> API name, and the PASCAL stack-purge table keyed by (MODULE, API) |
| `idt_to_json.py` | The ordinal map, built from the `.idt` files IDA ships, with no IDA run |
| `gen_win16_stubs.py` | Prototypes, plus a correctly purging stub for every import with no shim yet; refuses an import whose purge it does not know |
| `gen_segments_h.py` | `segments.h` generated from the lifted definitions, so prototypes cannot drift |
| `gen_unresolved_stubs.py` | Defines the call targets nothing lifted, as stubs that **abort** rather than return |
| `gen_image.py` | The flat memory image and `mem_layout.h`, internal relocations applied |

**Everything else**

| Tool | What it does |
|------|--------------|
| `classify/classify_functions.py`, `combined_classify.py`, `deep_classify.py` | SDK vs custom code in a GoldSrc game: SDK names, string references, call-graph and address clustering |
| `classify/resolve_stubs.py` | Maps `far_SSSS_XXXX` stubs to real functions and names the MSC 5.x C library |
| `cpp/msvc_mangler.py`, `cross_mangler.py`, `mac_unmangler.py`, `parse_vtables.js` | MSVC mangling, Metrowerks (Mac) demangling and Mac -> MSVC translation, vtable parsing |
| `ghidra/*.java` | Headless: decompile everything or by address, export functions, stats, xrefs, range disassembly, function bounds |
| `ida/ida_funcs.py`, `ida_export.py`, `ida_xrefs.py`, `ida_probe_segs.py` | Headless: function catalog with FLIRT flags, instruction-head code map, call graph + import use + FPU density, segment probe |
| `drm/safedisc_dump.py`, `inject_and_run.c` | Dump SafeDisc-decrypted `.text` from a running process; a version.dll injector for SafeDiscLoader2 |
| `assets/extract_wise.py`, `isextract.py`, `extract_cab.sh`, `pk3_inspect.py`, `bin2iso.js` | Wise and InstallShield installers, CABs, PK3/ZIP, BIN/CUE -> ISO |
| `assets/iso_peek.py` | Read an ISO's directory, locally or **over HTTP range requests**, and pull one file out without downloading the image |
| `formats/` | FIF/FTC fractal image, M20/MVB, SPAM, DAT and string-table decoders (C) |
| `audit_repo.py` | Game material or lifted output tracked in a repo, in HEAD or in history; see [docs/PUBLISHING.md](docs/PUBLISHING.md) |

### What the 64-bit path does that the 32-bit one never needed

The x86-64 lifter came in from [systemes3recomp](https://github.com/sp00nznet/systemes3recomp),
where it runs Star Wars Battle Pods: a shipping UE3 build, 3.6M instructions,
92,552 functions, 0 lift errors. That binary forced four things, and all of them
live in `generate64.py` and `runtime/recomp64_cpu/`:

- **The catalog is closed, not trusted.** `.pdata` is not a function list (it
  splits functions into chunks and leaves out frameless leaves), so the catalog
  comes from IDA and generate64 finishes it. It reads back every literal
  target the generated C dispatches to and adds the ones that are not entries,
  repeating until nothing new appears (6 rounds, +1,101). It sweeps the `DIR64`
  relocations for stored pointers into `.text`, which finds the functions only
  a vtable points at exactly, with no heuristic (+412). It takes entries from
  `lea r64, [rip+disp]` for callbacks whose address is only ever computed
  (+217). And it catalogs the int3-padded lone `jmp rel32` thunks that MSVC
  emits and vtable slots point at, which IDA names only most of the time.
- **Switch arms are reachable.** MSVC x64 computes a switch target in a
  register. So a function with an indirect jump labels every instruction and
  ends in a local dispatch switch. It falls back to the global dispatcher only
  for a real cross-function tail call.
- **Guest C++ exceptions work.** `eh64.c` walks the *guest* stack with the
  original `.pdata`/`.xdata` and reads `__CxxFrameHandler3`'s FuncInfo. It runs
  the catch funclet as guest code, then longjmps into the landing pad the lifter
  emits for every function that had a handler. The throw is intercepted at
  `_CxxThrowException`.
- **Imports are forwarded, not reimplemented.** A Win64 guest on a Win64 host
  shares the calling convention, so the loader puts the real function address
  in the IAT slot. The import map generate64 emits is for reading crash trails.

## The Projects That Built This

Every tool here was forged in the fires of an actual recompilation project.
These are the PC games and apps we've taken apart so far. Statuses are what the
project's own README claims; the numbers are function counts from its last
pipeline run.

| Project | What | Era | Engine/Tech | Status |
|---------|------|-----|-------------|--------|
| **[wholeearth](https://github.com/sp00nznet/wholeearth)** | The Electronic Whole Earth Catalog | 1988 | Macintosh HFS CD-ROM, HyperCard 1.2.2 | Format project - no PC binary on the disc; ships the classic-HFS lister, hands the stacks to `macrecomp` |
| **[civ](https://github.com/sp00nznet/civ)** | Civilization | 1991 | 16-bit DOS / MSC 5.x | Runs! 672 functions, interactive boot/menu, 164K lines |
| **[operationneptune](https://github.com/sp00nznet/operationneptune)** | Operation Neptune | 1991 / Win32 1998 | Borland PE32, ships its own linker map | **Plays!** CRT -> WinMain -> opening -> in the submarine |
| **[skifree](https://github.com/sp00nznet/skifree)** | SkiFree | 1991 | Win16/Win32 (`ski32.exe`) | Playable rebuild from decompiled C, cross-platform + extras |
| **[missileattack](https://github.com/sp00nznet/missileattack)** | Missile Attack! | 1992 | 16-bit Win16 NE, MS linker 5.14 | P0 - the 16-bit pipeline's fixture: 87 KB NE, **one** code segment, 21 KB of code, no segmentation at all |
| **[tim](https://github.com/sp00nznet/tim)** | The Even More Incredible Machine | 1993 | Borland C++ Win16 NE | P0 - 27 code segments, imports nothing but KERNEL/USER/GDI, names its own window procs |
| **[bolo](https://github.com/sp00nznet/bolo)** | Bolo Adventures III | 1993 | 16-bit DOS, PKLITE-packed QuickBASIC | Boots & runs! 932 functions, 70K lines, EGA/DOS shimmed to SDL2; shipped `tools/unpklite.py` |
| **[coaster](https://github.com/sp00nznet/coaster)** | Roller Coaster Construction Set | 1993 | 16-bit DOS, Microsoft C (Code To Go) | Boots - 886 functions lifted, runs the MSC startup into `main()` and through device setup, DOS on SDL2 |
| **[dinopark](https://github.com/sp00nznet/dinopark)** | DinoPark Tycoon | 1993 | 16-bit DOS / Borland large model | Boots! Whole game lifted (~90K lines), renders .PIC screens + .ACT dinosaurs in colour |
| **[elfish](https://github.com/sp00nznet/elfish)** | El-Fish | 1993 | 16-bit NE + TSXLIB extender | Lifted & links - 2,236 functions, 121 segments, startup executes |
| **[msbus](https://github.com/sp00nznet/msbus)** | The Magic School Bus Explores the Human Body | 1994 | Win16 NE, 18 binaries | P0 - ~60 KB of code driving 190 MB of content |
| **[worldempire](https://github.com/sp00nznet/worldempire)** | World Empire | 1994 | Visual Basic 3 p-code over `VBRUN300.DLL` (Win16 NE) | Runs! The interpreter is the target: 99/99 segments, 14,826 functions, 226K lines, links and executes a real Win16 init path |
| **[tv](https://github.com/sp00nznet/tv)** | Terminal Velocity | 1995 | Watcom C, DOS/4GW LE | P0 - P1 is building the LE/LX front end this toolbox does not have yet |
| **[bob](https://github.com/sp00nznet/bob)** | Microsoft Bob | 1995 | Win16 NE + MFC, Jet/Access, WinG | Bring-up - all three modules lift link-clean, `InitInstance` runs Bob's real startup, frontier is inside Jet |
| **[hellbender](https://github.com/sp00nznet/hellbender)** | Hellbender | 1996 | Terminal Reality voxel engine (Win32/MSVC) | Bring-up - lifts clean (5,262 functions, 0 errors), 507 import bridges; same toolchain as Fury³ |
| **[fury3](https://github.com/sp00nznet/fury3)** | Fury³ | 1995 | Terminal Reality voxel engine (Win32/MSVC) | **Playable!** Flies the canyon - 1,945 functions, SDL2+imgui frontend, real joystick |
| **[mtm](https://github.com/sp00nznet/mtm)** | Monster Truck Madness 1 + 2 | 1996 / 1998 | Terminal Reality, voxel runtime as a standalone DLL | P0 - the Fury³ engine a third time, renderer split into named DLLs |
| **[catz](https://github.com/sp00nznet/catz-recomp)** | Catz | 1996 | 16-bit NE engine DLL (PF Magic) | Runs! Win32 window, original frame loop, toys and saving work |
| **[encarta](https://github.com/sp00nznet/encarta)** | Encarta 97 Encyclopedia | 1996 | MFC 4.0 + proprietary | **Runs!** Whole app lifted (7,326 fns); hybrid boundary puts the app body in recompiled code - 10,242 real MFC virtual dispatches land lifted per session |
| **[gta](https://github.com/sp00nznet/gta)** | Grand Theft Auto | 1997 | DMA "Race'n'Chase" | Builds & runs - 4,094 functions, 444K lines, runtime bringup |
| **[pod](https://github.com/sp00nznet/pod-recomp)** | POD Gold | 1997 | Ubi Soft MMX software rasteriser | Compiles & links - 3,405 functions, 0 lift errors, 422K lines |
| **[ejay](https://github.com/sp00nznet/ejay)** | Dance eJay 1 + 2 | 1997 | PXD Musicsoft audio engine behind a VB front end | **Plays and draws!** Decodes its intro, streams to a real sound card at 22,050 Hz and animates its cursor - out of recompiled 16-bit code |
| **[xvt](https://github.com/sp00nznet/xvt)** | X-Wing vs TIE Fighter + Balance of Power | 1997 | Totally Games (the X-Wing Alliance engine's predecessor) | Boots to a window - 1,790 functions, the guest CRT runs into `WinMain` and messages dispatch into recompiled code; DirectDraw next |
| **[fallout1-re](https://github.com/sp00nznet/fallout1-re)** | Fallout | 1997 | Custom (Interplay) | Fork - native + HTML5 web port, multiplayer |
| **[fallout2-re](https://github.com/sp00nznet/fallout2-re)** | Fallout 2 | 1998 | Custom (Interplay) | Fork - decompilation ~complete (alexbatalov upstream) |
| **[trespasser](https://github.com/sp00nznet/trespasser)** | Jurassic Park: Trespasser | 1998 | DreamWorks Interactive rigid-body engine (MSVC 6.0) | P0 - reconnaissance. Ships a linker map, which makes it the calibration target for function recovery |
| **[nocturne](https://github.com/sp00nznet/nocturne)** | Nocturne | 1999 | Terminal Reality, Watcom C/C++32 | Phase 7 - 6,027 functions lift with 0 errors; real window, 42 MB image mapped, IAT dispatch, 95 of 171 imports live |
| **[mechwarrior3-recomp](https://github.com/sp00nznet/mechwarrior3-recomp)** | MechWarrior 3 | 1999 | Zipper GOS engine (VC6 + MFC42, DirectX 6) | Compiles - 2,805 functions, 0 lift errors, 158K lines, all 7 TUs build as a static lib |
| **[recoil-recomp](https://github.com/sp00nznet/recoil-recomp)** | Recoil | 1999 | Zipper GOS engine (VC6 + MFC42) | Compiles - 3,490 functions, 0 lift errors, 321K lines, 8/8 TUs build |
| **[xwa](https://github.com/sp00nznet/xwa)** | X-Wing Alliance | 1999 | Custom (LucasArts) | Active - D3D11 port, concourse UI runs, 2,702 functions |
| **[sof](https://github.com/sp00nznet/sof)** | Soldier of Fortune | 2000 | Quake II + GHOUL | Active - SDL2 port, 8 subsystems, full maps render |
| **[gunman](https://github.com/sp00nznet/gunman)** | Gunman Chronicles | 2000 | GoldSrc (Half-Life) | Phase 2 - 3,990 functions, weapons/entities rebuilt |
| **[heavymetal](https://github.com/sp00nznet/heavymetal)** | Heavy Metal: FAKK2 | 2000 | id Tech 3 + UberTools | Foundation - 57 source files, core systems scaffolded |
| **[crimsonskies](https://github.com/sp00nznet/crimsonskies)** | Crimson Skies | 2000 | Zipper GOS engine | Compiles & links - 6,232 functions, 826K lines, runtime bringup |
| **[forcecommander](https://github.com/sp00nznet/forcecommander)** | Star Wars: Force Commander | 2000 | LucasArts Ronin engine (MSVC 6) | **In game!** The campaign's briefing room renders in 3D - 39,038 functions, 10.7M lines, 0 lift errors |
| **[bw](https://github.com/sp00nznet/bw)** | Black & White | 2001 | Lionhead custom | Active - all 569 types done, 10 Hz game loop runs |
| **[omfbg](https://github.com/sp00nznet/omfbg)** | One Must Fall: Battlegrounds | 2003 | Diversions Entertainment, C++ module DLLs | P0 - 10,374 mangled C++ exports name the engine; SafeDisc covers 1% of the code |
| **[bw2](https://github.com/sp00nznet/bw2)** | Black & White 2 | 2005 | Lionhead custom | P0 partial - `white.exe` (21.7 MB, the largest target yet) not extracted from the discs |
| **[rol](https://github.com/sp00nznet/rol)** | Rise of Nations: Rise of Legends | 2006 | Big Huge Games rts2 (MSVC 7.1) | Phase 3 - the largest binary this toolchain has faced: 13.25 MB, 25,513 vtable-only functions, no RTTI |

Every row above links to a repo that is actually there. See
[docs/PROJECTS.md](docs/PROJECTS.md) for what each one taught the toolbox,
including the three fixes One Must Fall: Battlegrounds forced before its
disc would even open.

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
- **[systemes3recomp](https://github.com/sp00nznet/systemes3recomp)** -- Sega
  System ES3 arcade, which is Windows on x86-64. The 64-bit lifter, its runtime
  and difftest64 were written there against Star Wars Battle Pods and merged
  into this repo; see [the 64-bit path](#what-the-64-bit-path-does-that-the-32-bit-one-never-needed).

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
# large model). For NE, tools/lift/ne_lift.py is in this repo; see below.
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

Names come from IDA, which ships the Win16 ordinal maps as `.idt` files, so no
IDA run is needed. `win16.py` looks for `work/win16_imports.json`, then
`analysis/win16_imports.json`, walking up from the project root, then falls
back to `tools/ne/win16_imports.json`. Without any of them, imports resolve to
`MODULE_OrdN` and the purge lookups all miss:

```bash
python tools/ne/idt_to_json.py --ida "C:/Program Files/IDA Professional 9.1" \
                               -o tools/ne/win16_imports.json
```

Then close the lift -> compile -> link loop. Each of these is generated from
the target or from the lifted sources, so none of them is committed:

```bash
python tools/ne/gen_segments_h.py --src work/src --out runtime/segments.h --ne GAME.DLL
python tools/ne/gen_unresolved_stubs.py --src work/src --out work/src/_unresolved_stubs.c
python tools/ne/gen_image.py GAME.DLL --image work/mem_image.bin --header work/runtime/mem_layout.h
```

Link against `runtime/win16/`: `cpu.h` plus `recomp_stubs.c`, which gets a
fresh target from "compiles" to "links" on day one and aborts loudly at the
first thing that is not implemented.

### "It's a 64-bit exe"

```bash
# 1. A function catalog from a real disassembler, one "0xADDR size name" per
#    line. .pdata is NOT one (see "the 64-bit path" above).
# 2. Lift the whole image into a build tree. The catalog is closed here:
#    dispatch targets, stored code pointers, lea-computed callbacks, jmp thunks.
py -3.11 tools/lift/generate64.py game.exe funcs.txt build/gen --split 400

# One function, to read what the lifter makes of it
py -3.11 tools/lift/lift64_cpu.py game.exe funcs.txt out.c 0x140001000

# Check the lifter against the host CPU, on instructions taken from THIS
# binary plus hand-picked edge cases. Needs MSVC x64 (ml64 + cl).
py -3.11 tools/lift/difftest64.py game.exe funcs.txt --count 2000
```

The generated C compiles against `runtime/recomp64_cpu/cpu64.h`. Add `eh64.c`
when the guest uses C++ exceptions -- a UE3 build does, for every "failed to
find object".

### "Is this repo safe to make public?"

```bash
# Game files or lifted C tracked anywhere, including in history
python tools/audit_repo.py ../myproject
```

[docs/PUBLISHING.md](docs/PUBLISHING.md) says what to do about what it finds,
including how to strip history with `git-filter-repo`.

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
- `unicorn` - the reference x86 that `lift/difftest.py` and `difftest16.py`
  check the lifted C against. Only needed to run the differential tests.
  `difftest64.py` needs no emulator: the reference is the host CPU, built with
  MSVC x64 (`ml64` + `cl`).

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
   - **16-bit Windows/OS-2 (NE)**: `ne/ne_parse` -> `ne/ne_decode` -> `lift/ne_lift`
     -> `ne/gen_*` -> `runtime/win16` (see `tools/ne/README.md`)
   - **64-bit PE**: IDA catalog -> `lift/generate64` -> `runtime/recomp64_cpu`,
     checked with `lift/difftest64`
   - **GoldSrc/SDK game**: `DecompileAll.java` -> `combined_classify.py` (SDK separation)
   - **C++ heavy**: `GhidraStats.java` + `msvc_mangler.py` + `parse_vtables.js`
4. **Score the recovery before you lift it.** `disasm/score_recovery.py`
   against a linker map, a PDB or IDA. Lifting a catalog you have not scored
   means finding its gaps at runtime, 30,000 calls deep, instead of now.
5. Drop in the appropriate `runtime/` files
6. Build with CMake, fix, repeat
7. Before going public, run `audit_repo.py` and read
   [docs/PUBLISHING.md](docs/PUBLISHING.md). Lifted output never goes in git.

### Where the docs are

| Doc | What it covers |
|-----|----------------|
| [docs/PHILOSOPHY.md](docs/PHILOSOPHY.md) | Why static recompilation, and the approach end to end |
| [docs/PIPELINE.md](docs/PIPELINE.md) | Each phase, which tool, what it emits |
| [docs/HYBRID.md](docs/HYBRID.md) | Running lifted code *inside* a real program - the lifted/real boundary, its three non-obvious correctness rules, and how to bisect a hybrid build when it breaks 30,000 calls deep |
| [docs/PROJECTS.md](docs/PROJECTS.md) | Which project contributed which tool, and why it exists |
| [docs/PUBLISHING.md](docs/PUBLISHING.md) | What must not be in a public repo, how to strip it from history, and the order to do it in |
| [tools/ne/README.md](tools/ne/README.md) | The Win16 NE front end in detail |
| [tools/ida/README.md](tools/ida/README.md) | Running the IDA scripts headless |
| [docs/CONSOLIDATION.md](docs/CONSOLIDATION.md) | What pcrecomp and [xboxrecomp](https://github.com/sp00nznet/xboxrecomp) should share, what has been ported, what is queued |

## Philosophy (the short version)

> Any PC application ever compiled can be systematically deconstructed and rebuilt for modern hardware. It's not magic, it's just work -- and with the right tools, it's *less* work every time.

We've proven this across DOS, Win16, Win32, Win64, MFC, Quake-family engines, GoldSrc, id Tech 3, and completely custom engines. The pattern is always the same: **Analyze -> Disassemble -> Classify -> Lift -> Shim -> Build -> Debug -> Ship.**

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
