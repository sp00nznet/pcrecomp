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
                   protection/DRM detection, recursive binary catalog)
    ne/            NE (16-bit New Executable) parse / disasm / call-graph
    disasm/        Disassemblers (32-bit recursive descent, 16-bit table-driven,
                   x87 FPU decoder, direct call-graph scanner, large-model
                   far-call + code/data-boundary call-graph completion)
    lift/          Code lifters (x86-32 and x86-16 to readable C)
    classify/      Function classifiers (SDK vs custom, multi-signal, string refs)
    ghidra/        Ghidra headless scripts (decompile, export, stats, xrefs,
                   range disasm, function bounds)
    ida/           IDA headless scripts (code-map export, segment probe)
    drm/           DRM analysis (SafeDisc memory dumping, DLL injection)
    assets/        Asset extraction (InstallShield, Wise, PK3/ZIP, BIN/ISO, CAB)
    cpp/           C++ RE helpers (MSVC/MWerks name mangling, vtable parsing)
    formats/       Format decoders (FIF fractal images, M20/MVB, SPAM, DAT)
  runtime/         Drop-in runtime support for recompiled code
    recomp32/      32-bit x86 runtime (global registers, memory model, dispatch)
    recomp16/      16-bit DOS runtime (CPU state, INT handlers, HAL, SDL2)
    compat/        Win32 API compatibility layers (Win32 -> SDL2 mapping)
  templates/       Starter files for new projects (CMake, .gitignore)
  docs/            Deep dives and philosophy
```

## The Projects That Built This

Every tool here was forged in the fires of an actual recompilation project. These are the PC games and apps we've taken apart so far:

| Project | What | Era | Engine/Tech | Status |
|---------|------|-----|-------------|--------|
| **[civ](https://github.com/sp00nznet/civ)** | Civilization | 1991 | 16-bit DOS / MSC 5.x | Runs! 672 functions, interactive boot/menu, 164K lines |
| **[dinopark](https://github.com/sp00nznet/dinopark)** | DinoPark Tycoon | 1993 | 16-bit DOS / Borland large model | Boots! Whole game lifted (~90K lines), runs startup→main; renders .PIC screens + .ACT dinosaurs in colour from recompiled code |
| **[elfish](https://github.com/sp00nznet/elfish)** | El-Fish | 1993 | 16-bit NE + TSXLIB extender | Lifted & links - 2,236 functions, 121 segments, startup executes |
| **[fury3](https://github.com/sp00nznet/fury3)** | Fury³ | 1995 | Terminal Reality voxel engine (Win32/MSVC) | **Playable!** Flies the canyon - 1,945 functions, SDL2+imgui frontend, real joystick |
| **[encarta](https://github.com/sp00nznet/encarta)** | Encarta 97 Encyclopedia | 1996 | MFC 4.0 + proprietary | Format RE - FIF/M20/SPAM decoders, 16-bit thunk analysis |
| **[gta](https://github.com/sp00nznet/gta)** | Grand Theft Auto | 1997 | DMA "Race'n'Chase" | Builds & runs - 4,094 functions, 444K lines, runtime bringup |
| **[fallout1-re](https://github.com/sp00nznet/fallout1-re)** | Fallout | 1997 | Custom (Interplay) | Fork - native + HTML5 web port, multiplayer |
| **[fallout2-re](https://github.com/sp00nznet/fallout2-re)** | Fallout 2 | 1998 | Custom (Interplay) | Fork - decompilation ~complete (alexbatalov upstream) |
| **[xwa](https://github.com/sp00nznet/xwa)** | X-Wing Alliance | 1999 | Custom (LucasArts) | Active - D3D11 port, concourse UI runs, 2,702 functions |
| **[recoil](https://github.com/sp00nznet/recoil)** | Recoil | 1999 | Zipper GOS engine | Phase 2 - compiles, 3,490 functions, 321K lines |
| **[mw3](https://github.com/sp00nznet/mw3)** | MechWarrior 3 | 1999 | Zipper GOS engine | Phase 2 - compiles, 2,805 functions, 159K lines |
| **[sof](https://github.com/sp00nznet/sof)** | Soldier of Fortune | 2000 | Quake II + GHOUL | Active - SDL2 port, 8 subsystems, full maps render |
| **[gunman](https://github.com/sp00nznet/gunman)** | Gunman Chronicles | 2000 | GoldSrc (Half-Life) | Phase 2 - 3,990 functions, weapons/entities rebuilt |
| **[heavymetal](https://github.com/sp00nznet/heavymetal)** | Heavy Metal: FAKK2 | 2000 | id Tech 3 + UberTools | Foundation - 57 source files, core systems scaffolded |
| **[crimsonskies](https://github.com/sp00nznet/crimsonskies)** | Crimson Skies | 2000 | Zipper GOS engine | Compiles & links - 6,232 functions, 826K lines, runtime bringup |
| **[bw](https://github.com/sp00nznet/bw)** | Black & White | 2001 | Lionhead custom | Active - all 569 types done, 10 Hz game loop runs |

## Quick Start

### "I have a mystery .exe and I want to know what's inside"

```bash
# What are we dealing with?
python tools/pe/pe_analyze.py mystery.exe --json > analysis.json

# What DLLs does it import? (including delay-loaded ones)
python tools/pe/extract_imports.py mystery.exe
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
python -m tools --exe game.exe --all --output src/recomp/gen/

# Or step by step:
python tools/pe/pe_analyze.py game.exe --json > config/pe_analysis.json
python tools/disasm/disasm32.py game.exe --output functions.json
python tools/lift/lift32.py --functions functions.json --output src/
```

### "It's a 16-bit DOS game from 1991"

```bash
# Decode the 16-bit instructions
python tools/disasm/decode16.py GAME.EXE --output decoded.json

# Find function boundaries (MSC 5.x patterns)
python tools/disasm/analyze.py decoded.json --output functions.json

# Lift to C with DOS INT handlers
python tools/lift/lift16.py functions.json --output RecompiledFuncs/
```

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
```

### "The exe has SafeDisc DRM"

```bash
# Confirm it statically first (entry point inside a high-entropy section?)
python tools/pe/analyze_sections.py game.exe

# Dump decrypted code from a running process (Steam/CD version)
python tools/drm/safedisc_dump.py --exe game.exe --output decrypted.exe
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
- `capstone` - disassembly engine
- `pefile` - PE parsing (optional, has pure-struct fallback)
- `lief` - advanced binary analysis (optional)

**For Ghidra scripts:** Ghidra 11.0+

**For format tools:** C compiler (MSVC or GCC)

**For runtime:** CMake 3.20+, Visual Studio 2022 or compatible

```bash
pip install capstone pefile lief
```

## Starting a New Project

1. Copy `templates/CMakeLists.txt.template` and `templates/.gitignore.template`
2. Run `pe_analyze.py` on your target binary
3. Pick your pipeline:
   - **32-bit PE**: `disasm32` -> `lift32` -> `translator` (fully automated)
   - **16-bit DOS**: `decode16` -> `analyze` -> `lift16` (with DOS compat runtime)
   - **16-bit Windows/OS-2 (NE)**: `ne/ne_parse` -> `ne/ne_decode` -> `lift16` (see `tools/ne/README.md`)
   - **GoldSrc/SDK game**: `DecompileAll.java` -> `combined_classify.py` (SDK separation)
   - **C++ heavy**: `GhidraStats.java` + `msvc_mangler.py` + `parse_vtables.js`
4. Drop in the appropriate `runtime/` files
5. Build with CMake, fix, repeat

See [docs/PHILOSOPHY.md](docs/PHILOSOPHY.md) for the full approach, and [docs/PIPELINE.md](docs/PIPELINE.md) for detailed pipeline docs.

## Philosophy (the short version)

> Any PC application ever compiled can be systematically deconstructed and rebuilt for modern hardware. It's not magic, it's just work -- and with the right tools, it's *less* work every time.

We've proven this across DOS, Win16, Win32, MFC, Quake-family engines, GoldSrc, id Tech 3, and completely custom engines. The pattern is always the same: **Analyze -> Disassemble -> Classify -> Lift -> Shim -> Build -> Debug -> Ship.**

Read the full philosophy in [docs/PHILOSOPHY.md](docs/PHILOSOPHY.md).

## License

MIT. Use these tools to bring back whatever software you love.

---

*Built with stubbornness and too much coffee by [sp00nznet](https://github.com/sp00nznet)*
