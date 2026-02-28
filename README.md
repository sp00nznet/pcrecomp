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
    pe/            PE binary analysis (imports, exports, sections, hashes)
    disasm/        Disassemblers (32-bit recursive descent, 16-bit table-driven)
    lift/          Code lifters (x86-32 and x86-16 to readable C)
    classify/      Function classifiers (SDK vs custom, multi-signal, string refs)
    ghidra/        Ghidra headless scripts (batch decompile, export, stats)
    drm/           DRM analysis (SafeDisc memory dumping, DLL injection)
    assets/        Asset extraction (InstallShield, PK3/ZIP, BIN/ISO, CAB)
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
| **[sof](https://github.com/sp00nznet/sof)** | Soldier of Fortune | 2000 | Quake II + GHOUL | Active - SDL2 port, 28+ systems |
| **[xwa](https://github.com/sp00nznet/xwa)** | X-Wing Alliance | 1999 | Custom (LucasArts) | Active - 2,701 functions lifted |
| **[heavymetal](https://github.com/sp00nznet/heavymetal)** | Heavy Metal: FAKK2 | 2000 | id Tech 3 + UberTools | Foundation - 54 source files |
| **[gunman](https://github.com/sp00nznet/gunman)** | Gunman Chronicles | 2000 | GoldSrc (Half-Life) | Phase 2 - 3,990 functions classified |
| **[bw](https://github.com/sp00nznet/bw)** | Black & White | 2001 | Lionhead custom | Active - 309/569 types done |
| **[civ](https://github.com/sp00nznet/civ)** | Civilization (1991) | 1991 | 16-bit DOS / MSC 5.x | Compiles! 482 functions, 132K lines |
| **[encarta](https://github.com/sp00nznet/encarta)** | Encarta 97 Encyclopedia | 1996 | MFC 4.0 + proprietary | Format RE phase |
| **[fallout1-re](https://github.com/sp00nznet/fallout1-re)** | Fallout | 1997 | Custom (Interplay) | Fork + multiplayer ecosystem |
| **[fallout2-re](https://github.com/sp00nznet/fallout2-re)** | Fallout 2 | 1998 | Custom (Interplay) | Upstream tracking |

## Quick Start

### "I have a mystery .exe and I want to know what's inside"

```bash
# What are we dealing with?
python tools/pe/pe_analyze.py mystery.exe --json > analysis.json

# What DLLs does it import?
python tools/pe/extract_imports.py mystery.exe

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

### "The exe has SafeDisc DRM"

```bash
# Dump decrypted code from a running process (Steam/CD version)
python tools/drm/safedisc_dump.py --exe game.exe --output decrypted.exe
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
