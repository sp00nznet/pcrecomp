# Project Index

A reference card for every PC static recompilation project, what tools they contributed to this repo, and their current status.

---

## Soldier of Fortune (2000)

**Repo**: [sp00nznet/sof](https://github.com/sp00nznet/sof)
**Engine**: Quake II (heavily modified) + GHOUL gore system
**Original**: `SoF.exe` (2.05 MB) + `gamex86.dll` + `ref_gl.dll` + `player.dll` + 3 sound DLLs
**Compiler**: MSVC 6.0, compiled 2000-03-10
**Approach**: Clean-room reimplementation with Win32->SDL2 compat layer
**Status**: Active development. 28+ gameplay systems implemented.

**Contributed to pcrecomp**:
- `tools/pe/pe_analyze.py` (merged into best-of-breed version)
- `tools/pe/extract_imports.py`
- `tools/assets/isextract.py` (InstallShield extractor)
- `runtime/compat/win32_compat.h` (275 Win32 API mappings)

**Notable**: Non-standard image bases (0x20M, 0x30M, 0x40M, 0x50M), Winsock imported by ordinal, different `GetRefAPI` calling convention than Quake II, 26-zone GHOUL gore system.

---

## X-Wing Alliance (1999)

**Repo**: [sp00nznet/xwa](https://github.com/sp00nznet/xwa)
**Engine**: Custom (LucasArts)
**Original**: `xwingalliance.exe` (2.05 MB, SafeDisc v1 protected)
**Compiler**: MSVC, fixed base 0x00400000
**Approach**: Fully automated x86-32->C pipeline
**Status**: Active. 2,701 functions discovered, 631,944 lines of C generated.

**Contributed to pcrecomp**:
- `tools/disasm/disasm32.py` (Capstone recursive descent)
- `tools/lift/lift32.py` (x86-32->C lifter, 938 lines)
- `tools/lift/translator.py` (pipeline orchestrator)
- `tools/lift/generate.py` (fast linear sweep)
- `tools/drm/safedisc_dump.py` (SafeDisc v1 memory dumper)
- `runtime/recomp32/recomp_types.h` (global register model, macros)
- `runtime/recomp32/main.c` (entry point, VEH handler, dispatch)
- `templates/CMakeLists.txt.template`
- `templates/.gitignore.template`

**Notable**: This project produced the core automated pipeline. SafeDisc decryption required a custom memory dumper. 176 imports across 12 DLLs including SMUSH video (tgsmush.dll).

---

## Heavy Metal: FAKK2 (2000)

**Repo**: [sp00nznet/heavymetal](https://github.com/sp00nznet/heavymetal)
**Engine**: id Tech 3 + Ritual's UberTools (TIKI models, Morpheus scripting, Ghost particles)
**Original**: `fakk2.exe` (1.3 MB) + `gamex86.dll` (1.74 MB) + `cgamex86.dll` (340 KB)
**Compiler**: MSVC 6.0, compiled 2000-08-22
**Approach**: Clean-room reimplementation from binary analysis + SDK references
**Status**: Foundation phase. 54 source files, 13,114 lines. TIKI parser, PK3 filesystem, BSP loader implemented.

**Contributed to pcrecomp**:
- `tools/pe/pe_analyze.py` (merged into best-of-breed version)
- `tools/assets/pk3_inspect.py` (PK3/ZIP inspector)

**Notable**: Copy-on-write `str` class exported by all 3 binaries (50 symbols) -- critical ABI bridge. TIKI model format with $define macros and $include inheritance.

---

## Gunman Chronicles (2000)

**Repo**: [sp00nznet/gunman](https://github.com/sp00nznet/gunman)
**Engine**: GoldSrc (Half-Life / Valve)
**Original**: `gunman.dll` (1.32 MB) + `client.dll` (552 KB)
**Compiler**: MSVC 6.0, November 2000
**Approach**: Ghidra batch decompile -> classify against Half-Life SDK -> reconstruct custom code
**Status**: Phase 2. 3,990 functions classified (78% SDK, 13% Rewolf custom).

**Contributed to pcrecomp**:
- `tools/classify/classify_functions.py`
- `tools/classify/combined_classify.py` (4-pass multi-signal classifier)
- `tools/classify/deep_classify.py`
- `tools/ghidra/DecompileAll.java`
- `tools/ghidra/ExportFunctions.java`

**Notable**: Game in rights limbo (Valve + Activision Blizzard legacy). Only 499 of 3,990 functions need actual RE work. 11 custom weapon systems with player-configurable parameters.

---

## Black & White (2001)

**Repo**: [sp00nznet/bw](https://github.com/sp00nznet/bw)
**Engine**: Lionhead Studios custom (C++ heavy, deep vtable hierarchy)
**Original**: Large PE32 binary, SafeDisc protected
**Compiler**: MSVC 6.0
**Approach**: Header generation from reference decomp + manual C++ reconstruction
**Status**: Active. 309/569 types implemented (54%), 26,852 lines of C++.

**Contributed to pcrecomp**:
- `tools/ghidra/GhidraStats.java`
- `tools/drm/inject_and_run.c` (SafeDisc DLL injector)
- `tools/assets/bin2iso.js` (BIN/CUE->ISO converter)
- `tools/assets/extract_cab.sh` (InstallShield CAB extraction)
- `tools/cpp/cross_mangler.py` (Mac->MSVC name mangling)
- `tools/cpp/msvc_mangler.py` (C++ declaration->mangled name)
- `tools/cpp/mac_unmangler.py` (Metrowerks demangling)
- `tools/cpp/parse_vtables.js` (vtable assembly parser)

**Notable**: Most C++-heavy project in the collection. 7-level deep class hierarchy (Base->GameThing->Object->Mobile->Living...). CreatureMental struct is 135KB. Required full name mangling/demangling toolchain.

---

## Sid Meier's Civilization (1991)

**Repo**: [sp00nznet/civ](https://github.com/sp00nznet/civ)
**Engine**: Custom DOS (16-bit x86)
**Original**: `CIV.EXE` (305 KB, 16-bit MZ format) + 23 overlay modules
**Compiler**: Microsoft C 5.x
**Approach**: Custom 16-bit decoder -> analyzer -> lifter -> DOS compat runtime
**Status**: Compiles! 482 functions lifted to 132,585 lines of C.

**Contributed to pcrecomp**:
- `tools/disasm/decode16.py` (8086/80186 instruction decoder)
- `tools/disasm/analyze.py` (MSC 5.x function boundary detection)
- `tools/lift/lift16.py` (16-bit x86->C lifter)
- `tools/classify/resolve_stubs.py` (symbol resolution)
- `runtime/recomp16/` (complete 16-bit DOS runtime: CPU, INTs, HAL, SDL2)

**Notable**: Oldest binary in the collection (1991). 16-bit segmented memory model with overlay loading via INT 3Fh. Required a complete DOS environment simulation including VGA Mode 13h framebuffer emulation.

---

## Microsoft Encarta 97 Encyclopedia (1996)

**Repo**: [sp00nznet/encarta](https://github.com/sp00nznet/encarta)
**Engine**: MFC 4.0 + proprietary multimedia stack
**Original**: `ENC97.EXE` (1.7 MB) + 5 DLLs + 6 legacy 16-bit components + 14 .M20 data files
**Compiler**: MSVC 4.x
**Approach**: Format-first reverse engineering (decode proprietary multimedia formats before tackling application code)
**Status**: Phase 1. Format decoders for FIF, M20/MVB, SPAM, DAT, STR complete.

**Contributed to pcrecomp**:
- `tools/formats/fifdecode/` (Iterated Systems FIF fractal image format)
- `tools/formats/ftcdecode/` (Fractal Transform Table decoder)
- `tools/formats/m20dump/` (Microsoft Multimedia Viewer 2.0 containers)
- `tools/formats/spamdump/` (SPAM multimedia format)
- `tools/formats/datdump/` (Encarta DAT file parser)
- `tools/formats/strdump/` (String table extractor)

**Notable**: Not a game -- a multimedia encyclopedia. Shows the approach works on any kind of application. EEUIL10.DLL exports 1,868 symbols. DECO_32.DLL is a third-party fractal image codec (Iterated Systems).

---

## Fallout (1997)

**Repo**: [sp00nznet/fallout1-re](https://github.com/sp00nznet/fallout1-re)
**Engine**: Custom (Interplay)
**Original**: Reverse-engineered by alexbatalov (upstream fork)
**Approach**: Fork of complete RE'd source + multiplayer ecosystem additions
**Status**: Playable. sp00nznet added: web port, multiplayer server, Electron launcher, Docker stack.

**sp00nznet additions** (27 commits ahead of upstream):
- HTML5/TypeScript web port with Canvas 2D rendering
- Node.js/Express/Prisma backend with JWT auth and WebSocket sync
- Turn-based multiplayer with combat AI bots
- Electron desktop launcher with named-pipe IPC
- Docker Compose + Kubernetes deployment

**Notable**: Demonstrates that once code is recompiled/RE'd, you can extend it in ways the original developers never imagined. A 1997 DOS game now runs in a web browser with multiplayer.

---

## Fallout 2 (1998)

**Repo**: [sp00nznet/fallout2-re](https://github.com/sp00nznet/fallout2-re)
**Engine**: Custom (Interplay)
**Original**: Reverse-engineered by alexbatalov (upstream fork)
**Approach**: Tracking upstream RE work
**Status**: Upstream maintained. Most functions decompiled.

**Notable**: Upstream project (962 commits). Included for completeness and to track against Fallout 1 changes.

---

## Cross-Project Statistics

| Metric | Total |
|--------|-------|
| Projects | 9 |
| Time span of original software | 1991-2001 (10 years) |
| Architectures covered | 16-bit DOS, 32-bit Win32 |
| Compilers encountered | MSC 5.x, MSVC 4.x, MSVC 6.0 |
| Engines/frameworks | 7 distinct (Quake II, id Tech 3, GoldSrc, Lionhead, LucasArts, Interplay, MFC) |
| Functions analyzed | 14,000+ |
| Lines of C generated | 750,000+ |
| Tools in this repo | 55 files |
| DRM schemes handled | SafeDisc v1, SafeDisc v2+ |
| Proprietary formats decoded | 10+ (GHOUL, TIKI, FIF, M20, SPAM, ROFF, MIP32, PK3, DAT, overlay) |
