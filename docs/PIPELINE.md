# The Static Recompilation Pipeline

Detailed documentation of each phase, what tools to use, and what to expect.

---

## Phase 0: Reconnaissance

**Goal**: Understand what the binary is before you touch it.

**Tools**:
- `tools/pe/pe_analyze.py` -- PE header analysis, sections, imports, exports, hashes
- `tools/pe/extract_imports.py` -- Detailed import table extraction across modules
- `tools/pe/delay_imports.py` -- Delay-loaded import table (the easy-to-miss deps)
- `tools/pe/analyze_sections.py` -- Per-section entropy + SafeDisc/SecuROM/packer detection
- `tools/pe/catalog.py` -- Recursively catalog/categorize every PE in an install tree

**What you learn**:

| Question | Where to Look |
|----------|---------------|
| When was it compiled? | PE timestamp (`TimeDateStamp`) |
| What compiler? | Linker version, rich header, CRT imports |
| Image base? | `ImageBase` field (fixed = no ASLR) |
| Has relocations? | `.reloc` section presence, reloc data directory |
| DRM? | Section names (UPX0, .mackt, .sforce), unusual entry points |
| Dependencies? | Import table -- this is your shimming TODO list |
| What it exports? | Export table -- DLL interface contracts |

**Output**: `pe_analysis.json` -- machine-readable binary metadata used by all downstream tools.

**Time**: 10 minutes per binary. Do this first, always.

---

## Phase 1: Disassembly

**Goal**: Turn bytes into structured instruction data with function boundaries.

### 32-bit (PE32 / Win32)

**Tool**: `tools/disasm/disasm32.py`

Uses Capstone disassembly engine with recursive descent:
1. Find entry point and all call targets (`E8 xx xx xx xx` pattern)
2. Detect function prologues (`push ebp; mov ebp, esp` = `55 8B EC`)
3. Recursive descent from each entry point
4. Build basic blocks with successor addresses
5. Group blocks into functions

**Output**: JSON with all discovered functions, their addresses, instruction counts, and basic block structure.

### 16-bit (MZ / DOS)

**Tools**: `tools/disasm/decode16.py` + `tools/disasm/analyze.py`

Two-step process because 16-bit code has complications:
1. **decode16.py** -- Table-driven 8086/80186 decoder. Handles segment:offset addressing, overlay modules (INT 3Fh), and all MSC 5.x code generation patterns.
2. **analyze.py** -- Function boundary detection using MSC prologue/epilogue patterns, near/far call resolution, overlay segment mapping.

**Output**: Symbol table (TOML) + decoded instruction stream.

### 16-bit Windows / OS-2 (NE)

**Tools**: `tools/ne/ne_parse.py` -> `tools/ne/ne_decode.py` -> `tools/ne/ne_xref.py`

The "New Executable" format is segmented and relocatable, unlike flat DOS MZ
images, so it needs its own front end:
1. **ne_parse.py** -- segment table, per-segment relocations, entry table, import/name tables.
2. **ne_decode.py** -- NE-aware 16-bit disassembly; resolves relocations so far calls and imports are annotated inline (builds on `decode16.py` + `disasm/fpu_decode.py`).
3. **ne_xref.py** -- segment-level call graph, clustering, and per-segment import usage.

For data-in-code accuracy, export a code map from IDA (`tools/ida/ida_export.py`)
and pass it via `ne_decode.py --ida-json`. See `tools/ne/README.md`.

**Output**: Annotated per-segment disassembly + segment call graph.

### Helper: lightweight call graph

`tools/disasm/callgraph.py` scans a 32-bit PE for direct `E8`/`E9` edges with no
Ghidra/IDA needed -- answers "who calls X" / "what's hot", and (with a
`ghidra/DumpBounds.java` CSV) builds a function-level graph and finds leaf
functions for differential testing.

---

## Phase 2: Classification

**Goal**: Separate code you need to reverse-engineer from code you can get from public sources.

**Tools**:
- `tools/classify/classify_functions.py` -- Basic name-based classification
- `tools/classify/combined_classify.py` -- Multi-signal 4-pass classifier (recommended)
- `tools/classify/deep_classify.py` -- String reference deep analysis
- `tools/classify/resolve_stubs.py` -- Symbol resolution for CRT/library functions

### The Four Passes (combined_classify.py)

1. **Name-based**: Match function names against known SDK/library names
2. **String references**: Match string constants used by each function against known SDK strings
3. **Call graph propagation**: Functions that only call SDK functions are likely SDK code
4. **Address clustering**: Functions from the same source file are compiled adjacent in the binary

### Typical Results

| Project | Total Functions | SDK/Library | Custom | Unknown |
|---------|----------------|-------------|--------|---------|
| Gunman Chronicles | 3,990 | 3,131 (78%) | 499 (13%) | 360 (9%) |
| X-Wing Alliance | 2,701 | ~400 (15%) | ~2,300 (85%) | ~0 |
| Civilization 1991 | 482 | ~130 (27%) | ~352 (73%) | ~0 |

The ratio depends heavily on whether the game uses a public engine/SDK.

---

## Phase 3: Lifting (x86 -> C)

**Goal**: Generate compilable C code that is functionally equivalent to the original binary.

### 32-bit Lifter (`tools/lift/lift32.py`)

**Architecture**:
- Global register model: `g_eax`, `g_ecx`, `g_edx`, `g_ebx`, `g_esi`, `g_edi`, `g_esp`
- Memory access via VA translation: `MEM32(addr)` = `*(uint32_t*)(addr + g_mem_base)`
- Pattern-matched condition codes: flag-setter -> flag-consumer = semantic condition
- FPU stack simulation: `_st[8]` array with `fp_push`/`fp_pop`

**Instruction Coverage**: All common x86-32 instructions:
- Arithmetic: mov, add, sub, imul, idiv, xor, or, and, neg, not, shl, shr, sar, rol, ror
- Control: jmp, jcc (all conditions), call, ret, loop
- Stack: push, pop, pushad, popad, enter, leave
- FPU: fld, fst, fadd, fsub, fmul, fdiv, fcom, fsqrt, fsin, fcos, fpatan, fyl2x
- String: rep movsb/d, rep stosb/d, rep cmpsb/d, rep scasb/d
- System: cpuid, rdtsc, int3, in, out (stubbed)

**Pipeline Orchestrator** (`tools/lift/translator.py`):
1. Load PE analysis
2. Discover functions via disassembler
3. Lift each function to C
4. Split output into chunks (max 1000 functions per file)
5. Generate forward declarations header
6. Generate dispatch table (sorted by address for binary search)

**Fast Generator** (`tools/lift/generate.py`):
Alternative linear-sweep approach when recursive descent is too slow or gets confused. Trades accuracy for speed.

### 16-bit Lifter (`tools/lift/lift16.py`)

**Architecture**:
- CPU state struct: all registers including segment registers and flags
- Segment:offset memory model with proper translation
- Port I/O dispatch for timer/VGA/keyboard
- DOS INT handler integration

---

## Phase 4: Shimming

**Goal**: Bridge the gap between the original APIs and modern equivalents.

### Win32 -> Modern (`runtime/compat/win32_compat.h`)

Categories every Win32 API call:
- **KEEP**: Still works on modern Windows (file I/O, memory, basic Win32)
- **SHIM**: Needs a thin wrapper (version queries, path redirection)
- **SDL2**: Replaced with cross-platform equivalent (windowing, input, audio)
- **STUB**: Dead functionality (CD checks, obsolete DRM, 16-bit compat)
- **CRT**: Handled by modern compiler runtime

### DOS -> Modern (`runtime/recomp16/`)

Complete DOS environment simulation:
- INT 21h: File I/O, memory management, console I/O, system info
- INT 10h: Video BIOS (mode setting, palette, character output)
- INT 16h: Keyboard BIOS
- INT 33h: Mouse driver
- Port I/O: VGA registers, PIT timer, keyboard controller

All backed by SDL2 for actual display/input.

### DRM Removal (`tools/drm/`)

- **SafeDisc v1**: `safedisc_dump.py` -- launch via Steam, dump decrypted .text section
- **SafeDisc v2+**: `inject_and_run.c` -- DLL injection for deeper analysis
- **General approach**: Let the DRM decrypt at runtime, capture the result

---

## Phase 5: Build & Debug

**Goal**: Get the lifted code compiling and running.

### Build Setup

Use `templates/CMakeLists.txt.template` as a starting point. Key settings:
- **No ASLR** (`/DYNAMICBASE:NO`) -- fixed addresses match original binary
- **Large stack** (8 MB) -- deep call chains in lifted code
- **Warning suppression** -- generated code is ugly but correct
- **32-bit target** (`-A Win32`) -- match original architecture

### Runtime Infrastructure (`runtime/recomp32/`)

- **main.c**: Entry point, VirtualAlloc memory mapping, VEH crash handler
- **recomp_types.h**: Register globals, memory macros, condition macros, dispatch

### Debugging

The runtime includes:
- **VEH crash handler**: Catches access violations, dumps register state
- **ICALL trace buffer**: Ring buffer of last 32 indirect calls (invaluable for debugging dispatch failures)
- **Dispatch lookup logging**: Identifies unresolved function addresses

### The Debug Loop

```
Build -> Run -> Crash -> Check ICALL trace -> Fix -> Repeat
```

This is where most time goes. Common issues:
1. **Missing import bridge**: Function called through IAT without a shim -> add to import table
2. **Bad memory layout**: Data at wrong address -> check section loading in main.c
3. **Unresolved indirect call**: Dispatch table miss -> add manual override or find missed function
4. **Condition code mismatch**: Lifter got a flag pattern wrong -> fix in lifter
5. **FPU stack imbalance**: Push/pop mismatch in FPU simulation -> trace through x87 instructions

---

## Phase 6: Ship

**Goal**: Native binary, modern OS, no emulation.

At this point you have:
- Compilable C code for all functions
- Working shim layer for all API calls
- Proper memory layout matching original binary
- Tested and debugged execution

The output is a standard native executable that runs on modern Windows (or Linux/macOS with the SDL2 backend). It can be extended with modern features: widescreen support, modern renderers, network play, whatever you want.

---

## Tool Reference Quick Card

| Task | Tool | Input | Output |
|------|------|-------|--------|
| PE analysis | `pe/pe_analyze.py` | `.exe`/`.dll` | JSON metadata |
| Import extraction | `pe/extract_imports.py` | `.exe`/`.dll` | Import table text |
| Delay imports | `pe/delay_imports.py` | `.exe`/`.dll` | Delay-load import list |
| Section/DRM analysis | `pe/analyze_sections.py` | `.exe`/`.dll` | Entropy + protection report |
| Binary catalog | `pe/catalog.py` | Install dir | Per-PE catalog (text/JSON) |
| NE parse | `ne/ne_parse.py` | NE binary | Segments/relocs/imports |
| NE disassembly | `ne/ne_decode.py` | NE binary | Annotated disasm |
| NE call graph | `ne/ne_xref.py` | NE binary | Segment graph / clusters |
| 32-bit disassembly | `disasm/disasm32.py` | PE binary | Function JSON |
| 16-bit decoding | `disasm/decode16.py` | MZ binary | Instruction stream |
| 16-bit analysis | `disasm/analyze.py` | Instruction stream | Symbol table |
| x87 FPU decode | `disasm/fpu_decode.py` | ESC opcode + ModR/M | FPU mnemonic (library) |
| Call-graph scan | `disasm/callgraph.py` | PE (+bounds CSV) | Callers/callees/leaves |
| 32-bit lifting | `lift/lift32.py` | Function JSON | C source files |
| 16-bit lifting | `lift/lift16.py` | Symbol table | C source files |
| Full pipeline | `lift/translator.py` | PE binary | Complete C project |
| Fast generation | `lift/generate.py` | PE binary | C source (linear sweep) |
| Basic classify | `classify/classify_functions.py` | Function list + SDK | Classification |
| Multi-signal classify | `classify/combined_classify.py` | Decompiled C + SDK | Classification |
| String analysis | `classify/deep_classify.py` | Decompiled C | String-based classification |
| Stub resolution | `classify/resolve_stubs.py` | Symbol table | Resolved symbols |
| Batch decompile | `ghidra/DecompileAll.java` | Any binary | C pseudocode |
| Function export | `ghidra/ExportFunctions.java` | Any binary | Function metadata |
| Binary stats | `ghidra/GhidraStats.java` | Any binary | Analysis statistics |
| Decompile by address | `ghidra/DecompAddrs.java` | Addresses / `@file` | C pseudocode |
| Find references | `ghidra/FindRefs.java` | Addresses | Caller/writer sites |
| Range disassembly | `ghidra/DisasmRange.java` | Start/end addr | Listing |
| Function bounds CSV | `ghidra/DumpBounds.java` | Any binary | `start,end` CSV |
| IDA code-map export | `ida/ida_export.py` | Any binary (in IDA) | Code map JSON |
| IDA segment probe | `ida/ida_probe_segs.py` | Any binary (in IDA) | Segment layout |
| SafeDisc dump | `drm/safedisc_dump.py` | Protected PE | Clean PE |
| DLL injection | `drm/inject_and_run.c` | DRM'd process | Memory dump |
| Wise installer extract | `assets/extract_wise.py` | Wise setup `.exe` | Script + file list |
| InstallShield extract | `assets/isextract.py` | .hdr/.cab | Extracted files |
| PK3/ZIP inspect | `assets/pk3_inspect.py` | .pk3/.zip | Content listing |
| BIN->ISO convert | `assets/bin2iso.js` | .bin/.cue | .iso |
| CAB extraction | `assets/extract_cab.sh` | CAB archive | Extracted files |
| MSVC name mangle | `cpp/msvc_mangler.py` | C++ declarations | Mangled names |
| Cross-platform mangle | `cpp/cross_mangler.py` | Mac mangled names | MSVC mangled names |
| Mac demangling | `cpp/mac_unmangler.py` | Mangled names | Readable names |
| Vtable parsing | `cpp/parse_vtables.js` | Assembly vtables | Structured vtable data |
