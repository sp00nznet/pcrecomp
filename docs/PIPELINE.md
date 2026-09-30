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
- `tools/pe/catalog.py` -- Recursively catalog/categorize every PE in an install tree,
  and identify the ones that are not PE (NE, LE/LX, plain-MZ DOS) rather than
  reporting them as broken -- each is named and routed to the front end that reads it

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
1. Seed from the entry point and every direct `rel32` branch target -- both
   `call` (`E8`) **and `jmp` (`E9`)**. The `jmp` half is not optional: an
   optimising compiler turns `call f; ret` into `jmp f`, and a method that is
   only ever tail-called is named by no CALL anywhere in the image. Measured
   against a linker map, seeding `E8` alone missed 7,331 real functions.
2. Detect function prologues (`push ebp; mov ebp, esp` = `55 8B EC`)
3. Recursive descent from each entry point, to a fixpoint -- newly decoded code
   yields new branch targets, which yield more code
4. Scan non-code sections for function pointers that exist only in data
   (vtables, callback tables, handler arrays). Unaligned on purpose; packed
   struct arrays put them at odd addresses
5. Build basic blocks with successor addresses, group blocks into functions

**Output**: JSON with all discovered functions, their addresses, instruction counts, and basic block structure.

**Then score it.** See Phase 1b -- a catalog nobody scored is a catalog nobody
knows the shape of.

### 16-bit (MZ / DOS)

**Tools**: `tools/disasm/decode16.py` + `tools/disasm/analyze.py`

Two-step process because 16-bit code has complications:
1. **decode16.py** -- Table-driven 8086/80186 decoder. Handles segment:offset addressing, overlay modules (INT 3Fh), and all MSC 5.x code generation patterns.
2. **analyze.py** -- Function boundary detection using MSC prologue/epilogue patterns, near/far call resolution, overlay segment mapping.
3. **largemodel16.py** (Borland/large model only, a library rather than a
   CLI) -- `detect_code_end()` finds where prologue-driven code stops and the
   DGROUP initialized-data segment begins, which `analyze.py` otherwise decodes
   as one bogus multi-KB function; `build_call_graph()` resolves the far calls
   (`9A seg:off`) that `analyze.py` records as unconnected tuples, turning a
   graph with hundreds of false roots into a usable one.

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

## Phase 1b: Score the recovery

**Goal**: find out how wrong the catalog is *before* lifting 400,000 lines from it.

**Tool**: `tools/disasm/score_recovery.py`

```bash
python tools/disasm/score_recovery.py --reference ida_funcs.json                                       --candidate functions.json
```

Recursive descent reports how many functions it found. It cannot report how
many of them are real. Scoring against a reference -- a linker map, a PDB
export, or IDA -- gives precision and recall on function *start addresses*, and
splits the false positives into the two defects that both read as "false
positive" but need opposite fixes:

| Kind | Means | Costs you |
|------|-------|-----------|
| **split** | The address lands *inside* a function the reference knows | One function entered twice; duplicated code in the lift |
| **invented** | The address lands outside every known function | Data decoded as code; lifts to garbage |

Telling them apart needs function *ranges*, so a reference that carries end
addresses (IDA, a PDB) gets the better breakdown. Get one from IDA headless in
about a minute with `tools/ida/ida_funcs.py`.

**A reference is only ground truth if it came from symbols.** Otherwise it is a
second opinion, and a disagreement means one of the two is wrong -- go look at
which before quoting the number.

This phase is new, and it exists because it was skipped for years. The first
time anyone ran it, it found the disassembler missing 7,331 functions.

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

A snapshot from three projects, to show the *shape* rather than to be current.
Live counts are in the [README table](../README.md#the-projects-that-built-this).

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

### Every vtable slot is a function entry

Union the vtable slot addresses into the function list before lifting. The
disassembler's recovery will not find all of them, and the ones it misses are
the ones that break a C++ target.

MSVC's virtual-inheritance adjustor thunks are the case that matters:

```
00762820  sub ecx, dword ptr [ecx - 4]     ; apply the vtordisp
00762823  jmp 0x761880                     ; the real method
```

Eight bytes, nothing calls them, nothing falls through into them -- so no
recovery pass names one, "lift everything" does not lift one, and the runtime
answers the slot with `ICALL: unresolved VA` and sets `eax = 0`. That zero is
then an ordinary null return value, and the fault lands hundreds of
instructions later in whatever took it as an object. On Force Commander 130 of
5,682 vtable slots were uncatalogued, and the two the run actually reached were
both adjustor thunks.

Give injected entries a TIGHT bound -- the next known entry above, capped at a
few hundred bytes. Handing them the end of `.text` like a normal seed gives the
extent walk the whole section to descend through, and the lift hangs on its
first chunk.

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

### Differential test (`tools/lift/difftest.py`)

**Goal**: catch a wrong flag before a play session does.

Runs the same instruction bytes twice -- once through Unicorn, once through the
lifter's own output compiled as C -- and reports every architectural field the
two disagree on by name: the eight GPRs, each of the six arithmetic flags plus
DF, and every byte of guest memory either machine wrote. Cases the model
knowingly gets wrong carry a `known=` note explaining why, so a real regression
still stands out. The 16-bit model's hand-written flag logic has the same check
as a plain C file: `runtime/recomp16/cpu_selftest.c`.

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

### Anything that SENDS a message blocks on a thread that may never pump

A recompiled program's windows do not belong to the threads a native program's
would. The host makes one before the target runs; the target makes its own
from whatever host thread its worker landed on; and the host's main thread is
usually inside lifted code from the entry point until the program exits, so it
never pumps anything.

Every `SendMessage`-shaped call then becomes a deadlock waiting for a specific
thread: `UpdateWindow`, `ShowWindow`, `SetWindowPos` without
`SWP_NOSENDCHANGING`, `SetForegroundWindow`. One project hung on the very first
`Flip` the program issued because the present path called `UpdateWindow`, and
hung again later on a `ShowWindow` meant to hide a window.

`GetDC` / `BitBlt` / `ReleaseDC` on another thread's window is fine and does
not wait for anybody -- which is worth knowing, because "cross-thread GDI is
too slow" is an easy wrong conclusion to draw from a hang. Measured on the
same project: 4,400 presents in 130 s into another thread's window. If a
window needs to be visible, create it visible; if it needs to be hidden, do
not create it.

### A timer callback is a thread you already know how to run

`timeSetEvent`, `SetTimer` with a TIMERPROC, waitable-timer APC callbacks: the
callback is lifted code, and "lifted code cannot run on a host thread" is only
true until `CreateThread` is implemented. After that a timer is the same
machinery -- a host thread with its own target stack, its own simulated TIB and
its own saved machine state, claiming the global machine lock around each call
-- and returning a handle while never calling back is a silent stub in an area
where the program will not tell you it is broken. iMUSE, for one, runs its
whole music script on a 20 ms multimedia timer.

Watch the budget when you do it: a program that creates and kills its timer
four times during audio startup will leak four thread slots if each gets a
fresh stack. One stack per timer SLOT, not per timer.

### A no-op shim for a RECORDING API is not neutral

The usual rule for a shim is that doing nothing is the safe default: return
success, leave the out-parameters alone, add behaviour when something is
measured to want it. That rule breaks for any API whose contract is "from now
until I say stop, do not act on what I tell you".

Direct3D 7's state blocks are the case that taught this. Between
`BeginStateBlock` and `EndStateBlock` the runtime RECORDS state-setting calls
instead of applying them, and `ApplyStateBlock` applies the recorded set. With
all three stubbed, every state in every block was applied the instant it was
RECORDED -- and never applied again -- so the live device state at every draw
was whatever the last block to be BUILT had happened to want. The symptom was
a 3D scene drawn with a 2D overlay's blend mode and depth settings, which
looks like a renderer bug and is a shim bug.

The same shape turns up in transactions, batched updates, deferred contexts,
display lists and any "begin/end capture" pair. If a stub cannot both suppress
and replay, it is not a stub, it is a behaviour change. The fix is small --
record `(kind, args)` into an array and replay it -- and it is much smaller
than finding it later.

### Report every failed file operation, unconditionally

Failed opens are usually logged; failed directory ENUMERATIONS usually are
not, because they are noisy in the normal case of a loose-file lookup falling
back to an archive. Log them anyway, outside the verbose flag.

An empty directory and a missing one are indistinguishable to the caller, and
a program that enumerates a directory it needs, gets nothing and waits for
something that will never arrive says nothing at all about why. One
unconditional line -- `FindFirstFileA("...\Players") -> not found` -- is worth
more than the whole verbose trace it would otherwise be buried in.

### A retail install is not the disc

The installer copies and RENAMES. Assembling an install by hand from a mounted
image gets the 8.3 names out of the ISO-9660 tree (`1201-O~1.IMU`) while the
program asks for what the installer wrote (`1201 - OpeningScreen.imu`), so
read the **Joliet** tree instead: the supplementary volume descriptor at
sector 17, escape `%/@`, `%/C` or `%/E`, names in UCS-2.

And check what is missing before blaming the recompilation. One project ran
for a long time with `Resource\Music` and `Resource\Movies` simply absent --
260 MB the install step had never copied -- with the program silent about it.

### DRM Removal (`tools/drm/`)

- **SafeDisc v1**: `safedisc_dump.py` -- launch via Steam, dump decrypted .text section
- **SafeDisc v2+**: `inject_and_run.c` -- DLL injection for deeper analysis
- **General approach**: Let the DRM decrypt at runtime, capture the result
- **Compressors (PECompact 2.x, Steam2's wrapper)**: `emu_unpack.py` -- run the stub
  under Unicorn instead of Windows. Everything below the stub is mapped
  non-executable, so the first fetch from it faults at the OEP; the IAT is the
  run of GetProcAddress results the code calls through, and a new import
  directory is written pointing at it. No process, no window.

---

## Phase 5: Build & Debug

**Goal**: Get the lifted code compiling and running.

### Build Setup

Use `templates/CMakeLists.txt.template` as a starting point. Key settings:
- **No ASLR** (`/DYNAMICBASE:NO`) -- fixed addresses match original binary
- **Large stack** (8 MB) -- deep call chains in lifted code
- **Warning suppression** -- generated code is ugly but correct
- **32-bit target** (`-A Win32`) -- match original architecture

### A build that fails without saying anything

MinGW: if `cmake --build` reports `FAILED` for every object and prints **no
compiler diagnostics at all**, `<msys root>/mingw64/bin` is missing from `PATH`.
`gcc.exe` is found by absolute path and starts, but the real compiler,
`cc1.exe`, lives under `lib/gcc/...` and loads `libmpfr-6.dll` and friends from
`mingw64/bin` at run time. Without them the loader kills cc1 before it can
write to stderr, and gcc exits 1 with empty output. `-fsyntax-only` "passes"
because nothing is checked. Run `cc1.exe` directly and it says so:

```
cc1.exe: error while loading shared libraries: libmpfr-6.dll: cannot open ...
```

This is worth knowing because the failure mode is indistinguishable from a
build system problem, and because a shell that has its own unrelated
`/mingw64/bin` on `PATH` (Git Bash does) hides it completely.

### Runtime Infrastructure (`runtime/recomp32/`)

- **main.c**: Entry point, VirtualAlloc memory mapping, VEH crash handler
- **recomp_types.h**: Register globals, memory macros, condition macros, dispatch
- **recomp_trace.c/.h**: the bring-up diagnostics that hang off `RECOMP_ENTER`

### Debugging

The runtime includes:
- **VEH crash handler**: Catches access violations, dumps register state
- **ICALL trace buffer**: Ring buffer of last 32 indirect calls (invaluable for debugging dispatch failures)
- **Dispatch lookup logging**: Identifies unresolved function addresses

`recomp_trace.c` is the other half, and it is a library, not scaffolding --
every target needs the same handful of instruments and they are tedious to
rewrite. Build the generated code with `-DRECOMP_TRACE`, add the file, and
route unknown options through `recomp_trace_arg(argc, argv, i)`:

| option | what it answers |
|---|---|
| `--calltrace FILE` | what ran, in order, per thread (buffered: 9 M calls in 10 s) |
| `--firsthit LO HI` | did execution ever reach THIS subsystem, and in what order |
| `--argtrace VA` | the sequence of ids that went through one dispatcher |
| `--watch VA` | registers, stack arguments and the object under `ecx` |
| `--watchspan LO HI` | move that object window to a member at +0x234 |
| `--poison ADDR` | when did this dword change, and which shim was running |
| `--poke ADDR VAL VA` | force a flag the program cleared, once past the code that cleared it |

Two of those are worth spelling out. `--calltrace` is **buffered**: unbuffered,
so that a crash could not take the tail with it, it was slower than the code it
traced and so was never used -- the fault handler calls
`recomp_trace_flush()` instead. And `--poke` exists because a retail build can
still carry its original developers' assertion and logging machinery, gated on
a byte that startup clears from a setting nobody has; poking the byte back is
how you get the program to tell you what is wrong in its own words.

A target with a diagnostic of its own (a watch that knows a class layout) sets
`recomp_trace_extra` rather than forking the file.

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
| Import extraction | `pe/extract_imports.py` | `.exe`/`.dll`, or an install dir | Per-module imports + shared-API summary |
| Delay imports | `pe/delay_imports.py` | `.exe`/`.dll` | Delay-load import list |
| Section/DRM analysis | `pe/analyze_sections.py` | `.exe`/`.dll` | Entropy + protection report |
| Binary catalog | `pe/catalog.py` | Install dir | Per-binary catalog, PE + NE/LE/MZ (text/JSON) |
| stdcall stack purge | `pe/stdcall_argc.py` | Import names + SDK headers | Bytes each import pops (library) |
| NE parse | `ne/ne_parse.py` | NE binary | Segments/relocs/imports |
| NE disassembly | `ne/ne_decode.py` | NE binary | Annotated disasm |
| NE call graph | `ne/ne_xref.py` | NE binary | Segment graph / clusters |
| Win16 import shims | `ne/gen_win16_stubs.py` | NE binary + purge table | Prototypes + purging stubs |
| 32-bit disassembly | `disasm/disasm32.py` | PE binary | Function JSON |
| 16-bit decoding | `disasm/decode16.py` | MZ binary | Instruction stream |
| 16-bit analysis | `disasm/analyze.py` | MZ binary | Symbol table (TOML) |
| Large-model completion | `disasm/largemodel16.py` | An `analyze.py` analyzer | Far-call graph + code/data boundary (**library**) |
| Score a catalog | `disasm/score_recovery.py` | Reference + candidate JSON | Precision/recall, split vs invented |
| x87 FPU decode | `disasm/fpu_decode.py` | ESC opcode + ModR/M | FPU mnemonic (library) |
| Call-graph scan | `disasm/callgraph.py` | PE (+bounds CSV) | Callers/callees/leaves |
| 32-bit lifting | `lift/lift32.py` | Function JSON | C source (**library**: `from lift32 import Lifter`) |
| 32-bit lifting, CPU struct | `lift/lift32_cpu.py` | Function JSON | Reentrant C for hybrid builds (**library**) |
| 16-bit lifting | `lift/lift16.py` | Symbol table | C source (**library**: `from lift16 import Lifter`) |
| Full pipeline | `lift/translator.py` (`python -m tools`) | PE binary | Complete C project |
| Fast generation | `lift/generate.py` | PE binary | C source (linear sweep) |
| Missed entry points | `lift/recover.py` | Catalog + binary | Alternate entries, thunk chains |
| Differential test (32) | `lift/difftest.py` | -- | Lifted C vs Unicorn, field by field |
| Differential test (16) | `lift/difftest16.py` | Raw/NE bytes | Lifted C vs Unicorn, field by field |
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
| IDA function ranges | `ida/ida_funcs.py` | Any binary (in IDA) | Reference catalog for scoring |
| IDA xrefs | `ida/ida_xrefs.py` | Addresses (in IDA) | Caller/writer sites |
| SafeDisc dump | `drm/safedisc_dump.py` | Protected PE | Clean PE |
| DLL injection | `drm/inject_and_run.c` | DRM'd process | Memory dump |
| Emulated unpack | `drm/emu_unpack.py` | Packed PE32 | PE at its OEP, imports rebuilt |
| Wise installer extract | `assets/extract_wise.py` | Wise setup `.exe` | Script + file list |
| InstallShield extract | `assets/isextract.py` | .hdr/.cab | Extracted files |
| PK3/ZIP inspect | `assets/pk3_inspect.py` | .pk3/.zip | Content listing |
| BIN->ISO convert | `assets/bin2iso.js` | .bin/.cue | .iso |
| CAB extraction | `assets/extract_cab.sh` | CAB archive | Extracted files |
| MSVC name mangle | `cpp/msvc_mangler.py` | C++ declarations | Mangled names |
| Cross-platform mangle | `cpp/cross_mangler.py` | Mac mangled names | MSVC mangled names |
| Mac demangling | `cpp/mac_unmangler.py` | Mangled names | Readable names |
| Vtable parsing | `cpp/parse_vtables.js` | Assembly vtables | Structured vtable data |
| FIF fractal images | `formats/fifdecode/` | `.fif` | Decoded bitmap |
| Fractal transform tables | `formats/ftcdecode/` | `.ftc` | Decoded tables |
| MM Viewer 2.0 containers | `formats/m20dump/` | `.m20`/`.mvb` | Extracted members |
| SPAM multimedia | `formats/spamdump/` | SPAM blobs | Extracted members |
| Encarta DAT | `formats/datdump/` | `.dat` | Records |
| String tables | `formats/strdump/` | Binary | Strings |
| 16-bit CPU self-test | `runtime/recomp16/cpu_selftest.c` | -- | Flag/BCD checks vs hardware values |
| MMX self-test | `runtime/recomp32/mmx_selftest.c` | -- | MMX model checks |
| 32-bit CPU-struct self-test | `runtime/recomp32_cpu/cpu_selftest.c` | -- | Reentrant model checks |
