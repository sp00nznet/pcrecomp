# NE (New Executable) tools

Support for the 16-bit segmented **New Executable** format -- the binary
format used by Windows 1.x-3.x, Win386, OS/2 1.x, and many self-loading
DOS-extended applications and games from the early 1990s.

PE is the format Windows 95+ uses; raw MZ is plain real-mode DOS. NE sits
between them: 16-bit, but *segmented and relocatable* with an import/export
model. The toolkit's PE tools and flat 16-bit DOS decoder don't understand it,
so this package fills the gap.

## The pipeline

```
ne_parse   ->  structure: segment table, per-segment relocations,
               entry table, module/resident/non-resident name tables
ne_decode  ->  NE-aware 16-bit disassembly: resolves relocations so far
               calls, imports, and data refs are annotated inline
ne_xref    ->  segment-level call graph, connected-component clusters,
               per-segment import usage, DOT export
```

`ne_decode` builds on the shared decoders in `../disasm/`:
- `decode16.py` -- the 16-bit x86 instruction decoder
- `fpu_decode.py` -- x87 mnemonics (so FPU ops aren't opaque `esc_*` blobs)

## Usage

```bash
# What is this thing? (segments, imports, entry points)
python tools/ne/ne_parse.py GAME.EXE

# Disassemble a single code segment with relocation annotations
python tools/ne/ne_decode.py GAME.EXE --seg 3

# Per-segment function/instruction counts across the whole binary
python tools/ne/ne_decode.py GAME.EXE --summary

# Call graph and tightly-coupled segment clusters
python tools/ne/ne_xref.py GAME.EXE --clusters
python tools/ne/ne_xref.py GAME.EXE --dot | dot -Tsvg -o callgraph.svg

# Which imports does each segment call?
python tools/ne/ne_xref.py GAME.EXE --imports
```

## Symbols a game shipped: MAPSYM `.SYM`

Some Win16 programs shipped `GAME.SYM` beside `GAME.EXE`: MAPSYM's
condensed linker map, kept there for the debugger. It gives every public
function's segment, offset and real name. Check for one before anything else.

```bash
python tools/ne/mapsym.py GAME.SYM          # seg:off name
```

`mapsym.read()` returns `(seg, offset, name)` with NE segment numbers, ready
to feed `ne_link --seeds`. SimAnt's relift is a worked example.

## Improving accuracy with an external code map

Linear sweep desyncs on data-in-code. If you have IDA (or any tool that can
classify code vs. data), export a code map with `tools/ida/ida_export.py` and
feed it in -- `ne_decode` will decode at exactly the verified instruction
heads and treat exported function entries as authoritative:

```bash
# inside IDA:  py -3 tools/ida/ida_export.py GAME.EXE code_map.json
python tools/ne/ne_decode.py GAME.EXE --ida-json code_map.json
# or:  set PCRECOMP_IDA_JSON=code_map.json
```

The code map is keyed by NE segment number; `ida_export.py` maps IDA segment
index `i` to NE segment `i + 1` for CODE-class segments.

## Lifting to C

NE code lifts with the shared 16-bit lifter (`../lift/lift16.py`) through
`../lift/ne_lift.py`, which resolves relocations to far-call/import targets and
emits a Win16 import as a `MODULE_API(cpu)` shim call.

### A whole Win16 program: `ne_link.py`

A Win16 game is a host plus the DLLs it imports by ordinal, and a static
recompile has to turn each cross-module import into a direct call. `ne_link.py`
lifts all of them into one tree:

```bash
python tools/ne/ne_link.py --work work --ida-dir work/ida --seeds tools/entry_seeds.json \
    --shims <pcrecomp>/runtime/win16/host --shims runtime \
    game/ENGINE.DLL game/OTHER.DLL game/HOST.EXE      # DLLs first, host last
```

It renumbers the modules into one segment space (`NEHeader.renumber`), gives
the lifter every module's export table (data exports included: an importer
loads a DLL's variables through the same relocations), lifts every code
segment into `work/src/segNNN.c`, and writes the flat image and
`mem_layout.h` (`gen_image.py`, whose `RECOMP_MODULES[]` table tells the runtime
each module's segments, entry and DGROUP). It then regenerates the glue:
unresolved-call stubs, `segments.h`, the indirect-call table
(`gen_dispatch.py`) and the Win16 import surface of all modules minus the
lifted ones (`gen_win16_stubs.py`, which reads a purge the table lacks from the
exporting DLL's own `retf N`).

Everything under `--work` is derived from the game's binaries: gitignore it.

Companions:

| Tool | Does |
|---|---|
| `patch_borland_eh.py` | Guards Borland C++'s EH cleanup-chain walker, found by signature, against the re-entrant-WNDPROC chain corruption that otherwise hangs the first exception. |
| `seed_misses.py` | Turns `[dispatch] far MISS seg=N off=X` lines from a run log into `--seeds` entries (module, module-local segment). |
| `bpguard.py` | Instruments every lifted call site with a callee-saved BP/DS/SP check, for hunting frame corruption. |

Used by catz (2 modules), dogz (4) and oddballz (8).

## The Win16 host runtime

`runtime/win16/host/` is Win16-on-Win32 for a program lifted with `ne_link.py`:
KERNEL/USER/GDI/WinG/MMSYSTEM shims, NE resource serving (string tables,
`RT_NAMETABLE`, `AccessResource`), INT 21h file services, the window/dialog
bridge and the host `main()`, which runs each DLL's LibMain from
`RECOMP_MODULES[]` and then the host's startup. A game supplies one
`RecompGame` (`recomp_game.h`) with the few facts the shims need about it --
guest install directory, INI fallbacks and defaults, palette resource, licence
key hint, and an optional `GetProcAddress` hook for DLLs it loads but does not
lift -- and links the host sources with its lifted tree.
