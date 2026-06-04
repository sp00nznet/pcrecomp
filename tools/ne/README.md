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

NE code lifts with the shared 16-bit lifter (`../lift/lift16.py`) once
relocations are resolved to far-call/import targets. Runtime-library imports
(DOS extenders, the Windows kernel, vendor DLLs) need an ordinal->signature
map for the specific module -- that map is per-application reverse-engineering,
not something the toolkit can ship generically. See the `elfish` project's
`ne_lift.py` / `tsxlib.py` for a worked example of wiring an extender's import
library into the lifter.
