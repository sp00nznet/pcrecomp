# IDA scripts

Scripts that run inside IDA Pro to export ground-truth analysis the toolkit's
own disassemblers can consume. The toolkit leans on Ghidra for batch
decompilation (see `../ghidra/`); these cover the case where you have IDA and
want its (often superior) code/data classification driving the lifters.

They use the **idalib / idapro** headless interface, so they run from a normal
Python interpreter that has IDA's bindings on its path -- no GUI required:

```bash
py -3 tools/ida/ida_probe_segs.py GAME.EXE          # see the segment layout
py -3 tools/ida/ida_export.py   GAME.EXE map.json   # export the code map
```

## ida_probe_segs.py

Dumps IDA's segment table: name, class, address range, selector, bitness,
size, and per-segment function count. Use it to confirm how IDA numbered the
segments before exporting (for NE, IDA index `i` is NE segment `i + 1`).
`--code-only` hides data segments.

## ida_export.py

Exports a **code map** -- per CODE segment: function entry offsets, every
instruction-head offset, and merged code ranges -- as JSON. Feed it to a
disassembler so it decodes only at verified instruction boundaries instead of
linear-sweeping through data-in-code.

The `--key` mode chooses how segments are keyed so one export fits different
toolchains:

| `--key` | keys are | offsets | consumer |
|---------|----------|---------|----------|
| `ne` (default) | NE segment number (IDA index + 1) | segment-relative | `tools/ne/ne_decode.py --ida-json` |
| `index` | raw IDA segment index | segment-relative | custom |
| `name`  | segment name (`.text`) | segment-relative | custom |
| `va`    | segment start address (hex) | absolute | flat 32-bit images |

Example, wiring it into the NE pipeline:

```bash
py -3 tools/ida/ida_export.py GAME.EXE code_map.json --key ne
python tools/ne/ne_decode.py GAME.EXE --ida-json code_map.json
```

## Writing your own

These double as templates for one-off IDA exports. The pattern is:
`idapro.open_database(binary, run_auto_analysis=True)` ->
`ida_auto.auto_wait()` -> walk `ida_segment` / `idautils.Functions` ->
`idapro.close_database(save=False)`. The same data can be produced from Ghidra
(`../ghidra/`) or Binary Ninja with equivalent APIs if IDA isn't available.
