# Mach-O tools (NeXTSTEP / OPENSTEP)

Front end for NeXTSTEP 3.x applications. Their executables are fat Mach-O
(m68k + i486, sometimes hppa/sparc); we lift the **i386 slice** with the same
disasm32 + lift32 as PE targets. What differs is everything around the code:
a UFS disk instead of an ISO, Mach-O instead of PE, and imports that are
*direct* calls into fixed-address shared libraries instead of an IAT.

## The pipeline

```
hd.img (NeXT disklabel + 4.3BSD UFS)
   | ufs.py      ls / find / get        -> Foo.app, /usr/shlib/*.shlib
   v
fat Mach-O
   | macho.py    slices, segments, sections, fvmlibs, symbols, entry;
   |             pe_sections() + gcc_prologues() feed disasm32
   | survey.py   shlib imports and ObjC classes/selectors  <- the scope gate
   v
disasm32 (seeds = gcc prologues, data_scan=False) -> lift32 (iat_map = import_map)
```

```bash
MSYS_NO_PATHCONV=1 python ufs.py hd.img get /LocalApps/Doom.app Doom.app
MSYS_NO_PATHCONV=1 python ufs.py hd.img get /usr/shlib shlib
python survey.py Doom.app/Doom --shlibs shlib
```

(`MSYS_NO_PATHCONV=1` stops Git Bash rewriting `/usr/shlib` into a Windows path.)

## Things that are not like PE

* **Imports.** Shared libraries are fixed-VM (`LC_LOADFVMLIB`): libsys at
  `0x05000000`, libNeXT (AppKit + DPS) at `0x06000000`, libMedia at
  `0x09000000`. The app calls `call 0x0500xxxx` straight into the lib's branch
  table, whose slot is a `jmp rel32` to the real body. `survey.import_map`
  follows the slot to the lib's own symbol and hands `{slot VA: (lib, name)}`
  to the Lifter as its `iat_map`, so each site lifts to `RECOMP_ICALL(slot)`
  and the runtime bridges it by address. The shlibs on an i386 install are
  thin i386, so only that slice's imports resolve by name.
* **Low load address.** Text starts at `0x3990`, so small integers look like
  code pointers and disasm32's data scan invents functions (~480 on Doom).
  Seed with `MachO.gcc_prologues()` -- NeXT's gcc encodes the frame setup as
  `55 89 E5`, not MSVC's `55 8B EC` -- and pass `data_scan=False`.
* **Big-endian filesystem.** The disklabel and UFS are big-endian even on an
  i386 install; `ufs.py` detects the byte order from the superblock magic.
* **Objective-C.** AppKit is reached through `objc_msgSend`, so the real host
  surface is the selector list `survey.py` prints, not the C imports.

## Measured scope

| App | i386 insns | libsys fns | libNeXT fns | ObjC classes def/ref | selectors |
|---|---|---|---|---|---|
| NeXTDoom 1.2 | 43k | 47 | 12 | 2 / 4 | 38 |
| DoomEd 0.91 | 42k | 61 | 39 | 37 / 18 | 455 |

`__fvmlib_init0` is not code: it is {value, address} pairs crt0 stores into
the shlibs' data (app symbols the libs call back into).
