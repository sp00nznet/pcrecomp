"""
ne_link.py - Lift a Win16 program made of several NE modules into one tree.

A Win16 game is rarely one file. Catz is a host (CATZ.WAD) plus its engine DLL;
Dogz is a host plus three DLLs; Oddballz is one big module plus a sound-callback
DLL. They call each other by ORDINAL through NE import relocations, and the
static recompile has to turn every such call into a direct C call. So the
modules are lifted together, into one segment numbering and one flat image:

  1. parse every module, in load order (DLLs first, the host last), and shift
     each one's segment numbers past the previous one's (NEHeader.renumber),
     so `segNNN_XXXX` names and SEG_n selectors never collide;
  2. build each module's export table (ordinal -> global seg:off) and hand all
     of them to the lifter, which resolves a cross-module call straight to the
     target's lifted function instead of a Win16 shim;
  3. lift every code segment of every module into <work>/src/segNNN.c, using a
     per-module code map if one was exported (tools/ida/ida_export.py writes
     one keyed by the module's OWN segment numbers; renumber() accounts for it);
  4. write the flat image and mem_layout.h (gen_image.write), whose
     RECOMP_MODULES[] table tells the runtime where each module's segments,
     DGROUP and entry point are;
  5. regenerate the glue from the lifted tree: segments.h, the unresolved-call
     stubs, the indirect-call dispatch table, and the Win16 import surface of
     all modules minus the ones lifted here.

Usage, from the project root:

    python <pcrecomp>/tools/ne/ne_link.py --work work --ida-dir work/ida \\
        game/DOGZDLL.DLL game/THINK.DLL game/NEURON.DLL game/DOGZ.WAD

--ida-dir holds <MODULE-FILE-STEM>.json per module (DOGZDLL.json, ...); a module
without one is lifted from a linear sweep.

--seeds adds function entries a code map does not know about -- typically the
targets of indirect calls that missed at run time, found by running the game:

    {"CATZDLL": {"1": ["0x245A", "0x4E8E"]}, "CATZ": {"4": ["0x1DFC"]}}

keyed by module name and by the module's OWN segment numbers, like a code map. Everything written under --work is
derived from the game's binaries: gitignore it, never commit it.
"""
import argparse
import contextlib
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, '..', 'lift'))
from ne_parse import parse_ne
import ne_decode
import ne_lift
import gen_image


def exports(ne):
    """ordinal -> (global seg, offset) for every entry this module exports.

    DATA entries too: a DLL exports variables in its DGROUP, and an importer
    loads their selector and offset through the same import relocations it
    uses for calls. Keeping only code entries left CATZ.WAD pushing the
    loader's 0xFFFF:0000 placeholders instead of CATZDLL's data -- it booted,
    then idled in its message loop with the pet never loaded."""
    return {e.ordinal: (e.segment, e.offset) for e in ne.entries
            if 1 <= e.segment < 0xFE and ne.seg(e.segment) is not None}


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('modules', nargs='+', help='NE files in load order, host last')
    ap.add_argument('--work', default='work', help='output root (gitignored)')
    ap.add_argument('--ida-dir', help='directory of per-module code maps')
    ap.add_argument('--seeds', help='JSON of extra function entries per module')
    ap.add_argument('--prefix', default='recomp', help='ne_lift.PREFIX')
    ap.add_argument('--shims', action='append', default=[],
                    help='directory of hand-written Win16 shims (repeatable)')
    ap.add_argument('--stack', type=lambda v: int(v, 0), default=0,
                    help='see gen_image.py --stack; only for a DLL-only program')
    args = ap.parse_args()

    src = os.path.join(args.work, 'src')
    rt = os.path.join(args.work, 'runtime')
    os.makedirs(src, exist_ok=True)
    os.makedirs(rt, exist_ok=True)
    ne_lift.PREFIX = args.prefix

    nes = gen_image.renumber_all([parse_ne(p) for p in args.modules])
    names = [ne.module_name.upper() for ne in nes]
    xmod = {name: exports(ne) for name, ne in zip(names, nes)}
    for ne, name in zip(nes, names):
        print(f'{name:10s} {os.path.basename(ne.filename):14s} '
              f'segs {ne.seg_base + 1}-{ne.seg_base + len(ne.segments)}  '
              f'{len(xmod[name])} exports')

    # Old seg*.c from a previous lift with a different module list must not
    # survive into this one: the glue below is generated from whatever is here.
    for f in os.listdir(src):
        if f.endswith('.c'):
            os.remove(os.path.join(src, f))

    seeds = json.load(open(args.seeds, encoding='utf-8')) if args.seeds else {}
    stray = set(seeds) - set(names)
    if stray:   # keyed by file stem, say: every seed would be dropped without a word
        sys.exit(f'--seeds names {sorted(stray)}, not a module being lifted '
                 f'(module names: {names})')
    for ne, name in zip(nes, names):
        stem = os.path.splitext(os.path.basename(ne.filename))[0]
        ida = os.path.join(args.ida_dir, stem + '.json') if args.ida_dir else None
        data = ne_decode.load_ida_data(ne, ida if ida and os.path.exists(ida) else None)
        if not data:
            print(f'  {stem}: no code map, linear sweep')
        for seg, offs in seeds.get(name, {}).items():
            fn = data.setdefault(seg, {}).setdefault('functions', [])
            fn.extend(int(o, 16) for o in offs)
        for s in ne.segments:
            if not s.is_code or not s.data:
                continue
            with open(os.path.join(src, f'seg{s.index:03d}.c'), 'w',
                      encoding='utf-8', newline='\n') as f, contextlib.redirect_stdout(f):
                ne_lift.lift_segment(ne, s.index, xmod=xmod)
    print(f'lifted into {src}')

    gen_image.write(nes, os.path.join(args.work, 'mem_image.bin'),
                    os.path.join(rt, 'mem_layout.h'), stack=args.stack)

    py = sys.executable
    run = lambda *a: subprocess.run([py, *a], check=True)
    # Stubs first: segments.h declares every segNNN_XXXX defined in src/,
    # and the stubs are definitions the lifted code calls.
    run(os.path.join(HERE, 'gen_unresolved_stubs.py'), '--src', src,
        '--out', os.path.join(src, '_unresolved_stubs.c'), '--prefix', args.prefix)
    run(os.path.join(HERE, 'gen_segments_h.py'), '--src', src,
        '--out', os.path.join(rt, 'segments.h'),
        '--max-seg', str(nes[-1].seg_base + len(nes[-1].segments) + (1 if args.stack else 0)))
    run(os.path.join(HERE, 'gen_dispatch.py'), '--src', src,
        '--out', os.path.join(src, '_dispatch.c'))
    stubs = [os.path.join(HERE, 'gen_win16_stubs.py'), *args.modules,
             '--api', os.path.join(rt, 'runtime_api.h'),
             '--stubs', os.path.join(src, '_win16_stubs.c')]
    for name in names:
        stubs += ['--skip-module', name]
    for d in args.shims:
        stubs += ['--shims', d]
    # The imported DLLs usually ship next to the game (SOSLIB03, WING): their
    # own retf is the best source for a purge the table lacks.
    for d in sorted({os.path.dirname(os.path.abspath(m)) for m in args.modules}):
        stubs += ['--dll-dir', d]
    return subprocess.run([py, *stubs]).returncode


if __name__ == '__main__':
    sys.exit(main())
