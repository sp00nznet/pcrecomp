"""
gen_win16_stubs.py - Emit a Win16 NE binary's import surface as C.

Reads the target's own relocations and writes two files, so the shim layer can
never drift from what the binary actually imports:

  <api-header>   prototypes for every import, plus the indirect dispatchers and
                 the INT handlers, each annotated with its PASCAL purge
  <stubs.c>      a default body for every import with NO hand-written shim in
                 the shim directory

The contract every shim obeys, generated or hand-written, matches what
tools/lift/lift16.py (via a project's NE lifter) emits at a far call:

    push16(cs); push16(ret_off); MODULE_API(cpu);

so a shim pops 4 bytes of far return address plus its PASCAL argument purge
(win16.PURGE), returns WORD in AX and DWORD in DX:AX, and returns normally -
there is no RETF to execute, the C return IS the RETF.

A generated stub still purges correctly and says so once, so an unimplemented
call announces itself instead of silently returning garbage and shifting its
caller's frame.

Usage:
    python gen_win16_stubs.py GAME.DLL --api runtime/runtime_api.h \\
        --stubs runtime/win16/win16_stubs.c --shims runtime/win16 \\
        --guard MYGAME
"""
import argparse
import glob
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ne_parse import parse_ne
import win16

# A hand-written shim is any `void MODULE_API(CPU *cpu)` definition in the shim
# directory, other than the generated stub file itself.
# Mixed case: a shim for an unnamed ordinal is MODULE_OrdN, and missing it
# here emits a second definition of a hand-written one.
DEF_RE = re.compile(r'^void\s+([A-Za-z0-9_]+)\(CPU\s*\*', re.M)


def imports_used(ne, skip=(), seen=None):
    """Every distinct import the binary's relocations reference.

    Returns {shim_name: (Win16Import, called)}. `called` is False for imports
    that only ever appear as OFFSET16 relocations - __AHSHIFT, __AHINCR and
    __WINFLAGS are absolute VALUES the loader patches into the code stream, not
    routines, and a stub that unwound a frame for one would corrupt the caller.
    """
    seen = {} if seen is None else seen
    for seg in ne.segments:
        for r in seg.relocations:
            if (r.flags & 3) not in (1, 2):
                continue
            mod = win16.module_name(ne, r.module_idx)
            if mod.upper() in skip:
                continue            # another lifted module: a direct call, not a shim
            imp = win16.get_import(mod, r.ordinal, r.name)
            entry = seen.setdefault(imp.name, [imp, False])
            if r.src_type != 5:
                entry[1] = True
    return seen


def retf_purge(ne, ordinal):
    """The purge an exported PASCAL function performs, read from its own code:
    the immediate of the first `retf N` reached by decoding from the entry.

    Every return of a PASCAL function pops the same N, so the first one found is
    as good as any. It is the callee's own statement of its argument size, which
    beats a table: checked against WinG's documented prototypes it gives 0, 4
    and 10 for CreateDC, RecommendDIBFormat and CreateBitmap, and it caught
    SOSLIB03.SOSDIGIDETECTINIT at 6 where the table said 4 (the function reads
    a far pointer at [bp+6] AND a word at [bp+0xA]). None when there is no
    such export or no retf within reach."""
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'disasm'))
    from decode16 import Decoder
    e = next((e for e in ne.entries if e.ordinal == ordinal), None)
    seg = ne.seg(e.segment) if e and 1 <= e.segment < 0xFE else None
    if seg is None or not seg.is_code or not seg.data:
        return None
    d = Decoder(seg.data, base_offset=0)
    d.pos = e.offset
    for _ in range(4000):
        inst = d.decode_one()
        if inst is None:
            return None
        if inst.mnemonic == 'retf':
            return inst.op1.disp if inst.op1 is not None else 0
    return None


def dll_purges(dll_dirs, modules):
    """{(MODULE, API): purge} for every export of every imported module whose
    DLL is found in dll_dirs."""
    out = {}
    for mod in modules:
        path = next((os.path.join(d, f) for d in dll_dirs for f in os.listdir(d)
                     if f.upper() in (mod + '.DLL', mod + '.DRV')), None)
        if not path:
            continue
        ne = parse_ne(path)
        for e in ne.entries:
            p = retf_purge(ne, e.ordinal)
            if p is not None:
                out[(mod, win16.get_import(mod, e.ordinal).api.upper())] = p
    return out


def hand_written(shim_dirs, stubs_path):
    names = set()
    for path in [p for d in shim_dirs for p in glob.glob(os.path.join(d, '*.c'))]:
        if os.path.abspath(path) == os.path.abspath(stubs_path):
            continue
        names.update(DEF_RE.findall(
            open(path, encoding='utf-8', errors='replace').read()))
    return names


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('binary', nargs='+',
                    help='the NE executables/DLLs being lifted; their import '
                         'surfaces are unioned')
    ap.add_argument('--api', required=True, help='runtime_api.h to write')
    ap.add_argument('--stubs', required=True, help='win16_stubs.c to write')
    ap.add_argument('--shims', action='append',
                    help='directory of hand-written shims, repeatable '
                         '(default: the stubs file directory)')
    ap.add_argument('--skip-module', action='append', default=[],
                    help='an imported module that is lifted too, so its '
                         'imports are direct calls and get no stub (repeatable)')
    ap.add_argument('--dll-dir', action='append', default=[],
                    help='directory holding imported DLLs (SOSLIB03.DLL, WING.DLL, '
                         '...); a purge the table lacks is read from the DLL\'s '
                         'own retf, and a table entry that disagrees is reported')
    ap.add_argument('--guard', default='RECOMP', help='include-guard prefix')
    args = ap.parse_args()

    shim_dirs = args.shims or [os.path.dirname(args.stubs) or '.']
    skip = {m.upper() for m in args.skip_module}
    used = {}
    for path in args.binary:
        imports_used(parse_ne(path), skip, used)
    have = hand_written(shim_dirs, args.stubs)

    by_mod = {}
    for name, (imp, called) in used.items():
        by_mod.setdefault(imp.module, []).append((name, imp, called))

    from_dll = dll_purges(args.dll_dir, {m.upper() for m in by_mod}) if args.dll_dir else {}
    for (mod, api), p in sorted(from_dll.items()):
        known = win16.PURGE.get((mod, api))
        if known is not None and known != p:
            print(f'  purge table says {mod}.{api} = {known}, the DLL\'s retf says {p}; '
                  f'using {p}', file=sys.stderr)

    def purge_of(imp):
        p = from_dll.get((imp.module.upper(), imp.api.upper()))
        return p if p is not None else win16.get_purge(imp.module, imp.api)

    target = ' + '.join(os.path.basename(b) for b in args.binary)
    guard = args.guard.upper()

    # ---- the API header ----
    h = ['/* runtime_api.h - Auto-generated by gen_win16_stubs.py. Do not edit. */',
         f'/* Host entry points the lifted {target} code calls: indirect-call',
         ' * dispatchers, INT handlers, and the Win16 import shims. */',
         f'#ifndef {guard}_RUNTIME_API_H',
         f'#define {guard}_RUNTIME_API_H',
         '',
         '#include "cpu.h"',
         '',
         '/* ---- Indirect call dispatchers (function pointers) ---- */',
         'void dispatch_far(CPU *cpu, uint16_t seg, uint16_t off);',
         'void dispatch_near(CPU *cpu, uint16_t seg, uint16_t off);',
         '/* 1 = ran the lifted function at seg:off; 0 = none there (gen_dispatch.py) */',
         'int recomp_dispatch_lookup(CPU *cpu, uint16_t seg, uint16_t off);',
         '',
         '/* ---- Software interrupts ---- */',
         'void int_handler(CPU *cpu, int int_num);',
         'void dos_int21(CPU *cpu);',
         '',
         f'/* ---- Win16 import shims ({len(used)} total) ---- */']
    unknown_purge = []
    for mod in sorted(by_mod):
        entries = sorted(by_mod[mod])
        h.append('')
        h.append(f'/* {mod} ({len(entries)}) */')
        for name, imp, called in entries:
            purge = purge_of(imp)
            # Only a GENERATED stub needs the table: a hand-written shim pops
            # its own arguments, and knows how many from the API it implements.
            if called and purge is None and name not in have:
                unknown_purge.append(f'{imp.module}.{imp.api} (@{imp.ordinal})')
            kind = f'purge {purge}' if called else 'absolute value, not called'
            h.append(f'void {name}(CPU *cpu);  /* @{imp.ordinal} {imp.api}, {kind} */')
    h += ['', f'#endif /* {guard}_RUNTIME_API_H */']
    os.makedirs(os.path.dirname(os.path.abspath(args.api)), exist_ok=True)
    with open(args.api, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(h) + '\n')

    # ---- the generated stubs ----
    c = ['/* win16_stubs.c - Auto-generated by gen_win16_stubs.py. Do not edit. */',
         '/* Default body for every import with no hand-written shim: purge the  */',
         '/* frame correctly, return 0, and say so once so an unimplemented call */',
         '/* announces itself instead of silently returning garbage.             */',
         '',
         '#include <stdio.h>',
         '#include "cpu.h"',
         '#include "runtime_api.h"',
         '',
         'static void unimpl(CPU *cpu, const char *api, int purge)',
         '{',
         '    static const char *seen[256];',
         '    static int nseen;',
         '    int i;',
         '    for (i = 0; i < nseen; i++)',
         '        if (seen[i] == api) break;',
         '    if (i == nseen && nseen < 256) {',
         '        seen[nseen++] = api;',
         '        fprintf(stderr, "[win16] unimplemented: %s\\n", api);',
         '    }',
         '    cpu->ax = 0; cpu->dx = 0;',
         '    cpu->sp = (uint16_t)(cpu->sp + 4 + purge);   /* far retaddr + PASCAL args */',
         '}',
         '']
    generated = 0
    # int_handler is declared above for every target; a runtime that has no
    # INT support of its own still has to link, and an unhandled INT should
    # say which one rather than fail at link time.
    if 'int_handler' not in have:
        c.append('void int_handler(CPU *cpu, int int_num) { (void)cpu; '
                 'fprintf(stderr, "[int] unhandled INT 0x%02X\\n", int_num); }')
    for mod in sorted(by_mod):
        for name, imp, called in sorted(by_mod[mod]):
            if name in have:
                continue
            if not called:
                msg = f'[win16] {imp.api} called, but it is an absolute value import'
                c.append(f'void {name}(CPU *cpu) {{ (void)cpu; '
                         f'fprintf(stderr, "{msg}\\n"); }}')
            else:
                purge = purge_of(imp)
                c.append(f'void {name}(CPU *cpu) {{ '
                         f'unimpl(cpu, "{imp.module}.{imp.api}", {purge if purge is not None else 0}); }}')
            generated += 1
    c.append('')
    os.makedirs(os.path.dirname(os.path.abspath(args.stubs)), exist_ok=True)
    with open(args.stubs, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(c) + '\n')

    print(f'{args.api}: {len(used)} imports across {len(by_mod)} modules')
    print(f'{args.stubs}: {generated} generated, {len(used) - generated} hand-written')
    for mod in sorted(by_mod):
        n = len(by_mod[mod])
        hw = sum(1 for name, _, _ in by_mod[mod] if name in have)
        print(f'  {mod:<10s} {n:3d}  ({hw} hand-written)')

    if unknown_purge:
        # Not a warning to skim past. Win16 is PASCAL: a shim that pops the
        # wrong number of bytes shifts its CALLER's frame, so the crash lands
        # far from here. Add the entries to win16.PURGE before running.
        print(f'\n{len(unknown_purge)} imports have NO purge value - the frame '
              f'will be wrong at every one of these call sites:', file=sys.stderr)
        for item in sorted(set(unknown_purge)):
            print(f'  {item}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
