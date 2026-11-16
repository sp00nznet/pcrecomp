#!/usr/bin/env python3
"""msvceh_probe lift driver: work/ehprobe.exe -> work/gen/ (run.cmd).

The Galactic Battlegrounds driver (swgb-recomp run_lift.py), pointed at the
probe. Galactic Battlegrounds' description follows.


Battlegrounds.exe (v1.1) is the whole game (MSVC6 C++, DirectDraw, base
0x00400000, no relocations), catalogued by disasm32 into work/functions.json.
The driver is Crazy Taxi's, plus MSVC exception frames: every function that
installs a C++ try or a __try gets a landing pad (pcrecomp tools/lift/eh32.py,
docs/exceptions.md).

    py -3 run_lift.py --all
    py -3 run_lift.py --roots 0x00632881
"""
import argparse
import json
import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
os.environ.setdefault('PCRECOMP', os.path.join(_HERE, '..', '..', '..'))
# PCRECOMP picks the toolkit checkout, the same knob CMakeLists.txt has: the
# lifter and the runtime header must come from the same tree.
_TOOLS = os.path.join(os.environ.get('PCRECOMP', os.path.join(_HERE, '..', 'pcrecomp')), 'tools')
sys.path.insert(0, os.path.join(_TOOLS, 'lift'))
sys.path.insert(0, os.path.join(_TOOLS, 'pe'))

from capstone import Cs, CS_ARCH_X86, CS_MODE_32          # noqa: E402
from generate import (EXTENT_REACH, closure, find_splits, true_extent,  # noqa: E402
                      linear_disassemble_function, lift_function_linear, write_chunk)
from lift32 import Lifter                                  # noqa: E402
import eh32                                                # noqa: E402
from pe_analyze import analyze_pe, build_iat_map           # noqa: E402

OUT = os.path.join(_HERE, "work", "gen")
STATS = os.path.join(_HERE, "work", "lift_stats.json")

# (file, catalog, PE timestamp of the one build supported, what it is).
# A different build lifts, but the patches and seeds are at this build's
# addresses: it would crash in the game, so it is refused (README).
MODULES = [(os.path.join(_HERE, 'work', 'ehprobe.exe'), os.path.join(_HERE, 'work', 'functions.json'), None, 'probe')]

# Entries the catalog does not find (seed_from_log.py from runs).
RUN_SEEDS = []

DATA_IN_CODE = []


def is_data(va):
    return any(lo <= va < hi for lo, hi in DATA_IN_CODE)

# Fixes to the game itself: C run after the instruction at the address.
PATCHES = {}

# Functions the host does instead (src/runtime/*.c says why for each).
HLE = {}
PATCH_DECLS = ''.join('void %s(void);\n' % f for f in HLE.values())


def apply_patches(body, patches):
    """Add each patch's C after the lines that lift its instruction.

    Some instructions lift to a block over several lines (idiv's `{ ... }`):
    the patch goes after the block closes, not inside it. From the Tiberium
    Wars driver (tiberiumwars-recomp run_lift.py)."""
    for va, c in patches.items():
        tag = '/* 0x%08X:' % va
        k = body.find(tag)
        if k != -1:
            s = body.rfind('\n', 0, k) + 1
            e = body.index('\n', k)
            depth = body[s:e].count('{') - body[s:e].count('}')
            while depth > 0:
                s, e = e + 1, body.index('\n', e + 1)
                depth += body[s:e].count('{') - body[s:e].count('}')
            body = body[:e + 1] + '    ' + c + '\n' + body[e + 1:]
    return body


def load_seeds(path):
    """Addresses from a seed file: a list of {'address': va} or of plain VAs."""
    if not path or not os.path.exists(path):
        return set()
    return {e['address'] if isinstance(e, dict) else e for e in json.load(open(path))}


def exe_stamp(path):
    """The PE header's TimeDateStamp: which build of a module this is."""
    with open(path, 'rb') as f:
        head = f.read(4096)
    nt = int.from_bytes(head[0x3C:0x40], 'little')
    return int.from_bytes(head[nt + 8:nt + 12], 'little')


class Out:
    """The generated tree: chunks numbered across both modules."""

    def __init__(self, path, split):
        self.path, self.split = path, split
        self.chunk, self.idx, self.entries = [], 0, []

    def add(self, body, addr, name):
        self.chunk.append((body, addr, name))
        self.entries.append((addr, name))
        if len(self.chunk) >= self.split:
            self.flush()

    def flush(self):
        if self.chunk:
            write_chunk(self.path, self.idx, self.chunk)
            self.idx += 1
            self.chunk = []


def lift_module(path, catalog, args, out, extra_roots):
    """Lift one module into `out`. Returns (entry VA, stats)."""
    info = analyze_pe(path)
    iat = build_iat_map(info)
    cs, ce = info.code_start, info.code_end
    print('[*] %s: base=0x%08X code=0x%08X-0x%08X IAT=%d'
          % (os.path.basename(path), info.image_base, cs, ce, len(iat)))

    # The code section, by address.
    cat = json.load(open(catalog))
    byaddr = {f['address']: f for f in cat['functions'] if cs <= f['address'] < ce and not is_data(f['address'])}
    print('[*]   catalog: %d functions inside the code section' % len(byaddr))

    raw = open(path, 'rb').read()
    # The code range spans sections here (THIS_COD after .text: matrix and
    # blit routines), so every section is laid out at its address. Read from
    # .text alone, a function in the second section lifted to an empty body
    # that never popped its return address.
    code = bytearray(ce - cs)
    for sec in info.sections:
        lo = info.image_base + sec.virtual_address
        a, b = max(lo, cs), min(lo + sec.raw_size, ce)
        if a < b:
            code[a - cs:b - cs] = raw[sec.raw_offset + a - lo:sec.raw_offset + b - lo]
    code = bytes(code)

    def read(va, n):
        """n bytes of the image at va (FuncInfo and scope tables live in .rdata)."""
        for sec in info.sections:
            lo = info.image_base + sec.virtual_address
            if lo <= va and va + n <= lo + sec.raw_size:
                return raw[sec.raw_offset + va - lo:sec.raw_offset + va - lo + n]
        return None

    # Bound each injected entry by the next known one: an entry landing
    # mid-code handed `ce` makes the extent walk descend the whole section.
    want = {a for a in set(RUN_SEEDS) | load_seeds(args.seeds) if cs <= a < ce and a not in byaddr}
    known = sorted(set(byaddr) | want)
    nxt = {a: (known[i + 1] if i + 1 < len(known) else ce) for i, a in enumerate(known)}
    for a in want:
        byaddr[a] = {'address': a, 'end': min(nxt[a], a + 0x100), 'calls_to': [], 'entry_kind': 'start'}

    entry = info.image_base + info.entry_point_rva
    roots = [entry] + [info.image_base + e.rva for e in getattr(info, 'exports', [])
                       if getattr(e, 'rva', 0)] + [r for r in extra_roots if cs <= r < ce]
    chosen = set(byaddr) if args.all else set(closure(byaddr, roots, args.max))
    print('[*]   lifting %d of %d functions (%s)'
          % (len(chosen), len(byaddr), 'all' if args.all else 'closure, cap %d' % args.max))

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True

    # MSVC exception frames (eh32.frame). Where a handler continues inside the
    # function that installed the frame (an __except block, a catch's
    # continuation) is a label in that body, never an entry of its own:
    # disasm32 takes a scope table's __except pointers for functions, and
    # dispatched as one an __except block would run as a call and "return"
    # into _except_handler3.
    frames = {}
    for a in sorted(byaddr):
        head = list(md.disasm(code[a - cs:a - cs + 64], a, 12))
        if not any(i.op_str == 'dword ptr fs:[0], esp' for i in head):
            continue
        reached = set()
        end, _ = true_extent(md, code, cs, a, min(a + EXTENT_REACH, ce), set(byaddr), reached=reached)
        insns, _ = linear_disassemble_function(md, code, cs, a, end, reached=reached)
        fr = eh32.frame(md, read, insns)
        if fr and fr[0]:
            frames[a] = fr
    resume = set().union(*(r for r, _ in frames.values())) if frames else set()
    dropped = resume & set(byaddr)
    for a in dropped:
        del byaddr[a]
    chosen -= dropped
    print('[*]   %d functions install an exception frame with somewhere to continue '
          '(%d frame-pointer-omitted); %d resume points, %d were catalog entries'
          % (len(frames), sum(1 for _, o in frames.values() if o == 0), len(resume), len(dropped)))

    # precise carry: adc/sbb take their carry from the flag state that set it.
    # The default reads a `_cf` that add/sub/cmp never write, which breaks every
    # 64-bit add and subtract (The Movies lost its menu video to it).
    lifter = Lifter(iat_map=iat, lifted=set(byaddr), precise_carry=True, precise_sbb=True)
    ordered = sorted(byaddr)
    starts = {a for a in ordered if byaddr[a].get('entry_kind') != 'alias'}
    splits = find_splits(md, code, cs, ce, starts)
    starts -= splits          # still dispatchable; just not a wall inside its parent
    errors = dirty = 0

    def lift_one(addr, name, end, reached):
        nonlocal errors
        try:
            lo = min(reached) if reached else addr   # a chunk can sit below the entry
            insns, leaders = (linear_disassemble_function(md, code, cs, lo, end, reached=reached)
                              if end > addr else ([], None))
            if leaders is not None:
                leaders.add(addr)
            resume, off = frames.get(addr, (None, None))
            if addr in HLE:
                out.add('void %s(void) { %s(); }\n' % (name, HLE[addr]), addr, name)
                return
            if not insns:
                raise ValueError('no instructions at 0x%08X' % addr)
            body = lift_function_linear(lifter, name, insns, leaders, addr, eh_resume=resume, eh_off=off)
            body = apply_patches(body, {va: c for va, c in PATCHES.items() if reached and va in reached})
        except Exception as e:                      # noqa: BLE001 -- counted, not hidden
            body = '/* ERROR %s: %s */\nvoid %s(void) { }\n' % (name, e, name)
            errors += 1
        out.add(body, addr, name)

    # A direct branch or call to an address nothing catalogued is a tail call
    # or a jump into shared code the catalog missed. The target has to be
    # dispatchable or the RECOMP_ITAIL cannot resolve, so each round's outside
    # targets are lifted in the next round, until none are new.
    todo, added = sorted(chosen), 0
    while todo:
        outside = set()
        for addr in todo:
            reached, behind, called = set(), set(), set()
            end, clean = true_extent(md, code, cs, addr, min(addr + EXTENT_REACH, ce), starts,
                                     reached=reached, behind=behind, called=called,
                                     seeds=frames.get(addr, ((),))[0])
            outside |= {t for t in behind if t not in reached} | called
            dirty += not clean
            lift_one(addr, 'sub_%08X' % addr, end, reached)
        todo = sorted(t for t in outside if cs <= t < ce and t not in byaddr and not is_data(t))
        for t in todo:
            byaddr[t] = {'address': t, 'end': ce, 'calls_to': [], 'entry_kind': 'start'}
            chosen.add(t)
        added += len(todo)

    stubs = [a for a in ordered if a not in chosen]
    for a in stubs:
        name = 'sub_%08X' % a
        out.add('void %s(void) { RECOMP_NOT_LIFTED(0x%08Xu); }\n' % (name, a), a, name)
    print('[*]   lifted %d, %d outside targets added, %d stubs, %d errors, %d with no terminator'
          % (len(chosen), added, len(stubs), errors, dirty))
    return entry, {'lifted': len(chosen), 'stubs': len(stubs), 'errors': errors, 'no_terminator': dirty}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', default=OUT)
    ap.add_argument('--roots', default='', help='comma-separated extra root VAs')
    ap.add_argument('--max', type=int, default=3000, help='closure size cap')
    ap.add_argument('--all', action='store_true', help='lift every function')
    ap.add_argument('--split', type=int, default=400, help='functions per .c file')
    ap.add_argument('--seeds', default=os.path.join(_HERE, 'work', 'run_seeds.json'),
                    help='seed_from_log.py JSON of unresolved targets from runs')
    args = ap.parse_args()
    for path, catalog, stamp, what in MODULES:
        if not os.path.exists(path):
            sys.exit('no %s -- README, Step by step' % path)
        if not os.path.exists(catalog):
            sys.exit('no catalog at %s -- run disasm32.py first (README, Step by step)' % catalog)
        if stamp and exe_stamp(path) != stamp:
            sys.exit('%s is not the build this project supports: its PE timestamp is 0x%08X, '
                     'expected 0x%08X: %s (README).' % (path, exe_stamp(path), stamp, what))

    os.makedirs(args.out, exist_ok=True)
    for fn in os.listdir(args.out):                 # a smaller lift must not leave stale chunks
        if fn.startswith('recomp_') and fn.endswith('.c'):
            os.remove(os.path.join(args.out, fn))
    t0 = time.time()
    out = Out(args.out, args.split)
    roots = [int(x, 0) for x in args.roots.split(',') if x.strip()]
    entries_va, stats = [], {'lifted': 0, 'stubs': 0, 'errors': 0, 'no_terminator': 0}
    for path, catalog, _, _ in MODULES:
        entry, s = lift_module(path, catalog, args, out, roots)
        entries_va.append(entry)
        for k in stats:
            stats[k] += s[k]
    out.flush()

    with open(os.path.join(args.out, 'recomp_funcs.h'), 'w', newline='\n') as f:
        f.write('/* Battlegrounds.exe - AUTO-GENERATED by run_lift.py */\n#pragma once\n'
                '#include <stdint.h>\n\n'
                'void recomp_not_lifted(uint32_t va);\n'
                '#define RECOMP_NOT_LIFTED(va) recomp_not_lifted(va)\n\n' + PATCH_DECLS + '\n')
        for a, n in out.entries:
            f.write('void %s(void);\n' % n)
    with open(os.path.join(args.out, 'recomp_dispatch.c'), 'w', newline='\n') as f:
        f.write('/* Battlegrounds.exe - AUTO-GENERATED by run_lift.py */\n'
                '#include "recomp_types.h"\n#include "recomp_funcs.h"\n\n'
                'const recomp_dispatch_entry_t recomp_dispatch_table[] = {\n')
        for a, n in sorted(out.entries):
            f.write('    { 0x%08Xu, %s },\n' % (a, n))
        f.write('};\nconst uint32_t recomp_dispatch_count = %d;\n'
                'const uint32_t swgb_entry_va = 0x%08Xu;\n'
                % (len(out.entries), entries_va[0]))

    # A patch that found no instruction to follow is a fix that silently isn't there.
    gen = ''.join(open(os.path.join(args.out, fn), encoding='utf-8', errors='replace').read()
                  for fn in os.listdir(args.out) if fn.endswith('.c'))
    for va, c in PATCHES.items():
        if c not in gen:
            sys.exit('patch at 0x%08X (%s) was not applied: is 0x%08X lifted?' % (va, c, va))
    print('[*] patches applied: %d' % len(PATCHES))

    lines = sum(sum(1 for _ in open(os.path.join(args.out, fn), encoding='utf-8', errors='replace'))
                for fn in os.listdir(args.out))
    stats.update({'files': out.idx, 'lines': lines})
    json.dump(stats, open(STATS, 'w'), indent=1)
    print('=' * 60)
    print('  lifted %(lifted)d   not-lifted stubs %(stubs)d   errors %(errors)d   '
          'no terminator %(no_terminator)d' % stats)
    print('  %s lines of C in %d files, %.1fs' % (format(lines, ','), out.idx, time.time() - t0))
    print('=' * 60)


if __name__ == '__main__':
    main()
