#!/usr/bin/env python3
"""Scope a NeXTSTEP app before lifting it -- the nextrecomp analogue of scan_traps.py.

Disassembles the i386 slice and reports:
  * every call/jmp into a fixed-VM shared library, resolved to a symbol name
    (the shlib's branch table is followed to the real target)
  * Objective-C: classes defined, classes referenced, selectors sent
  * raw kernel entries (lcall / int) that bypass libsys

  python survey.py Doom.app/Doom --shlibs shlib [--json out.json]
"""
import argparse, bisect, collections, json, os, sys
import capstone
from capstone import x86
sys.path.insert(0, os.path.dirname(__file__))
from macho import MachO, slices


class Shlib:
    def __init__(self, path):
        m = MachO(slices(open(path, 'rb').read())[0][1])
        self.m, self.name = m, os.path.basename(path)
        text = m.section('__TEXT', '__text')
        self.lo, self.hi = min(g['vmaddr'] for g in m.segments), max(g['vmaddr'] + g['vmsize'] for g in m.segments)
        self.text = text
        # external text symbols; N_EXT=1, N_SECT=0xe
        syms = sorted((s['value'], s['name']) for s in m.symbols if s['type'] & 0x0e == 0x0e and s['name'])
        self.addrs, self.names = [a for a, _ in syms], {}
        for a, n in syms:  # prefer a global name at the same address
            if a not in self.names or not n.startswith('L'):
                self.names[a] = n

    def contains(self, a):
        return any(g['vmaddr'] <= a < g['vmaddr'] + g['vmsize'] for g in self.m.segments)

    def resolve(self, a):
        """Name for address a; follows one branch-table jmp."""
        if a in self.names and not self.names[a].startswith('.branch_table_slot'):
            return self.names[a]
        b = self.m.read(a, 5)
        if b and b[0] == 0xE9:  # jmp rel32 -- branch table slot
            t = (a + 5 + int.from_bytes(b[1:5], 'little', signed=True)) & 0xFFFFFFFF
            if t in self.names:
                return self.names[t]
            if a in self.names:
                return self.names[a]
            return '%s+%#x' % self._near(t)
        return '%s+%#x' % self._near(a)

    def _near(self, a):
        i = bisect.bisect_right(self.addrs, a) - 1
        if i < 0:
            return ('?', a)
        return (self.names[self.addrs[i]], a - self.addrs[i])


def load_shlibs(m, shlib_dir):
    libs = []
    for l in m.fvmlibs:
        p = os.path.join(shlib_dir, os.path.basename(l['name']))
        if os.path.exists(p):
            libs.append(Shlib(p))
        else:
            print('warning: missing %s' % p, file=sys.stderr)
    return libs


def import_map(m, libs):
    """{branch-table VA: (lib, symbol)} for every shlib address the code
    calls or jumps to -- the Lifter's iat_map, so those sites lift to
    RECOMP_ICALL(va) and the runtime bridges them by address."""
    return {t: (lib.name, lib.resolve(t)) for t, lib in _external_targets(m, libs)[0]}


def _external_targets(m, libs):
    """([(target, lib)], unresolved Counter, kernel Counter, ninsn)."""
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    md.skipdata = True
    hits, unresolved, kernel, ninsn = [], collections.Counter(), collections.Counter(), 0
    for sect in ('__text', '__fvmlib_init0'):
        s = m.section('__TEXT', sect)
        if not s or not s['size']:
            continue
        for ins in md.disasm(m.sect_bytes(s), s['addr']):
            ninsn += 1
            if ins.mnemonic in ('lcall', 'int', 'sysenter', 'syscall'):
                kernel['%s %s' % (ins.mnemonic, ins.op_str)] += 1
                continue
            if ins.mnemonic not in ('call', 'jmp') or not ins.operands:
                continue
            op = ins.operands[0]
            if op.type == x86.X86_OP_IMM:
                t = op.imm & 0xFFFFFFFF
            elif op.type == x86.X86_OP_MEM and op.mem.base == 0 and op.mem.index == 0:
                t = m.u32(op.mem.disp & 0xFFFFFFFF)  # call *[abs] -- pointer in our data
                if t is None:
                    continue
            else:
                continue
            lib = next((l for l in libs if l.contains(t)), None)
            if lib:
                hits.append((t, lib))
            elif not m.read(t, 1):
                unresolved[hex(t)] += 1
    return hits, unresolved, kernel, ninsn


def objc(m):
    ptrs = lambda s: [m.u32(s['addr'] + 4 * i) for i in range(s['size'] // 4)] if s else []
    sels = [m.cstr_at(p) for p in ptrs(m.section('__OBJC', '__message_refs'))]
    cls_refs = [m.cstr_at(p) for p in ptrs(m.section('__OBJC', '__cls_refs'))]
    classes = []
    s = m.section('__OBJC', '__class')
    for off in range(0, s['size'] if s else 0, 40):  # objc_class is 10 words on NeXTSTEP 3
        classes.append(m.cstr_at(m.u32(s['addr'] + off + 8)))
    return dict(classes=classes, class_refs=sorted(set(cls_refs)), selectors=sorted(set(sels)))


def survey(path, shlib_dir):
    sl = dict(slices(open(path, 'rb').read()))
    if 'i386' not in sl:
        raise SystemExit('no i386 slice (arches: %s)' % ', '.join(sl))
    m = MachO(sl['i386'])
    libs = load_shlibs(m, shlib_dir)
    hits, unresolved, kernel, ninsn = _external_targets(m, libs)
    calls = collections.Counter((lib.name, lib.resolve(t)) for t, lib in hits)
    return dict(file=path, instructions=ninsn, fvmlibs=[l['name'] for l in m.fvmlibs],
                imports={'%s:%s' % k: v for k, v in sorted(calls.items())},
                unresolved=dict(unresolved), kernel=dict(kernel), objc=objc(m))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('binary')
    ap.add_argument('--shlibs', required=True)
    ap.add_argument('--json')
    a = ap.parse_args()
    r = survey(a.binary, a.shlibs)
    if a.json:
        json.dump(r, open(a.json, 'w'), indent=1)
    by_lib = collections.defaultdict(list)
    for k, v in r['imports'].items():
        lib, name = k.split(':', 1)
        by_lib[lib].append((v, name))
    print('%s: %d i386 instructions' % (r['file'], r['instructions']))
    for lib, items in by_lib.items():
        print('\n%s -- %d distinct, %d call sites' % (lib, len(items), sum(v for v, _ in items)))
        for v, name in sorted(items, key=lambda x: (-x[0], x[1])):
            print('  %5d  %s' % (v, name))
    o = r['objc']
    print('\nobjc: %d classes defined %s' % (len(o['classes']), o['classes']))
    print('objc: %d classes referenced %s' % (len(o['class_refs']), o['class_refs']))
    print('objc: %d selectors: %s' % (len(o['selectors']), ' '.join(o['selectors'])))
    print('\nkernel entries bypassing libsys: %s' % (r['kernel'] or 'none'))
    if r['unresolved']:
        print('unresolved external targets: %s' % r['unresolved'])


if __name__ == '__main__':
    main()
