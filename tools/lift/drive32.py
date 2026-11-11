"""drive32.py - lift one 32-bit PE image from its catalog: the loop every
project's run_lift.py used to carry its own copy of.

    from drive32 import lift_image
    stats, entries = lift_image('work/rebased/core.dll', 'work/core.dll.functions.json',
                                'src/recomp/gen/core', seeds=[0x10401234])

It does what the per-project drivers had grown, in one place:

  - every catalogued function (plus `seeds`) is a dispatchable entry;
  - find_splits: a start that is the middle of the function before it stays
    dispatchable but does not cut that function short;
  - C++ catch resume points (eh32.resume_points) are roots of their parent's
    body and labels in it, not functions of their own (ut99, Bully);
  - an entry whose code another body already lifts (a catalog alias, a split,
    a start the walk before it fell into) is a stub that enters that body
    through its local dispatch (generate.alias_stub), not a second copy of the
    rest of the body. Rise of Legends had this first; Sambar Server's 20 KB
    config parser with ~50 aliases made it an 84 MB C file and a compiler
    that ran for an hour without it. A stub is only written when the host
    body really has a case for it, else the entry is lifted as a copy (the
    stub would otherwise recurse through the host's default dispatch);
  - a body whose indirect jumps are all jump tables (`jmp [reg*4 + table]`)
    labels only the table's arms, not every instruction: the local dispatch
    switch of Sambar's config parser went from 8,018 cases to 155 (its
    table's arms and its alias entries) and the function from 29k lines of C
    to 14.6k. Any other indirect jump keeps the label-everything fallback;
  - a direct branch or call to an address nothing catalogued is lifted too, in
    rounds, until no target is new.

Returns (stats dict, sorted entry VAs). The caller writes the dispatch table
over all of its modules (one image or several, rebased: tools/pe/rebase.py).
"""
import os
import re
import shutil
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
import pefile

from generate import (EXTENT_REACH, alias_stub, find_splits, true_extent,
                      linear_disassemble_function, lift_function_linear, write_chunk)
from lift32 import Lifter
from eh32 import resume_points
from pe_analyze import analyze_pe, build_iat_map

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'disasm'))
from disasm32 import _TABLE_JMP, table_entries   # noqa: E402  the arms recursive descent follows


def lift_image(img, catalog, out, seeds=(), split=400, log=print, precise_carry=True):
    import json
    info = analyze_pe(img)
    iat = build_iat_map(info)
    cs, ce = info.code_start, info.code_end
    log('[*] %s base=0x%08X code=0x%08X-0x%08X IAT=%d'
        % (os.path.basename(img), info.image_base, cs, ce, len(iat)))
    byaddr = {f['address']: f for f in json.load(open(catalog))['functions'] if cs <= f['address'] < ce}
    for a in set(seeds) - set(byaddr):
        if cs <= a < ce:
            byaddr[a] = {'address': a, 'entry_kind': 'start'}

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    text = [s for s in info.sections if s.name == '.text'][0]
    code = open(img, 'rb').read()[text.raw_offset:text.raw_offset + text.raw_size]
    mapped = pefile.PE(img).get_memory_mapped_image()
    base = info.image_base
    read = lambda va, n: mapped[va - base:va - base + n] if 0 <= va - base < len(mapped) else None  # noqa: E731
    # precise carry: adc/sbb take their carry from the flag state that set it
    # (64-bit adds and subtracts; ra2's run_lift.py has the history).
    lifter = Lifter(iat_map=iat, lifted=set(byaddr), precise_carry=precise_carry, precise_sbb=precise_carry)

    shutil.rmtree(out, ignore_errors=True)            # a smaller lift must not leave stale chunks
    os.makedirs(out)
    starts = {a for a in byaddr if byaddr[a].get('entry_kind') != 'alias'}
    starts -= find_splits(md, code, cs, ce, starts)
    eh_at = {}
    for a in byaddr:
        r = resume_points(md, read, list(md.disasm(read(a, 64) or b'', a))[:12])
        if r:
            eh_at[a] = r
    starts -= set().union(*eh_at.values()) if eh_at else set()

    def walk(addr):
        reached, behind, called = set(), set(), set()
        end, clean = true_extent(md, code, cs, addr, min(addr + EXTENT_REACH, ce), starts,
                                 reached=reached, behind=behind, called=called)
        for r in eh_at.get(addr, ()):
            if cs <= r < ce:
                e2, _ = true_extent(md, code, cs, r, min(r + EXTENT_REACH, ce), starts,
                                    reached=reached, behind=behind, called=called)
                end = max(end, e2)
        return end, clean, reached, {t for t in behind if t not in reached} | called

    def jump_tables(insns):
        """Every local target of the body's indirect jumps, or None when one
        of them is not a plain jump table (then every instruction is a label)."""
        out = set()
        for i in insns:
            if i.is_uncond_jump and i.get_branch_target() is None:
                m = _TABLE_JMP.search(i.op_str)
                if not m:
                    return None
                arms = table_entries(read, int(m.group(1), 16), lambda v: cs <= v < ce)
                if not arms:
                    return None
                out |= set(arms)
        return out

    st = {'lifted': 0, 'alias_stubs': 0, 'added': 0, 'errors': 0, 'no_terminator': 0,
          'catch': 0, 'unimplemented': {}}
    bodies, entries = {}, []

    def lift(addr, w, aliases=None):
        name = 'sub_%08X' % addr
        end, clean, reached, _ = w
        st['no_terminator'] += not clean
        try:
            lo = min(reached) if reached else addr
            insns, leaders = (linear_disassemble_function(md, code, cs, lo, end, reached=reached)
                              if end > addr else ([], None))
            if leaders is not None:
                leaders.add(addr)
            ind = jump_tables(insns)
            if ind is not None and leaders is not None:
                leaders |= ind & {i.address for i in insns}
            eh = eh_at.get(addr)
            st['catch'] += bool(eh)
            body = (lift_function_linear(lifter, name, insns, leaders, addr, eh_resume=eh,
                                         alias_entries=aliases, indirect_targets=ind) if insns
                    else 'void %s(void) { }\n' % name)
        except Exception as e:                      # noqa: BLE001 -- counted, not hidden
            body = '/* ERROR %s: %s */\nvoid %s(void) { }\n' % (name, e, name)
            st['errors'] += 1
        for m in re.findall(r'UNIMPLEMENTED: (\w+)', body):
            st['unimplemented'][m] = st['unimplemented'].get(m, 0) + 1
        bodies[addr] = body
        st['lifted'] += 1

    # Round 1: walk every real start and record which body owns each
    # instruction, so an entry inside another body becomes a stub into it.
    walked, owner = {}, {}
    for a in sorted(a for a in byaddr if a in starts):
        walked[a] = walk(a)
        for va in walked[a][2]:
            owner.setdefault(va, a)

    def host(a):
        o = owner.get(a)
        return o if o is not None and o != a and owner.get(o) == o else None

    inside = {}
    for a in byaddr:
        if host(a) is not None:
            inside.setdefault(host(a), []).append(a)
    outside = set()
    for a in sorted(byaddr):
        if host(a) is None:
            w = walked.pop(a, None) or walk(a)
            outside |= w[3]
            lift(a, w, inside.get(a))
    for a in sorted(byaddr):
        h = host(a)
        if h is None:
            continue
        if 'case 0x%08Xu:' % a in bodies.get(h, ''):
            bodies[a] = alias_stub('sub_%08X' % a, a, 'sub_%08X' % h)
            st['alias_stubs'] += 1
        else:                                       # the host has no label there: a copy
            w = walk(a)
            outside |= w[3]
            lift(a, w)
    # Later rounds: targets outside the catalog, lifted as their own bodies.
    todo = sorted(t for t in outside if cs <= t < ce and t not in bodies)
    while todo:
        outside = set()
        for t in todo:
            lifter.lifted.add(t)
            w = walk(t)
            outside |= w[3]
            lift(t, w)
        st['added'] += len(todo)
        todo = sorted(t for t in outside if cs <= t < ce and t not in bodies)

    entries = sorted(bodies)
    files = 0
    for i in range(0, len(entries), split):
        write_chunk(out, files, [(bodies[a], a, 'sub_%08X' % a) for a in entries[i:i + split]])
        files += 1
    st['files'] = files
    log('    %s: %d entries: %d lifted (+%d outside the catalog), %d alias stubs, errors %d, '
        'no terminator %d, %d catch, %d files'
        % (os.path.basename(img), len(entries), st['lifted'], st['added'], st['alias_stubs'],
           st['errors'], st['no_terminator'], st['catch'], files))
    if st['unimplemented']:
        log('      unimplemented: ' + ' '.join('%s %d' % kv for kv in sorted(st['unimplemented'].items(),
                                                                          key=lambda kv: -kv[1])))
    return st, entries
