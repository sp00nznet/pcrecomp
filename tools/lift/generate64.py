#!/usr/bin/env python3
"""
generate64.py - drive lift64_cpu over a whole x86-64 PE and emit a build tree.

The 64-bit sibling of generate.py. Given the executable and a function catalog,
writes chunked translation units, the declarations header, and the dispatch
table that turns a guest address into a call.

Two things it does NOT do, both deliberate:

  * It does not discover functions. generate.py scans for call targets and
    prologues because a stripped 32-bit binary gives it nothing else. A 64-bit
    PE looks like it does better - it carries .pdata, an unwind table - but
    measured against IDA on Star Wars Battle Pods that table is NOT a function
    list in either direction: it splits real functions into chunks (22,550
    entries here that are continuations, not entries) and omits every leaf that
    allocates no stack and calls nothing (37,767 functions IDA finds that it
    does not, median 12 bytes). So the catalog comes from a real disassembler
    and .pdata is used only to cross-check it.

  * It does not resolve imports in the lifter. A PE reaches its imports through
    the IAT - an indirect call through a data slot - so the boundary is drawn
    at load time instead, which catches every way an import can be reached and
    not just `call [__imp_X]`: the one-line thunks MSVC emits, a pointer copied
    out of the IAT and called later, and the vtables D3D and Wwise hand back.

    Where a 32-bit target needs a sentinel in each slot - the import has to be
    reimplemented, so it must be recognised when called - a 64-bit Windows
    guest on a 64-bit Windows host does not. The calling convention on both
    sides is the same one, so the loader puts the REAL function address in the
    slot and forwards the call. The map emitted here is for diagnostics: it is
    what turns an address in a crash trail back into KERNEL32!CreateFileW.

This file also closes the catalog; see the note in main().

Usage:
  py -3.11 generate64.py <game.exe> <funcs.txt> <outdir> [--split N]
"""

import bisect
import json
import os
import re
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import lift64_cpu
from lift64_cpu import Lifter, load_bounds

# Sentinel addresses for imports. Chosen far above any plausible image (this one
# loads at 0x140000000 and is 34 MB) and far below the 64-bit heap, so a
# sentinel arriving at dispatch() can only have come out of an IAT slot.
# The stride is 8 because an x64 IAT slot is a pointer.
HLE_BASE = 0x0000E5E30000
HLE_STRIDE = 8


def read_pe(path):
    data = open(path, 'rb').read()
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    nsec = struct.unpack_from('<H', data, pe + 6)[0]
    optsz = struct.unpack_from('<H', data, pe + 20)[0]
    magic = struct.unpack_from('<H', data, pe + 24)[0]
    if magic != 0x20b:
        raise SystemExit('not a PE32+ image (optional header magic %#x)' % magic)
    opt = pe + 24
    base = struct.unpack_from('<Q', data, opt + 24)[0]
    soi = struct.unpack_from('<I', data, opt + 56)[0]
    entry = struct.unpack_from('<I', data, opt + 16)[0]
    secs = []
    off = opt + optsz
    for i in range(nsec):
        n, vs, va, rs, ra = struct.unpack_from('<8sIIII', data, off + i * 40)
        secs.append((n.rstrip(b'\0').decode(), va, vs, ra, rs))
    # data directory 1 is the import table; 12 is the IAT
    ddoff = opt + 112
    imp_rva, imp_sz = struct.unpack_from('<II', data, ddoff + 8)
    reloc_rva, reloc_sz = struct.unpack_from('<II', data, ddoff + 5 * 8)
    return data, base, soi, entry, secs, imp_rva, reloc_rva, reloc_sz


def make_reader(data, base, secs):
    def read_va(va, n):
        for (nm, vsa, vs, ra, rs) in secs:
            lo = base + vsa
            if lo <= va < lo + max(vs, rs):
                off = ra + (va - lo)
                return data[off:off + n]
        raise KeyError('va %#x not mapped' % va)
    return read_va


def rva_to_off(secs, rva):
    for (nm, vsa, vs, ra, rs) in secs:
        if vsa <= rva < vsa + max(vs, rs):
            return ra + (rva - vsa)
    return None


def parse_imports(data, base, secs, imp_rva):
    """{IAT slot VA: (dll, name)} for every import.

    Walks the FirstThunk array, because that is the one the loader overwrites
    and therefore the one whose addresses the code actually calls. The
    OriginalFirstThunk array holds the same names but is not what a `call
    [__imp_X]` reaches.
    """
    out = {}
    o = rva_to_off(secs, imp_rva)
    if o is None:
        return out
    while True:
        oft, ts, fc, nm, fta = struct.unpack_from('<IIIII', data, o)
        if nm == 0 and fta == 0:
            break
        no = rva_to_off(secs, nm)
        dll = data[no:data.index(b'\0', no)].decode('ascii', 'replace')
        names_rva = oft or fta
        nt = rva_to_off(secs, names_rva)
        slot = base + fta
        while True:
            v = struct.unpack_from('<Q', data, nt)[0]
            if v == 0:
                break
            if v & (1 << 63):
                fn = '#%d' % (v & 0xFFFF)
            else:
                so = rva_to_off(secs, v & 0x7FFFFFFF)
                fn = data[so + 2:data.index(b'\0', so + 2)].decode('ascii', 'replace')
            out[slot] = (dll, fn)
            slot += 8
            nt += 8
        o += 20
    return out


def reloc_code_pointers(data, base, secs, reloc_rva, reloc_sz, text_lo, text_hi):
    """Addresses in .text that some relocated qword points at.

    A disassembler finds functions by following calls and recognising
    prologues, and it therefore misses any function that is ONLY ever reached
    through a pointer - a virtual method in a vtable, a callback in a static
    table, a jump table of function pointers. IDA missed 0x140B2D770 in Battle
    Pods exactly this way: sixteen bytes sitting in a gap between two
    catalogued functions, called through a vtable a million dispatches in.

    The .reloc table settles it without heuristics. In a 64-bit PE every
    absolute address stored in the image has a DIR64 relocation, because the
    loader must fix it up if the image moves - so the relocations ARE the
    complete list of stored pointers. The ones whose value lands in .text are
    stored code pointers, and a stored code pointer is a function entry.
    Guessing from alignment or from a `48 89 5C 24` prologue would find most of
    them and invent others; this finds exactly the real ones.
    """
    out = set()
    if not reloc_rva:
        return out
    off = rva_to_off(secs, reloc_rva)
    if off is None:
        return out
    end = off + reloc_sz
    while off < end:
        va_page, blk = struct.unpack_from('<II', data, off)
        if not blk:
            break
        for i in range((blk - 8) // 2):
            ent = struct.unpack_from('<H', data, off + 8 + i * 2)[0]
            if (ent >> 12) != 10:            # IMAGE_REL_BASED_DIR64
                continue
            slot = rva_to_off(secs, va_page + (ent & 0xFFF))
            if slot is None or slot + 8 > len(data):
                continue
            v = struct.unpack_from('<Q', data, slot)[0]
            if text_lo <= v < text_hi:
                out.add(v)
        off += blk
    return out


def jmp_thunks(data, base, secs, text_lo, text_hi):
    """Aligned one-instruction `jmp rel32` stubs, padded with int3 either side.

    MSVC emits these for incremental linking and for identical-code folding,
    and a C++ vtable slot points at the STUB rather than at the function. They
    are not reached by any direct call, so the catalog closure never sees them;
    a disassembler usually marks them, but not always - this image has 396 and
    IDA named 392.

    The four it missed are the kind of gap that only shows up when a particular
    subsystem runs: 0x140D236A0 is reached the first time the I/O library is
    asked for a board, and before that nothing in the program had ever needed
    it. One aborts the process with "call into uncatalogued guest code".
    """
    found = set()
    for name, va, size in ((s[0], base + s[1], s[2]) for s in secs):
        if name != '.text':
            continue
        off = rva_to_off(secs, va - base)
        if off is None:
            continue
        for i in range(0, size - 16, 16):
            p = off + i
            # 0xE9 rel32, preceded and followed by padding: a lone thunk, not
            # the tail of a real function that happens to end in a jump.
            if data[p] != 0xE9 or data[p - 1] != 0xCC or data[p + 5] != 0xCC:
                continue
            t = va + i + 5 + struct.unpack_from('<i', data, p + 1)[0]
            if text_lo <= t < text_hi:
                found.add(va + i)
    return found


_CODE_MD = None


def plausible_code(read_va, va):
    """Does this address look like the start of a function rather than data?

    A rip-relative lea into .text is as often a jump table, a string, or a
    constant pool as it is a function pointer, and adding the data ones costs a
    translation unit each and lifts garbage. Requiring a few instructions to
    decode, with no int3 or privileged instruction among them, separates the
    two cheaply - a real entry always begins with a prologue or a load.
    """
    global _CODE_MD
    if _CODE_MD is None:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64
        _CODE_MD = Cs(CS_ARCH_X86, CS_MODE_64)
    try:
        code = read_va(va, 16)
    except Exception:
        return False
    n = 0
    for ins in _CODE_MD.disasm(code, va):
        if ins.mnemonic in ('int3', 'in', 'out', 'hlt', 'iretd', 'iretq',
                            'cli', 'sti', 'lock', 'salc', 'bound'):
            return False
        n += 1
        if n >= 3:
            return True
    return False


def eh_tables(data, base, secs):
    """Function starts that had a C++ try/catch, and the catch funclets.

    The lifted body of such a function needs a landing pad (see lift64_cpu's
    has_eh and runtime eh64.c), and the funclets are entries no disassembler
    finds by following control flow: nothing CALLS them, .xdata names them.
    """
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    dd = pe + 0x18 + 0x70 + 3 * 8
    pd_rva, pd_size = struct.unpack_from('<II', data, dd)
    if not pd_rva or not pd_size:
        return frozenset(), frozenset()
    off = rva_to_off(secs, pd_rva)
    starts, handlers = set(), set()

    def u32(rva):
        o = rva_to_off(secs, rva)
        return struct.unpack_from('<I', data, o)[0] if o is not None else 0

    for i in range(pd_size // 12):
        begin, end, unwind = struct.unpack_from('<III', data, off + 12 * i)
        seen = 0
        while unwind and seen < 8:
            seen += 1
            uo = rva_to_off(secs, unwind)
            if uo is None:
                break
            ver_flags = data[uo]
            ncodes = data[uo + 2]
            tail = unwind + 4 + ((ncodes + 1) & ~1) * 2
            if ver_flags & 0x20:                       # UNW_FLAG_CHAININFO
                unwind = u32(tail + 8)
                continue
            if not (ver_flags & 0x08):                 # UNW_FLAG_EHANDLER
                break
            fi = u32(tail + 4)
            if not fi:
                break
            fo = rva_to_off(secs, fi)
            if fo is None:
                break
            magic, _max, _um, ntry, trymap = struct.unpack_from('<IiiiI', data, fo)
            # 0x1993052x is MSVC's; any other personality routine keeps its own
            # shape behind that pointer and is not ours to read.
            if magic & 0xfffffff0 != 0x19930520:
                break
            starts.add(base + begin)
            to = rva_to_off(secs, trymap)
            if to is None or ntry <= 0 or ntry > 4096:
                break
            for t in range(ntry):
                _lo, _hi, _ch, nc, ha = struct.unpack_from('<iiiiI', data, to + 20 * t)
                ho = rva_to_off(secs, ha)
                if ho is None or nc <= 0 or nc > 256:
                    continue
                for k in range(nc):
                    hv = struct.unpack_from('<I', data, ho + 20 * k + 12)[0]
                    if hv:
                        handlers.add(base + hv)
            break
    return frozenset(starts), frozenset(handlers)


def main():
    argv = sys.argv[1:]
    split = 400
    if '--split' in argv:
        i = argv.index('--split')
        split = int(argv[i + 1])
        del argv[i:i + 2]
    if len(argv) < 3:
        print(__doc__)
        raise SystemExit(2)
    exe_path, funcs_path, outdir = argv[0], argv[1], argv[2]
    os.makedirs(outdir, exist_ok=True)

    data, base, soi, entry, secs, imp_rva, reloc_rva, reloc_sz = read_pe(exe_path)
    lift64_cpu.IMAGE_BASE = base
    read_va = make_reader(data, base, secs)
    lf = Lifter(image_size=soi, read_va=read_va, image_base=base)

    bounds = load_bounds(funcs_path)
    iat = parse_imports(data, base, secs, imp_rva)

    print('[*] image base %#x, entry %#x, %d sections' % (base, base + entry, len(secs)))
    print('[*] catalog: %d functions' % len(bounds))
    print('[*] imports: %d IAT slots' % len(iat))

    # ---- close the catalog ----
    #
    # A catalog of function ENTRIES is not closed under the addresses the code
    # actually jumps to. An optimising compiler tail-jumps into the middle of a
    # function it shares an epilogue with, and a switch arm can be any
    # instruction at all; both produce a `dispatch(c, 0x...)` to an address that
    # is inside .text and is not an entry, and at runtime that is a hard stop -
    # the dispatch table cannot enter a function body part-way through.
    #
    # Battle Pods hits this 1.75 million dispatches in, tail-jumping to
    # 0x140BA97D5, which sits 0x75 bytes inside the catalogued function at
    # 0x140BA9760.
    #
    # So: lift, read back every literal target the generated text dispatches to,
    # add the ones that are not catalogued as entries of their own, and repeat
    # until nothing new appears. The new entry overlaps the function containing
    # it and that is fine - the same bytes lift to the same code twice under two
    # extents, and only the entry that is dispatched to is ever called.
    DISPATCH_RE = re.compile(r'dispatch(?:_jmp)?\(c, 0x([0-9A-Fa-f]+)ull\)')

    def lift_one(va):
        size, name = bounds[va]
        fname = 'L_%012X' % va
        try:
            return lf.lift_function(read_va(va, size), va, name=fname)
        except Exception as e:
            return ('/* ERROR %s at %#x: %s */\n'
                    'void %s(CPU *c) { (void)c; RECOMP_TODO(%#x, "lift error"); }'
                    % (name, va, e, fname, va))

    text_lo = base + [s for s in secs if s[0] == '.text'][0][1]
    text_hi = text_lo + [s for s in secs if s[0] == '.text'][0][2]

    # Stored code pointers first: these are entries the disassembler could not
    # have found, and adding them before the closure loop means their own
    # dispatch targets get closed over too.
    ptrs = reloc_code_pointers(data, base, secs, reloc_rva, reloc_sz,
                               text_lo, text_hi)
    starts = sorted(bounds)
    added_ptr = 0
    for t in sorted(ptrs):
        if t in bounds:
            continue
        i = bisect.bisect_right(starts, t)
        end_of = starts[i] if i < len(starts) else text_hi
        size = min(end_of - t, 0x10000)
        if size > 0:
            bounds[t] = (size, 'sub_%X_ptr' % t)
            added_ptr += 1
    if added_ptr:
        print('[*] %d stored code pointers were not in the catalog (%d relocated '
              'pointers into .text)' % (added_ptr, len(ptrs)))

    # Lone jump thunks: a vtable slot points at the stub, not the function, and
    # nothing calls the stub directly so the closure below never reaches it.
    thunks = jmp_thunks(data, base, secs, text_lo, text_hi)
    starts = sorted(bounds)
    added_thunk = 0
    for t in sorted(thunks):
        if t in bounds:
            continue
        bounds[t] = (5, 'sub_%X_thunk' % t)
        added_thunk += 1
    if added_thunk:
        print('[*] %d of %d jump thunks were not in the catalog'
              % (added_thunk, len(thunks)))

    # C++ exception handling. The funclets go in as entries, and the functions
    # that had handlers are marked so the lifter gives them a landing pad.
    eh_starts, eh_handlers = eh_tables(data, base, secs)
    lf.eh_funcs = eh_starts
    starts = sorted(bounds)
    added_eh = 0
    for t in sorted(eh_handlers):
        if t in bounds:
            continue
        i = bisect.bisect_right(starts, t)
        end_of = starts[i] if i < len(starts) else text_hi
        size = min(end_of - t, 0x10000)
        if size > 0:
            bounds[t] = (size, 'sub_%X_catch' % t)
            added_eh += 1
    if eh_starts:
        print('[*] C++ EH: %d functions with handlers, %d catch funclets '
              '(%d new entries)' % (len(eh_starts), len(eh_handlers), added_eh))

    bodies = {}
    pending = sorted(bounds)
    rounds = 0
    added_total = 0
    t0 = time.time()
    while pending and rounds < 16:
        rounds += 1
        targets = set()
        for va in pending:
            body = lift_one(va)
            bodies[va] = body
            for m in DISPATCH_RE.finditer(body):
                targets.add(int(m.group(1), 16))
        # Addresses the round's code TOOK rather than called. An entry found
        # this way is a callback the disassembler had no path to: it is called
        # only through the pointer, so nothing in .text names it and, because
        # the address is computed with a rip-relative lea rather than stored,
        # .reloc does not either. Filtered to what actually decodes as code,
        # since a lea into .text is just as often a jump table or a literal.
        for t in lf.lea_targets:
            if text_lo <= t < text_hi and t not in bounds and plausible_code(read_va, t):
                targets.add(t)
        lf.lea_targets.clear()

        known = set(bounds)
        starts = sorted(known)
        new = []
        for t in sorted(targets):
            if t in known or not (text_lo <= t < text_hi):
                continue
            # Extent runs to the next catalogued start, capped: an entry carved
            # out of the middle of a function ends where the next one begins.
            i = bisect.bisect_right(starts, t)
            end = starts[i] if i < len(starts) else text_hi
            size = min(end - t, 0x10000)
            if size <= 0:
                continue
            bounds[t] = (size, 'sub_%X_split' % t)
            new.append(t)
        if not new:
            break
        added_total += len(new)
        print('[*] closure round %d: +%d dispatch targets not in the catalog'
              % (rounds, len(new)), flush=True)
        pending = new

    if added_total:
        print('[*] catalog closed after %d rounds, %d entries added (%d total)'
              % (rounds, added_total, len(bounds)))

    entries = []
    chunk = []
    file_idx = 0
    nerr = 0
    ntodo = 0

    def flush():
        nonlocal file_idx, chunk
        if not chunk:
            return
        p = os.path.join(outdir, 'recomp_funcs_%04d.c' % file_idx)
        with open(p, 'w') as f:
            f.write('/* generated by generate64.py - do not edit */\n')
            f.write('#include "cpu64.h"\n')
            f.write('#include "recomp_funcs.h"\n\n')
            f.write('\n\n'.join(chunk))
            f.write('\n')
        file_idx += 1
        chunk = []

    for va in sorted(bounds):
        size, name = bounds[va]
        if size <= 0:
            continue
        fname = 'L_%012X' % va
        body = bodies.get(va)
        if body is None:
            body = lift_one(va)
        if body.startswith('/* ERROR'):
            nerr += 1
        ntodo += body.count('RECOMP_TODO(')
        chunk.append(body)
        entries.append((va, fname, name))
        if len(chunk) >= split:
            flush()
            if file_idx % 25 == 0:
                el = time.time() - t0
                print('[*] %d/%d functions (%d files, %.0f/s)'
                      % (len(entries), len(bounds), file_idx,
                         len(entries) / max(el, 1e-6)), flush=True)
    flush()

    with open(os.path.join(outdir, 'recomp_funcs.h'), 'w') as f:
        f.write('#pragma once\n#include "cpu64.h"\n\n')
        f.write('/* %d recompiled functions */\n\n' % len(entries))
        for va, fname, orig in entries:
            f.write('void %s(CPU *c);  /* %#x %s */\n' % (fname, va, orig))

    with open(os.path.join(outdir, 'recomp_dispatch.c'), 'w') as f:
        f.write('/* generated by generate64.py - do not edit */\n')
        f.write('#include "cpu64.h"\n#include "recomp_funcs.h"\n')
        f.write('#include "recomp_dispatch.h"\n\n')
        f.write('const recomp_entry_t recomp_dispatch_table[] = {\n')
        for va, fname, orig in entries:
            f.write('    { 0x%Xull, %s },\n' % (va, fname))
        f.write('};\n\n')
        f.write('const uint32_t recomp_dispatch_count = %d;\n' % len(entries))

    with open(os.path.join(outdir, 'recomp_dispatch.h'), 'w') as f:
        f.write('#pragma once\n#include "cpu64.h"\n\n')
        f.write('typedef struct { uint64_t va; void (*fn)(CPU *); } recomp_entry_t;\n')
        f.write('extern const recomp_entry_t recomp_dispatch_table[];\n')
        f.write('extern const uint32_t recomp_dispatch_count;\n\n')
        f.write('/* Import boundary. The loader writes HLE_SENTINEL(i) into IAT\n'
                ' * slot i; dispatch() routes that range to the HLE layer. */\n')
        f.write('#define HLE_BASE   0x%Xull\n' % HLE_BASE)
        f.write('#define HLE_STRIDE %d\n' % HLE_STRIDE)
        f.write('#define HLE_COUNT  %d\n' % len(iat))
        f.write('#define HLE_SENTINEL(i) (HLE_BASE + (uint64_t)(i) * HLE_STRIDE)\n\n')
        f.write('typedef struct { uint64_t slot; const char *dll; const char *name; } hle_import_t;\n')
        f.write('extern const hle_import_t recomp_imports[];\n')

    with open(os.path.join(outdir, 'recomp_imports.c'), 'w') as f:
        f.write('/* generated by generate64.py - do not edit */\n')
        f.write('#include "recomp_dispatch.h"\n\n')
        f.write('const hle_import_t recomp_imports[] = {\n')
        for i, (slot, (dll, nm)) in enumerate(sorted(iat.items())):
            f.write('    { 0x%Xull, "%s", "%s" },\n' % (slot, dll, nm))
        f.write('};\n')

    meta = {
        'image_base': base,
        'entry_point': base + entry,
        'size_of_image': soi,
        'functions': len(entries),
        'translation_units': file_idx,
        'lift_errors': nerr,
        'recomp_todo_sites': ntodo,
        'imports': len(iat),
    }
    with open(os.path.join(outdir, 'recomp_meta.json'), 'w') as f:
        json.dump(meta, f, indent=2)

    el = time.time() - t0
    print()
    print('[*] === COMPLETE in %.0fs ===' % el)
    for k, v in meta.items():
        print('[*] %-20s %s' % (k, hex(v) if 'base' in k or 'entry' in k else v))


if __name__ == '__main__':
    main()
