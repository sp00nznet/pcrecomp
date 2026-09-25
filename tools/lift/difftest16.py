"""
difftest16.py -- does the lifted 16-bit C do what a 16-bit x86 does?

The 32-bit sibling of this file has existed for a while and has caught a steady
trickle of flag and carry bugs. The 16-bit lifter had no such check, and the
cost showed up in civ: a decoder change masked near-branch targets to 16 bits,
which is right when `pos` is a segment offset and wrong when a project decodes
a slice of a flat image, and every backwards call in the program silently
landed 0x10000 away. Nothing crashed. It just stopped drawing.

Same method as difftest.py. Run the same bytes twice -- once through Unicorn,
which is the reference for what an x86 does, once through this repo's lifter,
compiled and executed as C -- then compare every architectural field both
machines are supposed to agree on: the eight GPRs, the five arithmetic flags
each by name, and a hash of guest memory so a write to the wrong address is
caught too.

lift16's output does not carry the instruction address in its comment, so
instructions cannot be matched back to bytes the way difftest.py does it.
Instead the lifter is driven directly: decode the code, lift each instruction
on its own, and test that one statement.

    python tools/lift/difftest16.py --raw work/civ_decompressed.bin
    python tools/lift/difftest16.py --ne IR32.DLL --seg 7
    python tools/lift/difftest16.py --raw image.bin -k shl     # only these
    python tools/lift/difftest16.py --raw image.bin --keep     # keep the C

Two ways in, because 16-bit code arrives in two shapes: an NE segment, and a
flat real-mode image (a DOS dump, an unpacked EXE). Everything after the load
is the same.

Needs: unicorn, capstone (pip), and a C compiler (gcc/clang/cc, or $RECOMP_CC).
"""
import argparse
import os
import re
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, '..', '..'))
for p in (os.path.join(ROOT, 'tools', 'disasm'),
          os.path.join(ROOT, 'tools', 'ne'),
          HERE, ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

MEM_SIZE = 0x20000
CODE_AT = 0x30000
R16 = ['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di']
FLAGS = ['CF', 'ZF', 'SF', 'OF', 'PF']


# Which flags an instruction actually defines.
#
# Comparing a flag the architecture leaves undefined is how a differential
# tester manufactures findings: MUL and IMUL leave SF, ZF and PF undefined, so
# every multiply in the program "disagrees" with whatever Unicorn's host CPU
# happened to leave behind. Forty-three of the first seventy-five findings on
# civ were exactly that. A check nobody trusts is a check nobody runs, so the
# undefined ones are not compared -- and the ones below ARE compared, because
# for these the manual is explicit.
UNDEFINED = {
    # only CF and OF are defined; the rest is whatever the silicon leaves
    'mul': {'SF', 'ZF', 'PF'}, 'imul': {'SF', 'ZF', 'PF'},
    'div': set(FLAGS), 'idiv': set(FLAGS),
    # BCD: CF (and AF, which is not compared here) are defined; OF is not
    'daa': {'OF'}, 'das': {'OF'}, 'aaa': {'OF', 'SF', 'ZF', 'PF'},
    'aas': {'OF', 'SF', 'ZF', 'PF'}, 'aam': {'OF', 'CF'}, 'aad': {'OF', 'CF'},
    # bit tests define CF and nothing else
    'bt': set(FLAGS) - {'CF'}, 'bts': set(FLAGS) - {'CF'},
    'btr': set(FLAGS) - {'CF'}, 'btc': set(FLAGS) - {'CF'},
}
# Shifts and rotates define OF only for a count of exactly 1. A `, cl` form's
# count is not known until it runs, so OF is not compared there.
SHIFTS = ('shl', 'shr', 'sal', 'sar', 'rol', 'ror', 'rcl', 'rcr')


def undefined_flags(text):
    """Flags this instruction is allowed to disagree on."""
    m = text.split()[0].lower()
    if m in UNDEFINED:
        return UNDEFINED[m]
    if m in SHIFTS:
        # `shl bx, 0x1` defines OF; `shl bx, cl` and `shl bx, 0x4` do not.
        return set() if text.rstrip().endswith(('0x1', ', 1')) else {'OF'}
    return set()


def rnd(state):
    state[0] = (state[0] * 1103515245 + 12345) & 0xFFFFFFFF
    return state[0]


def testable(stmt, text):
    """Can this one statement be run on its own and compared?

    Anything that transfers control, touches the stack, or calls into a
    project's runtime cannot: the reference executes one instruction against a
    bare machine, and there is nothing on the other side to call.
    """
    if any(k in stmt for k in ('goto', 'return', 'recomp_dispatch', 'abort',
                               'UNHANDLED', 'int_handler', 'push16', 'pop16',
                               'push32', 'pop32', 'dos_int')):
        return False
    # Any call into a host runtime: div0 helpers (named per project), lifted
    # functions, overlay entries. Matching the shape rather than listing each
    # project's spelling is what keeps this file generic.
    if re.search(r'\b(res_|far_|ovl|sub_)\w*\s*\(', stmt):
        return False
    if re.search(r'\w*div0\w*\s*\(', stmt):
        return False
    if re.search(r'cpu->(ds|es|fs|gs|ss|cs)\s*=', stmt):
        return False
    # A cs: override cannot be compared: the reference needs CS to carry the
    # high bits of the code address (16-bit IP is only 16 bits wide), while
    # this harness resolves every selector through SEG_OFF. The two read
    # different addresses by construction -- a property of the harness, not a
    # finding.
    if 'cs:' in text:
        return False
    if text.startswith(('rep', 'movs', 'stos', 'lods', 'scas', 'cmps', 'int',
                        'call', 'j', 'loop', 'ret', 'push', 'pop', 'lds',
                        'les', 'nop', 'in ', 'ins', 'out', 'hlt', 'iret', 'cli',
                        'sti', 'enter', 'leave')):
        return False
    return True


def load_code(a):
    """The bytes to test, from whichever shape this project keeps them in."""
    if a.ne:
        import ne_parse
        ne = ne_parse.parse_ne(a.ne)
        segs = [s for s in ne.code_segments if s.index == a.seg]
        if not segs:
            raise SystemExit(f'{a.ne}: no code segment {a.seg}')
        return bytes(segs[0].data)
    data = open(a.raw, 'rb').read()
    end = len(data) if a.length is None else a.offset + a.length
    return data[a.offset:end]


def collect(a):
    """Decode the code, lift each distinct instruction alone, keep the testable."""
    import decode16
    import lift16
    # A flat image is decoded as a slice, exactly as the projects that use one
    # do it -- so this tests the configuration they actually ship.
    if a.raw:
        decode16.WRAP_NEAR_TARGETS = False

    code = load_code(a)
    insns, off = [], 0
    while off < len(code):
        d = decode16.Decoder(code, 0)
        d.pos = off
        try:
            i = d.decode_one()
        except Exception:
            off += 1
            continue
        if i is None or i.length <= 0 or (i.mnemonic or '').lower() == 'db':
            off += 1
            continue
        insns.append(i)
        off += i.length

    lifter = lift16.Lifter()
    seen, tests = set(), []
    pat = re.compile(r'^\s*(.+?)\s*/\* (.+?) \*/\s*$')
    for i in insns:
        raw = code[i.address:i.address + i.length]
        if raw in seen:
            continue
        seen.add(raw)
        try:
            c = lifter.lift_function('probe', [i], i.address)
        except Exception:
            continue
        if isinstance(c, list):
            c = '\n'.join(c)
        for line in c.split('\n'):
            m = pat.match(line)
            if not m:
                continue
            stmt, text = m.group(1), m.group(2)
            if not stmt.endswith(';') and not stmt.endswith('}'):
                continue
            if testable(stmt, text) and (not a.filter or a.filter in text):
                tests.append((raw, stmt, text))
            break
    return tests


def reference(tests, vectors):
    """What a real 16-bit x86 does with each instruction, per Unicorn."""
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_16, UC_PROT_ALL
    from unicorn import x86_const as X
    REG = {n: getattr(X, 'UC_X86_REG_' + n.upper()) for n in R16}
    pattern = bytes(((i * 7 + 13) & 0xFF) for i in range(MEM_SIZE))

    rows = {}
    for t, (raw, _stmt, _text) in enumerate(tests):
        for v in range(vectors):
            st = [(t * 977 + v * 7919 + 1) & 0xFFFFFFFF]
            vals = {n: rnd(st) & 0xFFFF for n in R16}
            fl = rnd(st)
            uc = Uc(UC_ARCH_X86, UC_MODE_16)
            uc.mem_map(0, MEM_SIZE, UC_PROT_ALL)
            uc.mem_map(CODE_AT, 0x1000, UC_PROT_ALL)
            uc.mem_write(0, pattern)
            uc.mem_write(CODE_AT, raw + b'\xf4')
            for n in R16:
                uc.reg_write(REG[n], vals[n])
            # Data segments at zero so the offset IS the linear address, which
            # is what SEG_OFF gives on the other side. CS cannot be: in 16-bit
            # mode the fetch address is CS*16 + IP with IP only 16 bits wide,
            # so a code address of 0x30000 with CS=0 truncates to 0 and the
            # emulator executes the data pattern instead of the instruction.
            for s in ('ds', 'es', 'ss'):
                uc.reg_write(getattr(X, 'UC_X86_REG_' + s.upper()), 0)
            uc.reg_write(X.UC_X86_REG_CS, CODE_AT >> 4)
            uc.reg_write(X.UC_X86_REG_EFLAGS,
                         0x2 | (fl & 1) | ((fl >> 1 & 1) << 2)
                         | ((fl >> 2 & 1) << 6) | ((fl >> 3 & 1) << 7)
                         | ((fl >> 4 & 1) << 11))
            try:
                uc.emu_start(CODE_AT, CODE_AT + len(raw), count=1)
            except Exception:
                continue          # the reference refused it; nothing to compare
            e = uc.reg_read(X.UC_X86_REG_EFLAGS)
            mem = uc.mem_read(0, MEM_SIZE)
            crc = 0
            for o in range(0, MEM_SIZE, 4):
                crc = ((crc * 16777619) ^ struct.unpack_from('<I', mem, o)[0]) \
                      & 0xFFFFFFFF
            rows[(t, v)] = ([uc.reg_read(REG[n]) for n in R16],
                            [(e >> b) & 1 for b in (0, 6, 7, 11, 2)], crc)
    return rows


def compilers():
    """Every C compiler worth trying, best first."""
    import shutil
    if os.environ.get('RECOMP_CC'):
        return [os.environ['RECOMP_CC']]
    found = [shutil.which(n) for n in ('gcc', 'clang', 'cc')]
    # Not being on PATH is normal on Windows, where the compiler lives in an
    # environment you have to enter first.
    found += [g for g in (r'C:\msys64\mingw64\bin\clang.exe',
                          r'C:\msys64\mingw64\bin\gcc.exe',
                          r'C:\msys64\ucrt64\bin\gcc.exe',
                          r'C:\mingw64\bin\gcc.exe') if os.path.exists(g)]
    found = [c for c in found if c]
    if not found:
        raise SystemExit('no C compiler found: put gcc/clang on PATH or set RECOMP_CC')
    return found


def run_lifted(tests, workdir, vectors):
    """Build the lifted statements into a program and run it."""
    src = os.path.join(workdir, 'dt16_gen.c')
    exe = os.path.join(workdir, 'dt16_gen.exe')
    with open(src, 'w') as f:
        f.write(HEAD)
        for n, (_raw, stmt, text) in enumerate(tests):
            f.write('static void t%d(CPU *cpu) { %s }  /* %s */\n'
                    % (n, stmt, text.replace('*/', '* /')))
        f.write('\nstatic void (*const TESTS[])(CPU *) = {\n')
        f.write(''.join('    t%d,\n' % n for n in range(len(tests))))
        f.write('};\n')
        f.write(TAIL)

    include = os.path.join(ROOT, 'runtime')
    # An installed compiler is not a working one -- a broken MSYS2 gcc exits 1
    # with no diagnostic at all -- so take the first that produces a binary
    # rather than the first that exists.
    err = ''
    for cc in compilers():
        r = subprocess.run([cc, '-O0', '-g', '-w', '-I', include, src, '-o', exe],
                           capture_output=True, text=True)
        if r.returncode == 0:
            break
        err += f'--- {cc} exited {r.returncode}\n{r.stdout}{r.stderr}'
    else:
        raise SystemExit(f'no compiler could build the test:\n{err}')

    out = subprocess.run([exe, str(vectors)], capture_output=True, text=True)
    if out.returncode != 0:
        raise SystemExit(f'lifted program exited {out.returncode}:\n'
                         f'{out.stdout[-2000:]}{out.stderr}')
    rows = {}
    for line in out.stdout.splitlines():
        f = line.split()
        if len(f) != 12:
            continue
        t, v = int(f[0]), int(f[1])
        rows[(t, v)] = ([int(x, 16) for x in f[2:10]],
                        [int(c) for c in f[10]], int(f[11], 16))
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__.strip().split('\n')[0])
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument('--raw', help='flat real-mode image (DOS dump, unpacked EXE)')
    src.add_argument('--ne', help='NE executable; pick a 16-bit segment with --seg')
    ap.add_argument('--seg', type=int, default=1, help='NE code segment index')
    ap.add_argument('--offset', type=lambda s: int(s, 0), default=0)
    ap.add_argument('--length', type=lambda s: int(s, 0), default=None)
    ap.add_argument('-k', '--filter', help='only instructions whose text contains this')
    ap.add_argument('--vectors', type=int, default=2)
    ap.add_argument('--keep', action='store_true', help='keep the generated C')
    a = ap.parse_args()

    tests = collect(a)
    print(f'{len(tests)} distinct testable instructions')
    if not tests:
        return 0

    ref = reference(tests, a.vectors)
    workdir = tempfile.mkdtemp(prefix='dt16_')
    got = run_lifted(tests, workdir, a.vectors)

    bad, checked = {}, 0
    for key, (rregs, rflags, rcrc) in ref.items():
        if key not in got:
            continue
        checked += 1
        gregs, gflags, gcrc = got[key]
        skip = undefined_flags(tests[key[0]][2])
        why = [f'{n}={g:04X} want {r:04X}'
               for n, g, r in zip(R16, gregs, rregs) if g != r]
        why += [f'{n}={g} want {r}'
                for n, g, r in zip(FLAGS, gflags, rflags)
                if g != r and n not in skip]
        if gcrc != rcrc:
            why.append('memory differs')
        if why:
            bad.setdefault(tests[key[0]][2], set()).update(why)

    print(f'{checked} (instruction, vector) pairs compared against real x86')
    if not bad:
        print('all agree')
        if not a.keep:
            import shutil as sh
            sh.rmtree(workdir, ignore_errors=True)
        return 0
    print(f'\n{len(bad)} instructions disagree:\n')
    for text in sorted(bad):
        print(f'  {text}')
        for w in sorted(bad[text]):
            print(f'      {w}')
    print(f'\ngenerated C kept in {workdir}')
    return 1


HEAD = r'''/* AUTO-GENERATED by difftest16.py */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
/* Not MEM_SIZE: recomp16/cpu.h defines that as 1 MB + 64 K and its definition
 * wins, which made the fill loop run a megabyte into a 128 K array and take
 * the harness down before the first test. */
#define DT_MEM 0x20000
static unsigned char g_mem[DT_MEM];
/* every selector at zero, so the offset IS the address - which is what the
 * Unicorn side computes with all segment registers set to zero */
#define SEG_OFF(seg, off) ((uint32_t)(uint16_t)(off))
#include "recomp16/cpu.h"
'''

TAIL = r'''
static uint32_t rnd(uint32_t *s){ *s = (*s*1103515245u+12345u); return *s; }

int main(int argc, char **argv)
{
    unsigned nv = argc > 1 ? (unsigned)atoi(argv[1]) : 2;
    unsigned n = (unsigned)(sizeof TESTS / sizeof TESTS[0]);
    /* Unbuffered: if one test faults, the last line printed names it. With
     * buffering the whole run's output is lost and the crash says nothing. */
    setvbuf(stdout, NULL, _IONBF, 0);
    for (unsigned t = 0; t < n; t++) {
        for (unsigned v = 0; v < nv; v++) {
            uint32_t s = t*977u + v*7919u + 1u;
            CPU cpu; memset(&cpu, 0, sizeof cpu);
            cpu.mem = g_mem;
            cpu.ax = (uint16_t)rnd(&s); cpu.cx = (uint16_t)rnd(&s);
            cpu.dx = (uint16_t)rnd(&s); cpu.bx = (uint16_t)rnd(&s);
            cpu.sp = (uint16_t)rnd(&s); cpu.bp = (uint16_t)rnd(&s);
            cpu.si = (uint16_t)rnd(&s); cpu.di = (uint16_t)rnd(&s);
            uint32_t fl = rnd(&s);
            cpu.flags = 0x2
                      | ((fl    & 1))
                      | (((fl>>1)&1) << 2)
                      | (((fl>>2)&1) << 6)
                      | (((fl>>3)&1) << 7)
                      | (((fl>>4)&1) << 11);
            for (unsigned i = 0; i < DT_MEM; i++)
                g_mem[i] = (unsigned char)((i*7+13) & 0xFF);
            TESTS[t](&cpu);
            unsigned long crc = 0;
            for (unsigned i = 0; i < DT_MEM; i += 4) {
                unsigned long w = *(uint32_t *)(g_mem + i);
                crc = crc * 16777619ul ^ w;
            }
            printf("%u %u %04X %04X %04X %04X %04X %04X %04X %04X %u%u%u%u%u %08lX\n",
                   t, v, cpu.ax, cpu.cx, cpu.dx, cpu.bx, cpu.sp, cpu.bp,
                   cpu.si, cpu.di,
                   (cpu.flags>>0)&1, (cpu.flags>>6)&1, (cpu.flags>>7)&1,
                   (cpu.flags>>11)&1, (cpu.flags>>2)&1,
                   crc);
        }
    }
    return 0;
}
'''

if __name__ == '__main__':
    sys.exit(main())
