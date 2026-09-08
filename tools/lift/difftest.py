"""
difftest.py -- does the lifted C do what the CPU does?

Every semantics bug this lifter has shipped was found the same way: play the
game, watch something be subtly wrong, bisect backwards to an instruction. A
flag derived at the wrong width or a carry read from the wrong place does not
crash -- it returns a plausible number, and the cost is a debugging session.

So: run the same bytes twice. Once through Unicorn, which is the reference for
what an x86 does. Once through this repo's lifter, compiled and executed as C.
Then compare every architectural field both machines are supposed to agree on
and name each one that differs -- the eight GPRs, the six arithmetic flags
(each by name, not as a word, so a report says ZF rather than "flags"), DF,
and every byte of guest memory either machine wrote.

The flags are the interesting half. The lifter's model is lazy: an instruction
records its operands and kind, and each flag is derived when something asks.
recomp_eflags() is that derivation done all at once, so comparing it against
hardware EFLAGS tests the whole model, not one condition at a time.

    python tools/lift/difftest.py            # run every case
    python tools/lift/difftest.py -k shift   # only cases matching a substring
    python tools/lift/difftest.py --keep     # leave the generated C behind

Needs: unicorn, capstone (pip), and a C compiler (gcc/clang/cc, or $RECOMP_CC).
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
from unicorn import x86_const as X

from tools.lift.lift32 import Lifter

# One guest window, shared by both machines: code at the bottom, a scratch page
# for memory operands, a stack in the middle. Small enough that comparing every
# byte of it after each case is free.
BASE    = 0x00400000
SIZE    = 0x00040000
SCRATCH = BASE + 0x10000
STACK   = BASE + 0x20000

# EFLAGS bit 1 reads as 1 on every x86 and IF is set in any user-mode process;
# both machines start there so a comparison is not measuring the start state.
EFLAGS_START = 0x202

# The flags both models claim to represent, by name and bit.
FLAGS = (('CF', 0), ('PF', 2), ('AF', 4), ('ZF', 6), ('SF', 7), ('DF', 10), ('OF', 11))

REGS = ('eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi')
UC_REGS = {
    'eax': X.UC_X86_REG_EAX, 'ecx': X.UC_X86_REG_ECX, 'edx': X.UC_X86_REG_EDX,
    'ebx': X.UC_X86_REG_EBX, 'esp': X.UC_X86_REG_ESP, 'ebp': X.UC_X86_REG_EBP,
    'esi': X.UC_X86_REG_ESI, 'edi': X.UC_X86_REG_EDI,
}

DEFAULT_REGS = {
    'eax': 0x00000010, 'ecx': 0x00000003, 'edx': 0x00000000, 'ebx': 0x00000080,
    'esp': STACK,      'ebp': 0x00000000, 'esi': SCRATCH,    'edi': SCRATCH + 0x100,
}


@dataclass
class Case:
    """Bytes to run, the state to run them from, and what not to compare.

    `undef` names flags the architecture leaves undefined for this instruction
    (a shift's OF for counts other than 1, the AF of a logic op). Hardware
    still puts something there; comparing it would be measuring one CPU's
    choice rather than a specification.

    `known` is different: the two machines really do disagree and we have
    decided to live with it. It names why, so the divergence reads as a
    documented ceiling instead of a failure everyone learns to scroll past --
    and if the case ever starts matching, the run says so and the note can go.
    """
    name: str
    code: bytes
    regs: dict = field(default_factory=dict)
    mem: dict = field(default_factory=dict)   # guest VA -> bytes
    undef: tuple = ()
    known: str = ''      # a divergence we know about and have chosen to keep

    def start_regs(self):
        r = dict(DEFAULT_REGS)
        r.update(self.regs)
        return r


WIDTH = ('the flag tuple stores what the operand read but not how wide it was, '
         'so every flag is derived at 32 bits. Fixing it needs a width in the '
         'tuple AND width-aware CMP_* macros at every statically paired jcc.')

CASES = [
    # --- the plain arithmetic the lazy tuple is built for ---
    Case('add', bytes.fromhex('01c8')),                       # add eax, ecx
    Case('add.carry-out', bytes.fromhex('01c8'), {'eax': 0xFFFFFFFF, 'ecx': 2}),
    Case('add.overflow', bytes.fromhex('01c8'), {'eax': 0x7FFFFFFF, 'ecx': 1}),
    Case('sub', bytes.fromhex('29c8')),                       # sub eax, ecx
    Case('sub.borrow', bytes.fromhex('29c8'), {'eax': 1, 'ecx': 2}),
    Case('cmp.equal', bytes.fromhex('39c8'), {'eax': 7, 'ecx': 7}),

    # --- AF: derived from the tuple, and previously not represented at all ---
    Case('add.aux-carry', bytes.fromhex('01c8'), {'eax': 0x0F, 'ecx': 0x01}),
    Case('sub.aux-borrow', bytes.fromhex('29c8'), {'eax': 0x10, 'ecx': 0x01}),

    # --- INC/DEC preserve CF; the tuple's kind has to say so ---
    Case('inc.preserves-cf', bytes.fromhex('f940')),          # stc; inc eax
    Case('dec.preserves-cf', bytes.fromhex('f948')),          # stc; dec eax

    # --- logic clears CF ---
    Case('and.clears-cf', bytes.fromhex('f921c8')),           # stc; and eax, ecx
    Case('xor.self', bytes.fromhex('f931c0')),                # stc; xor eax, eax
    Case('or', bytes.fromhex('09c8')),                        # or eax, ecx
    Case('test', bytes.fromhex('85c8')),                      # test eax, ecx

    # --- shifts: CF is the running _cf, not the tuple ---
    Case('shl', bytes.fromhex('c1e003'), undef=('OF', 'AF')),        # shl eax, 3
    Case('shl.carry-out', bytes.fromhex('c1e004'), {'eax': 0x10000000}, undef=('OF', 'AF')),
    Case('shr.1', bytes.fromhex('d1e8'), {'eax': 0x11}, undef=('AF',)),
    Case('sar', bytes.fromhex('c1f805'), {'eax': 0x80000000}, undef=('OF', 'AF')),
    Case('shift.by-zero', bytes.fromhex('f9c1e000'), {'eax': 0}, undef=('OF', 'AF'),
         known='a shift of zero writes no flags at all; the lifter captures the '
               'result anyway. No compiler emits a shift by a literal zero, and '
               'guarding the variable-count form costs a branch on every shift.'),

    # --- carry consumers ---
    Case('neg', bytes.fromhex('f7d8'), {'eax': 5}),
    Case('neg.zero', bytes.fromhex('f7d8'), {'eax': 0}),
    Case('adc', bytes.fromhex('f911c8')),                     # stc; adc eax, ecx
    # cmp eax, ecx; sbb eax, eax
    Case('sbb.idiom', bytes.fromhex('39c819c0'), {'eax': 1, 'ecx': 2},
         known='cmp does not publish CF, so sbb reads the running _cf. Making it '
               'precise deterministically broke Fury3; see the note on sbb in '
               'lift32.py.'),

    # --- PUSHFD/POPFD: the reason recomp_eflags exists ---
    Case('pushfd.after-cmp', bytes.fromhex('39c89c58'), {'eax': 1, 'ecx': 2}),
    Case('pushfd.after-add', bytes.fromhex('01c89c58'), {'eax': 0x0F, 'ecx': 1}),
    Case('popfd.restores-cf',
         # stc; pushfd; clc; popfd; adc ebx, 0 -- the carry has to survive the
         # round trip or the adc adds the wrong number.
         bytes.fromhex('f99cf89d83d300'), {'ebx': 0}),
    Case('popfd.restores-df',
         # std; pushfd; cld; popfd; lodsb -- DF decides which way esi moves.
         bytes.fromhex('fd9cfc9dac'), undef=('CF', 'PF', 'AF', 'ZF', 'SF', 'OF')),

    # --- memory operands, so the comparison covers stores too ---
    Case('store', bytes.fromhex('8906'), {'eax': 0xAABBCCDD}),          # mov [esi], eax
    Case('add.mem', bytes.fromhex('0106'), mem={SCRATCH: (0x11).to_bytes(4, 'little')}),
    Case('push.pop', bytes.fromhex('50595b')),                          # push eax; pop ecx; pop ebx

    # --- sub-register widths: the flag tuple stores what the operand read ---
    Case('add.8bit-sign', bytes.fromhex('00d8'),                  # add al, bl
         {'eax': 0x00, 'ebx': 0x80}, known=WIDTH),
    Case('cmp.8bit-signed', bytes.fromhex('38d8'),                # cmp al, bl
         {'eax': 0x80, 'ebx': 0x01}, known=WIDTH),
    Case('add.16bit-carry', bytes.fromhex('6601c8'),              # add ax, cx
         {'eax': 0xFFFF, 'ecx': 2}, known=WIDTH),
]


# ---------------------------------------------------------------- reference

def run_unicorn(case):
    """What the CPU does. The reference, not a second opinion."""
    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    mu.mem_map(BASE, SIZE)
    mu.mem_write(BASE, case.code)
    for va, data in case.mem.items():
        mu.mem_write(va, data)
    for name, val in case.start_regs().items():
        mu.reg_write(UC_REGS[name], val)
    mu.reg_write(X.UC_X86_REG_EFLAGS, EFLAGS_START)

    before = bytearray(mu.mem_read(BASE, SIZE))
    mu.emu_start(BASE, BASE + len(case.code))
    after = bytearray(mu.mem_read(BASE, SIZE))

    return {
        'regs': {n: mu.reg_read(UC_REGS[n]) for n in REGS},
        'eflags': mu.reg_read(X.UC_X86_REG_EFLAGS),
        'mem': mem_diff(before, after),
    }


def mem_diff(before, after):
    """Guest addresses either machine wrote, and what it left there."""
    return {BASE + i: after[i] for i in range(len(after)) if after[i] != before[i]}


# ---------------------------------------------------------------- lifted

def lift_case(case):
    """Lift one case's bytes to the body of a C function."""
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    lifter = Lifter()
    lifter._labels = set()
    lifter._jump_targets = set()
    lifter._flag_state = None

    body, seen = [], 0
    for insn in md.disasm(bytes(case.code), BASE):
        seen += insn.size
        for line in lifter.lift_instruction(insn):
            body.append('    ' + line)
    if seen != len(case.code):
        raise SystemExit(f'{case.name}: capstone decoded {seen} of {len(case.code)} bytes')
    return body


PRELUDE = r'''/* generated by tools/lift/difftest.py -- do not edit */
#define RECOMP_GENERATED_CODE
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "recomp_types.h"

uint32_t g_eax, g_ecx, g_edx, g_esp, g_ebx, g_esi, g_edi, g_ebp;
double   g_st[8];
int      g_fp_top;
uint16_t g_fpu_cw = 0x037F;
uint16_t g_seg_cs, g_seg_ds, g_seg_es, g_seg_fs, g_seg_gs, g_seg_ss;
uint32_t g_fs_base, g_gs_base, g_cur_func;
ptrdiff_t g_mem_base;
void recomp_dump_trace(const char *why) { (void)why; }

#define WIN_BASE 0x%08Xu
#define WIN_SIZE 0x%08Xu

static unsigned char *win, *ref;
static uint32_t out_eflags;
'''

CASE_FN = r'''
static void case_%d(void) {   /* %s */
    int _fpu_cmp = 0;
    uint32_t _cf = 0;
    int _df = 1;
    uint32_t _flag_a = 0, _flag_b = 0;
    uint32_t _flag_k = FK_NONE;
%s
    /* The whole lazy model, collapsed into the word hardware would have. */
    out_eflags = recomp_eflags(_flag_k, _flag_a, _flag_b, _cf, _df);
}
'''


def c_bytes(data):
    return ', '.join(f'0x{b:02X}' for b in data)


def build_c(cases):
    out = [PRELUDE % (BASE, SIZE)]
    for i, case in enumerate(cases):
        out.append(CASE_FN % (i, case.name, '\n'.join(lift_case(case))))

    out.append('int main(void) {\n'
               '    uint32_t i;\n'
               '    win = (unsigned char *)malloc(WIN_SIZE);\n'
               '    ref = (unsigned char *)malloc(WIN_SIZE);\n'
               '    g_mem_base = (ptrdiff_t)win - (ptrdiff_t)WIN_BASE;\n')
    for i, case in enumerate(cases):
        regs = case.start_regs()
        seeds = []
        for va, data in case.mem.items():
            seeds.append(f'    {{ static const unsigned char s[] = {{{c_bytes(data)}}};\n'
                         f'      memcpy(win + (0x{va:08X}u - WIN_BASE), s, sizeof s); }}')
        seed_text = '\n'.join(seeds)
        out.append(f'''
    /* ---- case {i}: {case.name} ---- */
    memset(win, 0, WIN_SIZE);
{seed_text}
    memcpy(ref, win, WIN_SIZE);
    g_eax = 0x{regs['eax']:08X}u; g_ecx = 0x{regs['ecx']:08X}u;
    g_edx = 0x{regs['edx']:08X}u; g_ebx = 0x{regs['ebx']:08X}u;
    g_esp = 0x{regs['esp']:08X}u; g_ebp = 0x{regs['ebp']:08X}u;
    g_esi = 0x{regs['esi']:08X}u; g_edi = 0x{regs['edi']:08X}u;
    memset(g_st, 0, sizeof g_st); g_fp_top = 0;
    out_eflags = 0;
    case_{i}();
    printf("CASE {i}\\n");
    printf("R %08X %08X %08X %08X %08X %08X %08X %08X\\n",
           g_eax, g_ecx, g_edx, g_ebx, g_esp, g_ebp, g_esi, g_edi);
    printf("F %08X\\n", out_eflags);
    for (i = 0; i < WIN_SIZE; i++)
        if (win[i] != ref[i]) printf("M %08X %02X\\n", (unsigned)(WIN_BASE + i), win[i]);
    printf("ENDCASE\\n");
''')
    out.append('    return 0;\n}\n')
    return ''.join(out)


def compilers():
    """Every C compiler worth trying, best first."""
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


def run_lifted(cases, workdir, keep):
    src = os.path.join(workdir, 'difftest.c')
    exe = os.path.join(workdir, 'difftest.exe')
    with open(src, 'w') as f:
        f.write(build_c(cases))

    include = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..',
                                           'runtime', 'recomp32'))
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

    out = subprocess.run([exe], capture_output=True, text=True)
    if out.returncode != 0:
        raise SystemExit(f'lifted program exited {out.returncode}:\n{out.stderr}')
    return parse_output(out.stdout)


def parse_output(text):
    results, cur = [], None
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        if parts[0] == 'CASE':
            cur = {'regs': {}, 'eflags': 0, 'mem': {}}
        elif parts[0] == 'R':
            cur['regs'] = {n: int(v, 16) for n, v in zip(REGS, parts[1:])}
        elif parts[0] == 'F':
            cur['eflags'] = int(parts[1], 16)
        elif parts[0] == 'M':
            cur['mem'][int(parts[1], 16)] = int(parts[2], 16)
        elif parts[0] == 'ENDCASE':
            results.append(cur)
    return results


# ---------------------------------------------------------------- compare

def diff(case, lifted, real):
    """Every architectural field the two machines disagree on, by name."""
    out = []
    for name in REGS:
        if lifted['regs'][name] != real['regs'][name]:
            out.append((name, f"{lifted['regs'][name]:08X}", f"{real['regs'][name]:08X}"))

    for name, bit in FLAGS:
        if name in case.undef:
            continue
        a = (lifted['eflags'] >> bit) & 1
        b = (real['eflags'] >> bit) & 1
        if a != b:
            out.append((name, str(a), str(b)))

    for addr in sorted(set(lifted['mem']) | set(real['mem'])):
        a, b = lifted['mem'].get(addr), real['mem'].get(addr)
        if a != b:
            out.append((f'[{addr:08X}]',
                        '--' if a is None else f'{a:02X}',
                        '--' if b is None else f'{b:02X}'))
    return out


def main():
    ap = argparse.ArgumentParser(description='differential test: lifted C vs Unicorn')
    ap.add_argument('-k', '--filter', help='only cases whose name contains this')
    ap.add_argument('--keep', action='store_true', help='keep the generated C')
    ap.add_argument('-v', '--verbose', action='store_true', help='show passing cases')
    args = ap.parse_args()

    cases = [c for c in CASES if not args.filter or args.filter in c.name]
    if not cases:
        raise SystemExit('no cases match')

    workdir = tempfile.mkdtemp(prefix='difftest-')
    try:
        lifted = run_lifted(cases, workdir, args.keep)
    finally:
        if args.keep:
            print(f'generated source in {workdir}')
        else:
            shutil.rmtree(workdir, ignore_errors=True)

    if len(lifted) != len(cases):
        raise SystemExit(f'lifted program reported {len(lifted)} of {len(cases)} cases')

    failed = ceilings = 0
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    for case, got in zip(cases, lifted):
        want = run_unicorn(case)
        fields = diff(case, got, want)
        asm = '; '.join(f'{i.mnemonic} {i.op_str}'.strip()
                        for i in md.disasm(bytes(case.code), BASE))
        if fields and case.known:
            ceilings += 1
            print(f'KNOWN {case.name}   [{asm}]')
            for name, a, b in fields:
                print(f'       {name:>10}  lifted {a:>8}   cpu {b:>8}')
            print(f'       -- {case.known}')
        elif fields:
            failed += 1
            print(f'FAIL {case.name}   [{asm}]')
            for name, a, b in fields:
                print(f'       {name:>10}  lifted {a:>8}   cpu {b:>8}')
        elif case.known:
            print(f'FIXED {case.name}   [{asm}] -- matches now; drop the known= note')
        elif args.verbose:
            print(f'ok   {case.name}   [{asm}]')

    matched = len(cases) - failed - ceilings
    print(f'\n{matched}/{len(cases)} match hardware, '
          f'{ceilings} known divergences, {failed} failures')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
