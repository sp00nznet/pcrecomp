"""sse_shift_selftest.py -- do the lifted packed shifts do what the CPU does?

difftest.py answers that question for the recomp32 backend, and cannot answer
it for this one: it is wired to lift32's Lifter and to recomp32's runtime, and
the two backends do not share a CPU struct. Rather than make that harness
dual-backend for one instruction family, this does the smallest version of the
same idea.

The packed shifts are register-only, so nothing here needs the runtime at all
- the lifted statements touch `c->xmm` and nothing else, and a struct with one
field is enough to compile and run them. Unicorn stays the reference for what
an x86 does, so the expected values are hardware's rather than mine.

What it is really guarding: x86 saturates a shift whose count reaches the lane
width - the lane becomes zero, or all sign bits for the arithmetic forms -
where C calls the same shift undefined. A lifter that writes the shift
straight through passes every ordinary count and gets those wrong, quietly.

    python tools/lift/sse_shift_selftest.py

Needs: unicorn, capstone, and a C compiler (gcc/clang/cc, or $RECOMP_CC).
"""

import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
from unicorn import x86_const as X

from tools.lift.lift32_cpu import Lifter, IMAGE_BASE
from tools.lift.difftest import compilers    # finding a compiler is the same job

CODE = IMAGE_BASE
XMM3 = 0xFEDCBA9876543210_0123456789ABCDEF          # the value under test
XMM2 = 33                                           # a count past a dword

CASES = [
    ('psllq.imm',      'psllq xmm3, 0x20',   '660f73f320'),
    ('psrlq.imm',      'psrlq xmm3, 0x20',   '660f73d320'),
    ('pslld.imm',      'pslld xmm3, 8',      '660f72f308'),
    ('psrld.imm',      'psrld xmm3, 8',      '660f72d308'),
    ('psllw.imm',      'psllw xmm3, 4',      '660f71f304'),
    ('psrlw.imm',      'psrlw xmm3, 4',      '660f71d304'),
    ('psrad.imm',      'psrad xmm3, 8',      '660f72e308'),
    ('psraw.imm',      'psraw xmm3, 4',      '660f71e304'),
    # The saturating counts. These are the cases C gets wrong on its own.
    ('pslld.saturate', 'pslld xmm3, 40',     '660f72f328'),
    ('psrlq.saturate', 'psrlq xmm3, 128',    '660f73d380'),
    ('psrad.saturate', 'psrad xmm3, 99',     '660f72e363'),
    # Byte shifts of the whole register: no lanes, so no saturation either.
    ('pslldq',         'pslldq xmm3, 5',     '660f73fb05'),
    ('psrldq',         'psrldq xmm3, 5',     '660f73db05'),
    # Count from a register rather than an immediate.
    ('psllq.by-reg',   'psllq xmm3, xmm2',   '660ff3da'),
]

SHIM = r'''
#include <stdint.h>
#include <stdio.h>

typedef union {
    float    f32[4];
    double   f64[2];
    uint32_t u32[4];
    uint64_t u64[2];
    int32_t  i32[4];
    uint16_t u16[8];
    int16_t  i16[8];
    uint8_t  u8[16];
} XMM;

/* Only the field the packed shifts touch. A whole CPU would drag in the
 * runtime, and the runtime is what this deliberately does without. */
typedef struct { XMM xmm[8]; } CPU;
'''


def reference(code):
    """What the hardware does, via Unicorn."""
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(CODE, 0x1000)
    uc.mem_write(CODE, code)
    uc.reg_write(X.UC_X86_REG_XMM3, XMM3)
    uc.reg_write(X.UC_X86_REG_XMM2, XMM2)
    uc.emu_start(CODE, CODE + len(code))
    return uc.reg_read(X.UC_X86_REG_XMM3)


def lifted_c(code):
    """The statements this lifter emits for those bytes."""
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    lif = Lifter(None, 0x1000)
    out = []
    for insn in md.disasm(code, CODE):
        out += lif.translate(insn, {})
    return out


def build_and_run(workdir, keep):
    src = os.path.join(workdir, 'shifts.c')
    exe = os.path.join(workdir, 'shifts.exe')

    body = []
    for i, (name, _, hexbytes) in enumerate(CASES):
        stmts = '\n        '.join(lifted_c(bytes.fromhex(hexbytes)))
        body.append('''
    {
        CPU cpu; CPU *c = &cpu;
        int _j; for (_j = 0; _j < 8; _j++) { c->xmm[_j].u64[0] = 0; c->xmm[_j].u64[1] = 0; }
        c->xmm[3].u64[0] = 0x%016XULL; c->xmm[3].u64[1] = 0x%016XULL;
        c->xmm[2].u64[0] = 0x%016XULL; c->xmm[2].u64[1] = 0;
        %s
        printf("%d %%016llX%%016llX\\n", (unsigned long long)c->xmm[3].u64[1],
                                         (unsigned long long)c->xmm[3].u64[0]);
    }''' % (XMM3 & 0xFFFFFFFFFFFFFFFF, XMM3 >> 64, XMM2, stmts, i))

    with open(src, 'w') as f:
        f.write(SHIM + '\nint main(void) {' + ''.join(body) + '\n    return 0;\n}\n')

    err = ''
    for cc in compilers():
        r = subprocess.run([cc, '-O0', '-g', '-w', src, '-o', exe],
                           capture_output=True, text=True)
        if r.returncode == 0:
            break
        err += '--- %s exited %d\n%s%s' % (cc, r.returncode, r.stdout, r.stderr)
    else:
        raise SystemExit('no compiler could build the test:\n' + err)

    if keep:
        print('generated source in', workdir)
    out = subprocess.run([exe], capture_output=True, text=True)
    if out.returncode != 0:
        raise SystemExit('lifted program exited %d:\n%s' % (out.returncode, out.stderr))

    got = {}
    for line in out.stdout.split('\n'):
        if line.strip():
            i, v = line.split()
            got[int(i)] = int(v, 16)
    return got


def main():
    keep = '--keep' in sys.argv
    workdir = tempfile.mkdtemp(prefix='sse-shift-')
    try:
        got = build_and_run(workdir, keep)
    finally:
        if not keep:
            shutil.rmtree(workdir, ignore_errors=True)

    bad = 0
    for i, (name, asm, hexbytes) in enumerate(CASES):
        want = reference(bytes.fromhex(hexbytes))
        have = got.get(i)
        if have == want:
            print('ok   %-16s %s' % (name, asm))
        else:
            bad += 1
            print('FAIL %-16s %s' % (name, asm))
            print('       lifted %032X' % (have or 0))
            print('       cpu    %032X' % want)

    print('\n%d/%d match hardware' % (len(CASES) - bad, len(CASES)))
    return 1 if bad else 0


if __name__ == '__main__':
    raise SystemExit(main())
