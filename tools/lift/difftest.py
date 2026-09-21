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
import struct
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
# See the note on g_fpu_cw in PRELUDE: precision control = double, so the model
# and the hardware round identically instead of disagreeing in the last place.
FPU_CONTROL_WORD = 0x027F

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


WIDTH = ('a narrow operand is stored left-aligned, so CF, ZF, SF and OF are '
         'derived at the right width by the 32-bit macros -- but PF and AF are '
         'read off the bottom of the result, which is now zeros. Nothing '
         'branches on either: CMP_P/CMP_NP are stubs and no BCD instruction is '
         'lifted. Real narrow PF is what a width in the tuple would buy.')

CASES = [
    # --- x87: the stack, which nothing here used to look at ------------------
    #
    # Depth is the thing worth comparing. A handler that pushes or pops the
    # wrong number of times leaves every later st(i) reading its neighbour, and
    # the values stay plausible for a long time afterwards -- so a comparison
    # of values alone can pass while the model is already one slot out. These
    # cases check the balance first and the arithmetic second.
    Case('fpu.push', bytes.fromhex('d9e8')),                       # fld1
    Case('fpu.push-twice', bytes.fromhex('d9e8d9e8')),             # fld1; fld1
    Case('fpu.push-pop', bytes.fromhex('d9e8ddd8')),               # fld1; fstp st(0)
    Case('fpu.addp-pops-one', bytes.fromhex('d9e8d9e8dec1')),      # fld1; fld1; faddp
    Case('fpu.store-pops', bytes.fromhex('d9e8dd1f')),             # fld1; fstp qword [edi]
    Case('fpu.zero', bytes.fromhex('d9ee')),                       # fldz

    # fxch has to actually exchange. Capstone reports `fxch st(1)` with BOTH
    # registers - st(0) first - so reading its first operand gives st(0) and
    # the swap becomes st(0) with st(0), which is nothing at all. Nothing
    # crashes: the wrong one of two live values gets stored and the arithmetic
    # after it stays plausible. So store the one that should have moved.
    #
    # fld 1.0; fld 3.0; fxch st(1); fstp qword [edi]  ->  3.0, not 1.0
    Case('fpu.xch-1', bytes.fromhex('dd06dd4608d9c9dd1f'),
         mem={SCRATCH: struct.pack('<dd', 1.0, 3.0)}),
    # And at a depth greater than one, because an emitter that hardcodes st(1)
    # passes the case above.
    # fld 1; fld 2; fld 3; fxch st(2); fstp qword [edi]  ->  1.0
    Case('fpu.xch-2', bytes.fromhex('dd06dd4608dd4610d9cadd1f'),
         mem={SCRATCH: struct.pack('<ddd', 1.0, 2.0, 3.0)}),

    # The popping arithmetic names its DESTINATION, unlike the non-popping
    # form: `faddp st(1)` is st(1) = st(1) + st(0), and the result survives the
    # pop because it was written one slot down. Written to st(0) instead it is
    # thrown away by the very next pop, and the instruction returns the operand
    # it was supposed to have added to.
    #
    # fld 1.0; fld 3.0; faddp st(1); fstp qword [edi]  ->  4.0, not 1.0
    Case('fpu.addp-dest', bytes.fromhex('dd06dd4608dec1dd1f'),
         mem={SCRATCH: struct.pack('<dd', 1.0, 3.0)}),
    # fld 1; fld 2; fld 3; fmulp st(2); fstp st(0); fstp qword [edi]  ->  3.0
    Case('fpu.mulp-dest-2', bytes.fromhex('dd06dd4608dd4610deca ddd8 dd1f'.replace(' ', '')),
         mem={SCRATCH: struct.pack('<ddd', 1.0, 2.0, 3.0)}),
    # fsubrp reverses the operands as well as naming the destination:
    # fld 1.0; fld 3.0; fsubrp st(1); fstp qword [edi]  ->  3.0 - 1.0 = 2.0
    Case('fpu.subrp-dest', bytes.fromhex('dd06dd4608dee1dd1f'),
         mem={SCRATCH: struct.pack('<dd', 1.0, 3.0)}),

    # Load and store a value back unchanged: any mangling shows in memory, and
    # the stack must end where it started.
    Case('fpu.load-store', bytes.fromhex('dd06dd1f'),              # fld [esi]; fstp [edi]
         mem={SCRATCH: b'\x00\x00\x00\x00\x00\x00\xf0?'}),

    # Arithmetic that is not exact in binary. At the x87 default of extended
    # precision the hardware keeps eleven bits the model cannot, and the stored
    # doubles differ in the last place; at PC=53 they must agree exactly.
    Case('fpu.divide', bytes.fromhex('dd06dd4608def9dd1f'),
         mem={SCRATCH: b'\x00\x00\x00\x00\x00\x00\xf0?' + b'\x00\x00\x00\x00\x00\x00\x08@'}),                            # 1.0 / 3.0
    Case('fpu.multiply', bytes.fromhex('dd06dd4608dec9dd1f'),
         mem={SCRATCH: b'\x00\x00\x00\x00\x00\x00\x08@' + b'\x00\x00\x00\x00\x00\x00\x08@'}),
    Case('fpu.subtract', bytes.fromhex('dd06dd4608dee9dd1f'),
         mem={SCRATCH: b'\x00\x00\x00\x00\x00\x00\xf0?' + b'\x00\x00\x00\x00\x00\x00\x08@'}),
    Case('fpu.sqrt', bytes.fromhex('dd06d9fadd1f'),                # fld [esi]; fsqrt; fstp
         mem={SCRATCH: b'\x00\x00\x00\x00\x00\x00\x00@'}),
    Case('fpu.chs', bytes.fromhex('dd06d9e0dd1f'),                 # fld; fchs; fstp
         mem={SCRATCH: b'\x00\x00\x00\x00\x00\x00\x08@'}),
    Case('fpu.abs', bytes.fromhex('dd06d9e1dd1f'),                 # fld; fabs; fstp
         mem={SCRATCH: struct.pack('<d', -7.5)}),

    # Integer conversion, which is where a rounding mode disagreement shows up
    # as a whole number rather than a last-place one.
    Case('fpu.int-roundtrip', bytes.fromhex('db06db1f'),           # fild [esi]; fistp [edi]
         mem={SCRATCH: struct.pack('<i', -12345)}),

    # Single precision in, double out: the model holds everything as a double,
    # so a float load that does not narrow first will disagree here.
    # The one case that makes the control word above load-bearing rather than
    # decorative. Every other division here rounds to the same double whether
    # the hardware computed it at 53 or 64 bits, because a single operation
    # followed by a store to double usually survives the double rounding.
    #
    # This one does not: at extended precision the quotient keeps eleven extra
    # bits, and rounding *that* to a double lands one ulp away from rounding
    # the exact quotient directly. Searching random divisions, about 1 in 4,000
    # behaves this way -- rare enough to look like a flake, common enough that
    # a suite of FPU cases would carry a couple of permanent unexplained
    # divergences without the pin.
    #
    #   PC=53  ->  1.3295924020625665
    #   PC=64  ->  1.3295924020625667
    Case('fpu.double-rounding', bytes.fromhex('dd06dd4608def9dd1f'),
         mem={SCRATCH: b'\xda\x02\xe7\x83\xb0e+C' + b'\xecs\x01@\x11\x9b$C'}),
    Case('fpu.float-load', bytes.fromhex('d906dd1f'),              # fld dword; fstp qword
         mem={SCRATCH: struct.pack('<f', 0.1)}),
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
    # A shift of zero writes no flags at all, and the guard on the shift's flag
    # publication now says exactly that.
    Case('shift.by-zero', bytes.fromhex('f9c1e000'), {'eax': 0}, undef=('OF', 'AF')),
    # --- rep movs/stos honour the direction flag ---
    #
    # The rep forms used to ignore DF entirely: always a forward memcpy, always
    # incrementing. With `std` set a real CPU walks DOWN from esi/edi, so the
    # lifted copy read and wrote from the wrong end and ran off past its
    # buffer. MechCommander Gold's VFX_pane_copy takes that path for an
    # overlapping blit, and it was overwriting the object after its
    # destination -- a live C++ object, vtable and all.
    Case('movsb.rep-backward', bytes.fromhex('fdf3a4'),      # std; rep movsb
         {'ecx': 4, 'esi': SCRATCH + 3, 'edi': SCRATCH + 0x103},
         mem={SCRATCH: b'ABCD'}),
    Case('movsd.rep-backward', bytes.fromhex('fdf3a5'),      # std; rep movsd
         {'ecx': 2, 'esi': SCRATCH + 4, 'edi': SCRATCH + 0x104},
         mem={SCRATCH: b'ABCDEFGH'}),
    Case('movsb.rep-forward', bytes.fromhex('fcf3a4'),       # cld; rep movsb
         {'ecx': 4, 'esi': SCRATCH, 'edi': SCRATCH + 0x100},
         mem={SCRATCH: b'ABCD'}),
    Case('stosb.rep-backward', bytes.fromhex('fdf3aa'),      # std; rep stosb
         {'eax': 0x5A, 'ecx': 4, 'edi': SCRATCH + 0x103}),
    Case('stosd.rep-backward', bytes.fromhex('fdf3ab'),      # std; rep stosd
         {'eax': 0x11223344, 'ecx': 2, 'edi': SCRATCH + 0x104}),

    # --- string compare / scan, every width ---
    #
    # Only the byte forms were implemented, so `repe cmpsd` lifted to an empty
    # statement -- and that is the aligned fast path in the MSVC 6 memcmp, which
    # then returned whatever was in eax. Two identical buffers compared as
    # different, and MechCommander Gold's config parser found none of its keys
    # in a file it had read perfectly.
    Case('cmpsd.repe-equal', bytes.fromhex('f3a7'),          # repe cmpsd
         {'ecx': 2},
         mem={SCRATCH: b'ABCDEFGH', SCRATCH + 0x100: b'ABCDEFGH'}),
    Case('cmpsd.repe-differs', bytes.fromhex('f3a7'),
         {'ecx': 2},
         mem={SCRATCH: b'ABCDEFGH', SCRATCH + 0x100: b'ABCDwxyz'}),
    Case('cmpsw.repe-differs', bytes.fromhex('f366a7'),      # repe cmpsw
         {'ecx': 3},
         mem={SCRATCH: b'ABCDEF', SCRATCH + 0x100: b'ABxxEF'}),
    Case('cmpsb.repe-equal', bytes.fromhex('f3a6'),          # repe cmpsb
         {'ecx': 4},
         mem={SCRATCH: b'ABCD', SCRATCH + 0x100: b'ABCD'}, undef=('AF',)),
    Case('cmpsd.single', bytes.fromhex('a7'),                # cmpsd, no prefix
         mem={SCRATCH: b'ABCD', SCRATCH + 0x100: b'ABCE'}),
    # The count and the pointers advance for the element that ENDS the loop too,
    # which is what `repne scasb; not ecx; dec ecx` depends on for strlen.
    Case('scasb.repne-found', bytes.fromhex('f2ae'),         # repne scasb
         {'eax': 0x41, 'ecx': 4},
         mem={SCRATCH + 0x100: b'xyAB'}, undef=('AF',)),
    Case('scasd.repne-found', bytes.fromhex('f2af'),         # repne scasd
         {'eax': 0x44434241, 'ecx': 3},
         mem={SCRATCH + 0x100: b'zzzzABCDwwww'}),

    # x86 masks a shift count to 5 bits before doing anything, so `shl eax,0x6e`
    # shifts by 14. Emitting the raw immediate shifted a uint32_t by more than
    # its width, which is undefined in C -- the compiler may hold the operand,
    # zero it, or use the low bits, and those disagree. MechCommander Gold has
    # 172 of these.
    Case('shl.count-masked', bytes.fromhex('c1e06e'),            # shl eax, 0x6e -> 14
         {'eax': 0x0000FFFF}, undef=('OF', 'AF')),
    Case('shr.count-masked', bytes.fromhex('c1e825'),            # shr eax, 0x25 -> 5
         {'eax': 0xDEADBEEF}, undef=('OF', 'AF')),
    Case('sar.count-masked', bytes.fromhex('c1f8ff'),            # sar eax, 0xff -> 31
         {'eax': 0x80000000}, undef=('OF', 'AF')),
    # ...and a count that masks to zero is a true no-op: CF has to survive it,
    # which is also the case that made the carry read one bit past the operand.
    Case('shl.count-masks-to-zero', bytes.fromhex('f9c1e0a0'),   # stc; shl eax, 0xa0 -> 0
         {'eax': 0x12345678}, undef=('OF', 'AF')),

    # The carry a shift writes has to reach its consumer. `shr ecx,1` leaves the
    # odd bit in CF and the next branch decides whether a trailing byte gets
    # copied -- which is the background blitter's entire inner loop.
    Case('shr.publishes-cf', bytes.fromhex('d1e919c0'),          # shr ecx,1; sbb eax,eax
         {'ecx': 0x00000007, 'eax': 0}, undef=('OF', 'AF')),
    Case('shl.publishes-cf', bytes.fromhex('d1e019c9'),          # shl eax,1; sbb ecx,ecx
         {'eax': 0x80000000, 'ecx': 0}, undef=('OF', 'AF')),

    # --- the jcc/setcc PAIRING, which comparing flags never tested ---
    #
    # Everything above compares recomp_eflags() against hardware EFLAGS, and
    # that derivation was right all along. What it could not see is the OTHER
    # path: when the lifter knows the flag-setter statically it emits a CMP_*
    # macro instead, and those macros SUBTRACT. Paired with an add or an inc,
    # which added, the condition asked a different question entirely.
    #
    # `inc eax; jne` is how you ask "was that -1?". Against a subtracting macro
    # it asked "was that 1?", and Treasure Cove (1996) put up "Could not find
    # Resource File!" over a resource DLL it had just opened successfully.
    #
    # setcc goes through the same pairing and lands in a register, so a wrong
    # answer shows up as a wrong value rather than only as a flag.
    Case('inc.paired.sete-true', bytes.fromhex('400f94c3'),      # inc eax; sete bl
         {'eax': 0xFFFFFFFF, 'ebx': 0}),
    Case('inc.paired.sete-false', bytes.fromhex('400f94c3'),     # inc eax; sete bl
         {'eax': 1, 'ebx': 0}),
    Case('add.paired.sete', bytes.fromhex('01c80f94c3'),         # add eax,ecx; sete bl
         {'eax': 1, 'ecx': 0xFFFFFFFF, 'ebx': 0}),
    Case('add.paired.setb', bytes.fromhex('01c80f92c3'),         # add eax,ecx; setb bl
         {'eax': 0xFFFFFFFF, 'ecx': 2, 'ebx': 0}),
    Case('add.paired.setl', bytes.fromhex('01c80f9cc3'),         # add eax,ecx; setl bl
         {'eax': 0x7FFFFFFF, 'ecx': 1, 'ebx': 0}),
    # dec and sub pair with a subtracting macro correctly; guard that.
    Case('dec.paired.sete', bytes.fromhex('480f94c3'),           # dec eax; sete bl
         {'eax': 1, 'ebx': 0}),
    Case('sub.paired.setl', bytes.fromhex('29c80f9cc3'),         # sub eax,ecx; setl bl
         {'eax': 1, 'ecx': 2, 'ebx': 0}),

    # --- and so must the instructions whose whole job IS the carry ---
    #
    # Borland's strcpy and strcat are one routine entered at two addresses, clc
    # at one and stc at the other, with a single `jb` deciding whether to scan
    # for the end of the destination first. With the carry unpublished, strcpy
    # ran as strcat. The cmp ahead of each of these sets the carry the other
    # way, so a stale read shows up in the result.
    Case('clc.publishes-cf', bytes.fromhex('39c8f819c0'),        # cmp eax,ecx; clc; sbb eax,eax
         {'eax': 1, 'ecx': 2}, undef=('OF', 'AF')),
    Case('stc.publishes-cf', bytes.fromhex('39c8f919c0'),        # cmp eax,ecx; stc; sbb eax,eax
         {'eax': 2, 'ecx': 1}, undef=('OF', 'AF')),
    Case('cmc.publishes-cf', bytes.fromhex('39c8f519c0'),        # cmp eax,ecx; cmc; sbb eax,eax
         {'eax': 1, 'ecx': 2}, undef=('OF', 'AF')),
    # They leave ZF alone, so a je after one still reads the compare.
    Case('stc.keeps-zf', bytes.fromhex('39c8f9'),                # cmp eax,ecx; stc
         {'eax': 7, 'ecx': 7}, undef=('OF', 'AF')),

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

    # --- rotates: the right width, and the carry they actually write ---
    #
    # All four were lifted as 32-bit whatever the operand width, so `rcr cl,1`
    # fed the carry in at bit 31 where the write back to CL then dropped it.
    # And they published no flags at all, so a following carry-conditional read
    # the PREVIOUS instruction's carry. Gizmos & Gadgets' RLE sprite decoder is
    # `sub bx,cx; rcr cl,1; rep movsw; jae` -- the jae asking "was the count
    # odd?" -- and answering it with the subtract's borrow ran the decoder off
    # the end of both the sprite and the framebuffer.
    Case('rcr.8bit.carry-in', bytes.fromhex('f9d0d9'),            # stc; rcr cl, 1
         {'ecx': 0xAAAAAA0A}, undef=('OF',)),
    Case('rcr.8bit.carry-out', bytes.fromhex('f8d0d9'),           # clc; rcr cl, 1
         {'ecx': 0xAAAAAA0B}, undef=('OF',)),
    Case('rcl.8bit', bytes.fromhex('f9d0d1'),                     # stc; rcl cl, 1
         {'ecx': 0xAAAAAA81}, undef=('OF',)),
    Case('rcr.16bit', bytes.fromhex('f966d1d9'),                  # stc; rcr cx, 1
         {'ecx': 0xAAAA0003}, undef=('OF',)),
    Case('rcr.32bit', bytes.fromhex('f9d1d9'),                    # stc; rcr ecx, 1
         {'ecx': 0x00000003}, undef=('OF',)),
    Case('rol.8bit', bytes.fromhex('d0c1'), {'ecx': 0xAAAAAA81}, undef=('OF',)),
    Case('ror.8bit', bytes.fromhex('d0c9'), {'ecx': 0xAAAAAA81}, undef=('OF',)),
    Case('rol.16bit', bytes.fromhex('66d1c1'), {'ecx': 0xAAAA8001}, undef=('OF',)),
    # The whole point: the rotate's carry has to reach the consumer, not the
    # subtract's. sub cx,dx leaves CF=0; rcr cl,1 sets CF from the old bit 0,
    # which is 1; sbb eax,eax is then -1 only if that carry got through.
    Case('rcr.publishes-cf', bytes.fromhex('6629d1d0d919c0'),
         {'ecx': 0x00000005, 'edx': 1, 'eax': 0}, undef=('OF', 'AF')),

    # --- 16-bit push/pop move esp by two and keep the register's top half ---
    #
    # Lifted as their 32-bit cousins the stack still balanced, so it looked
    # fine, and then `pop bp` replaced the whole of ebp with a zero-extended
    # word. The `leave` after it handed that to esp, and the next stack access
    # was down at 64 KB.
    Case('push16.then.pop32', bytes.fromhex('6655665d'),          # push bp; pop bp
         {'ebp': 0x0022FD48}),
    Case('push16.esp-by-two', bytes.fromhex('6655'),              # push bp
         {'ebp': 0x12345678}),
    Case('pop16.keeps-high-half', bytes.fromhex('6650665b'),      # push ax; pop bx
         {'eax': 0x0000BEEF, 'ebx': 0xDEAD0000}),

    # --- setcc / cmovcc after test, which used to read the wrong macro -------
    #
    # `test a, b` leaves CF=0 and OF=0 and sets ZF/SF from `a & b`, so an
    # ordering condition after it is a comparison of that result against ZERO.
    # The jcc forms were mapped to the TEST_* macros; the setcc and cmovcc forms
    # were looked up under their own spelling, missed, and fell back to
    # CMP_LE(a, b) -- a comparison of the two operands. For the `test r, r`
    # idiom that reads `r <= r`, true for every value in the register, so
    # `setle al` returned 1 no matter what. MechCommander's
    # PacketFile::seekPacket builds its return code out of exactly that and so
    # failed on every call, which is what kept the campaign from loading.
    #
    # The sign of the register is the whole point, so each is run three ways.
    Case('setle.after-test.positive', bytes.fromhex('85db0f9ec0'),  # test ebx,ebx; setle al
         {'ebx': 0x0000002C, 'eax': 0}),
    Case('setle.after-test.zero', bytes.fromhex('85db0f9ec0'),
         {'ebx': 0, 'eax': 0}),
    Case('setle.after-test.negative', bytes.fromhex('85db0f9ec0'),
         {'ebx': 0xFFFFFFF0, 'eax': 0}),
    Case('setg.after-test.positive', bytes.fromhex('85db0f9fc0'),   # setg al
         {'ebx': 0x0000002C, 'eax': 0}),
    Case('setl.after-test.negative', bytes.fromhex('85db0f9cc0'),   # setl al
         {'ebx': 0xFFFFFFF0, 'eax': 0}),
    Case('setge.after-test.zero', bytes.fromhex('85db0f9dc0'),      # setge al
         {'ebx': 0, 'eax': 0}),
    # The whole tail of seekPacket: setle, dec, and, add -- the return code is
    # 0 only when the AND result is above zero, and 0xBADF0004 otherwise.
    Case('seekpacket.tail.ok', bytes.fromhex('31c085db0f9ec04825fcff2045050400dfba'),
         {'ebx': 0x0000002C}),
    Case('seekpacket.tail.fail', bytes.fromhex('31c085db0f9ec04825fcff2045050400dfba'),
         {'ebx': 0}),
    # `and` sets the same flags from the same value, so it takes the same path.
    Case('setle.after-and.positive', bytes.fromhex('21c80f9ec2'),   # and eax,ecx; setle dl
         {'eax': 0xFF, 'ecx': 0x2C, 'edx': 0}),
    Case('cmovle.after-test.positive', bytes.fromhex('85db0f4ec1'), # test ebx,ebx; cmovle eax,ecx
         {'ebx': 0x0000002C, 'eax': 0x11111111, 'ecx': 0x22222222}),
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
    mu.reg_write(X.UC_X86_REG_FPCW, FPU_CONTROL_WORD)

    before = bytearray(mu.mem_read(BASE, SIZE))
    mu.emu_start(BASE, BASE + len(case.code))
    after = bytearray(mu.mem_read(BASE, SIZE))

    return {
        'regs': {n: mu.reg_read(UC_REGS[n]) for n in REGS},
        'eflags': mu.reg_read(X.UC_X86_REG_EFLAGS),
        'mem': mem_diff(before, after),
        'fp_depth': fpu_depth(mu),
        'st': fpu_stack(mu),
    }


def fpu_depth(mu):
    """How many values are on the x87 stack.

    x87 has no depth register. TOP in the status word is a rotating index that
    starts at 0 on an empty stack and counts *down* as values are pushed, so
    after n pushes it reads (0 - n) & 7. The model counts up from zero instead,
    which is the same number stated the easy way; this converts.

    Depth is the point of the whole exercise. A handler that pops the wrong
    number of times leaves the stack shifted, every later st(i) reads its
    neighbour, and the values can still look plausible for a long time. The
    value comparison alone never shows it.
    """
    return (8 - ((mu.reg_read(X.UC_X86_REG_FPSW) >> 11) & 7)) & 7


def fpu_stack(mu):
    """[st(0), st(1), ...] as doubles, for the live entries only.

    Unicorn's ST0..ST7 accessor returns the 64-bit mantissa with the exponent
    and sign dropped, and its FP0..FP7 accessor returns (0, 0) on this build --
    neither can be turned back into a number. So the values are not read out of
    registers at all: the case is expected to store whatever it wants compared
    into guest memory, which both machines already compare byte for byte.

    This returns the depth-derived view only, so a case that stores nothing is
    still checked for stack balance.
    """
    return []


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
/* Round to nearest, all exceptions masked, and precision control = double
   (53-bit) rather than the x87 default of extended (64-bit).

   The model holds the x87 stack as C doubles. At the hardware's default
   extended precision it carries eleven more bits of mantissa than the model
   can, so add/sub/mul/div/sqrt disagree in the last place for reasons that
   have nothing to do with lifting, and every real bug is buried in that noise.
   At PC=53 both sides are correctly rounded to double and those five must
   agree exactly. Only the transcendentals -- hardware polynomial against libm
   -- still diverge, and those are marked `known` on the case. */
uint16_t g_fpu_cw = 0x027F;
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
    printf("T %d\\n", g_fp_top);
    {{ int _k; for (_k = 0; _k < g_fp_top && _k < 8; _k++)
        printf("S %d %.17g\\n", _k, g_st[_k]); }}
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
            cur = {'regs': {}, 'eflags': 0, 'mem': {}, 'fp_depth': 0, 'st': []}
        elif parts[0] == 'R':
            cur['regs'] = {n: int(v, 16) for n, v in zip(REGS, parts[1:])}
        elif parts[0] == 'F':
            cur['eflags'] = int(parts[1], 16)
        elif parts[0] == 'T':
            cur['fp_depth'] = int(parts[1])
        elif parts[0] == 'S':
            cur['st'].append(float(parts[2]))
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

    if lifted.get('fp_depth', 0) != real.get('fp_depth', 0):
        out.append(('x87 depth', str(lifted.get('fp_depth', 0)),
                    str(real.get('fp_depth', 0))))

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
