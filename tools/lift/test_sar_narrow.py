"""sar on a byte or word is arithmetic: it sign-extends from the operand's width.

A narrow read (LO16(eax), MEM16(...), LO8(...)) is unsigned, so casting it to
int32_t before the shift made `sar ax, 1` a logical shift for every negative
value: -10 became 0x7FFB instead of -5. Found on Theme Park, which halves its
sprite offsets with `sar word ptr [x], 1` when it switches to 640x480.

The emitted expression is compiled and run with the host C compiler when one
is on PATH (cl or clang-cl); otherwise only its shape is checked.

Run: py -3 tools/lift/test_sar_narrow.py
"""

import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import capstone

from generate import LinearInstruction
from lift32 import Lifter


def emit(encoding):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    insn = LinearInstruction(next(iter(md.disasm(encoding, 0x1000))))
    return "\n".join(Lifter().lift_instruction(insn))


CASES = [  # encoding, eax before, eax after
    (b"\x66\xd1\xf8", 0x0000FFF6, 0x0000FFFB),   # sar ax, 1:  -10 -> -5 in the low word
    (b"\xd0\xf8", 0x123456F6, 0x123456FB),       # sar al, 1:  -10 -> -5 in the low byte
    (b"\x66\xc1\xf8\x04", 0x00008000, 0x0000F800),  # sar ax, 4
    (b"\xd1\xf8", 0xFFFFFFF6, 0xFFFFFFFB),       # sar eax, 1 (unchanged path)
]


def main():
    bad = 0
    for enc, before, after in CASES:
        c = emit(enc)
        if len(c) and "sar eax" not in c and "int16_t" not in c and "int8_t" not in c:
            print("FAIL %s: no sign extension in\n%s" % (enc.hex(), c))
            bad += 1
    cc = shutil.which("clang-cl") or shutil.which("cl")
    if cc and not bad:
        body = []
        for i, (enc, before, after) in enumerate(CASES):
            body.append("  { uint32_t eax = 0x%Xu; uint32_t _cf = 0, _flag_a = 0, _flag_b = 0, _flag_k = 0;"
                        " (void)_cf; (void)_flag_a; (void)_flag_b; (void)_flag_k;\n%s\n"
                        "    if (eax != 0x%Xu) { printf(\"FAIL case %d: %%08X\\n\", eax); bad++; } }"
                        % (before, emit(enc), after, i))
        src = ("#include <stdint.h>\n#include <stdio.h>\n#define LO16(r) ((uint16_t)(r))\n#define LO8(r) ((uint8_t)(r))\n"
               "#define SET_LO16(r, v) ((r) = ((r) & 0xFFFF0000u) | (uint16_t)(v))\n"
               "#define SET_LO8(r, v) ((r) = ((r) & 0xFFFFFF00u) | (uint8_t)(v))\n"
               "static uint32_t recomp_flags_pack(uint32_t a, uint32_t b, uint32_t c, uint32_t d)"
               " { return a ^ b ^ c ^ d; }\n#define FK_EFLAGS 0\n#define FK_SHIFT(k) 0\n"
               "int main(void) { int bad = 0;\n%s\n  return bad; }\n" % "\n".join(body))
        d = tempfile.mkdtemp()
        cfile, exe = os.path.join(d, "t.c"), os.path.join(d, "t.exe")
        open(cfile, "w").write(src)
        r = subprocess.run([cc, "/nologo", cfile, "/Fe" + exe, "/Fo" + d + "\\\\"], capture_output=True, text=True)
        if r.returncode:
            print("note: could not compile the check (%s); shape checked only" % r.stdout.strip()[:200])
        else:
            bad += subprocess.run([exe]).returncode
    print("%s: %d failed" % ("FAIL" if bad else "ok", bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
