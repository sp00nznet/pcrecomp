"""Compare the headless emulator's reconstructed .txt pages against the real
decrypted shell (shell.bin from the VM). Hook the patch engine's rep-movsd
(0x415AC8): edi=dest VA, esi=source (plaintext), ebp=size. The first page whose
source != shell.bin[dest] is where the page decryptor diverges."""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
DRM = r"G:\recomp\pc\pcrecomp-fs2000\tools\drm"
sys.path.insert(0, DRM)
sys.path.insert(0, os.path.join(r"G:\recomp\pc\pcrecomp-fs2000\tools", "pe"))

LOADER = r"G:\recomp\pc\fs2000\game\FS2000.EXE"
ICD = r"G:\recomp\pc\fs2000\game\FS2000.ICD"
BASE = 0x400000
REF = open(os.path.join(HERE, "shell.bin"), "rb").read()

import safedisc1
from unicorn import UcError, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_EDI, UC_X86_REG_ESI, UC_X86_REG_EBP

# match main()'s argc resolver so stdcall purges are right
try:
    safedisc1._ARGC = safedisc1.ArgcResolver(dll_dirs=[os.path.dirname(LOADER)])
except Exception as e:
    print("argc resolver:", e)

t = safedisc1.Tracer(LOADER, ICD)
t.map()

from unicorn.x86_const import UC_X86_REG_EIP
try:
    t.uc.emu_start(t.entry, 0xFFFFFFFF, count=200_000_000  # full 13-page reconstruction)
except UcError as e:
    print("stopped:", e, "eip=0x%08X" % t.uc.reg_read(UC_X86_REG_EIP))

# Compare FINAL emulator memory to shell.bin over .txt (0x401000..0x40D800).
LO, HI = 0x401000, 0x40D800
emu = bytes(t.uc.mem_read(LO, HI - LO))
ref = REF[LO - BASE: HI - BASE]
# find matching runs vs mismatching runs (granularity 0x40)
G = 0x40
first_bad = None
nbad = 0
for off in range(0, HI - LO, G):
    e = emu[off:off+G]; r = ref[off:off+G]
    if e != r:
        nbad += 1
        if first_bad is None:
            first_bad = LO + off
emu_ent = __import__('math')
def ent(b):
    import math
    if not b: return 0.0
    f=[0]*256
    for x in b: f[x]+=1
    n=len(b); return -sum((c/n)*math.log2(c/n) for c in f if c)
print("--- final .txt compare 0x%X..0x%X (gran 0x%X) ---" % (LO, HI, G))
print("mismatching %dB-blocks: %d / %d" % (G, nbad, (HI-LO)//G))
print("emu .txt entropy %.2f  ref .txt entropy %.2f" % (ent(emu), ent(ref)))
if first_bad is not None:
    o = first_bad - LO
    print("first mismatch at 0x%08X:" % first_bad)
    print("  emu:", emu[o:o+32].hex())
    print("  ref:", ref[o:o+32].hex())
else:
    print("ALL MATCH -- .txt fully reconstructed correctly!")
