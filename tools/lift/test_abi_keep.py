"""generate.abi_scan / _abi_fixpoint (LIFT32_ABI): which callee-saved registers a body keeps."""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
import generate
from generate import LinearInstruction, abi_scan, _abi_fixpoint

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True


def scan(code, va=0x1000):
    return abi_scan([LinearInstruction(i) for i in md.disasm(code, va)], va)


# mov edi,edi; push ebp; mov ebp,esp; push esi; mov esi,ecx; pop esi; pop ebp; ret
assert scan(bytes.fromhex('8bff 55 8bec 56 8bf1 5e 5d c3'))[0] == 0xF
# test ecx,ecx; je +3; push esi; pop esi; ret; mov esi,1 (path that never pushed); ret
s = scan(bytes.fromhex('85c9 7403 56 5e c3 be01000000 c3'))
assert s[0] == 0xF & ~2, s
# push ebx; pop ebx; xor ebx,ebx; ret -- written after its restore
assert scan(bytes.fromhex('53 5b 31db c3'))[0] == 0xE
# rep movsd writes esi and edi; cpuid writes ebx
assert scan(bytes.fromhex('f3a5 c3'))[0] == 0x9
assert scan(bytes.fromhex('0fa2 c3'))[0] == 0xE
# push ebp; mov ebp,esp; leave; ret
assert scan(bytes.fromhex('55 8bec c9 c3'))[0] == 0xF
# a call and a tail jump out of the body
s = scan(bytes.fromhex('e8fb0f0000 e9f60f0000'))        # call 0x2000; jmp 0x2000
assert s[1] == [0x2000] and s[2] == [0x2000], s
# jmp [import]: an import thunk keeps nothing (msvcrt's _EH_prolog sets ebp)
assert scan(bytes.fromhex('ff2598100001'))[2] == [0]
# fixpoint: A calls B, B writes esi; C calls an unknown target
rec = {1: [0xF, [2], [], ''], 2: [0xD, [], [], ''], 3: [0xF, [9], [], '']}
assert _abi_fixpoint(rec) == {1: 0xD, 2: 0xD, 3: 0}
# recursion keeps what it keeps
assert _abi_fixpoint({1: [0xF, [1], [], '']}) == {1: 0xF}
print('test_abi_keep: ok')
