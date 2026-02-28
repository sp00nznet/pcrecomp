"""
analyze.py - Function Boundary Detection & Control Flow Analysis

Detects MSC 5.x function boundaries using prologue/epilogue patterns,
resolves INT 3Fh overlay calls, builds a function map with call graph,
and identifies key game subsystems.

Microsoft C 5.x function conventions:
  Prologue:  PUSH BP / MOV BP, SP [/ SUB SP, N]
  Epilogue:  MOV SP, BP / POP BP / RET or RETF
  Callee:    Near CALL (E8) for same-segment, FAR CALL (9A) for cross-segment
  Args:      Pushed right-to-left, caller cleans stack (cdecl)
  Overlay:   INT 3Fh <ovl_num:u8> <offset:u16>

Part of the Civ Recomp project (sp00nznet/civ)
"""

import struct
import sys
from dataclasses import dataclass, field
from typing import Optional
from decode16 import Decoder, Instruction, OpType


@dataclass
class Function:
    """A detected function in the binary."""
    name: str = ''
    start: int = 0        # Start offset (file-relative)
    end: int = 0          # End offset (exclusive)
    size: int = 0         # Byte count
    local_size: int = 0   # Local stack frame size
    is_far: bool = False  # Uses RETF (far return)
    is_overlay: bool = False
    overlay_num: int = 0  # Which overlay module (0 = resident)

    # Call information
    calls: list = field(default_factory=list)       # Direct call targets
    called_by: list = field(default_factory=list)    # Callers
    ovl_calls: list = field(default_factory=list)    # Overlay calls (ovl_num, offset)

    # Instruction count
    inst_count: int = 0

    # Identified purpose
    category: str = ''  # e.g., 'init', 'gfx', 'input', 'game', 'runtime'


@dataclass
class OverlayInfo:
    """Information about an overlay module."""
    index: int = 0         # 1-based overlay number
    file_offset: int = 0   # Start of overlay MZ header in file
    code_offset: int = 0   # Start of code (after overlay MZ header)
    code_size: int = 0     # Size of code section
    functions: list = field(default_factory=list)


class Analyzer:
    """Analyze CIV.EXE to detect functions and build call graph."""

    def __init__(self, data: bytes):
        self.data = data
        self.functions = []
        self.overlays = []
        self.call_graph = {}
        self.strings = {}

        # Parse main MZ header
        self.hdr_size = struct.unpack_from('<H', data, 8)[0] * 16
        pages = struct.unpack_from('<H', data, 4)[0]
        last_page = struct.unpack_from('<H', data, 2)[0]
        self.img_size = (pages - 1) * 512 + last_page if last_page else pages * 512

    def find_overlays(self):
        """Locate all overlay modules in the file."""
        scan = (self.img_size + 0x1FF) & ~0x1FF
        index = 0

        while scan + 28 < len(self.data):
            if self.data[scan] == 0x4D and self.data[scan+1] == 0x5A:
                op = struct.unpack_from('<H', self.data, scan + 4)[0]
                olp = struct.unpack_from('<H', self.data, scan + 2)[0]
                ohp = struct.unpack_from('<H', self.data, scan + 8)[0]
                if 0 < op < 500 and 0 < ohp < 100:
                    index += 1
                    hdr_sz = ohp * 16
                    o_img = (op - 1) * 512 + olp if olp else op * 512
                    code_sz = o_img - hdr_sz
                    self.overlays.append(OverlayInfo(
                        index=index,
                        file_offset=scan,
                        code_offset=scan + hdr_sz,
                        code_size=code_sz,
                    ))
            scan += 0x200

    def _detect_functions_in_range(self, start, end, overlay_num=0):
        """Detect function boundaries in a code range using prologue patterns."""
        code = self.data[start:end]
        decoder = Decoder(code, base_offset=start)
        instructions = decoder.decode_all()

        functions = []
        current_func = None
        i = 0

        while i < len(instructions):
            inst = instructions[i]

            # MSC 5.x prologue: PUSH BP (55) / MOV BP, SP (8B EC or 89 E5)
            is_prologue = False
            if (inst.mnemonic == 'push' and inst.op1 and
                inst.op1.type == OpType.REG16 and inst.op1.reg == 5):  # BP
                # Check next instruction is MOV BP, SP
                if i + 1 < len(instructions):
                    next_inst = instructions[i + 1]
                    if (next_inst.mnemonic == 'mov' and
                        next_inst.op1 and next_inst.op1.type == OpType.REG16 and
                        next_inst.op1.reg == 5 and  # BP
                        next_inst.op2 and next_inst.op2.type == OpType.REG16 and
                        next_inst.op2.reg == 4):    # SP
                        is_prologue = True

            if is_prologue:
                # Close previous function
                if current_func:
                    current_func.end = inst.offset
                    current_func.size = current_func.end - current_func.start
                    functions.append(current_func)

                # Start new function
                current_func = Function()
                current_func.start = inst.offset
                current_func.overlay_num = overlay_num
                current_func.is_overlay = overlay_num > 0

                # Check for SUB SP, N (local frame allocation)
                if i + 2 < len(instructions):
                    sub_inst = instructions[i + 2]
                    if (sub_inst.mnemonic == 'sub' and
                        sub_inst.op1 and sub_inst.op1.type == OpType.REG16 and
                        sub_inst.op1.reg == 4 and  # SP
                        sub_inst.op2 and sub_inst.op2.type in (OpType.IMM8, OpType.IMM16)):
                        current_func.local_size = sub_inst.op2.disp

            # Track calls within current function
            if current_func:
                current_func.inst_count += 1

                if inst.mnemonic == 'call':
                    if inst.op1 and inst.op1.type == OpType.REL16:
                        # Near call - target is relative to code range
                        target = start + inst.op1.disp
                        current_func.calls.append(target)
                    elif inst.op1 and inst.op1.type == OpType.FAR:
                        current_func.calls.append(
                            (inst.op1.far_seg, inst.op1.disp))

                # Overlay calls
                if inst.mnemonic == 'int' and inst.overlay_num >= 0:
                    current_func.ovl_calls.append(
                        (inst.overlay_num, inst.overlay_off))

                # Detect far returns
                if inst.mnemonic in ('retf',):
                    current_func.is_far = True

            i += 1

        # Close last function
        if current_func:
            current_func.end = end
            current_func.size = current_func.end - current_func.start
            functions.append(current_func)

        return functions

    def detect_all_functions(self):
        """Detect functions in resident code and all overlays."""
        # Resident code
        print(f"Analyzing resident code (0x{self.hdr_size:X} - 0x{self.img_size:X})...")
        resident_funcs = self._detect_functions_in_range(
            self.hdr_size, self.img_size, overlay_num=0)

        for i, f in enumerate(resident_funcs):
            f.name = f'res_{f.start:06X}'
        self.functions.extend(resident_funcs)
        print(f"  Found {len(resident_funcs)} functions in resident code")

        # Overlay modules
        for ovl in self.overlays:
            ovl_funcs = self._detect_functions_in_range(
                ovl.code_offset, ovl.code_offset + ovl.code_size,
                overlay_num=ovl.index)

            for i, f in enumerate(ovl_funcs):
                f.name = f'ovl{ovl.index:02d}_{f.start:06X}'
            ovl.functions = ovl_funcs
            self.functions.extend(ovl_funcs)
            print(f"  Overlay {ovl.index:2d}: {len(ovl_funcs)} functions "
                  f"({ovl.code_size} bytes)")

        # Build call graph (map callee → list of callers)
        for func in self.functions:
            for target in func.calls:
                if isinstance(target, int):
                    # Find function containing target
                    for f2 in self.functions:
                        if f2.start <= target < f2.end:
                            if func.name not in f2.called_by:
                                f2.called_by.append(func.name)
                            break

    def extract_strings(self):
        """Extract strings from the data section."""
        # Data section is roughly between the last code and overlay area
        # Scan the entire resident image for strings
        current = b''
        str_start = 0

        for i in range(self.hdr_size, self.img_size):
            b = self.data[i]
            if 32 <= b < 127:
                if not current:
                    str_start = i
                current += bytes([b])
            else:
                if len(current) >= 4:
                    self.strings[str_start] = current.decode('ascii', errors='replace')
                current = b''

    def categorize_functions(self):
        """Attempt to categorize functions by the strings they reference."""
        # Build a map of which address ranges contain interesting strings
        categories = {
            'gfx': ['.pic', '.pal', 'graphic', 'sprite', 'icon', 'VGA', 'EGA'],
            'sound': ['.cvl', 'sound', 'AdLib', 'Blaster', 'Tandy'],
            'input': ['Mouse', 'Keyboard', 'mouse', 'keyboard'],
            'game': ['city', 'unit', 'build', 'combat', 'wonder', 'advance',
                     'Civilization', 'civilization', 'GAME OVER'],
            'map': ['Map', 'map', 'terrain', 'continent', 'ocean'],
            'diplo': ['king', 'President', 'Warlord', 'Emperor', 'treaty',
                      'peace', 'war'],
            'save': ['Save', 'Load', 'CIVIL0', 'civil0', 'fame'],
            'ui': ['menu', 'Menu', 'Status', 'screen', 'display'],
            'init': ['Start', 'New Game', 'logo', 'credits', 'intro'],
        }

        for func in self.functions:
            # Check strings in the function's address range
            for addr, string in self.strings.items():
                if func.start <= addr < func.end:
                    for cat, keywords in categories.items():
                        if any(kw in string for kw in keywords):
                            func.category = cat
                            break

    def print_report(self, verbose=False):
        """Print analysis report."""
        print()
        print("=" * 70)
        print("  Sid Meier's Civilization (1991) - Function Analysis")
        print("=" * 70)

        print(f"\n  Total functions detected:  {len(self.functions)}")
        print(f"  Resident functions:        {sum(1 for f in self.functions if not f.is_overlay)}")
        print(f"  Overlay functions:         {sum(1 for f in self.functions if f.is_overlay)}")
        print(f"  Total instructions:        {sum(f.inst_count for f in self.functions)}")
        print(f"  Strings extracted:         {len(self.strings)}")

        # Overlay summary
        print(f"\n  === Overlay Module Functions ===")
        for ovl in self.overlays:
            print(f"  OVL {ovl.index:2d}: {len(ovl.functions):3d} functions, "
                  f"{ovl.code_size:6d} bytes")

        # Category summary
        cats = {}
        for f in self.functions:
            cat = f.category or 'unknown'
            if cat not in cats:
                cats[cat] = 0
            cats[cat] += 1
        if cats:
            print(f"\n  === Function Categories ===")
            for cat, count in sorted(cats.items(), key=lambda x: -x[1]):
                print(f"    {cat:12s}: {count:4d} functions")

        # Largest functions
        by_size = sorted(self.functions, key=lambda f: -f.size)
        print(f"\n  === Largest Functions (top 20) ===")
        print(f"  {'Name':<22s} {'Start':>8s} {'Size':>8s} {'Insts':>6s} "
              f"{'Stack':>6s} {'Far':>4s} {'Cat':>8s}")
        print(f"  {'-'*22} {'-'*8} {'-'*8} {'-'*6} {'-'*6} {'-'*4} {'-'*8}")
        for f in by_size[:20]:
            print(f"  {f.name:<22s} {f.start:08X} {f.size:7d}B {f.inst_count:5d} "
                  f"{f.local_size:5d}B {'Y' if f.is_far else 'N':>4s} "
                  f"{f.category or '-':>8s}")

        # Most-called functions
        by_callers = sorted(self.functions, key=lambda f: -len(f.called_by))
        print(f"\n  === Most-Called Functions (top 20) ===")
        print(f"  {'Name':<22s} {'Callers':>8s} {'Size':>8s} {'Cat':>8s}")
        print(f"  {'-'*22} {'-'*8} {'-'*8} {'-'*8}")
        for f in by_callers[:20]:
            if not f.called_by:
                break
            print(f"  {f.name:<22s} {len(f.called_by):7d}  {f.size:7d}B "
                  f"{f.category or '-':>8s}")

        # Overlay call hotspots
        all_ovl_calls = []
        for f in self.functions:
            for oc in f.ovl_calls:
                all_ovl_calls.append((oc, f.name))
        if all_ovl_calls:
            print(f"\n  === Overlay Call Summary ===")
            print(f"  Total overlay call sites: {len(all_ovl_calls)}")
            # Count per overlay
            ovl_counts = {}
            for (onum, ooff), fname in all_ovl_calls:
                ovl_counts[onum] = ovl_counts.get(onum, 0) + 1
            for onum in sorted(ovl_counts.keys()):
                print(f"    OVL {onum:02X}: {ovl_counts[onum]:3d} calls")

        if verbose:
            print(f"\n  === All Functions ===")
            for f in sorted(self.functions, key=lambda f: f.start):
                ovl_tag = f' (OVL {f.overlay_num})' if f.is_overlay else ''
                print(f"  {f.name:<22s} {f.start:08X}-{f.end:08X} "
                      f"{f.size:6d}B {f.inst_count:5d} insts{ovl_tag}")

    def export_symbols(self, path):
        """Export function map to a TOML-like symbols file."""
        with open(path, 'w') as out:
            out.write("# Civilization function symbols\n")
            out.write("# Auto-generated by analyze.py\n\n")

            out.write("[resident]\n")
            for f in sorted(self.functions, key=lambda f: f.start):
                if not f.is_overlay:
                    out.write(f'{f.name} = {{ '
                              f'start = 0x{f.start:06X}, '
                              f'end = 0x{f.end:06X}, '
                              f'size = {f.size}, '
                              f'far = {"true" if f.is_far else "false"}'
                              f' }}\n')

            for ovl in self.overlays:
                out.write(f'\n[overlay_{ovl.index:02d}]\n')
                for f in sorted(ovl.functions, key=lambda f: f.start):
                    out.write(f'{f.name} = {{ '
                              f'start = 0x{f.start:06X}, '
                              f'end = 0x{f.end:06X}, '
                              f'size = {f.size}, '
                              f'far = {"true" if f.is_far else "false"}'
                              f' }}\n')


def main():
    if len(sys.argv) < 2:
        print("Usage: analyze.py <civ.exe> [-v] [-symbols <output.toml>]")
        print("\nDetects function boundaries and builds call graph.")
        sys.exit(1)

    with open(sys.argv[1], 'rb') as f:
        data = f.read()

    verbose = '-v' in sys.argv
    sym_path = None
    if '-symbols' in sys.argv:
        idx = sys.argv.index('-symbols')
        sym_path = sys.argv[idx + 1]

    analyzer = Analyzer(data)
    analyzer.find_overlays()
    analyzer.detect_all_functions()
    analyzer.extract_strings()
    analyzer.categorize_functions()
    analyzer.print_report(verbose=verbose)

    if sym_path:
        analyzer.export_symbols(sym_path)
        print(f"\nSymbols exported to: {sym_path}")


if __name__ == '__main__':
    main()
