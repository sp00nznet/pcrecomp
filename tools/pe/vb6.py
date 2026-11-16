"""
vb6.py - read a Visual Basic 5/6 executable's VB header.

A VB5/6 exe's entry point is `push <VBHeader>; call ThunRTMain` (an import
from MSVBVM60.DLL / MSVBVM50.DLL). The header ("VB5!" signature) leads to
ProjectInfo and the ObjectTable: the forms, modules and classes, and their
event tables. From that this says:

  * native or P-code: ProjectInfo.lpNativeCode is non-zero only in a
    native-compiled exe, and then the procedures are x86 in
    [ProjectInfo.lpCodeStart, lpCodeEnd). In a P-code exe they are P-code
    procedure descriptors interpreted by the runtime, and there is no x86 to
    lift.
  * the code range: everything else in a VB .text (the header, object
    tables, string constants, form data) is data, so a lift should not walk
    it (a linear sweep finds hundreds of junk "functions" there).
  * event handler addresses, seeds for the catalog: the runtime calls them
    through the forms' event sink tables, so no call instruction reaches
    them. Most are stubs below the code range (`sub [esp+4], n; jmp
    handler`, adjusting `this` from the control's sink to the form).

    python vb6.py <exe>          # summary
    python vb6.py <exe> --seeds  # event handler VAs, as JSON

Layouts: the well-known reverse-engineered VB6 structures (Alex Ionescu,
"Visual Basic Image Internal Structure Format"; Semi VB Decompiler).
"""
import json
import struct
import sys

import pefile

MOV_DESC = bytes((0xC7, 0x45, 0xEC))        # mov dword [ebp-14h], imm32
PUSH_EBP_MOV = bytes((0x55, 0x8B, 0xEC))    # push ebp; mov ebp, esp


class VB6Image:
    def __init__(self, path):
        self.pe = pefile.PE(path)
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.img = self.pe.get_memory_mapped_image()
        ep = self.base + self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        # push imm32 (68 xx xx xx xx) at the entry: the VB header.
        if self.img[ep - self.base] != 0x68:
            raise ValueError('entry point is not push <VBHeader>: not a VB5/6 exe')
        self.entry = ep
        self.header = self.u32(ep + 1)
        if self.read(self.header, 4) != b'VB5!':
            raise ValueError('no VB5! signature at 0x%08X' % self.header)
        pi = self.u32(self.header + 0x30)
        self.project_info = pi
        self.code_start = self.u32(pi + 0x0C)
        self.code_end = self.u32(pi + 0x10)
        self.native_code = self.u32(pi + 0x20)
        self.native = self.native_code != 0
        ot = self.u32(pi + 0x04)
        self.project_name = self.cstr(self.u32(ot + 0x40))
        n, arr = self.u16(ot + 0x2A), self.u32(ot + 0x30)
        self.objects = []
        for i in range(n):
            o = arr + i * 0x30
            info, kind = self.u32(o), self.u32(o + 0x28)
            handlers = []
            if info and kind & 2:                    # has OptionalObjectInfo, right after ObjectInfo
                opt = info + 0x38
                nctl, ctls = self.u32(opt + 0x20), self.u32(opt + 0x24)
                nev, ev = self.u16(opt + 0x28), self.u32(opt + 0x30)
                if ev:                               # the object's own events (Form_Load ...)
                    handlers += [self.u32(ev + 0x18 + 4 * k) for k in range(nev)]
                for c in range(nctl):                # each control's event handler table
                    ci = ctls + c * 0x28
                    t = self.u32(ci + 0x18)
                    if self.mapped(t):
                        handlers += [self.u32(t + 0x18 + 4 * k) for k in range(self.u16(ci + 2))]
            self.objects.append({'name': self.cstr(self.u32(o + 0x18)), 'type': kind,
                                 'handlers': [h for h in handlers if self.is_code(h)]})

    def read(self, va, n):
        return self.img[va - self.base:va - self.base + n]

    def u16(self, va):
        return struct.unpack('<H', self.read(va, 2))[0]

    def u32(self, va):
        return struct.unpack('<I', self.read(va, 4))[0]

    def cstr(self, va):
        return self.read(va, 256).split(b'\0')[0].decode('latin-1') if self.mapped(va) else ''

    def mapped(self, va):
        return 0 <= va - self.base < len(self.img) - 16

    def in_code(self, va):
        return self.code_start <= va < self.code_end

    def is_code(self, va):
        """In the native code range, or one of the stubs outside it that the
        runtime calls: an event stub `sub dword [esp+4], imm32; jmp handler`
        (81 6C 24 04 .. E9 ..), an import thunk `jmp [iat]` (FF 25), or a
        Declare stub `mov eax, [cache]; or eax, eax; je +2; jmp eax; push
        decl; mov eax, DllFunctionCall; call eax; jmp eax` (A1 .. 0B C0 74 02
        FF E0), which binds a `Declare Function` on its first call, or a
        bare `jmp handler` into the code range (a vtable slot's stub)."""
        if not self.mapped(va):
            return False
        b = self.read(va, 11)
        return (self.in_code(va) or b[:2] == b'\xff\x25'
                or (b[:4] == b'\x81\x6c\x24\x04' and b[8] == 0xE9)
                or (b[0] == 0xA1 and b[5:11] == b'\x0b\xc0\x74\x02\xff\xe0')
                or (b[0] == 0xE9 and self.in_code(va + 5 + struct.unpack_from('<i', b, 1)[0])))

    def seeds(self):
        """Every event handler entry (stubs included) the runtime can call,
        and every stub outside the code range that a stored dword points at
        (the forms' vtables point at their methods' stubs), and the
        procedures' cleanup blocks."""
        lo, hi = self.base, self.base + len(self.img)
        n = len(self.img) - 4
        stored = {v for k in range(4) for (v,) in struct.iter_unpack('<I', self.img[k:k + ((n - k) & ~3)])
                  if lo <= v < self.code_start and self.is_code(v)}
        return sorted(stored | {h for o in self.objects for h in o['handlers']} | set(self.cleanups()))

    def descriptors(self):
        """(procedure entry, descriptor) for each procedure with a VB frame:
        it stores its descriptor in the frame, `mov dword [ebp-14h], desc`
        (C7 45 EC imm32), right after the prologue."""
        lo = self.code_start - self.base
        code = self.img[lo:self.code_end - self.base]
        at = code.find(MOV_DESC)
        while at >= 0:
            desc = struct.unpack_from('<I', code, at + 3)[0]
            entry = code.rfind(PUSH_EBP_MOV, max(0, at - 0x40), at)
            if entry >= 0 and self.mapped(desc + 0x18) and not self.in_code(desc):
                yield self.code_start + entry, desc
            at = code.find(MOV_DESC, at + 1)

    def cleanups(self):
        """The code a descriptor names at +4 and +0Ch: the procedure's exit
        and cleanup blocks, which the runtime's error handler calls (with the
        procedure's ebp) when it unwinds the frame."""
        return sorted({v for _, d in self.descriptors() for v in (self.u32(d + 4), self.u32(d + 12))
                       if self.in_code(v)})

    def error_resumes(self):
        """{procedure entry: [addresses]} where the runtime's error handling
        continues inside a procedure: its `On Error GoTo` labels and its
        `Resume Next` points, one per statement. desc+10h is the handler
        table (count, then {id, address} pairs) and desc+14h the resume table
        (count, then an address per statement). __vbaExceptHandler continues
        at one of them with the procedure's own ebp and esp: a jump into the
        middle of its body."""
        out = {}
        for entry, desc in self.descriptors():
            pts = []
            h, r = self.u32(desc + 0x10), self.u32(desc + 0x14)
            if self.mapped(h) and self.u32(h) < 256:
                pts += [self.u32(h + 8 + 8 * k) for k in range(self.u32(h))]
            if self.mapped(r) and self.u32(r) < 4096:
                pts += [self.u32(r + 4 + 4 * k) for k in range(self.u32(r))]
            pts = sorted({p for p in pts if self.in_code(p)})
            if pts:
                out[entry] = pts
        return out


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    vb = VB6Image(sys.argv[1])
    if '--seeds' in sys.argv:
        print(json.dumps(['0x%08X' % a for a in vb.seeds()]))
        return
    print('VB header 0x%08X, project %r, %s' % (vb.header, vb.project_name,
                                                'NATIVE code' if vb.native else 'P-CODE'))
    print('code 0x%08X-0x%08X' % (vb.code_start, vb.code_end))
    for o in vb.objects:
        print('  %-24s type 0x%05X  %3d event handlers' % (o['name'], o['type'], len(o['handlers'])))


if __name__ == '__main__':
    main()
