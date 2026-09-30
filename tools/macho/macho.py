#!/usr/bin/env python3
"""NeXTSTEP Mach-O reader: fat slices, load commands, segments, fvmlibs, symbols.

  python macho.py Doom.app/Doom            # dump every slice
  python macho.py Doom.app/Doom i386
"""
import re, struct, sys

CPU = {6: 'm68k', 7: 'i386', 11: 'hppa', 14: 'sparc'}
CODE_SECTIONS = ("__text", "__fvmlib_init0")
LC_SEGMENT, LC_SYMTAB, LC_UNIXTHREAD, LC_LOADFVMLIB, LC_IDFVMLIB = 1, 2, 5, 6, 7


def slices(data):
    """[(arch, bytes)] for a fat or thin Mach-O."""
    if data[:4] == b'\xca\xfe\xba\xbe':
        n = struct.unpack_from('>I', data, 4)[0]
        out = []
        for i in range(n):
            cpu, _, off, size, _ = struct.unpack_from('>5I', data, 8 + 20 * i)
            out.append((CPU.get(cpu, str(cpu)), data[off:off + size]))
        return out
    return [(MachO(data).arch, data)]


class MachO:
    def __init__(self, data):
        self.d = data
        self.e = {b'\xfe\xed\xfa\xce': '>', b'\xce\xfa\xed\xfe': '<'}[data[:4]]
        _, cpu, _, self.filetype, ncmds, _, self.flags = self.u('7I', 0)
        self.arch = CPU.get(cpu, str(cpu))
        self.segments, self.sections, self.fvmlibs, self.symbols = [], [], [], []
        self.entry = self.ident = None
        off = 28
        for _ in range(ncmds):
            cmd, size = self.u('2I', off)
            if cmd == LC_SEGMENT:
                name = self.cstr(off + 8, 16)
                vmaddr, vmsize, fileoff, filesize, _, _, nsects, _ = self.u('8I', off + 24)
                self.segments.append(dict(name=name, vmaddr=vmaddr, vmsize=vmsize, fileoff=fileoff, filesize=filesize))
                for s in range(nsects):
                    so = off + 56 + 68 * s
                    addr, ssize, soff = self.u('3I', so + 32)
                    self.sections.append(dict(seg=self.cstr(so + 16, 16), name=self.cstr(so, 16),
                                              addr=addr, size=ssize, offset=soff))
            elif cmd in (LC_LOADFVMLIB, LC_IDFVMLIB):
                stroff, minor, hdr = self.u('3I', off + 8)
                lib = dict(name=self.cstr(off + stroff, size - stroff), minor=minor, header_addr=hdr)
                if cmd == LC_IDFVMLIB:
                    self.ident = lib
                else:
                    self.fvmlibs.append(lib)
            elif cmd == LC_SYMTAB:
                symoff, nsyms, stroff, _ = self.u('4I', off + 8)
                for i in range(nsyms):
                    strx, typ, sect, desc, value = struct.unpack_from(self.e + 'IBBhI', data, symoff + 12 * i)
                    self.symbols.append(dict(name=self.cstr(stroff + strx, 256), type=typ, sect=sect, value=value))
            elif cmd == LC_UNIXTHREAD:
                # ponytail: entry pc for i386 (eip = 11th reg) and m68k (pc = 17th reg); others left None
                flavor, count = self.u('2I', off + 8)
                regs = self.u('%dI' % count, off + 16)
                self.entry = {'i386': regs[10] if count > 10 else None, 'm68k': regs[16] if count > 16 else None}.get(self.arch)
            off += size

    def u(self, fmt, off):
        return struct.unpack_from(self.e + fmt, self.d, off)

    def cstr(self, off, n):
        return self.d[off:off + n].split(b'\0', 1)[0].decode('latin-1')

    def pe_sections(self):
        """Sections in the shape disasm32.Disassembler expects (image_base 0).
        Code = the __TEXT sections that hold instructions; __fvmlib_init0 is the
        shlib-init stub the linker appends, and it is code too."""
        from types import SimpleNamespace
        return [SimpleNamespace(name='%s,%s' % (s['seg'], s['name']), virtual_address=s['addr'],
                                virtual_size=s['size'], raw_offset=s['offset'],
                                raw_size=0 if s['name'] in ('__bss', '__common') else s['size'],
                                is_code=s['seg'] == '__TEXT' and s['name'] in CODE_SECTIONS)
                for s in self.sections if s['size']]

    def gcc_prologues(self):
        """Every `push ebp; mov ebp, esp` as NeXT's gcc encodes it (55 89 E5, not
        MSVC's 55 8B EC), 4-aligned as the linker placed them. On NeXTDoom this
        is every framed function -- 674 of them."""
        out = set()
        for s in self.sections:
            if s['seg'] == '__TEXT' and s['name'] in CODE_SECTIONS:
                b = self.sect_bytes(s)
                out |= {s['addr'] + m.start() for m in re.finditer(b'\x55\x89\xe5', b)
                        if (s['addr'] + m.start()) % 4 == 0}
        return out

    def section(self, seg, name):
        return next((s for s in self.sections if s['seg'] == seg and s['name'] == name), None)

    def sect_bytes(self, s):
        return self.d[s['offset']:s['offset'] + s['size']]

    def read(self, addr, n):
        """Bytes at a VM address (file-backed part of a segment only)."""
        for g in self.segments:
            if g['vmaddr'] <= addr < g['vmaddr'] + g['filesize']:
                o = g['fileoff'] + addr - g['vmaddr']
                return self.d[o:o + n]
        return None

    def u32(self, addr):
        b = self.read(addr, 4)
        return struct.unpack(self.e + 'I', b)[0] if b and len(b) == 4 else None

    def cstr_at(self, addr):
        b = self.read(addr, 256)
        return b.split(b'\0', 1)[0].decode('latin-1') if b else None


if __name__ == '__main__':
    data = open(sys.argv[1], 'rb').read()
    for arch, sl in slices(data):
        if len(sys.argv) > 2 and arch != sys.argv[2]:
            continue
        m = MachO(sl)
        print('== %s  filetype=%d flags=%#x entry=%s' % (arch, m.filetype, m.flags, m.entry and hex(m.entry)))
        for g in m.segments:
            print('  seg %-10s vm %08x+%-8x file %x+%x' % (g['name'], g['vmaddr'], g['vmsize'], g['fileoff'], g['filesize']))
        for s in m.sections:
            print('    %s,%-18s %08x %x' % (s['seg'], s['name'], s['addr'], s['size']))
        for l in m.fvmlibs:
            print('  fvmlib %s minor=%d @%08x' % (l['name'], l['minor'], l['header_addr']))
        if m.ident:
            print('  idfvmlib %s @%08x' % (m.ident['name'], m.ident['header_addr']))
        print('  %d symbols' % len(m.symbols))
