#!/usr/bin/env python3
"""Read-only NeXTSTEP UFS (4.3BSD FFS) reader for NeXT-labelled disk images.

  python ufs.py hd.img ls /NextApps
  python ufs.py hd.img get /LocalApps/Doom.app out/Doom.app     # file or whole tree
  python ufs.py hd.img find Doom
"""
import os, struct, sys

class UFS:
    def __init__(self, path):
        self.f = open(path, 'rb')
        lbl = self._read(0, 1 << 16).find(b'dlV3')
        if lbl < 0:
            raise SystemExit('no NeXT disklabel (dlV3)')
        secsize = struct.unpack('>I', self._read(lbl + 0x5c, 4))[0]
        front = struct.unpack('>H', self._read(lbl + 0x70, 2))[0]
        # ponytail: first partition only (base 0 after the front porch), add dl_part[] parsing for multi-partition disks
        self.base = front * secsize
        sb = self._read(self.base + 8192, 2048)
        for e in '<>':
            if struct.unpack(e + 'I', sb[1372:1376])[0] == 0x011954:
                self.e = e
                break
        else:
            raise SystemExit('no UFS superblock at %#x' % (self.base + 8192))
        g = lambda o: struct.unpack(self.e + 'i', sb[o:o + 4])[0]
        self.cgoffset, self.cgmask, self.iblkno = g(24), g(28), g(16)
        self.bsize, self.fsize, self.frag = g(48), g(52), g(56)
        self.nindir, self.inopb, self.ipg, self.fpg = g(116), g(120), g(184), g(188)

    def _read(self, off, n):
        self.f.seek(off)
        return self.f.read(n)

    def _frag(self, fbn, n):
        return self._read(self.base + fbn * self.fsize, n)

    def inode(self, ino):
        cg = ino // self.ipg
        cgstart = self.fpg * cg + self.cgoffset * (cg & ~self.cgmask)
        fbn = cgstart + self.iblkno + ((ino % self.ipg) // self.inopb) * self.frag
        raw = self._frag(fbn, self.bsize)[(ino % self.inopb) * 128:][:128]
        u = lambda fmt, o: struct.unpack_from(self.e + fmt, raw, o)[0]
        size = u('Q', 8)
        return {'mode': u('H', 0), 'size': size, 'mtime': u('i', 24),
                'db': [u('i', 40 + 4 * i) for i in range(12)],
                'ib': [u('i', 88 + 4 * i) for i in range(3)], 'raw': raw}

    def _blocks(self, ino):
        yield from ino['db']
        def walk(blk, depth):
            if blk == 0:
                return
            ptrs = struct.unpack(self.e + '%di' % self.nindir, self._frag(blk, self.bsize))
            for p in ptrs:
                if depth:
                    yield from walk(p, depth - 1)
                else:
                    yield p
        for depth, blk in enumerate(ino['ib']):
            yield from walk(blk, depth)

    def read(self, ino):
        if isinstance(ino, int):
            ino = self.inode(ino)
        if ino['mode'] & 0xF000 == 0xA000 and ino['size'] < 60:  # fast symlink
            return ino['raw'][40:40 + ino['size']]
        out, left = bytearray(), ino['size']
        for blk in self._blocks(ino):
            if left <= 0:
                break
            n = min(left, self.bsize)
            out += self._frag(blk, n) if blk else bytes(n)  # blk 0 = hole
            left -= n
        return bytes(out)

    def listdir(self, ino):
        d, i, out = self.read(ino), 0, {}
        while i + 8 <= len(d):
            num, reclen, namlen = struct.unpack_from(self.e + 'IHH', d, i)
            if reclen == 0:
                break
            if num:
                out[d[i + 8:i + 8 + namlen].decode('latin-1')] = num
            i += reclen
        return out

    def lookup(self, path):
        ino = 2
        for part in [p for p in path.split('/') if p]:
            ents = self.listdir(ino)
            if part not in ents:
                raise FileNotFoundError(path)
            ino = ents[part]
        return ino

    def walk(self, ino=2, path=''):
        for name, child in self.listdir(ino).items():
            if name in ('.', '..'):
                continue
            yield path + '/' + name, child
            if self.inode(child)['mode'] & 0xF000 == 0x4000:
                yield from self.walk(child, path + '/' + name)

    def extract(self, ino, dest):
        i = self.inode(ino)
        kind = i['mode'] & 0xF000
        if kind == 0x4000:
            os.makedirs(dest, exist_ok=True)
            for name, child in self.listdir(ino).items():
                if name not in ('.', '..'):
                    self.extract(child, os.path.join(dest, name))
        elif kind == 0x8000:
            open(dest, 'wb').write(self.read(i))
        elif kind == 0xA000:  # ponytail: symlinks become .symlink text files (Windows)
            open(dest + '.symlink', 'wb').write(self.read(i))


if __name__ == '__main__':
    fs, cmd, args = UFS(sys.argv[1]), sys.argv[2], sys.argv[3:]
    if cmd == 'ls':
        for name, ino in sorted(fs.listdir(fs.lookup(args[0] if args else '/')).items()):
            i = fs.inode(ino)
            print('%06o %10d %s' % (i['mode'], i['size'], name))
    elif cmd == 'find':
        for p, _ in fs.walk():
            if args[0].lower() in p.lower():
                print(p)
    elif cmd == 'get':
        fs.extract(fs.lookup(args[0]), args[1])
