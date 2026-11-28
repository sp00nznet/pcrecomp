"""Remove SteamStub 2.x and 3.x (x86) from a PE32, statically: nothing is run, Steam is not needed.

SteamStub is the wrapper Steam puts on retail executables: the code section is
AES-encrypted and the entry point moves into a `.bind` section. Every key it
uses is in the file, so this decodes the layers the way the stub would and
writes the original executable back out:

  1. The stub header (0x364 bytes on KotOR) is a running XOR: each dword is
     XORed with the previous *encoded* dword, starting from a seed. The stub's
     own first instructions name the header VA (`mov [ebp-x], imm32`), the
     dword count (`mov ecx, imm32`) and the seed (the next `mov [ebp-x], imm32`),
     so they are read from there rather than hard-coded.
  2. The header points at a payload block, encoded the same way with the
     stub's checksum as the seed. Its first dword *is* that checksum when the
     block is usable; otherwise Steam writes it at launch, and this tool stops.
  3. The payload holds the location, size and XTEA key of Valve's
     `steamdrm.dll`, which sits XTEA-encrypted (32 rounds, CBC, IV 0x55555555
     twice) inside `.bind`. The stub loads it in memory and calls one export.
  4. That export reads the code section's AES-256 key, its first encrypted
     block, the OEP and the code range from the payload, at offsets that are
     compiled into steamdrm.dll. They are found as the `mov r32, [eax+disp]` /
     `lea` / `add eax, disp` run right after the export checks the payload's
     first dword (`cmp dword ptr [eax], checksum`), so a steamdrm build that
     moves its fields still parses.
  5. The code decrypts as AES-256-CBC with the IV ECB-decrypted from the
     first block, PKCS#7-padded, which is the same scheme as SteamStub 3.x.

The result gets the OEP as its entry point and loses `.bind` when that is the
last thing in the file (it always is on KotOR). The original import table was never touched by the
wrapper -- the stub calls through it -- so nothing needs rebuilding.

    python tools/drm/steamstub.py swkotor.exe swkotor_unwrapped.exe
    python tools/drm/steamstub.py --selftest

Two x86 layouts are known. The 2.x one above, seen in KotOR (2004 build,
steamdrm.dll from `s3_main`); and the older one on Unreal Tournament's Steam
build (unwrap_v20): no steamdrm.dll at all, the stub copies its header with
`rep movsd`, the header's first dword is its own XOR seed, and the code section
is the same running XOR again, keyed by a header field. Any other layout fails
one of the checks below with a message saying which, rather than writing a
broken file.

3.x (Shadows of the Empire's Steam build) is simpler to unwrap, because the
code key is in the header rather than in steamdrm.dll: the stub opens with
`call $+5` to find itself, copies a 0xF0-byte header from just below its entry,
undoes the running XOR (seeded by the header's first dword, signature
0xC0DEC0DF), and hands it to steamdrm.dll. The header carries the OEP, the code
section, the AES-256 key, an ECB-encrypted IV and the code's first 16 bytes
(stolen from the section). The code decrypts as CBC over those 16 bytes plus
the section. The layout was read from the stub's own code and checked by
decrypting: the OEP disassembles to the MSVC CRT start.

Two more 3.x forms (V3_LAYOUTS, V3_COPY_LOOP), from the Steam builds of the
X-Wing games:

  - A 0xD0-byte header with signature 0xC0DEC0DE and 32-bit fields (X-Wing vs
    TIE Fighter, Balance of Power, X-Wing Alliance). Its layout was read from
    the stub's code and the steamdrm.dll it decrypts (XTEA, the key at +0x88):
    the stub returns to base + [+0x1C]; the DLL's export checks the signature
    and skips the code step when flag 4 of [+0x34] is set, and otherwise
    decrypts base + [+0x40], [+0x44] bytes with the 32-byte key at +0x48,
    feeding the 32 bytes at +0x68 (the encrypted IV, then the stolen first
    block) ahead of the section: the same scheme as above, at other offsets.
  - An unoptimized build of the stub (X-Wing and TIE Fighter), whose header is
    the 0xF0-byte one but is copied by a byte loop from `mov ecx, [ebp+8];
    sub ecx, size` instead of `push size; lea eax, [ebx-size]`.

emu_unpack.py is the
fallback for a wrapper this cannot parse: it gets as far as SteamAPI_Init.
"""
import argparse
import re
import struct
import sys

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_EAX

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:                                      # pragma: no cover
    sys.exit('steamstub needs the cryptography package: pip install cryptography')

M32 = 0xFFFFFFFF

# The 2.x x86 stub opens with push ebx/ecx/edx/esi/edi/ebp; mov ebp, esp; sub esp, 0x1000.
STUB_PROLOGUE = bytes.fromhex('5351525657558bec81ec00100000')

# Header fields, as the KotOR stub reads them. ponytail: one layout known;
# a second title with a different one would make this a per-variant table.
H_CHECKSUM, H_PAYLOAD_VA, H_PAYLOAD_SIZE = 0x20, 0x24, 0x28
H_APPID = 0x34                      # app id as ASCII digits
H_DRM_PTR, H_DRM_SIZE, H_DRM_KEY = 0x3C, 0x40, 0x44   # offsets *into the payload*

DRM_FIELDS = ('flags', 'appid', 'oep', 'code_va', 'code_size', 'aes_key', 'first_block')
FLAG_CODE_NOT_ENCRYPTED = 4         # steamdrm skips the AES step when set


class StubError(Exception):
    pass


def xor_chain(data, seed):
    """Undo the running XOR: out[i] = in[i] ^ in[i-1], with in[-1] = seed."""
    n = len(data) // 4
    words = struct.unpack_from('<%dI' % n, data)
    out, key = [], seed
    for w in words:
        out.append(w ^ key)
        key = w
    return struct.pack('<%dI' % n, *out)


def xtea_cbc_decrypt(data, key, iv=(0x55555555, 0x55555555)):
    """32-round XTEA, CBC, as the stub runs it; a trailing partial block stays as is."""
    out = bytearray()
    prev = iv
    for i in range(0, len(data) // 8 * 8, 8):
        v0, v1 = c0, c1 = struct.unpack_from('<II', data, i)
        s = (32 * 0x9E3779B9) & M32
        for _ in range(32):
            v1 = (v1 - ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (s + key[(s >> 11) & 3]))) & M32
            s = (s + 0x61C88647) & M32
            v0 = (v0 - ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (s + key[s & 3]))) & M32
        out += struct.pack('<II', v0 ^ prev[0], v1 ^ prev[1])
        prev = (c0, c1)
    return bytes(out) + data[len(data) // 8 * 8:]


def stub_constants(entry_bytes):
    """(header VA, header dword count, header seed) from the stub's first instructions."""
    if not entry_bytes.startswith(STUB_PROLOGUE):
        raise StubError('entry point is not a SteamStub 2.x x86 stub '
                        '(prologue %s)' % entry_bytes[:14].hex())
    head = entry_bytes[:0x60]
    movs = re.findall(rb'\xC7\x85(.{4})(.{4})', head, re.S)   # mov [ebp+disp32], imm32
    count = re.search(rb'\xB9(.{4})', head, re.S)                # mov ecx, imm32
    if len(movs) < 2 or not count:
        raise StubError('stub does not set up its header the 2.x way')
    hdr_va = struct.unpack('<I', movs[0][1])[0]
    seed = struct.unpack('<I', movs[1][1])[0]
    return hdr_va, struct.unpack('<I', count.group(1))[0], seed


def drm_field_offsets(dll, checksum):
    """Payload offsets of DRM_FIELDS, read from steamdrm.dll's code.

    The export compares payload[0] with the checksum, then copies its fields
    out: five `mov r32, [eax+disp]`, then `lea r32, [eax+disp]` (the AES key)
    and `add eax, disp` (the first encrypted block), in that order. A build that
    never encrypts the code (SimCity 4) compiles the last four as `[eax+0]`.
    """
    at = dll.find(b'\x81\x38' + struct.pack('<I', checksum))
    if at < 0:
        raise StubError('steamdrm.dll never compares the payload with the checksum')
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    found = []
    for ins in md.disasm(dll[at:at + 0x100], 0):
        ops = ins.operands
        if len(ops) != 2:
            continue
        dst, src = ops
        if ins.mnemonic in ('mov', 'lea') and dst.type == X86_OP_REG and src.type == X86_OP_MEM \
                and src.mem.base == X86_REG_EAX and src.mem.index == 0:
            found.append(src.mem.disp)
        elif ins.mnemonic == 'add' and dst.type == X86_OP_REG and dst.reg == X86_REG_EAX \
                and src.type == X86_OP_IMM:
            found.append(src.imm)
        if len(found) == len(DRM_FIELDS):
            return dict(zip(DRM_FIELDS, found))
    raise StubError('found %d of the %d payload fields in steamdrm.dll' % (len(found), len(DRM_FIELDS)))


# The older stub: `mov esi, header; mov ecx, dwords; lea edi, [ebp-x]; rep movsd`
# right after the common prologue. Its header's first dword seeds the XOR over
# the rest; fields below are offsets into that decoded rest.
V20_COPY = re.compile(rb'\xBE(.{4})\xB9(.{4})\x8D\xBD.{4}\xF3\xA5', re.S)
V20_FLAGS, V20_OEP, V20_CODE_VA, V20_CODE_SIZE, V20_CODE_KEY, V20_APPID = 0x14, 0x28, 0x2C, 0x30, 0x34, 0x38
V20_FLAG_CODE_XORED = 4             # the stub runs the XOR over the code only when set


def unwrap_v20(raw, pe, entry_bytes):
    """(unwrapped file bytes, info dict) for the older stub, or None if it is not one."""
    m = V20_COPY.match(entry_bytes, len(STUB_PROLOGUE))
    if not entry_bytes.startswith(STUB_PROLOGUE) or not m:
        return None
    base = pe.OPTIONAL_HEADER.ImageBase
    hdr_va, ndw = struct.unpack('<I', m.group(1))[0], struct.unpack('<I', m.group(2))[0]
    off = pe.get_offset_from_rva(hdr_va - base)
    if off is None or not 2 <= ndw <= 0x1000 or off + 4 * ndw > len(raw):
        raise StubError('header 0x%08X (%d dwords) is not backed by the file' % (hdr_va, ndw))
    seed = struct.unpack_from('<I', raw, off)[0]
    hdr = xor_chain(raw[off + 4:off + 4 * ndw], seed)
    word = lambda o: struct.unpack_from('<I', hdr, o)[0]   # noqa: E731
    f = {k: word(o) for k, o in (('flags', V20_FLAGS), ('oep', V20_OEP), ('code_va', V20_CODE_VA),
                                 ('code_size', V20_CODE_SIZE), ('appid', V20_APPID))}
    code = next((s for s in pe.sections if s.VirtualAddress == f['code_va'] - base), None)
    if code is None:
        raise StubError('code VA 0x%08X is not the start of a section' % f['code_va'])
    if not f['code_va'] <= f['oep'] < f['code_va'] + code.Misc_VirtualSize:
        raise StubError('OEP 0x%08X is outside the code section' % f['oep'])
    if f['code_size'] > code.SizeOfRawData:
        raise StubError('code size 0x%X is larger than the section on disk' % f['code_size'])
    out = bytearray(raw)
    if f['flags'] & V20_FLAG_CODE_XORED:
        lo = code.PointerToRawData
        out[lo:lo + f['code_size'] // 4 * 4] = xor_chain(raw[lo:lo + f['code_size']], word(V20_CODE_KEY))
    finish(out, pe, f['oep'])
    return bytes(out), dict(f, variant='2.0', header_va=hdr_va, section=code.Name.rstrip(b'\0').decode(),
                            encryption='XOR chain' if f['flags'] & V20_FLAG_CODE_XORED else None)


# The 3.x x86 stub: `call $+5; push eax..ebp; mov eax, [esp+0x1C]; sub eax, 5`,
# so eax is its own entry VA, which it hands to its main function. That copies
# the header from just below the entry, and the header's first dword seeds the
# same running XOR over the rest. Two copies are known: an optimized
# build's `push size; lea eax, [ebx-size]; push eax` (Shadows of the Empire,
# app 560170; X-Wing vs TIE Fighter) and an unoptimized build's byte loop from
# `mov ecx, [ebp+8]; sub ecx, size` (X-Wing, TIE Fighter).
V3_PROLOGUE = bytes.fromhex('e800000000505351525657558b44241c2d05000000')
V3_COPY = re.compile(rb'\x68(.{4})\x8D\x83(.{4})\x50', re.S)      # push size; lea eax, [ebx-size]; push eax
V3_COPY_LOOP = re.compile(rb'\x8B\x4D\x08\x81\xE9(.{4})', re.S)     # mov ecx, [ebp+8]; sub ecx, size

# The header's fields, by its signature (offsets into the decoded header; the
# OEP and the code section are RVAs). Each layout was read from a stub's code.
V3_LAYOUTS = {
    # 0xF0 bytes: Shadows of the Empire, X-Wing, TIE Fighter.
    0xC0DEC0DF: dict(size=0xF0, image_base=0x08, oep=0x20, appid=0x38, flags=0x3C, code_va=0x48,
                     code_size=0x50, aes_key=0x58, aes_iv=0x78, first_block=0x88, plain_flag=None),
    # 0xD0 bytes, 32-bit fields: X-Wing vs TIE Fighter, Balance of Power, X-Wing
    # Alliance. The stub returns to base + [+0x1C]; steamdrm.dll's export skips
    # the code step when flag 4 of [+0x34] is set, else decrypts base + [+0x40],
    # [+0x44] bytes with the key at +0x48 and the 32 bytes at +0x68 ahead of them.
    0xC0DEC0DE: dict(size=0xD0, image_base=0x08, oep=0x1C, appid=0x30, flags=0x34, code_va=0x40,
                     code_size=0x44, aes_key=0x48, aes_iv=0x68, first_block=0x78, plain_flag=4),
}


def v3_decrypt_code(hdr, enc, size, lay=V3_LAYOUTS[0xC0DEC0DF]):
    """The code section, decrypted: AES-256-CBC over the header's stolen first
    block followed by the section, IV ECB-decrypted from the header, PKCS#7."""
    key = hdr[lay['aes_key']:lay['aes_key'] + 32]
    iv = Cipher(algorithms.AES(key), modes.ECB()).decryptor().update(hdr[lay['aes_iv']:lay['aes_iv'] + 16])
    plain = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor().update(
        hdr[lay['first_block']:lay['first_block'] + 16] + enc[:size])
    pad = plain[-1]
    if not 1 <= pad <= 16 or plain[-pad:] != bytes([pad]) * pad or len(plain) - pad != size:
        raise StubError('code section did not decrypt (bad padding): wrong key or layout')
    return plain[:-pad]


def v3_header_size(entry_bytes):
    """The header size the 3.x stub copies, from either known copy."""
    m = V3_COPY.search(entry_bytes, 0x80, 0xC0) or V3_COPY.search(entry_bytes)
    if m:
        size, neg = struct.unpack('<I', m.group(1))[0], struct.unpack('<i', m.group(2))[0]
    else:
        m = V3_COPY_LOOP.search(entry_bytes)
        if not m:
            raise StubError('3.x stub does not copy its header the known way')
        size = struct.unpack('<I', m.group(1))[0]
        neg = -size
    if not 0x40 <= size <= 0x400 or neg != -size:
        raise StubError('3.x header size 0x%X / 0x%X is not plausible' % (size, -neg))
    return size


def unwrap_v3(raw, pe, entry_bytes):
    """(unwrapped file bytes, info dict) for the 3.x stub, or None if it is not one."""
    if not entry_bytes.startswith(V3_PROLOGUE):
        return None
    size = v3_header_size(entry_bytes)
    base = pe.OPTIONAL_HEADER.ImageBase
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    off = pe.get_offset_from_rva(ep - size)
    seed = struct.unpack_from('<I', raw, off)[0]
    hdr = struct.pack('<I', seed) + xor_chain(raw[off + 4:off + size], seed)
    word = lambda o: struct.unpack_from('<I', hdr, o)[0]   # noqa: E731
    lay = V3_LAYOUTS.get(word(4))
    if lay is None:
        raise StubError('3.x header signature 0x%08X is none of %s' % (
            word(4), ', '.join('0x%08X' % s for s in V3_LAYOUTS)))
    if size != lay['size']:
        raise StubError('3.x header with signature 0x%08X is 0x%X bytes, not 0x%X' % (word(4), size, lay['size']))
    if word(lay['image_base']) != base:
        raise StubError('3.x header image base 0x%08X is not the PE\'s' % word(lay['image_base']))
    f = {k: word(lay[k]) for k in ('flags', 'appid', 'code_size')}
    f['oep'], f['code_va'] = base + word(lay['oep']), base + word(lay['code_va'])
    code = next((s for s in pe.sections if s.VirtualAddress == word(lay['code_va'])), None)
    if code is None:
        raise StubError('code VA 0x%08X is not the start of a section' % f['code_va'])
    if not f['code_va'] <= f['oep'] < f['code_va'] + code.Misc_VirtualSize:
        raise StubError('OEP 0x%08X is outside the code section' % f['oep'])
    if f['code_size'] > code.SizeOfRawData:
        raise StubError('code size 0x%X is larger than the section on disk' % f['code_size'])
    # ponytail: the 0xF0 layout's flags are not decoded (no unencrypted file has
    # turned up; the padding check refuses one). The 0xD0 layout's code-step flag
    # was read from its steamdrm.dll.
    encrypted = not (lay['plain_flag'] and f['flags'] & lay['plain_flag'])
    lo = code.PointerToRawData
    out = bytearray(raw)
    if encrypted:
        out[lo:lo + f['code_size']] = v3_decrypt_code(hdr, raw[lo:lo + f['code_size']], f['code_size'], lay)
    finish(out, pe, f['oep'])
    return bytes(out), dict(f, variant='3.x', signature=word(4), header_va=base + ep - size,
                            encryption='AES-256-CBC' if encrypted else None, section=code.Name.rstrip(b'\0').decode())


def finish(out, pe, oep):
    """Point the entry at the OEP and drop .bind when nothing follows it in the file
    but, at most, the certificate table: left in, .bind is an executable section
    full of dead stub for every later tool. The certificate (Authenticode) signed
    the wrapped file, so it cannot match this one; it goes with .bind, and so
    does its directory entry (which holds a file offset, not an RVA)."""
    opt = pe.OPTIONAL_HEADER.get_file_offset()
    struct.pack_into('<I', out, opt + 16, oep - pe.OPTIONAL_HEADER.ImageBase)   # AddressOfEntryPoint
    struct.pack_into('<I', out, opt + 64, 0)                                    # CheckSum: stale now
    bind = pe.sections[-1]
    end = bind.PointerToRawData + bind.SizeOfRawData
    dirs = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    cert = dirs[4] if len(dirs) > 4 else None       # IMAGE_DIRECTORY_ENTRY_SECURITY
    signed = bool(cert and cert.Size and cert.VirtualAddress == end and end + cert.Size >= len(out))
    if bind.Name.rstrip(b'\0') == b'.bind' and (end >= len(out) or signed):
        if signed:
            struct.pack_into('<II', out, cert.get_file_offset(), 0, 0)
        hdr = bind.get_file_offset()
        out[hdr:hdr + 40] = bytes(40)
        struct.pack_into('<H', out, pe.FILE_HEADER.get_file_offset() + 2, len(pe.sections) - 1)
        struct.pack_into('<I', out, opt + 56, bind.VirtualAddress)   # SizeOfImage
        del out[bind.PointerToRawData:]


def unwrap(raw):
    """(unwrapped file bytes, info dict) for a SteamStub 2.x x86 executable."""
    pe = pefile.PE(data=raw, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase

    def file_at(va, n):
        off = pe.get_offset_from_rva(va - base)
        if off is None or off + n > len(raw):
            raise StubError('0x%08X+0x%X is not backed by the file' % (va, n))
        return raw[off:off + n]

    entry = base + pe.OPTIONAL_HEADER.AddressOfEntryPoint
    other = unwrap_v20(raw, pe, file_at(entry, 0x60)) or unwrap_v3(raw, pe, file_at(entry, 0x100))
    if other:
        return other
    hdr_va, ndw, seed = stub_constants(file_at(entry, 0x60))
    hdr = xor_chain(file_at(hdr_va, 4 * ndw), seed)
    word = lambda b, o: struct.unpack_from('<I', b, o)[0]   # noqa: E731

    checksum = word(hdr, H_CHECKSUM)
    payload_va, payload_size = word(hdr, H_PAYLOAD_VA), word(hdr, H_PAYLOAD_SIZE)
    if not 0 < payload_size <= 0x10000:
        raise StubError('header payload size 0x%X is not plausible' % payload_size)
    enc = file_at(payload_va, payload_size)
    if word(enc, 0) != checksum:
        raise StubError('payload is locked (first dword 0x%08X, checksum 0x%08X): this stub '
                        'expects Steam to unlock it at launch' % (word(enc, 0), checksum))
    payload = enc[:4] + xor_chain(enc[4:], checksum)

    drm_va = word(payload, word(hdr, H_DRM_PTR))
    drm_size = word(payload, word(hdr, H_DRM_SIZE))
    drm_key = struct.unpack_from('<4I', payload, word(hdr, H_DRM_KEY))
    dll = xtea_cbc_decrypt(file_at(drm_va, drm_size), drm_key)
    if dll[:2] != b'MZ':
        raise StubError('steamdrm.dll did not decrypt to an MZ image')

    offs = drm_field_offsets(dll, checksum)
    f = {k: (payload[o:o + 32] if k in ('aes_key', 'first_block') else word(payload, o))
         for k, o in offs.items()}

    appid = hdr[H_APPID:H_APPID + 12].split(b'\0')[0].decode('ascii', 'replace')
    if appid.isdigit() and int(appid) != f['appid']:
        raise StubError('payload app id %d does not match the header\'s %s' % (f['appid'], appid))
    if f['flags'] & FLAG_CODE_NOT_ENCRYPTED:
        # The code-range fields are unused then (SimCity 4 reads them all from
        # payload+0), so the code section is the one holding the OEP.
        code = next((s for s in pe.sections if s.contains_rva(f['oep'] - base)), None)
        if code is None:
            raise StubError('OEP 0x%08X is outside every section' % f['oep'])
        f['code_va'], f['code_size'] = base + code.VirtualAddress, code.SizeOfRawData
    code = next((s for s in pe.sections if s.VirtualAddress == f['code_va'] - base), None)
    if code is None:
        raise StubError('code VA 0x%08X is not the start of a section' % f['code_va'])
    if not f['code_va'] <= f['oep'] < f['code_va'] + code.Misc_VirtualSize:
        raise StubError('OEP 0x%08X is outside the code section' % f['oep'])
    if f['code_size'] > code.SizeOfRawData:
        raise StubError('code size 0x%X is larger than the section on disk' % f['code_size'])

    out = bytearray(raw)
    if not f['flags'] & FLAG_CODE_NOT_ENCRYPTED:
        key = f['aes_key']
        buf = f['first_block'] + raw[code.PointerToRawData:code.PointerToRawData + f['code_size']]
        iv = Cipher(algorithms.AES(key), modes.ECB()).decryptor().update(buf[:16])
        plain = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor().update(buf[16:])
        pad = plain[-1]
        if not 1 <= pad <= 16 or plain[-pad:] != bytes([pad]) * pad or len(plain) - pad != f['code_size']:
            raise StubError('code section did not decrypt (bad padding): wrong key or layout')
        out[code.PointerToRawData:code.PointerToRawData + f['code_size']] = plain[:-pad]

    finish(out, pe, f['oep'])
    info = dict(f, variant='2.x', encryption=None if f['flags'] & FLAG_CODE_NOT_ENCRYPTED else 'AES-256-CBC',
                header_va=hdr_va, checksum=checksum, payload_va=payload_va,
                drm_va=drm_va, drm_size=drm_size, section=code.Name.rstrip(b'\0').decode())
    return bytes(out), info


def selftest():
    # Running XOR round trip.
    plain = struct.pack('<4I', 1, 2, 3, 0xDEADBEEF)
    enc, key = [], 0x067262EF
    for w in struct.unpack('<4I', plain):
        key = w ^ key
        enc.append(key)
    assert xor_chain(struct.pack('<4I', *enc), 0x067262EF) == plain

    # XTEA-CBC against an encryptor written from the textbook cipher.
    def xtea_enc(v0, v1, k):
        s = 0
        for _ in range(32):
            v0 = (v0 + ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (s + k[s & 3]))) & M32
            s = (s + 0x9E3779B9) & M32
            v1 = (v1 + ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (s + k[(s >> 11) & 3]))) & M32
        return v0, v1
    k = (0xFE4F25B6, 0xF5E62733, 0x0035242C, 0xC56A6730)
    msg, prev, ct = b'MZ\x90\0steamdrm.dll', (0x55555555, 0x55555555), b''
    for i in range(0, 16, 8):
        a, b = struct.unpack_from('<II', msg, i)
        prev = xtea_enc(a ^ prev[0], b ^ prev[1], k)
        ct += struct.pack('<II', *prev)
    assert xtea_cbc_decrypt(ct + b'xy', k) == msg + b'xy'

    # Stub constants and payload offsets from the bytes KotOR's stub and steamdrm.dll hold.
    stub = bytes.fromhex(
        '5351525657558bec81ec00100000c78578ffffff04f286008bb578ffffffb9d90000008dbd10fcffff'
        'f3a58d8510fcffff898504fcffffc785d4fbffffef6272068b85d4fbffff89')
    assert stub_constants(stub) == (0x0086F204, 0xD9, 0x067262EF)
    drm = bytes.fromhex(
        '813821c4c10374076a51e9790300008b88f80d0000890d286d04108b90540e00008915246d04108b90ec06'
        '000089152c6d04108b90980c00008915306d04108b90340b00008915346d04108d907405000005ac0b0000'
        'f6c1028915386d0410a33c6d0410')
    assert drm_field_offsets(b'\xcc' * 16 + drm, 0x03C1C421) == dict(zip(
        DRM_FIELDS, (0xDF8, 0xE54, 0x6EC, 0xC98, 0xB34, 0x574, 0xBAC)))
    # SimCity 4's steamdrm.dll (code not encrypted): the unused fields are [eax+0], still found.
    sc4 = bytes.fromhex(
        '8138ef5360d674076a51e9790300008b88d0080000890d286d04108b909c0200008915246d04108b90d40d'
        '000089152c6d04108b90000000008915306d04108b90000000008915346d04108d90000000000500000000'
        'f6c1028915386d0410a33c6d0410')
    assert drm_field_offsets(sc4, 0xD66053EF) == dict(zip(DRM_FIELDS, (0x8D0, 0x29C, 0xDD4, 0, 0, 0, 0)))
    try:
        stub_constants(b'\x55\x8b\xec' + bytes(0x60))
        raise AssertionError('accepted a plain prologue')
    except StubError:
        pass
    # The older stub's header copy, from Unreal Tournament's bytes (header 0x10964380, 0xDD dwords).
    ut = STUB_PROLOGUE + bytes.fromhex('be80439610b9dd0000008dbdd0f8fffff3a5')
    m = V20_COPY.match(ut, len(STUB_PROLOGUE))
    assert m and struct.unpack('<2I', m.group(1) + m.group(2)) == (0x10964380, 0xDD)
    assert not V20_COPY.match(stub, len(STUB_PROLOGUE))     # KotOR's stub is not the older one

    # 3.x: both header copies, as the stubs of Shadows of the Empire (and X-Wing
    # vs TIE Fighter, with 0xD0) and of X-Wing hold them, 0x80 into the entry
    # bytes where the stub's main function starts; then each layout's code as a
    # round trip (stolen first block + section, PKCS#7).
    pad = bytes(0x80 - len(V3_PROLOGUE))
    assert v3_header_size(V3_PROLOGUE + pad + bytes.fromhex('558bec81ece404000053' '68f00000008d8310ffffff50')) == 0xF0
    assert v3_header_size(V3_PROLOGUE + pad + bytes.fromhex('558bec81ece404000053' '68d00000008d8330ffffff50')) == 0xD0
    assert v3_header_size(V3_PROLOGUE + pad + bytes.fromhex(
        '558bec81ec4008000056c785c0fefffff00000008d8540faffff898588fdffff8b4d0881e9f0000000')) == 0xF0
    try:
        v3_header_size(V3_PROLOGUE + bytes(0x100))
        raise AssertionError('found a header copy in zeros')
    except StubError:
        pass
    key, iv = bytes(range(32)), bytes(range(16, 32))
    code = bytes(range(256)) * 2 + b'\xc3' * 16
    enc_iv = Cipher(algorithms.AES(key), modes.ECB()).encryptor().update(iv)
    ct = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor().update(code + b'\x10' * 16)
    for sig, lay in V3_LAYOUTS.items():
        hdr = bytearray(lay['size'])
        hdr[lay['aes_key']:lay['aes_key'] + 32], hdr[lay['aes_iv']:lay['aes_iv'] + 16] = key, enc_iv
        hdr[lay['first_block']:lay['first_block'] + 16] = ct[:16]
        assert v3_decrypt_code(bytes(hdr), ct[16:], len(code), lay) == code, hex(sig)
    print('steamstub selftest: ok')


def main():
    if '--selftest' in sys.argv:
        return selftest()
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('wrapped')
    ap.add_argument('out')
    args = ap.parse_args()
    raw = open(args.wrapped, 'rb').read()
    try:
        out, info = unwrap(raw)
    except StubError as e:
        sys.exit('steamstub: %s' % e)
    if info['variant'] == '2.x':
        print('SteamStub 2.x: app %d, header 0x%08X, steamdrm.dll 0x%08X (0x%X bytes)'
              % (info['appid'], info['header_va'], info['drm_va'], info['drm_size']))
    else:
        sig = ' (signature 0x%08X)' % info['signature'] if 'signature' in info else ''
        print('SteamStub %s%s: app %d, header 0x%08X' % (info['variant'], sig, info['appid'], info['header_va']))
    print('  %s 0x%08X+0x%X %s; OEP 0x%08X' % (
        info['section'], info['code_va'], info['code_size'],
        'decrypted (%s)' % info['encryption'] if info['encryption'] else 'not encrypted', info['oep']))
    with open(args.out, 'wb') as f:
        f.write(out)
    print('wrote %s' % args.out)


if __name__ == '__main__':
    sys.exit(main())
