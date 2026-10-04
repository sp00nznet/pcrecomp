"""Remove SteamStub 2.x (x86) from a PE32, statically: nothing is run, Steam is not needed.

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

Only the 2.x x86 layout seen in KotOR (2004 build, steamdrm.dll from
`s3_main`) is known. Any other layout fails one of the checks below with a
message saying which, rather than writing a broken file. emu_unpack.py is the
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
    and `add eax, disp` (the first encrypted block), in that order.
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
                and src.mem.base == X86_REG_EAX and src.mem.index == 0 and src.mem.disp:
            found.append(src.mem.disp)
        elif ins.mnemonic == 'add' and dst.type == X86_OP_REG and dst.reg == X86_REG_EAX \
                and src.type == X86_OP_IMM:
            found.append(src.imm)
        if len(found) == len(DRM_FIELDS):
            return dict(zip(DRM_FIELDS, found))
    raise StubError('found %d of the %d payload fields in steamdrm.dll' % (len(found), len(DRM_FIELDS)))


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

    opt = pe.OPTIONAL_HEADER.get_file_offset()
    struct.pack_into('<I', out, opt + 16, f['oep'] - base)    # AddressOfEntryPoint
    struct.pack_into('<I', out, opt + 64, 0)                  # CheckSum: stale now
    # Drop .bind when it is the last section and nothing follows it in the file:
    # left in, it is an executable section full of dead stub for every later tool.
    bind = pe.sections[-1]
    if bind.Name.rstrip(b'\0') == b'.bind' and bind.PointerToRawData + bind.SizeOfRawData >= len(raw):
        hdr = bind.get_file_offset()
        out[hdr:hdr + 40] = bytes(40)
        struct.pack_into('<H', out, pe.FILE_HEADER.get_file_offset() + 2, len(pe.sections) - 1)
        struct.pack_into('<I', out, opt + 56, bind.VirtualAddress)   # SizeOfImage
        del out[bind.PointerToRawData:]
    info = dict(f, header_va=hdr_va, checksum=checksum, payload_va=payload_va,
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
    try:
        stub_constants(b'\x55\x8b\xec' + bytes(0x60))
        raise AssertionError('accepted a plain prologue')
    except StubError:
        pass
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
    print('SteamStub 2.x: app %d, header 0x%08X, steamdrm.dll 0x%08X (0x%X bytes)'
          % (info['appid'], info['header_va'], info['drm_va'], info['drm_size']))
    print('  %s 0x%08X+0x%X %s; OEP 0x%08X' % (
        info['section'], info['code_va'], info['code_size'],
        'not encrypted' if info['flags'] & FLAG_CODE_NOT_ENCRYPTED else 'decrypted (AES-256-CBC)',
        info['oep']))
    with open(args.out, 'wb') as f:
        f.write(out)
    print('wrote %s' % args.out)


if __name__ == '__main__':
    sys.exit(main())
