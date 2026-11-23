r"""SafeDisc 1.x per-page .txt decryptor primitive (measured on FS2000.EXE).

The shell reconstructs its own obfuscated .txt a page at a time. The inner
decrypt loop (FS2000.EXE at 0x426728..0x4267eb, reached from the patch engine
0x415a80) is, per byte i:

    out[i] = cipher[i] ^ foldbyte(K) ^ mask[i]
    K      = (K + out[i]) & 0xFFFFFFFF          # 32-bit running accumulator at [0x435A70]

where `foldbyte(K) = (K ^ (K>>8) ^ (K>>16) ^ (K>>24)) & 0xFF` xors the four
bytes of the key state together, `cipher` is the page being transformed in
place (pointer at [ebp+0x14]) and `mask` is a second byte stream (pointer at
[ebp+0x1c]); both pointers advance one byte per iteration. A second pass over
the data (0x426d85) shares the same K accumulator, so K is *stateful across
passes and pages* -- it is not reseeded from the page index.

This is **stage 2** of a two-stage per-page scheme. `mask` is the mapped `.txt2`
section (cleartext, one page per `.txt` page) and is correct by construction;
`cipher` is the `P` intermediate produced by **stage 1** -- an RC4-keyed 8-byte
block transform (helper tail `0x426490`, S-box at `0x435A60`, 512 blocks/page).

This module is the reference for the stage-2 primitive and a self-test against
the real decrypted shell. It is NOT the whole unwrapper. Page 0 reconstructs
byte-for-byte; pages 0x402000+ do not, and the divergence is isolated to stage 1
producing a wrong `P` for page 1 while `mask` and the stage-2 `K` carry are
proven correct (see docs/safedisc1.md "Narrowed to stage 1"). Having stage 2
pinned down is what let the bug be localised to stage 1 rather than the XOR math.
"""


def foldbyte(k):
    return (k ^ (k >> 8) ^ (k >> 16) ^ (k >> 24)) & 0xFF


def decrypt_page(cipher, mask, k=0):
    """Return (plaintext, k) for one pass of the primitive. `mask` must be at
    least len(cipher) bytes; `k` is the running 32-bit accumulator."""
    out = bytearray(len(cipher))
    for i in range(len(cipher)):
        o = cipher[i] ^ foldbyte(k) ^ mask[i]
        out[i] = o
        k = (k + o) & 0xFFFFFFFF
    return bytes(out), k


def _selftest():
    # A real input/output vector captured from the emulator at the first inner
    # loop over page 0 (0x401000), K=0: cipher[] and mask[] as the loop read
    # them, expected[] = the matching bytes of the decrypted shell (shell.bin).
    cipher = bytes.fromhex('035679f39cde7f')
    mask = bytes.fromhex('558bec83ec0856')
    expected = bytes.fromhex('568b74240856ff')   # = shell.bin[0x1000:0x1007]
    out, k = decrypt_page(cipher, mask, 0)
    assert out == expected, 'cipher primitive mismatch: %s != %s' % (out.hex(), expected.hex())
    assert k == sum(expected) & 0xFFFFFFFF
    # foldbyte identity on a known value
    assert foldbyte(0xEF189825) == 0x4A
    print('safedisc1_cipher self-test ok: primitive reproduces shell.bin page-0 bytes')


if __name__ == '__main__':
    _selftest()
