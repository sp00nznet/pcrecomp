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

This module is the reference for that primitive and a self-test against the
real decrypted shell. It is NOT the whole unwrapper: cipher[] and mask[] are
themselves produced by earlier reconstruction steps inside the shell, and those
feeders -- not this primitive -- are where the headless emulator currently
diverges (see docs/safedisc1.md "The frontier"). Having the primitive pinned
down means a divergence can be localised to a wrong cipher/mask/K input rather
than to the arithmetic.
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
