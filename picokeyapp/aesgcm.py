"""AES-GCM (NIST SP 800-38D) on top of the AES core in uvcrypto.

Why this exists
---------------
Two things in pico-fido need AES-GCM:

  * Vaulted Passkeys, where AES-256-GCM is one of the four PKV1 AEAD profiles
    and the cipher of the HPKE enrollment channel;
  * HPKE's `DHKEM(X448, HKDF-SHA512)` / `AES-256-GCM` suite (KEM 0x0021,
    AEAD 0x0002) used by enrollment protocol 2.

`cryptography` is not a build dependency, so GHASH and the counter mode are
implemented here and checked against NIST SP 800-38D test case 14 (256-bit
key, 60-byte plaintext with AAD).

Only encryption is needed on this side (the authenticator decrypts), but
decryption is implemented too so the vectors can be checked in both
directions.
"""

from __future__ import annotations

import struct

from . import uvcrypto as U


class GcmError(Exception):
    pass


_R = 0xE1000000000000000000000000000000     # GHASH's reflected polynomial


def _blk(data: bytes) -> int:
    """One 16-byte block as an integer.

    GCM numbers bits from the left, so the block is read big-endian and bit i
    of the string is bit 127-i of the integer. Reversing the BYTES (a common
    recipe for the bit-reflexive GF(2^128) formulation) is wrong here: it
    silently produces correct-looking ciphertext with a wrong tag, which is
    exactly the failure mode that makes an AEAD look "almost working".
    """
    return int.from_bytes(data, "big")


def _ghash_mul(x: int, y: int) -> int:
    """Multiply in GF(2^128) with the GCM polynomial, bit-reflexive form."""
    z = 0
    v = y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ _R
        else:
            v >>= 1
    return z


class GHash:
    def __init__(self, h: bytes):
        self._h = _blk(h)
        self._y = 0

    def update(self, block: bytes) -> None:
        self._y = _ghash_mul(self._y ^ _blk(block), self._h)

    def digest(self) -> bytes:
        return self._y.to_bytes(16, "big")


def _pad16(data: bytes) -> bytes:
    rem = len(data) % 16
    return b"\x00" * (16 - rem) if rem else b""


def _ghash(h: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    g = GHash(h)
    for i in range(0, len(aad), 16):
        g.update(aad[i:i + 16].ljust(16, b"\x00"))
    for i in range(0, len(ciphertext), 16):
        g.update(ciphertext[i:i + 16].ljust(16, b"\x00"))
    g.update(struct.pack(">QQ", len(aad) * 8, len(ciphertext) * 8))
    return g.digest()


def _inc32(block: bytes) -> bytes:
    """GCM's counter increment: only the last 32 bits, wrapped."""
    return block[:12] + struct.pack(">I", (struct.unpack(">I", block[12:])[0] + 1)
                                    & 0xFFFFFFFF)


def _ctr(key: bytes, j0: bytes, data: bytes) -> bytes:
    rk = U._key_expansion(key)
    out = bytearray()
    if not data:
        return b""
    ctr = j0
    for i in range(0, len(data), 16):
        ks = U._encrypt_block(ctr, rk)
        chunk = data[i:i + 16]
        out += bytes(a ^ b for a, b in zip(chunk, ks))
        ctr = _inc32(ctr)
    return bytes(out)


def _h(key: bytes) -> bytes:
    """H = AES_K(0^128)."""
    rk = U._key_expansion(key)
    return U._encrypt_block(b"\x00" * 16, rk)


def encrypt(key: bytes, iv: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """Return ciphertext || 16-byte tag. IV of 12 bytes is the normal case."""
    if len(key) not in (16, 24, 32):
        raise GcmError("AES-GCM needs a 16/24/32-byte key")
    if not iv:
        raise GcmError("AES-GCM needs a non-empty IV")
    h = _h(key)
    j0 = (iv + b"\x00\x00\x00\x01") if len(iv) == 12 else _ghash(h, b"", iv)
    ct = _ctr(key, _inc32(j0), plaintext)
    rk = U._key_expansion(key)
    s = _ghash(h, aad, ct)
    tag = bytes(a ^ b for a, b in zip(s, U._encrypt_block(j0, rk)))
    return ct + tag


def decrypt(key: bytes, iv: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    if len(blob) < 16:
        raise GcmError("AES-GCM blob is shorter than its 16-byte tag")
    h = _h(key)
    j0 = (iv + b"\x00\x00\x00\x01") if len(iv) == 12 else _ghash(h, b"", iv)
    ct, tag = blob[:-16], blob[-16:]
    rk = U._key_expansion(key)
    expected = bytes(a ^ b for a, b in zip(_ghash(h, aad, ct),
                                           U._encrypt_block(j0, rk)))
    if not _ct_equal(tag, expected):
        raise GcmError("GCM tag did not verify - wrong key or corrupt data")
    return _ctr(key, _inc32(j0), ct)


def _ct_equal(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0
