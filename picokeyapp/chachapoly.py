"""ChaCha20-Poly1305 (RFC 8439) in pure Python.

Why this exists
---------------
pico-fido uses ChaCha20-Poly1305 in two places:

  * the 24-word backup / key-device (AUT) ceremony, where the encrypted key
    device blob and the MSE transport are protected with it, and
  * Vaulted Passkeys, where it is one of the four AEAD profiles.

`cryptography` is deliberately not a build requirement (it needs a Rust
toolchain for modern wheels), so this is the only way to reach those features
on Android. Everything here is verified against RFC 8439 test vectors and, for
the AEAD construction, against RFC 8439 section 2.8.

The firmware derives keys with HKDF-SHA-256 and calls
mbedtls_chachapoly_auth_decrypt(ctx, len-16, nonce, aad, aad_len, tag, data,
data) -- i.e. the 16-byte tag is appended to the ciphertext, which is exactly
the layout used below.
"""

from __future__ import annotations

import struct


class ChaChaPolyError(Exception):
    pass


# ------------------------------------------------------------------ ChaCha20

_MASK32 = 0xFFFFFFFF


def _rotl(v: int, n: int) -> int:
    return ((v << n) & _MASK32) | (v >> (32 - n))


def _quarter(state, a, b, c, d):
    state[a] = (state[a] + state[b]) & _MASK32
    state[d] = _rotl(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & _MASK32
    state[b] = _rotl(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & _MASK32
    state[d] = _rotl(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & _MASK32
    state[b] = _rotl(state[b] ^ state[c], 7)


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """One 64-byte ChaCha20 block. RFC 8439 section 2.3."""
    if len(key) != 32:
        raise ChaChaPolyError("ChaCha20 needs a 32-byte key")
    if len(nonce) != 12:
        raise ChaChaPolyError("ChaCha20 needs a 12-byte nonce")
    const = b"expand 32-byte k"
    state = [struct.unpack("<I", const[i:i + 4])[0] for i in range(0, 16, 4)]
    state += [struct.unpack("<I", key[i:i + 4])[0] for i in range(0, 32, 4)]
    state.append(counter & _MASK32)
    state += [struct.unpack("<I", nonce[i:i + 4])[0] for i in range(0, 12, 4)]

    working = list(state)
    for _ in range(10):                      # 20 rounds = 10 double rounds
        _quarter(working, 0, 4, 8, 12)
        _quarter(working, 1, 5, 9, 13)
        _quarter(working, 2, 6, 10, 14)
        _quarter(working, 3, 7, 11, 15)
        _quarter(working, 0, 5, 10, 15)
        _quarter(working, 1, 6, 11, 12)
        _quarter(working, 2, 7, 8, 13)
        _quarter(working, 3, 4, 9, 14)
    out = [(working[i] + state[i]) & _MASK32 for i in range(16)]
    return b"".join(struct.pack("<I", v) for v in out)


def chacha20_stream(key: bytes, counter: int, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    while len(out) < length:
        out += chacha20_block(key, counter, nonce)
        counter += 1
    return bytes(out[:length])


def chacha20_xor(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    """RFC 8439 section 2.4: the keystream starts at the given counter."""
    stream = chacha20_stream(key, counter, nonce, len(data))
    return bytes(a ^ b for a, b in zip(data, stream))


# ------------------------------------------------------------------ Poly1305

_P1305 = (1 << 130) - 5


def _poly1305_le_num(data: bytes) -> int:
    """Little-endian integer of one block, with the 0x01 byte appended.

    The high bit sits at 8*len(data), NOT always at 128: for a final partial
    block rfc8439 appends a single 0x01 byte to that shorter block, so a
    4-byte remainder becomes a 5-byte number. Padding it up to 17 bytes
    instead changes the accumulator and produces a wrong tag - which is
    invisible until the very last block of a message whose length is not a
    multiple of 16 (i.e. most real ones).
    """
    return int.from_bytes(data, "little") | (1 << (8 * len(data)))


def poly1305_mac(msg: bytes, key: bytes) -> bytes:
    """One-shot Poly1305. RFC 8439 section 2.5."""
    if len(key) != 32:
        raise ChaChaPolyError("Poly1305 needs a 32-byte one-time key")
    r = int.from_bytes(key[0:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:32], "little")
    acc = 0
    pos = 0
    while pos < len(msg):
        block = msg[pos:pos + 16]
        pos += len(block)
        acc = (acc + _poly1305_le_num(block)) * r % _P1305
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


# ---------------------------------------------------------------------- AEAD

def _pad16(data: bytes) -> bytes:
    rem = len(data) % 16
    return b"\x00" * (16 - rem) if rem else b""


def _aead_tag(poly_key: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    mac_data = (aad + _pad16(aad) + ciphertext + _pad16(ciphertext)
                + struct.pack("<Q", len(aad))
                + struct.pack("<Q", len(ciphertext)))
    return poly1305_mac(mac_data, poly_key)


def encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """Return ciphertext || 16-byte tag."""
    if len(nonce) != 12:
        raise ChaChaPolyError("AEAD needs a 12-byte nonce")
    poly_key = chacha20_block(key, 0, nonce)[0:32]
    ct = chacha20_xor(key, 1, nonce, plaintext)
    return ct + _aead_tag(poly_key, aad, ct)


def decrypt(key: bytes, nonce: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    """Split off the trailing tag, verify it, return the plaintext.

    A failure to verify raises instead of returning garbage: an AEAD that
    hands back unverified plaintext turns every wrong-key mistake into
    silently corrupt credential data.
    """
    if len(blob) < 16:
        raise ChaChaPolyError("AEAD blob is shorter than its 16-byte tag")
    ct, tag = blob[:-16], blob[-16:]
    poly_key = chacha20_block(key, 0, nonce)[0:32]
    expected = _aead_tag(poly_key, aad, ct)
    if not _ct_equal(tag, expected):
        raise ChaChaPolyError("AEAD tag did not verify - wrong key or corrupt data")
    return chacha20_xor(key, 1, nonce, ct)


def _ct_equal(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0
