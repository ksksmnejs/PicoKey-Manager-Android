"""X448 (RFC 7748) and HPKE's DHKEM(X448, HKDF-SHA512).

Why this exists
---------------
Vaulted Passkeys enrollment is an HPKE Auth-mode exchange built on
DHKEM(X448, HKDF-SHA512) (KEM 0x0021) with AES-256-GCM. `cryptography` is not
a build dependency here, so the key agreement is implemented directly.

X448 is a Montgomery curve, so the shared secret is a single u-coordinate and
the whole ladder is RFC 7748 section 5.3. Verified against the RFC 7748
section 5.2 vectors and RFC 9180 appendix A.7 (HPKE with X448).
"""

from __future__ import annotations

# 2^448 - 2^224 - 1
P448 = (1 << 448) - (1 << 224) - 1
# (A - 2) / 4 with A = 156326 -> 39081.
#
# 39082 is the value used by formulations that write the ladder with
# (A + 2) / 4. Getting this wrong does not raise: the ladder simply returns
# an all-zero u-coordinate, which looks like "the peer sent a low-order
# point" rather than "the constant is wrong". The RFC 7748 vectors below are
# what catches it.
A24 = 39081

SCALAR_LEN = 56          # X448 scalars and u-coordinates are 56 octets


class X448Error(Exception):
    pass


def _decode_little_endian(data: bytes) -> int:
    return int.from_bytes(data, "little")


def _encode_u(u: int) -> bytes:
    return (u % P448).to_bytes(SCALAR_LEN, "little")


def clamp_scalar(k: bytes) -> bytes:
    """RFC 7748 section 5: clear the two low bits, set the top bit.

    Both halves matter. Skipping the low bits would make each scalar
    representable in several ways; skipping the top bit would let the ladder
    degenerate for small scalars.
    """
    if len(k) != SCALAR_LEN:
        raise X448Error(f"X448 scalar must be {SCALAR_LEN} bytes")
    k = bytearray(k)
    k[0] &= 252
    k[SCALAR_LEN - 1] |= 128
    return bytes(k)


def _cswap(swap: int, x2: int, z2: int, x3: int, z3: int):
    """Conditional swap; returns the four values.

    These are returned rather than mutated through a wrapper list: a helper
    that "swaps in place" on freshly built lists silently drops the swap, and
    the ladder then computes the wrong point while still looking plausible
    (it produces an all-zero result rather than an exception).
    """
    mask = -swap                       # 0 -> 0, 1 -> all ones
    d1 = mask & ((x2 - x3) % P448)
    d2 = mask & ((z2 - z3) % P448)
    return ((x2 - d1) % P448, (z2 - d2) % P448,
            (x3 + d1) % P448, (z3 + d2) % P448)


def x448(scalar: bytes, u: bytes) -> bytes:
    """The X448 function: u-coordinate of scalar*U. RFC 7748 section 5.3."""
    if len(u) != SCALAR_LEN:
        raise X448Error(f"X448 u-coordinate must be {SCALAR_LEN} bytes")
    k = clamp_scalar(scalar)
    x1 = _decode_little_endian(u) % P448
    x2, z2 = 1, 0
    x3, z3 = x1, 1
    swap = 0
    for t in range(448 - 1, -1, -1):
        kt = (k[t // 8] >> (t % 8)) & 1
        swap ^= kt
        x2, z2, x3, z3 = _cswap(swap, x2, z2, x3, z3)
        swap = kt

        A = (x2 + z2) % P448
        AA = A * A % P448
        B = (x2 - z2) % P448
        BB = B * B % P448
        E = (AA - BB) % P448
        C = (x3 + z3) % P448
        D = (x3 - z3) % P448
        DA = D * A % P448
        CB = C * B % P448
        x3 = pow(DA + CB, 2, P448)
        z3 = x1 * pow(DA - CB, 2, P448) % P448
        x2 = AA * BB % P448
        z2 = E * (AA + A24 * E) % P448
    x2, z2, x3, z3 = _cswap(swap, x2, z2, x3, z3)
    res = x2 * pow(z2, P448 - 2, P448) % P448
    if res == 0 and z2 == 0:          # low-order / zero input: all-zero output
        return bytes(SCALAR_LEN)
    return _encode_u(res)


BASE_U = 5


def generate_private() -> bytes:
    import os
    return os.urandom(SCALAR_LEN)


def public_from_private(private: bytes) -> bytes:
    return x448(private, _encode_u(BASE_U))


def shared_secret(private: bytes, peer_public: bytes) -> bytes:
    """Raw X448 shared secret. Callers MUST run it through a KDF."""
    return x448(private, peer_public)
