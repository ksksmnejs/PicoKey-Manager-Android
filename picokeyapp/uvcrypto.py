"""The crypto needed to talk to a FIDO2 authenticator's PIN/UV protocol.

Everything here is deliberately dependency-free. Adding `cryptography` to the
build was the obvious move and it was rejected: python-for-android would have
to compile it (a Rust toolchain and several minutes of CI per build) for two
operations - one scalar multiplication and a handful of AES blocks. The whole
of this module costs less than that and cannot fail to build.

Nothing here is secret-dependent in a way that matters for side channels: the
platform's ECDH key is ephemeral, generated fresh for every session and thrown
away when it is. A constant-time implementation is therefore not attempted; a
correct one is.

Only PIN/UV auth protocol ONE is implemented. Protocol two adds HKDF and a
32-byte auth tag, and while it is the better protocol, getting its key schedule
wrong produces a failure that looks exactly like a wrong PIN - untestable
without real hardware, and indistinguishable from the authenticator refusing.
Protocol one is supported by every authenticator that supports PINs at all, so
falling back to it costs nothing here.
"""

import hashlib
import hmac
import os

# --------------------------------------------------------------------- P-256

# NIST P-256 (prime256v1 / secp256r1), the only curve CTAP uses for key
# agreement. Verified against the published domain parameters.
P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
P256_A = P256_P - 3
P256_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
P256_GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
P256_GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5

P256_G = (P256_GX, P256_GY)


class EccError(Exception):
    """A point was not on the curve, or a key was degenerate."""


def _inv(a: int, m: int = P256_P) -> int:
    return pow(a, m - 2, m)


def _is_on_curve(pt):
    if pt is None:
        return False
    x, y = pt
    if not (0 <= x < P256_P and 0 <= y < P256_P):
        return False
    return (y * y - x * x * x - P256_A * x - P256_B) % P256_P == 0


def _add(p1, p2):
    """Point addition on a short Weierstrass curve over a prime field."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % P256_P == 0:
            return None          # p2 == -p1
        lam = (3 * x1 * x1 + P256_A) * _inv(2 * y1) % P256_P
    else:
        lam = (y2 - y1) * _inv(x2 - x1) % P256_P
    x3 = (lam * lam - x1 - x2) % P256_P
    y3 = (lam * (x1 - x3) - y1) % P256_P
    return (x3, y3)


def _mul(k: int, pt):
    """Scalar multiplication by double-and-add, MSB first."""
    if pt is None:
        return None
    k %= P256_N
    if k == 0:
        return None
    result = None
    addend = pt
    for bit in bin(k)[2:]:
        result = _add(result, result)
        if bit == '1':
            result = _add(result, addend)
    return result


def p256_keypair():
    """Return (private_scalar, public_point).

    `os.urandom` is used rather than `secrets` purely because it is what the
    rest of the codebase reaches for; both come from the same OS entropy.
    """
    while True:
        # Rejection sampling keeps the scalar uniform in [1, n-1].
        raw = int.from_bytes(os.urandom(32), "big")
        priv = raw % P256_N
        if priv == 0:
            continue
        return priv, _mul(priv, P256_G)


def p256_point_from_bytes(x: int, y: int):
    """Rebuild a point from its coordinates, checking it is really on P-256.

    The check matters: the authenticator sends us these, and accepting an
    off-curve point is how invalid-curve attacks recover a private key.
    """
    pt = (x % P256_P, y % P256_P)
    if not _is_on_curve(pt):
        raise EccError("public key point is not on the P-256 curve")
    if _mul(P256_N, pt) is not None:
        raise EccError("public key point is not in the prime-order subgroup")
    return pt


def p256_ecdh(priv: int, peer) -> bytes:
    """ECDH, returning the 32-byte big-endian x-coordinate of the shared point.

    The x-coordinate is what CTAP feeds into the key schedule. Returning the
    whole point would be wrong and returning y would be a different secret.
    """
    shared = _mul(priv, peer)
    if shared is None:
        raise EccError("ECDH produced the point at infinity")
    return shared[0].to_bytes(32, "big")


# ----------------------------------------------------------------------- AES

def _build_sbox():
    """Derive the AES S-box rather than transcribing 256 bytes by hand.

    Same table, generated: the multiplicative inverse in GF(2^8) followed by
    the affine map. A typo in a literal table would survive review and only
    show up as an authenticator rejecting every PIN.
    """
    sbox = [0] * 256
    p = q = 1
    while True:
        # p *= 3
        p ^= ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        # q /= 3
        q ^= (q << 1) & 0xFF
        q ^= (q << 2) & 0xFF
        q ^= (q << 4) & 0xFF
        if q & 0x80:
            q ^= 0x09
        x = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) \
              ^ ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4))
        sbox[p] = (x ^ 0x63) & 0xFF
        if p == 1:
            break
    sbox[0] = 0x63
    return sbox


_SBOX = _build_sbox()
_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i

# Round constants, generated the same way as the S-box (xtime of the previous).
_RCON = [0x01]
for _ in range(13):
    _prev = _RCON[-1]
    _RCON.append(((_prev << 1) ^ 0x1B) & 0xFF if _prev & 0x80 else _prev << 1)


def _xtime(a: int) -> int:
    a <<= 1
    if a & 0x100:
        a = (a ^ 0x1B) & 0xFF
    return a


def _gmul(a: int, b: int) -> int:
    """Multiply in GF(2^8) with the AES polynomial, by shift-and-add.

    Used for MixColumns and its inverse. The usual hand-unrolled expressions
    (14*a ^ 11*b ^ ...) are faster but easy to get subtly wrong, and a wrong
    inverse column mix still encrypts correctly - it only shows up when
    decrypting, which is exactly the direction that unblocks a PIN token.
    """
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return r


def _key_expansion(key: bytes):
    """Expand a 16/24/32-byte key into round keys of 16 bytes each."""
    nk = len(key) // 4
    nr = nk + 6
    words = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        temp = list(words[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]               # RotWord
            temp = [_SBOX[b] for b in temp]          # SubWord
            temp[0] ^= _RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            temp = [_SBOX[b] for b in temp]
        words.append([words[i - nk][j] ^ temp[j] for j in range(4)])
    # Round keys as flat byte strings, ready for AddRoundKey.
    return [bytes(b for w in words[4 * r:4 * r + 4] for b in w)
            for r in range(nr + 1)]


def _encrypt_block(block: bytes, rk) -> bytes:
    """One 16-byte block, FIPS-197 §5.1 with the standard column-major state."""
    nr = len(rk) - 1
    s = list(block)
    s = [s[i] ^ rk[0][i] for i in range(16)]
    for rnd in range(1, nr + 1):
        s = [_SBOX[b] for b in s]                                  # SubBytes
        s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]         # ShiftRows
        if rnd != nr:                                              # MixColumns
            out = [0] * 16
            for c in range(4):
                a0, a1, a2, a3 = s[4 * c:4 * c + 4]
                out[4 * c + 0] = (_gmul(a0, 2) ^ _gmul(a1, 3) ^ a2 ^ a3)
                out[4 * c + 1] = (a0 ^ _gmul(a1, 2) ^ _gmul(a2, 3) ^ a3)
                out[4 * c + 2] = (a0 ^ a1 ^ _gmul(a2, 2) ^ _gmul(a3, 3))
                out[4 * c + 3] = (_gmul(a0, 3) ^ a1 ^ a2 ^ _gmul(a3, 2))
            s = out
        s = [s[i] ^ rk[rnd][i] for i in range(16)]                 # AddRoundKey
    return bytes(s)


def _decrypt_block(block: bytes, rk) -> bytes:
    nr = len(rk) - 1
    s = list(block)
    s = [s[i] ^ rk[nr][i] for i in range(16)]
    for rnd in range(nr - 1, -1, -1):
        s = [s[(i - 4 * (i % 4)) % 16] for i in range(16)]         # InvShiftRows
        s = [_INV_SBOX[b] for b in s]                              # InvSubBytes
        s = [s[i] ^ rk[rnd][i] for i in range(16)]                 # AddRoundKey
        if rnd != 0:                                               # InvMixColumns
            out = [0] * 16
            for c in range(4):
                col = s[4 * c:4 * c + 4]
                a0, a1, a2, a3 = s[4 * c:4 * c + 4]
                out[4 * c + 0] = (_gmul(a0, 14) ^ _gmul(a1, 11)
                                  ^ _gmul(a2, 13) ^ _gmul(a3, 9))
                out[4 * c + 1] = (_gmul(a0, 9) ^ _gmul(a1, 14)
                                  ^ _gmul(a2, 11) ^ _gmul(a3, 13))
                out[4 * c + 2] = (_gmul(a0, 13) ^ _gmul(a1, 9)
                                  ^ _gmul(a2, 14) ^ _gmul(a3, 11))
                out[4 * c + 3] = (_gmul(a0, 11) ^ _gmul(a1, 13)
                                  ^ _gmul(a2, 9) ^ _gmul(a3, 14))
            s = out
    return bytes(s)


def aes_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """AES-CBC. `data` must be a whole number of blocks - see the note below."""
    if len(data) % 16:
        raise ValueError("AES-CBC input must be a multiple of 16 bytes")
    rk = _key_expansion(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        blk = bytes(data[i + j] ^ prev[j] for j in range(16))
        enc = _encrypt_block(blk, rk)
        out += enc
        prev = enc
    return bytes(out)


def aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    if len(data) % 16:
        raise ValueError("AES-CBC input must be a multiple of 16 bytes")
    rk = _key_expansion(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        dec = _decrypt_block(blk, rk)
        out += bytes(dec[j] ^ prev[j] for j in range(16))
        prev = blk
    return bytes(out)


# ------------------------------------------------------- PIN/UV protocol one

SHARED_SECRET_LEN = 32
AUTH_PARAM_LEN = 16        # protocol one truncates the HMAC to 16 bytes


def protocol1_shared_secret(ecdh_x: bytes) -> bytes:
    """Protocol one's key schedule: SHA-256 of the ECDH x-coordinate."""
    return hashlib.sha256(ecdh_x).digest()


def protocol1_authenticate(secret: bytes, message: bytes) -> bytes:
    """HMAC-SHA-256 over `message`, truncated to 16 bytes."""
    return hmac.new(secret, message, hashlib.sha256).digest()[:AUTH_PARAM_LEN]


def protocol1_encrypt(secret: bytes, plaintext: bytes) -> bytes:
    """AES-256-CBC with a zero IV.

    CTAP fixes the IV at all-zero for every PIN/UV protocol, which is safe here
    because the key is a fresh ECDH secret for each session - no two sessions
    ever encrypt under the same key, so the usual IV-reuse objection does not
    apply. The plaintext must already be block-aligned; CTAP's inputs are.
    """
    return aes_cbc_encrypt(secret, b"\x00" * 16, plaintext)


def protocol1_decrypt(secret: bytes, ciphertext: bytes) -> bytes:
    return aes_cbc_decrypt(secret, b"\x00" * 16, ciphertext)


def pin_hash(pin: str) -> bytes:
    """SHA-256 of the PIN, truncated to 16 bytes - protocol one's pinHashEnc.

    PINs are UTF-8 and normalisation-form C per the spec; we do not renormalise
    because the authenticator stored whatever it was given at set-PIN time and
    re-normalising here could turn a correct PIN into a different byte string.
    """
    return hashlib.sha256(pin.encode("utf-8")).digest()[:16]
