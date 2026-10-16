"""HKDF (RFC 5869) and the HPKE suite used by Vaulted Passkeys.

Why this exists
---------------
Vaulted Passkeys enrollment uses RFC 9180 HPKE in Auth mode with

    KEM  = 0x0021  DHKEM(X448, HKDF-SHA512)
    KDF  = 0x0003  HKDF-SHA512
    AEAD = 0x0002  AES-256-GCM

and the credential envelope derives its per-layer keys with HKDF-SHA-256.
HKDF-SHA-512 is not something the CTAP PIN/UV protocol ever needed, so it is
here rather than in uvcrypto.

Verified against RFC 5869 test vectors (HKDF) and RFC 9180 appendix A.7
(HPKE with DHKEM(X448, HKDF-SHA512), AES-256-GCM).
"""

from __future__ import annotations

import hashlib
import hmac

from . import aesgcm as GCM
from . import x448 as X448


class HpkeError(Exception):
    pass


# -------------------------------------------------------------------- HKDF

_HASHES = {
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
}

_KDF_ID = {"sha256": b"\x00\x01", "sha512": b"\x00\x03"}
_KEM_ID_X448 = b"\x00\x21"
_AEAD_ID_GCM256 = b"\x00\x02"


def hkdf_extract(ikm: bytes, salt: bytes = b"", algo: str = "sha256") -> bytes:
    h = _HASHES[algo]
    if not salt:
        salt = b"\x00" * h().digest_size
    return hmac.new(salt, ikm, h).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int, algo: str = "sha256") -> bytes:
    h = _HASHES[algo]
    digest_size = h().digest_size
    if length > 255 * digest_size:
        raise HpkeError("HKDF-Expand cannot produce that much output")
    out = bytearray()
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), h).digest()
        out += t
        counter += 1
    return bytes(out[:length])


def hkdf(ikm: bytes, info: bytes, length: int, salt: bytes = b"",
         algo: str = "sha256") -> bytes:
    return hkdf_expand(hkdf_extract(ikm, salt, algo), info, length, algo)


# -------------------------------------------------------------------- HPKE

def _labeled_extract(suite_id: bytes, salt: bytes, label: bytes, ikm: bytes,
                     algo: str) -> bytes:
    return hkdf_extract(b"HPKE-v1" + suite_id + label + ikm, salt, algo)


def _labeled_expand(suite_id: bytes, prk: bytes, label: bytes, info: bytes,
                    length: int, algo: str) -> bytes:
    return hkdf_expand(prk, bytes([length >> 8, length & 0xFF])
                       + b"HPKE-v1" + suite_id + label + info, length, algo)


def _dhkem_suite_id() -> bytes:
    return b"KEM" + _KEM_ID_X448


def _hpke_suite_id() -> bytes:
    return (b"HPKE" + _KEM_ID_X448 + _KDF_ID["sha512"] + _AEAD_ID_GCM256)


def _extract_and_expand(dh: bytes, kem_context: bytes, algo: str = "sha512") -> bytes:
    eae_prk = _labeled_extract(_dhkem_suite_id(), b"", b"eae_prk", dh, algo)
    return _labeled_expand(_dhkem_suite_id(), eae_prk, b"shared_secret",
                           kem_context, 32, algo)


def _key_schedule(shared_secret: bytes, info: bytes) -> tuple:
    suite = _hpke_suite_id()
    psk_id_hash = _labeled_extract(suite, b"", b"psk_id_hash", b"", "sha512")
    info_hash = _labeled_extract(suite, b"", b"info_hash", info, "sha512")
    key_schedule_context = b"\x02" + psk_id_hash + info_hash
    secret = _labeled_extract(suite, shared_secret, b"secret", b"", "sha512")
    key = _labeled_expand(suite, secret, b"key", key_schedule_context, 32, "sha512")
    base_nonce = _labeled_expand(suite, secret, b"base_nonce",
                                 key_schedule_context, 12, "sha512")
    exporter_secret = _labeled_expand(suite, secret, b"exp",
                                      key_schedule_context, 32, "sha512")
    return key, base_nonce, exporter_secret


def _xor_nonce(base_nonce: bytes, seq: int) -> bytes:
    """base_nonce XOR I2OSP(seq, Nn) - RFC 9180 section 5.2."""
    n = len(base_nonce)
    seq_bytes = seq.to_bytes(n, "big")
    return bytes(a ^ b for a, b in zip(base_nonce, seq_bytes))


def auth_seal(recipient_public: bytes, sender_auth_private: bytes,
              info: bytes, plaintext: bytes, aad: bytes = b"",
              ephemeral_private: bytes = None) -> tuple:
    """HPKE Auth-mode Seal for DHKEM(X448). Returns (enc, ciphertext).

    This is what the Vault enroller does in enrollment protocol 2: the device
    is the recipient (Q_e from Begin Enrollment) and the enroller is the
    authenticated sender. `dh` is the concatenation of BOTH agreements -
    ephemeral first, then the long-lived static key - which is what makes it
    Auth mode rather than Base mode.
    """
    if len(recipient_public) != X448.SCALAR_LEN:
        raise HpkeError("recipient public key must be 56 bytes")
    if len(sender_auth_private) != X448.SCALAR_LEN:
        raise HpkeError("sender static private key must be 56 bytes")

    if ephemeral_private is None:
        ephemeral_private = X448.generate_private()
    ephemeral_public = X448.public_from_private(ephemeral_private)
    sender_auth_public = X448.public_from_private(sender_auth_private)

    dh = (X448.shared_secret(ephemeral_private, recipient_public)
          + X448.shared_secret(sender_auth_private, recipient_public))
    kem_context = ephemeral_public + recipient_public + sender_auth_public
    shared_secret = _extract_and_expand(dh, kem_context)
    key, base_nonce, _ = _key_schedule(shared_secret, info)
    ct = GCM.encrypt(key, _xor_nonce(base_nonce, 0), plaintext, aad)
    return ephemeral_public, ct


def auth_open(enc: bytes, recipient_private: bytes, sender_auth_public: bytes,
              info: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    """The recipient side. Kept so the seal path can be tested in both
    directions without hardware."""
    recipient_public = X448.public_from_private(recipient_private)
    dh = (X448.shared_secret(recipient_private, enc)
          + X448.shared_secret(recipient_private, sender_auth_public))
    kem_context = enc + recipient_public + sender_auth_public
    shared_secret = _extract_and_expand(dh, kem_context)
    key, base_nonce, _ = _key_schedule(shared_secret, info)
    return GCM.decrypt(key, _xor_nonce(base_nonce, 0), blob, aad)
