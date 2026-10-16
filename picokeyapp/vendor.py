"""Vendor CTAP commands: credential policies and key backup.

Why this file exists
--------------------
The firmware exposes a set of commands that no general-purpose FIDO tool
ships: per-credential policies (revoke, expire, require touch) and an
encrypted key backup. They are reachable from a phone, but only by speaking
the vendor branch of `authenticatorConfig` (0x0D) and the vendor CBOR command
(0x41), which is why they stayed unused.

Everything here needs a PIN/UV auth token carrying the ACFG permission. The
token is fetched with the standard ClientPIN exchange, so the PIN never leaves
the device unprotected: it is encrypted under an ECDH secret that is unique to
the session.

One honest limitation
---------------------
The 24-word backup phrase is turned into the 32-byte `keydev` value by code
that lives in the `pico-keys-sdk` submodule, which is not vendored here. So
this module implements the *transport* — key agreement, unlock, export,
import — but it cannot derive `keydev` from a phrase, and it does not pretend
to. Importing a previously exported blob works without that step; generating
or typing a phrase does not.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct

from . import cbor_mini, ctapcfg
from .uvcrypto import (p256_keypair, p256_ecdh, p256_point_from_bytes,
                       protocol1_authenticate)

# ----------------------------------------------------------------- constants

CTAP_CLIENT_PIN = 0x06
CTAP_CONFIG = 0x0D
CTAP_VENDOR_CBOR = 0x41          # CTAPHID_VENDOR_FIRST + 1

# ClientPIN subcommands
PIN_GET_KEY_AGREEMENT = 0x02
PIN_GET_PIN_TOKEN = 0x05

# vendorConfig subcommand marker: 0xFF selects the vendor branch
CONFIG_VENDOR = 0xFF

# Vendor command ids (src/fido/ctap.h). These are 64-bit; they are sent as
# CBOR unsigned integers.
CONFIG_AUT_DISABLE = 0x0001A40F04A25ED9
CONFIG_EA_UPLOAD = 0x0002A674C29A8DCF
CONFIG_MCUV_NOTRQD = 0x000377913E17951F
CONFIG_AUT_ENABLE = 0x00043F56B34285E2
CONFIG_CREDENTIAL_EXPIRE = 0x0004E532E1FEB2FD
CONFIG_NORK = 0x00052B41F53590D3
CONFIG_CREDENTIAL_REVOKE = 0x0005961ECBA040F9
CONFIG_CREDENTIAL_BUTTON = 0x0005ABC39033A930
CONFIG_PIN_POLICY = 0x0007D70FE96C3897

# Permissions bit for authenticatorConfig. Requesting this without it is the
# usual reason a policy command comes back as PIN_AUTH_INVALID.
PERMISSION_ACFG = 0x20

VENDOR_BACKUP = 0x01
VENDOR_MSE = 0x02
VENDOR_UNLOCK = 0x03

# subParams keys
P_BYTE = 0x02
P_INT = 0x03
P_TEXT = 0x04
P_BOOL = 0x05

KEYDEV_LEN = 32
TAG_LEN = 16
MSE_KEY_LEN = 44                 # 12-byte nonce + 32-byte ChaCha20 key
BACKUP_BLOB_LEN = 12 + 32 + 16  # nonce + encrypted keydev + tag


class VendorError(Exception):
    pass


class SWError(VendorError):
    def __init__(self, sw: int):
        self.sw = sw
        super().__init__(f"SW={sw:04X}")


def ctap_sw_text(sw: int) -> str:
    """Plain-language reading of the status words these commands return.

    The wording matters most for the config commands: a rejection there is
    easy to misread as "this device has no such feature", which sends people
    looking for a setting that does not exist while the real cause is a
    missing permission or a parameter shape the firmware did not accept.
    """
    return {
        0x00: "ok",
        0x2E: "the value is out of range for this command",
        0x31: "not allowed: the request was understood but refused",
        0x32: "no credentials: the slot or credential id matched nothing",
        0x33: "the device needs a real-time clock it does not have",
        0x34: "the command needs a parameter that was not sent",
        0x35: "no space left for another entry",
        0x36: "PIN auth invalid: the token lacks the ACFG permission, or the "
              "PIN was wrong",
        0x37: "this firmware build does not implement the command",
        0x39: "user presence required: press the button on the device",
        0x3A: "operation denied: the button was not pressed in time",
        0x6A80: "malformed request",
        0x6A86: "wrong parameters for this command",
        0x6D00: "this command is not implemented here",
    }.get(sw, f"SW={sw:04X}")


def _ordered(pairs) -> dict:
    """Build a map whose keys come out in ascending CBOR order.

    The firmware rejects a map whose keys are not strictly increasing, and the
    encoder preserves insertion order rather than sorting, so the order has to
    be established here. Getting it wrong fails at parse time, before any of
    the policy logic runs.
    """
    return dict(sorted(pairs, key=lambda kv: kv[0]))


def _cose_p256(x: bytes, y: bytes) -> dict:
    """A P-256 public key as a COSE_Key, in the canonical field order.

    The negative keys (-1, -2, -3) sort after the positive ones once encoded,
    which is why they come last despite reading out of order.
    """
    return {
        1: 2,        # kty: EC2
        3: -25,      # alg: ECDH-ES + HKDF-256
        -1: 1,       # crv: P-256
        -2: x,
        -3: y,
    }


def _pad16(data: bytes) -> bytes:
    pad = (-len(data)) % 16
    return data + b"\x00" * pad


class VendorApp:
    """Vendor commands on top of a CTAP HID transport."""

    def __init__(self, transport):
        # The ClientPIN exchange is not reimplemented here. ctapcfg already
        # does it, and having two copies means two places to get the key
        # schedule subtly wrong - which is invisible until a device refuses
        # every command and the cause looks like a missing feature.
        self.hid = transport
        self._uv = ctapcfg.UvConfig(transport)
        self._pin_token = None
        self._mse = None            # (key material, device public point)

    # ------------------------------------------------------------ transport

    def _cbor_cmd(self, cmd: int, payload: bytes = b"", timeout: int = 10000):
        """One CTAP exchange.

        The transport hands back `(status, data)`, already split - not a
        status-word-prefixed blob. Treating it as the latter would read the
        first payload byte as a status word and reject perfectly good answers.
        """
        status, data = self.hid.cbor(cmd, payload, timeout=timeout)
        if status != 0x00:
            raise SWError(status)
        if not data:
            return {}
        try:
            return cbor_mini.loads(data)
        except cbor_mini.CBORError:
            return {}

    # ------------------------------------------------------------- PIN/UV

    def get_pin_token(self, pin: str, permissions: int = PERMISSION_ACFG) -> bytes:
        """Fetch a PIN/UV auth token carrying `permissions`.

        The PIN is encrypted under a session-unique ECDH secret, so a capture
        of the exchange does not yield the PIN. The returned token is what
        authorises the config commands; without the ACFG bit they are refused.
        """
        if not pin:
            raise VendorError("a PIN is required")
        try:
            self._pin_token = self._uv.obtain_token(pin, permissions)
        except ctapcfg.ConfigError as exc:
            # The PIN exchange lives in ctapcfg and raises its own type. Left
            # alone, a caller that guards against VendorError lets a wrong PIN
            # escape as an unhandled exception, which is worse than the refusal
            # itself: the UI shows a crash instead of "the PIN was wrong".
            raise VendorError(str(exc)) from exc
        return self._pin_token

    # -------------------------------------------------------------- config

    def _vendor_config(self, vendor_cmd: int, subparams: dict,
                       pin_token: bytes = None):
        """Run one vendor `authenticatorConfig` command.

        The auth parameter covers `0xFF * 32 || 0x0D || subcommand ||
        raw_subparams`, where `raw_subparams` is the exact encoded map — so the
        bytes handed to the HMAC have to be the same bytes that go on the wire.
        Re-encoding a dict for the request and hashing a different one would
        produce an auth tag the firmware rejects.
        """
        token = pin_token or self._pin_token
        if token is None:
            raise VendorError("a PIN/UV token is required; call get_pin_token")

        raw = cbor_mini.dumps(subparams)
        payload = b"\xff" * 32 + bytes([0x0D, CONFIG_VENDOR]) + raw
        auth = protocol1_authenticate(token, payload)

        req = cbor_mini.dumps(_ordered([
            (1, CONFIG_VENDOR),
            (2, subparams),
            (3, 1),
            (4, auth),
        ]))
        return self._cbor_cmd(CTAP_CONFIG, req, timeout=30000)

    # -- toggles: these flip a bit rather than setting it, so calling one
    #    twice returns to the original state.

    def toggle_nork(self, pin_token: bytes = None):
        """Disallow resident keys (or allow them again)."""
        return self._vendor_config(CONFIG_NORK, _ordered([(1, CONFIG_NORK)]),
                                   pin_token)

    def toggle_mcuv(self, pin_token: bytes = None):
        """Stop requiring user verification on every make-credential."""
        return self._vendor_config(CONFIG_MCUV_NOTRQD,
                                   _ordered([(1, CONFIG_MCUV_NOTRQD)]),
                                   pin_token)

    # -- per-credential policies

    def revoke_credential(self, slot: int = None, cred_id: bytes = None,
                          pin_token: bytes = None):
        """Mark a resident credential revoked.

        Either the slot number or the credential id may identify it; the
        firmware accepts exactly one and rejects anything else outright.
        """
        params = [(1, CONFIG_CREDENTIAL_REVOKE)]
        if cred_id is not None:
            params.append((P_BYTE, bytes(cred_id)))
        elif slot is not None:
            params.append((P_INT, int(slot)))
        else:
            raise VendorError("revoke needs either a slot or a credential id")
        return self._vendor_config(CONFIG_CREDENTIAL_REVOKE,
                                   _ordered(params), pin_token)

    def expire_credential(self, timestamp: int, slot: int = None,
                          cred_id: bytes = None, pin_token: bytes = None):
        """Set the Unix time at which a resident credential stops working.

        The two addressing forms carry their arguments in opposite fields,
        which is easy to get backwards: by slot the time goes in the byte
        string, by id it goes in the integer.
        """
        params = [(1, CONFIG_CREDENTIAL_EXPIRE)]
        if cred_id is not None:
            params.append((P_BYTE, bytes(cred_id)))
            params.append((P_INT, int(timestamp) & 0xFFFFFFFF))
        elif slot is not None:
            params.append((P_INT, int(slot)))
            params.append((P_BYTE, struct.pack(">I", int(timestamp) & 0xFFFFFFFF)))
        else:
            raise VendorError("expire needs either a slot or a credential id")
        return self._vendor_config(CONFIG_CREDENTIAL_EXPIRE,
                                   _ordered(params), pin_token)

    def require_button(self, require: bool, slot: int = None,
                       cred_id: bytes = None, pin_token: bytes = None):
        """Force (or stop forcing) a physical press for one credential."""
        params = [(1, CONFIG_CREDENTIAL_BUTTON)]
        if cred_id is not None:
            params.append((P_BYTE, bytes(cred_id)))
        elif slot is not None:
            params.append((P_INT, int(slot)))
        else:
            raise VendorError("the button policy needs a slot or a credential id")
        params.append((P_BOOL, bool(require)))
        return self._vendor_config(CONFIG_CREDENTIAL_BUTTON,
                                   _ordered(params), pin_token)

    def set_pin_policy(self, min_length: int, rp_ids: bytes = b"",
                       pin_token: bytes = None):
        """Set a minimum PIN length and, optionally, the RPIDs it applies to."""
        params = [
            (1, CONFIG_PIN_POLICY),
            (P_INT, int(min_length) & 0xFFFF),
        ]
        if rp_ids:
            params.append((P_BYTE, bytes(rp_ids)))
        return self._vendor_config(CONFIG_PIN_POLICY, _ordered(params), pin_token)

    # -------------------------------------------------------------- backup

    def mse_agree(self) -> bytes:
        """Key agreement for the backup channel.

        The shared secret is HKDF-SHA256 over the ECDH output, keyed with the
        device's own uncompressed public point as `info`. The firmware does the
        same on its side, so both end up with the same 44-byte key material.
        """
        from .hpke import hkdf

        priv, pub = p256_keypair()
        pub_x = pub[0].to_bytes(32, "big")
        pub_y = pub[1].to_bytes(32, "big")

        req = cbor_mini.dumps(_ordered([
            (1, VENDOR_MSE),
            (2, _ordered([
                (1, 0x01),
                (2, _cose_p256(pub_x, pub_y)),
            ])),
        ]))
        resp = self._cbor_cmd(CTAP_VENDOR_CBOR, req, timeout=30000)

        cose = resp.get(1)
        if not isinstance(cose, dict):
            raise VendorError("no key agreement came back from the device")
        dx = cose.get(-2)
        dy = cose.get(-3)
        if not isinstance(dx, (bytes, bytearray)) or not isinstance(dy, (bytes, bytearray)):
            raise VendorError("the device key agreement is malformed")

        device_point = bytes([0x04]) + bytes(dx).rjust(32, b"\x00") + \
            bytes(dy).rjust(32, b"\x00")
        peer = p256_point_from_bytes(int.from_bytes(dx, "big"),
                                     int.from_bytes(dy, "big"))
        dh = p256_ecdh(priv, peer)
        key_enc = hkdf(dh, device_point, MSE_KEY_LEN, salt=b"")
        self._mse = (key_enc, device_point)
        return key_enc

    def _mse_seal(self, plaintext: bytes) -> bytes:
        """ChaCha20-Poly1305 under the agreed key, AAD = the device point."""
        if self._mse is None:
            raise VendorError("call mse_agree first")
        from .chachapoly import encrypt
        key_enc, device_point = self._mse
        return encrypt(key_enc[12:44], key_enc[0:12], plaintext, device_point)

    def unlock(self, keydev: bytes) -> bool:
        """Hand the device the `keydev` value so it can use an encrypted one.

        `keydev` is 32 bytes. Deriving it from the 24-word phrase is done by
        code outside this project, which is why this takes the value rather
        than a phrase.
        """
        if len(keydev) != KEYDEV_LEN:
            raise VendorError(f"keydev must be {KEYDEV_LEN} bytes")
        self._cbor_cmd(CTAP_VENDOR_CBOR, cbor_mini.dumps(_ordered([
            (1, VENDOR_UNLOCK),
            (2, _ordered([(1, VENDOR_UNLOCK), (P_BYTE, self._mse_seal(keydev))])),
        ])), timeout=30000)
        return True

    def backup_export(self) -> bytes:
        """Return the encrypted backup blob (60 bytes) for safekeeping."""
        resp = self._cbor_cmd(CTAP_VENDOR_CBOR, cbor_mini.dumps(_ordered([
            (1, VENDOR_BACKUP),
            (2, _ordered([(1, 0x01)])),
        ])), timeout=30000)
        blob = resp.get(1)
        if not isinstance(blob, (bytes, bytearray)):
            raise VendorError("the device returned no backup")
        return bytes(blob)

    def backup_import(self, blob: bytes) -> bool:
        """Restore a blob previously returned by `backup_export`.

        The device asks for a button press before accepting it, so this blocks
        until the key is touched.
        """
        if len(blob) != BACKUP_BLOB_LEN:
            raise VendorError(
                f"a backup blob is {BACKUP_BLOB_LEN} bytes, got {len(blob)}")
        self._cbor_cmd(CTAP_VENDOR_CBOR, cbor_mini.dumps(_ordered([
            (1, VENDOR_BACKUP),
            (2, _ordered([(1, 0x02), (P_BYTE, bytes(blob))])),
        ])), timeout=60000)
        return True


def payload_for_auth(subparams: dict) -> bytes:
    """The exact bytes a vendor config command authenticates over.

    Kept as its own function because the self-test checks it against the
    firmware's own construction: 32 filler bytes, the command byte, the
    subcommand, then the raw subparameters.
    """
    return b"\xff" * 32 + bytes([0x0D, CONFIG_VENDOR]) + cbor_mini.dumps(subparams)
