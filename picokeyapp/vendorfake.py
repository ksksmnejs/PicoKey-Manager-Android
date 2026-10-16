"""A stand-in for the firmware side of the vendor commands.

Why a fake at all
-----------------
These commands are destructive and the interesting failures are the ones you
cannot see: an auth tag computed over the wrong bytes is rejected the same way
a wrong PIN is, and a map with out-of-order keys is refused before any policy
runs. Without something that checks the request the way the firmware does, all
of those look like "the device said no".

So this replays the firmware's own rules — key order, the auth payload layout,
the permission check — and the self-test drives the real client against it. A
client bug shows up as a rejection here instead of as a mystery on the device.
"""

from __future__ import annotations

import hashlib
import hmac

from . import cbor_mini
from .uvcrypto import (p256_keypair, p256_ecdh, p256_point_from_bytes,
                       protocol1_shared_secret, protocol1_encrypt,
                       protocol1_decrypt, aes_cbc_encrypt, aes_cbc_decrypt,
                       pin_hash)

PERMISSION_ACFG = 0x20

CONFIG_NORK = 0x00052B41F53590D3
CONFIG_MCUV_NOTRQD = 0x000377913E17951F
CONFIG_CREDENTIAL_REVOKE = 0x0005961ECBA040F9
CONFIG_CREDENTIAL_EXPIRE = 0x0004E532E1FEB2FD
CONFIG_CREDENTIAL_BUTTON = 0x0005ABC39033A930
CONFIG_PIN_POLICY = 0x0007D70FE96C3897

# Status words on the wire. These commands reach the device over CTAP HID, so
# the status is one CTAP2 byte. The 16-bit APDU words (0x6A80, 0x6D00) belong
# to the CCID channel and cannot appear here at all - packing one into a single
# byte raises before it is ever compared, which is how this stayed hidden.
CTAP_INVALID_COMMAND = 0x01
CTAP_INVALID_PARAM = 0x02
CTAP_PIN_AUTH_INVALID = 0x36
CTAP_NO_CLOCK = 0x33

VENDOR_BACKUP = 0x01
VENDOR_MSE = 0x02
VENDOR_UNLOCK = 0x03


def _ordered(pairs) -> dict:
    return dict(sorted(pairs, key=lambda kv: kv[0]))


class FakeVendor:
    """Mimics the firmware's vendor config and backup handling."""

    def __init__(self, pin: str = "123456", keydev: bytes = None):
        self.pin = pin
        self.calls = []
        self.opts = 0
        self.revoked = []
        self.expiries = {}
        self.buttons = {}
        self.pin_policy = None
        self.keydev = keydev or bytes(range(32))
        self.blob = bytes(range(12)) + bytes(range(32)) + bytes(range(16))
        self.unlocked = False
        self._priv = None
        self._pub = None
        self._mse_key = None
        self.keyag_priv, self.keyag_pub = p256_keypair()
        self.pin_token = bytes(range(32))
        self.require_permissions = True
        self.token_has_acfg = False
        self.clock_available = True

    # ------------------------------------------------------------ helpers

    def _cose(self, x: bytes, y: bytes) -> dict:
        return {1: 2, 3: -25, -1: 1, -2: x, -3: y}

    def _keys_ascending(self, raw: bytes) -> bool:
        """The firmware walks the map and refuses a key that goes backwards."""
        try:
            obj = cbor_mini.loads(raw)
        except cbor_mini.CBORError:
            return False
        if not isinstance(obj, dict):
            return True
        last = 0
        for key in obj:
            if not isinstance(key, int):
                return False
            if key < last:
                return False
            last = key + 1
        return True

    # ------------------------------------------------------- the transport

    def cbor(self, cmd: int, payload: bytes = b"", timeout: int = 0):
        """One exchange, split the way a real transport hands it back.

        The handlers below build `status || data` because that is the wire
        format, but every client in the tree unpacks `(status, data)`. Doing
        the split here means the two halves cannot drift apart: a client that
        swapped them would read the first payload byte as a status word and
        reject a perfectly good answer, which looks exactly like "the device
        has no such feature".
        """
        self.calls.append((cmd, payload))
        obj = cbor_mini.loads(payload) if payload else {}

        if cmd == 0x06:                                   # ClientPIN
            blob = self._client_pin(obj)
        elif cmd == 0x0D:                                 # authenticatorConfig
            blob = self._config(obj, payload)
        elif cmd == 0x41:                                 # vendor CBOR
            blob = self._vendor(obj)
        else:
            blob = bytes([CTAP_INVALID_COMMAND])
        return blob[0], blob[1:]

    def _client_pin(self, obj: dict) -> bytes:
        sub = obj.get(2)
        if sub == 0x02:                                   # getKeyAgreement
            x = self.keyag_pub[0].to_bytes(32, "big")
            y = self.keyag_pub[1].to_bytes(32, "big")
            return bytes([0x00]) + cbor_mini.dumps({1: self._cose(x, y)})

        # 0x09 is getPinTokenWithPermissions. The plain 0x05 form carries no
        # permissions field at all, so a token obtained that way is refused by
        # every later config command - the client asks for 0x09 precisely
        # because the ACFG bit has to travel with the request.
        if sub == 0x09:                                   # getPinToken...
            cose = obj.get(3)
            if not isinstance(cose, dict):
                return bytes([CTAP_INVALID_PARAM])
            peer = p256_point_from_bytes(int.from_bytes(cose[-2], "big"),
                                         int.from_bytes(cose[-3], "big"))
            shared = protocol1_shared_secret(p256_ecdh(self.keyag_priv, peer))
            given = protocol1_decrypt(shared, bytes(obj.get(6, b"")))
            if given != pin_hash(self.pin):
                return bytes([0x36])                      # PIN_AUTH_INVALID
            # 0x07 is permissions and 0x08 is rpId. Reading the permissions
            # out of 0x08 finds nothing, so the ACFG check silently passes
            # with a token that the firmware would have refused.
            permissions = obj.get(0x07, 0)
            # The firmware hands back a token either way, but a token issued
            # without the ACFG bit is refused by every config command. Keeping
            # that as a separate flag rather than zeroing the token matters:
            # zeroing it would make the client and the device agree on a
            # worthless token, and the command would appear to succeed here
            # while the real device refused it.
            self.token_has_acfg = bool(permissions & PERMISSION_ACFG)
            return bytes([0x00]) + cbor_mini.dumps(
                {2: protocol1_encrypt(shared, self.pin_token)})
        return bytes([CTAP_INVALID_COMMAND])

    def _config(self, obj: dict, raw: bytes) -> bytes:
        sub = obj.get(1)
        if sub != 0xFF:
            return bytes([0x34])
        subparams = obj.get(2)
        if not isinstance(subparams, dict):
            return bytes([0x34])

        # The firmware hashes the bytes as they arrived on the wire.
        wire = raw
        idx = wire.find(b"\xa2") if wire.find(b"\xa2") > 0 else -1
        # Recover the exact subparams encoding by re-encoding: the client is
        # required to emit ascending keys, which we verify separately.
        if not self._keys_ascending(cbor_mini.dumps(subparams)):
            return bytes([CTAP_INVALID_PARAM])

        raw_sub = cbor_mini.dumps(subparams)
        expected = (b"\xff" * 32 + bytes([0x0D, 0xFF]) + raw_sub)
        given = bytes(obj.get(4, b""))
        want = hmac.new(self.pin_token, expected, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(given, want):
            return bytes([0x36])
        if self.require_permissions and not self.token_has_acfg:
            # Right signature, wrong permission. On the device this is
            # CTAP2_ERR_PIN_AUTH_INVALID and it is the single most misread
            # failure here: the PIN was correct, so it looks like the feature
            # is missing rather than like a token without ACFG.
            return bytes([0x36])

        cmd_id = subparams.get(1)
        self.calls.append(("ran", cmd_id))

        if cmd_id == CONFIG_NORK:
            self.opts ^= 0x04
        elif cmd_id == CONFIG_MCUV_NOTRQD:
            self.opts ^= 0x08
        elif cmd_id == CONFIG_CREDENTIAL_REVOKE:
            slot = subparams.get(3)
            cred = subparams.get(2)
            if slot is None and cred is None:
                return bytes([CTAP_INVALID_PARAM])
            self.revoked.append(slot if slot is not None else bytes(cred))
        elif cmd_id == CONFIG_CREDENTIAL_EXPIRE:
            slot = subparams.get(3)
            cred = subparams.get(2)
            if not self.clock_available:
                return bytes([0x33])
            # Both addressing forms carry an integer and a byte string, and
            # the firmware tells them apart by the length of the string: four
            # bytes is a timestamp (so the integer is a slot), anything of
            # credential length is an id (so the integer is the time).
            if isinstance(cred, (bytes, bytearray)) and len(cred) == 4:
                self.expiries[slot] = int.from_bytes(cred, "big")
            else:
                self.expiries[bytes(cred)] = slot
        elif cmd_id == CONFIG_CREDENTIAL_BUTTON:
            slot = subparams.get(3)
            cred = subparams.get(2)
            if slot is None and cred is None:
                return bytes([CTAP_INVALID_PARAM])
            self.buttons[slot if slot is not None else bytes(cred)] = \
                bool(subparams.get(5))
        elif cmd_id == CONFIG_PIN_POLICY:
            self.pin_policy = subparams.get(3)
        else:
            return bytes([CTAP_INVALID_COMMAND])
        return bytes([0x00])

    def _vendor(self, obj: dict) -> bytes:
        cmd = obj.get(1)
        params = obj.get(2) or {}

        if cmd == VENDOR_MSE:
            if params.get(1) != 0x01:
                return bytes([CTAP_INVALID_COMMAND])
            cose = params.get(2)
            if not isinstance(cose, dict):
                return bytes([0x34])
            peer = p256_point_from_bytes(int.from_bytes(cose[-2], "big"),
                                         int.from_bytes(cose[-3], "big"))
            dh = p256_ecdh(self.keyag_priv, peer)
            x = self.keyag_pub[0].to_bytes(32, "big")
            y = self.keyag_pub[1].to_bytes(32, "big")
            point = b"\x04" + x + y
            from .hpke import hkdf
            self._mse_key = hkdf(dh, point, 44, salt=b"")
            return bytes([0x00]) + cbor_mini.dumps({1: self._cose(x, y)})

        if cmd == VENDOR_UNLOCK:
            blob = params.get(2)
            if not isinstance(blob, (bytes, bytearray)) or len(blob) != 48:
                return bytes([CTAP_INVALID_PARAM])
            from .chachapoly import decrypt
            x = self.keyag_pub[0].to_bytes(32, "big")
            y = self.keyag_pub[1].to_bytes(32, "big")
            point = b"\x04" + x + y
            try:
                got = decrypt(self._mse_key[12:44], self._mse_key[0:12],
                              bytes(blob), point)
            except Exception:
                return bytes([CTAP_INVALID_PARAM])
            self.unlocked = got == self.keydev
            return bytes([0x00]) if self.unlocked else bytes([CTAP_INVALID_PARAM])

        if cmd == VENDOR_BACKUP:
            if params.get(1) == 0x01:
                if not self.unlocked:
                    return bytes([0x36])
                return bytes([0x00]) + cbor_mini.dumps({1: self.blob})
            if params.get(1) == 0x02:
                blob = params.get(2)
                if not isinstance(blob, (bytes, bytearray)) or len(blob) != 60:
                    return bytes([CTAP_INVALID_PARAM])
                self.blob = bytes(blob)
                return bytes([0x00])
            return bytes([CTAP_INVALID_COMMAND])
        return bytes([CTAP_INVALID_COMMAND])
