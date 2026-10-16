"""A fake management applet, used by the self test.

It reproduces the two behaviours that matter and that a client can get wrong:

* the config blob is echoed back verbatim after a write, and the length prefix
  is validated exactly like the firmware does;
* a wrong password is 6982, not a generic error.

It does not try to emulate flash or user presence.
"""

from __future__ import annotations

import struct

from . import mgmt as M


class FakeMgmtDevice:
    def __init__(self, caps: int = None, version: str = "8.0.0"):
        self.selected = False
        self.version = version
        self.caps = M.CAP_FIDO2 | M.CAP_U2F | M.CAP_OTP | M.CAP_OATH
        if caps is not None:
            self.caps = caps
        self.enabled = self.caps
        self.serial = 0x01020304
        self.config = None
        self.reset_done = False
        self.pin = None
        self.write_calls = []

    def transmit(self, apdu):
        cla, ins, p1, p2 = apdu[0], apdu[1], apdu[2], apdu[3]
        body = b""
        if len(apdu) > 5:
            lc = apdu[4]
            body = bytes(apdu[5:5 + lc])

        if cla == 0x00 and ins == 0xA4 and p1 == 0x04 and p2 == 0x04:
            self.selected = True
            return list(self.version.encode("ascii")), 0x90, 0x00
        if not self.selected:
            return [], 0x6A, 0x82

        if ins == M.INS_READ_CONFIG:
            return list(self._config_blob()), 0x90, 0x00
        if ins == M.INS_WRITE_CONFIG:
            return self._write(body)
        if ins == M.INS_FACTORY_RESET:
            self.reset_done = True
            self.pin = None
            self.config = None
            return [], 0x90, 0x00

        if ins == M.INS_SET_PIN:
            if self.pin is not None:
                return [], 0x69, 0x85          # already set
            pw = M.tlv_get(body, M.TAG_PASSWORD)
            if pw is None:
                return [], 0x6A, 0x80
            self.pin = pw
            return [], 0x90, 0x00
        if ins == M.INS_CHANGE_PIN:
            if self.pin is None:
                return [], 0x69, 0x85
            old = M.tlv_get(body, M.TAG_PASSWORD)
            new = M.tlv_get(body, M.TAG_NEW_PASSWORD)
            if old is None or new is None:
                return [], 0x6A, 0x80
            if old != self.pin:
                return [], 0x69, 0x82
            self.pin = new
            return [], 0x90, 0x00
        if ins == M.INS_VERIFY_PIN:
            if self.pin is None:
                return [], 0x69, 0x85
            pw = M.tlv_get(body, M.TAG_PASSWORD)
            if pw is None:
                return [], 0x6A, 0x80
            if pw != self.pin:
                return [], 0x69, 0x82
            return [], 0x90, 0x00

        return [], 0x6D, 0x00

    # ------------------------------------------------------------ internals

    def _config_blob(self) -> bytes:
        out = M.tlv(M.TAG_USB_SUPPORTED, struct.pack(">H", self.caps))
        out += M.tlv(M.TAG_SERIAL, struct.pack(">I", self.serial))
        out += M.tlv(M.TAG_USB_ENABLED, struct.pack(">H", self.enabled))
        out += M.tlv(M.TAG_FORM_FACTOR, bytes([0x01]))
        out += M.tlv(M.TAG_VERSION, bytes([8, 0, 0]))
        out += M.tlv(M.TAG_DEVICE_FLAGS, bytes([M.FLAG_EJECT]))
        out += M.tlv(M.TAG_CONFIG_LOCK, bytes([0x00]))
        if self.config is not None:
            # Matches the firmware: once a config file exists it is appended
            # verbatim after the fixed tags.
            out += self.config
        return out

    def _write(self, body: bytes):
        self.write_calls.append(body)
        # The firmware checks that the first byte equals the remaining length.
        if len(body) < 1 or body[0] != len(body) - 1:
            return [], 0x6A, 0x80
        self.config = body[1:]
        for t, v in M.tlv_all(self.config):
            if t == M.TAG_USB_ENABLED:
                self.enabled = struct.unpack(">H", v)[0]
            elif t == M.TAG_CONFIG_LOCK:
                pass
        return [], 0x90, 0x00
