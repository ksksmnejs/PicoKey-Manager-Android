"""Device management applet and OATH password protection.

Two things live here:

* the Pico Keys management applet (AID A0 00 00 05 27 47 11 17), which
  reports what the device is and lets the enabled USB interfaces be changed;
* the password ("OTP PIN") commands that belong to the OATH applet but are
  separate from the access code.

Everything here is plain TLV over CCID: no CBOR, no crypto. That makes it the
safest part of the protocol to talk to, and the easiest to get wrong silently,
because a malformed config blob is accepted by the device and simply does
nothing.

Command numbers were taken from pico-fido src/fido/management.c and
src/fido/oath.c.
"""

from __future__ import annotations

import struct

# ------------------------------------------------------------------- tags

TAG_USB_SUPPORTED = 0x01
TAG_SERIAL = 0x02
TAG_USB_ENABLED = 0x03
TAG_FORM_FACTOR = 0x04
TAG_VERSION = 0x05
TAG_AUTO_EJECT_TIMEOUT = 0x06
TAG_CHALRESP_TIMEOUT = 0x07
TAG_DEVICE_FLAGS = 0x08
TAG_APP_VERSIONS = 0x09
TAG_CONFIG_LOCK = 0x0A
TAG_UNLOCK = 0x0B
TAG_REBOOT = 0x0C
TAG_NFC_SUPPORTED = 0x0D
TAG_NFC_ENABLED = 0x0E

# capabilities, from management.h
CAP_OTP = 0x0001
CAP_U2F = 0x0002
CAP_CCID = 0x0004
CAP_OATH = 0x0020
CAP_PIV = 0x0010
CAP_OPENPGP = 0x0008
CAP_HSMAUTH = 0x0100
CAP_FIDO2 = 0x0200

CAP_NAMES = [
    (CAP_FIDO2, "FIDO2"),
    (CAP_U2F, "U2F"),
    (CAP_OTP, "OTP"),
    (CAP_OATH, "OATH"),
    (CAP_PIV, "PIV"),
    (CAP_OPENPGP, "OpenPGP"),
    (CAP_HSMAUTH, "HSMauth"),
    (CAP_CCID, "CCID"),
]

FLAG_REMOTE_WAKEUP = 0x40
FLAG_EJECT = 0x80

INS_READ_CONFIG = 0x1D
INS_WRITE_CONFIG = 0x1C
INS_FACTORY_RESET = 0x1E

MAN_AID = bytes([0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17])

# OATH password commands
INS_SET_PIN = 0xB4
INS_CHANGE_PIN = 0xB3
INS_VERIFY_PIN = 0xB2
TAG_PASSWORD = 0x80
TAG_NEW_PASSWORD = 0x81


class MgmtError(Exception):
    pass


class SWError(MgmtError):
    def __init__(self, sw: int):
        super().__init__("device returned SW=%04X" % sw)
        self.sw = sw


def tlv(tag: int, value: bytes) -> bytes:
    if len(value) > 0xFF:
        raise MgmtError("TLV values are limited to 255 bytes")
    return bytes([tag, len(value)]) + bytes(value)


def tlv_all(data: bytes) -> list:
    """Parse a flat TLV stream.

    The config blob is flat: every value is raw bytes, never a nested TLV, so
    a linear walk is correct. Lengths above 255 do not occur here.
    """
    out = []
    i = 0
    while i + 2 <= len(data):
        t = data[i]
        ln = data[i + 1]
        if i + 2 + ln > len(data):
            break
        out.append((t, data[i + 2:i + 2 + ln]))
        i += 2 + ln
    return out


def tlv_get(data: bytes, tag: int) -> bytes | None:
    for t, v in tlv_all(data):
        if t == tag:
            return v
    return None


def cap_names(bits: int) -> list:
    return [name for mask, name in CAP_NAMES if bits & mask]


class ManagementApp:
    """The management applet, speaking TLV APDUs over an already opened card."""

    def __init__(self, card):
        self._card = card

    def _tx(self, ins: int, data: bytes = b"", p1: int = 0x00, p2: int = 0x00,
            ne: int = 0x00) -> tuple:
        apdu = [0x00, ins, p1, p2]
        if data:
            apdu += [len(data)]
            apdu += list(data)
        apdu += [ne]
        resp, sw1, sw2 = self._card.transmit(apdu)
        return bytes(resp), (sw1 << 8) | sw2

    def select(self) -> str:
        """SELECT the applet. Returns its version string, e.g. "8.0.0"."""
        apdu = [0x00, 0xA4, 0x04, 0x04, len(MAN_AID)] + list(MAN_AID) + [0x00]
        resp, sw1, sw2 = self._card.transmit(apdu)
        sw = (sw1 << 8) | sw2
        if sw != 0x9000:
            raise SWError(sw)
        return bytes(resp).decode("ascii", "replace")

    def read_config(self) -> dict:
        """Read the device configuration, decoded into plain Python types."""
        out, sw = self._tx(INS_READ_CONFIG)
        if sw != 0x9000:
            raise SWError(sw)
        raw = {}
        for t, v in tlv_all(out):
            raw.setdefault(t, v)
        cfg = {"raw": out, "tags": raw}
        if TAG_USB_SUPPORTED in raw:
            cfg["usb_supported"] = struct.unpack(">H", raw[TAG_USB_SUPPORTED])[0]
        if TAG_USB_ENABLED in raw:
            cfg["usb_enabled"] = struct.unpack(">H", raw[TAG_USB_ENABLED])[0]
        if TAG_USB_SUPPORTED in raw:
            cfg["usb_supported_names"] = cap_names(cfg.get("usb_supported", 0))
        if TAG_USB_ENABLED in raw:
            cfg["usb_enabled_names"] = cap_names(cfg.get("usb_enabled", 0))
        if TAG_SERIAL in raw:
            cfg["serial"] = struct.unpack(">I", raw[TAG_SERIAL])[0]
        if TAG_VERSION in raw and len(raw[TAG_VERSION]) == 3:
            cfg["version"] = "%d.%d.%d" % tuple(raw[TAG_VERSION])
        if TAG_FORM_FACTOR in raw:
            cfg["form_factor"] = raw[TAG_FORM_FACTOR][0]
        if TAG_DEVICE_FLAGS in raw:
            cfg["device_flags"] = raw[TAG_DEVICE_FLAGS][0]
        if TAG_CONFIG_LOCK in raw:
            cfg["config_lock"] = raw[TAG_CONFIG_LOCK][0]
        if TAG_NFC_SUPPORTED in raw:
            cfg["nfc_supported"] = struct.unpack(">H", raw[TAG_NFC_SUPPORTED])[0]
        if TAG_NFC_ENABLED in raw:
            cfg["nfc_enabled"] = struct.unpack(">H", raw[TAG_NFC_ENABLED])[0]
        return cfg

    def write_config(self, blob: bytes) -> None:
        """Write a new configuration.

        The device expects the blob prefixed by its own length, and validates
        that prefix: getting it wrong is SW_WRONG_DATA rather than corrupt
        storage. User presence is required, so this blocks until the button is
        pressed or the request times out.
        """
        if len(blob) > 0xFF:
            raise MgmtError("configuration is limited to 255 bytes")
        _, sw = self._tx(INS_WRITE_CONFIG, bytes([len(blob)]) + blob)
        if sw != 0x9000:
            raise SWError(sw)

    def set_usb_enabled(self, caps: int) -> None:
        """Enable exactly the given set of USB interfaces."""
        if caps > 0xFFFF:
            raise MgmtError("capability mask is 16 bit")
        self.write_config(tlv(TAG_USB_ENABLED, struct.pack(">H", caps)))

    def factory_reset(self) -> None:
        """Erase every credential and return the device to its initial state.

        There is no confirmation on the device side and no undo. Callers must
        ask before calling this.
        """
        _, sw = self._tx(INS_FACTORY_RESET)
        if sw != 0x9000:
            raise SWError(sw)


class OathPassword:
    """The OATH password, separate from the access code.

    The access code protects the whole applet; the password additionally gates
    individual credentials marked as password protected. The two are unrelated
    and either can exist without the other.
    """

    def __init__(self, card):
        self._card = card

    def _tx(self, ins: int, data: bytes = b"", p1: int = 0x00, p2: int = 0x00,
            ne: int = 0x00) -> tuple:
        apdu = [0x00, ins, p1, p2]
        if data:
            apdu += [len(data)]
            apdu += list(data)
        apdu += [ne]
        resp, sw1, sw2 = self._card.transmit(apdu)
        return bytes(resp), (sw1 << 8) | sw2

    def set_pin(self, password: bytes) -> None:
        """Set the password for the first time. Fails if one is already set."""
        _, sw = self._tx(INS_SET_PIN, tlv(TAG_PASSWORD, password))
        if sw != 0x9000:
            raise SWError(sw)

    def change_pin(self, old: bytes, new: bytes) -> None:
        _, sw = self._tx(INS_CHANGE_PIN,
                         tlv(TAG_PASSWORD, old) + tlv(TAG_NEW_PASSWORD, new))
        if sw != 0x9000:
            raise SWError(sw)

    def verify_pin(self, password: bytes) -> bool:
        """Verify the password. Returns False on a wrong password.

        A wrong password is 6982, while 6985 means no password is configured
        at all. Those two must not be folded together: reporting "wrong
        password" when none has ever been set sends the caller looking for a
        password that does not exist.
        """
        _, sw = self._tx(INS_VERIFY_PIN, tlv(TAG_PASSWORD, password))
        if sw == 0x9000:
            return True
        if sw == 0x6982:
            return False
        if sw == 0x6985:
            raise MgmtError("no password is configured on this device")
        raise SWError(sw)
