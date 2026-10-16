"""YKOATH client for the pico-fido OATH applet.

Why this exists
---------------
pico-fido ships an OATH applet (TOTP/HOTP) enabled by default, reachable over
CCID with the standard Yubico OATH AID. Nothing in the project talked to it,
so a board that can hold 30 TOTP secrets was only ever usable as a FIDO key.

The wire format is YKOATH, which uses raw TLV rather than CBOR:

    SELECT  00 A4 04 04 07 A0 00 00 05 27 21 01
    PUT     00 01 00 00 <tlv>           0x71 name, 0x73 key, 0x7a imf (HOTP)
    DELETE  00 02 00 00 <71 name>
    SETCODE 00 03 00 00 <73 key><74 challenge><75 response>
    RESET   00 04 de ad
    RENAME  00 05 00 00 <71 new><72 old>   (pico-fido extension)
    LIST    00 a1 00 00 [01]            -> 0x72 entries, 61 00 = more
    CALC    00 a2 00 <trunc> <74 chal><71 name>
    VALID   00 a3 00 00 <74 challenge><75 response>
    CALCALL 00 a4 00 <trunc> <74 chal>
    REMAIN  00 a5 00 00                 -> the rest of a chained response

Two things are easy to get wrong and are handled explicitly here:

  * SW 61 00 means "more data, send 0xA5", NOT the ISO 7816-4 "GET RESPONSE
    with 0xC0". PicoKey.send() does the 0xC0 chaining automatically, so this
    module uses raw transmit() and drives the chain itself.
  * The key TLV is [type|algorithm, digits?, secret...]: the HMAC is taken over
    key[2:], so byte 1 (digits) is part of the stored blob but not the secret.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
import time

# ------------------------------------------------------------------- TLV

TAG_NAME = 0x71
TAG_NAME_LIST = 0x72
TAG_KEY = 0x73
TAG_CHALLENGE = 0x74
TAG_RESPONSE = 0x75
TAG_T_RESPONSE = 0x76
TAG_NO_RESPONSE = 0x77
TAG_PROPERTY = 0x78
TAG_T_VERSION = 0x79
TAG_IMF = 0x7A
TAG_ALGO = 0x7B
TAG_TOUCH = 0x7C
TAG_SERIAL_NUMBER = 0x8F
TAG_PIN_COUNTER = 0x82

# ------------------------------------------------------------- algorithms

ALG_HMAC_SHA1 = 0x01
ALG_HMAC_SHA256 = 0x02
ALG_HMAC_SHA512 = 0x03
ALG_MASK = 0x0F

OATH_TYPE_HOTP = 0x10
OATH_TYPE_TOTP = 0x20
OATH_TYPE_MASK = 0xF0

PROP_INC = 0x01
PROP_TOUCH = 0x02
PROP_PIN = 0x03

ALG_NAMES = {ALG_HMAC_SHA1: "SHA1", ALG_HMAC_SHA256: "SHA256",
             ALG_HMAC_SHA512: "SHA512"}
_MD = {ALG_HMAC_SHA1: hashlib.sha1,
       ALG_HMAC_SHA256: hashlib.sha256,
       ALG_HMAC_SHA512: hashlib.sha512}


class OathError(Exception):
    pass


# ---------------------------------------------------------------------- SW

SW_TEXTS = {
    0x9000: "ok",
    0x6A80: "the data is malformed",
    0x6A81: "this function is not supported",
    0x6A82: "the OATH applet is not available on this device",
    0x6A84: "no space left for another credential",
    0x6982: "not authenticated - set or validate the access code first",
    0x6A86: "wrong P1/P2",
    0x6D00: "this instruction does not exist",
    0x6581: "memory failure",
    0x6B00: "wrong parameters",
    0x6C00: "the response is longer than the requested length",
}


def sw_text(sw: int) -> str:
    return SW_TEXTS.get(sw, "unexpected status 0x%04X" % sw)


class SWError(OathError):
    def __init__(self, sw: int):
        self.sw = sw
        super().__init__("%s (SW=%04X)" % (sw_text(sw), sw))


# -------------------------------------------------------------------- TLV

def tlv(tag: int, value: bytes) -> bytes:
    if len(value) > 0xFF:
        raise OathError("TLV values are limited to 255 bytes")
    return bytes([tag, len(value)]) + bytes(value)


def tlv_get(data: bytes, tag: int) -> bytes | None:
    """First value for `tag`. Names themselves contain no nested TLV, so a
    flat scan is correct here."""
    i = 0
    while i + 2 <= len(data):
        t = data[i]
        ln = data[i + 1]
        if i + 2 + ln > len(data):
            break
        if t == tag:
            return data[i + 2:i + 2 + ln]
        i += 2 + ln
    return None


def tlv_all(data: bytes) -> list:
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


# ------------------------------------------------------------------ client

OATH_AID = bytes([0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01])


class OathApp:
    """One session with the OATH applet.

    `card` is anything exposing transmit(apdu:list) -> (data, sw1, sw2), i.e.
    picokeyapp.pk.PicoKey.PicoKey.
    """

    def __init__(self, card):
        self._card = card
        self.validated = False

    # ---------------------------------------------------------- transport

    def _tx(self, ins: int, data: bytes = b"", p1: int = 0x00, p2: int = 0x00,
            ne: int = 0x00) -> tuple:
        apdu = [0x00, ins, p1, p2]
        if data:
            apdu += [len(data)]
            apdu += list(data)
        apdu += [ne]
        resp, sw1, sw2 = self._card.transmit(apdu)
        return bytes(resp), (sw1 << 8) | sw2

    def select(self) -> bytes:
        """SELECT the applet. Returns whatever it answers (name/serial TLVs).

        When an access code is configured the device puts an 8 byte challenge
        in this answer (TAG 0x74). That is the only place it is published:
        there is no command that asks for it. So it is cached here, because
        VALIDATE has to answer exactly this value.
        """
        apdu = [0x00, 0xA4, 0x04, 0x04, len(OATH_AID)] + list(OATH_AID) + [0x00]
        resp, sw1, sw2 = self._card.transmit(apdu)
        sw = (sw1 << 8) | sw2
        if sw != 0x9000:
            raise SWError(sw)
        self.validated = False
        resp = bytes(resp)
        self._select_challenge = tlv_get(resp, TAG_CHALLENGE)
        return resp

    @property
    def device_challenge(self) -> bytes | None:
        """The challenge from the last SELECT, or None if no code is set.

        A device without an access code omits the challenge entirely; that is
        the signal that no authentication is needed at all.
        """
        return getattr(self, "_select_challenge", None)

    @property
    def code_required(self) -> bool:
        return self.device_challenge is not None

    # ------------------------------------------------------- access code

    def validate(self, code: bytes, challenge: bytes = None) -> None:
        """Authenticate with the access code. Needed before PUT/DELETE/CALC.

        Two things are sent: the answer to the challenge the device published
        in SELECT, and a challenge of our own. The device answers with the
        HMAC of ours, which lets `validate_and_check` tell a right code from a
        wrong one without trusting the status word alone.
        """
        if challenge is None:
            challenge = self.device_challenge
        if challenge is None:
            # No code configured: nothing to answer, but a session still has
            # to be opened before the protected commands work.
            challenge = b""
        resp = hmac.new(code, challenge, hashlib.sha1).digest()
        own = os.urandom(8)
        data = tlv(TAG_RESPONSE, resp) + tlv(TAG_CHALLENGE, own)
        out, sw = self._tx(0xA3, data, ne=0x00)
        if sw != 0x9000 and sw != 0x6A80:
            # 6A80 is what an unconfigured device answers; it also leaves the
            # session validated, so it is not an error for our purposes.
            raise SWError(sw)
        self.validated = True
        self._last_validate_response = tlv_get(out, TAG_RESPONSE)
        self._own_challenge = own

    def validate_and_check(self, code: bytes) -> bool:
        """Validate and report whether the code was accepted.

        A wrong code is not reported as an error by every device, so the only
        reliable check is comparing the answer to our own challenge.
        compare_digest rather than ==: a plain comparison leaks the position
        of the first differing byte through timing, and this is a secret.
        """
        self.validate(code)
        expected = hmac.new(code, self._own_challenge, hashlib.sha1).digest()
        got = getattr(self, "_last_validate_response", None)
        return got is not None and hmac.compare_digest(got, expected)

    def set_code(self, code: bytes) -> None:
        """Set or clear the access code. Empty bytes clears it."""
        if code:
            key = bytes([ALG_HMAC_SHA1]) + code
            challenge = b"\x00" * 8
            resp = hmac.new(code, challenge, hashlib.sha1).digest()
            data = tlv(TAG_KEY, key) + tlv(TAG_CHALLENGE, challenge) \
                + tlv(TAG_RESPONSE, resp)
        else:
            data = b""
        _, sw = self._tx(0x03, data)
        if sw != 0x9000:
            raise SWError(sw)
        self.validated = True

    # ------------------------------------------------------------ listing

    def list(self) -> list:
        """Every credential as dicts, following the 61 00 chain if needed.

        The chain is driven with 0xA5 (SEND REMAINING), not 0xC0: in YKOATH
        SW=61 00 means "more entries", and a GET RESPONSE would be answered
        with something unrelated.
        """
        buf, sw = self._tx(0xA1, b"", ne=0x00)
        if sw != 0x9000 and (sw >> 8) != 0x61:
            raise SWError(sw)
        while (sw >> 8) == 0x61:
            more, sw = self._tx(0xA5, b"", ne=0x00)
            if not more:
                # A device that advertises more data and then sends none would
                # spin here forever. Stopping reports what was collected
                # instead of hanging the whole scan.
                break
            buf += more
            if sw != 0x9000 and (sw >> 8) != 0x61:
                raise SWError(sw)
        out = []
        for tag, value in tlv_all(buf):
            if tag != TAG_NAME_LIST or len(value) < 1:
                continue
            kind = value[0]
            name = value[1:]
            out.append({
                "name": name.decode("utf-8", "replace"),
                "type": "HOTP" if (kind & OATH_TYPE_MASK) == OATH_TYPE_HOTP
                        else "TOTP",
                "algorithm": ALG_NAMES.get(kind & ALG_MASK, "?"),
                "digits": 6 if (kind & ALG_MASK) == ALG_HMAC_SHA1 else 6,
                "touch": bool(kind & 0x00),   # properties are only in ext mode
            })
        return out

    # -------------------------------------------------------- calculating

    def calculate(self, name: str, timestamp: int = None,
                  truncate: bool = True) -> tuple:
        """One credential. Returns (digits, raw_hmac).

        `truncate` asks the device for the truncated OTP (P2=1) rather than
        the full HMAC (P2=0).
        """
        if timestamp is None:
            timestamp = int(time.time())
        chal = struct.pack(">Q", timestamp // 30)
        data = tlv(TAG_NAME, name.encode("utf-8")) + tlv(TAG_CHALLENGE, chal)
        out, sw = self._tx(0xA2, data, p2=0x01 if truncate else 0x00, ne=0x00)
        if sw != 0x9000:
            raise SWError(sw)
        resp = tlv_get(out, TAG_T_RESPONSE if truncate else TAG_RESPONSE)
        if resp is None:
            raise OathError("no OTP in the response")
        if truncate:
            if len(resp) < 5:
                raise OathError("truncated OTP is too short")
            digits = struct.unpack(">I", resp[1:5])[0] & 0x7FFFFFFF
            return str(digits % (10 ** resp[0])).zfill(resp[0]), resp
        return resp[1:].hex(), resp

    def calculate_all(self, timestamp: int = None, truncate: bool = True) -> list:
        """Every TOTP at once. HOTP entries are skipped by the device."""
        if timestamp is None:
            timestamp = int(time.time())
        chal = struct.pack(">Q", timestamp // 30)
        buf, sw = self._tx(0xA4, tlv(TAG_CHALLENGE, chal),
                           p2=0x01 if truncate else 0x00, ne=0x00)
        if sw != 0x9000 and (sw >> 8) != 0x61:
            raise SWError(sw)
        while (sw >> 8) == 0x61:
            more, sw = self._tx(0xA5, b"", ne=0x00)
            if not more:
                # A device that advertises more data and then sends none would
                # spin here forever. Stopping reports what was collected
                # instead of hanging the whole scan.
                break
            buf += more
            if sw != 0x9000 and (sw >> 8) != 0x61:
                raise SWError(sw)
        out = []
        for tag, value in tlv_all(buf):
            if tag == TAG_NAME:
                out.append({"name": value.decode("utf-8", "replace")})
            elif tag in (TAG_T_RESPONSE, TAG_RESPONSE) and out:
                if truncate and len(value) >= 5:
                    d = struct.unpack(">I", value[1:5])[0] & 0x7FFFFFFF
                    out[-1]["otp"] = str(d % (10 ** value[0])).zfill(value[0])
                    out[-1]["digits"] = value[0]
                else:
                    out[-1]["raw"] = value[1:].hex()
        return out

    # ---------------------------------------------------------- managing

    def put(self, name: str, secret: bytes, kind: int = None,
            algorithm: int = ALG_HMAC_SHA1, digits: int = 6,
            counter: int = 0, touch: bool = False) -> None:
        """Store or overwrite one credential.

        The stored key blob is [type|alg, digits, secret...] and the HMAC is
        taken over everything after the first TWO bytes, so `digits` must be
        present but is not part of the secret material.
        """
        if kind is None:
            kind = OATH_TYPE_TOTP
        if algorithm not in _MD:
            raise OathError("unknown algorithm")
        if digits not in (6, 7, 8):
            raise OathError("digits must be 6, 7 or 8")
        key = bytes([kind | algorithm, digits]) + secret
        data = tlv(TAG_NAME, name.encode("utf-8")) + tlv(TAG_KEY, key)
        if (kind & OATH_TYPE_MASK) == OATH_TYPE_HOTP:
            data += tlv(TAG_IMF, struct.pack(">Q", counter))
        if touch:
            data += tlv(TAG_PROPERTY, bytes([PROP_TOUCH]))
        _, sw = self._tx(0x01, data)
        if sw != 0x9000:
            raise SWError(sw)

    def delete(self, name: str) -> None:
        _, sw = self._tx(0x02, tlv(TAG_NAME, name.encode("utf-8")))
        if sw != 0x9000:
            raise SWError(sw)

    def rename(self, old: str, new: str) -> None:
        """pico-fido extension: 0x05 with the new name in 0x71, old in 0x72."""
        data = tlv(TAG_NAME, new.encode("utf-8")) \
            + tlv(TAG_NAME_LIST, old.encode("utf-8"))
        _, sw = self._tx(0x05, data)
        if sw != 0x9000:
            raise SWError(sw)

    def reset(self) -> None:
        """Wipe every OATH credential. Requires P1=DE P2=AD."""
        _, sw = self._tx(0x04, b"", p1=0xDE, p2=0xAD)
        if sw != 0x9000:
            raise SWError(sw)
        self.validated = True


# ---------------------------------------------------------------- helpers

def base32_decode(text: str) -> bytes:
    """Decode an otpauth:// secret. Yubico-style: uppercase, no padding."""
    s = "".join(text.split()).upper().rstrip("=")
    s = s.replace(" ", "")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    bits = 0
    value = 0
    out = bytearray()
    for ch in s:
        idx = alphabet.find(ch)
        if idx < 0:
            raise OathError("not a base32 character: %r" % ch)
        value = (value << 5) | idx
        bits += 5
        if bits >= 8:
            out.append((value >> (bits - 8)) & 0xFF)
            bits -= 8
    return bytes(out)


def parse_otpauth(uri: str) -> dict:
    """Pull issuer/account/secret/type/algorithm/digits/period out of a URI."""
    from urllib.parse import urlparse, parse_qs
    u = urlparse(uri)
    if u.scheme != "otpauth":
        raise OathError("not an otpauth:// URI")
    q = parse_qs(u.query)
    label = u.path.lstrip("/")
    issuer, account = "", label
    if ":" in label:
        issuer, account = label.split(":", 1)
    issuer = q.get("issuer", [issuer])[0]
    return {
        "type": u.netloc.upper(),                     # totp | hotp
        "issuer": issuer,
        "account": account,
        "secret": q.get("secret", [""])[0],
        "algorithm": {"SHA1": ALG_HMAC_SHA1, "SHA256": ALG_HMAC_SHA256,
                      "SHA512": ALG_HMAC_SHA512}.get(
                          q.get("algorithm", ["SHA1"])[0].upper(), ALG_HMAC_SHA1),
        "digits": int(q.get("digits", ["6"])[0]),
        "period": int(q.get("period", ["30"])[0]),
        "counter": int(q.get("counter", ["0"])[0]),
    }


def oath_name(issuer: str, account: str) -> str:
    """YKOATH display name. "issuer:account" when both are known."""
    issuer = (issuer or "").strip()
    account = (account or "").strip()
    if issuer and account:
        return "%s:%s" % (issuer, account)
    return issuer or account


def totp_local(secret: bytes, timestamp: int = None, digits: int = 6,
               algorithm: int = ALG_HMAC_SHA1, period: int = 30) -> str:
    """Compute a TOTP without the device.

    Only used to sanity-check a freshly written credential: it duplicates what
    the applet does, so if the board returns something else the write went
    wrong (wrong secret, wrong algorithm) rather than the clock being off.
    """
    if timestamp is None:
        timestamp = int(time.time())
    counter = timestamp // period
    msg = struct.pack(">Q", counter)
    digest = hmac.new(secret, msg, _MD[algorithm]).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)
