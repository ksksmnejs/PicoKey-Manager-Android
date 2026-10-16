"""A minimal YKOATH device used to exercise picokeyapp.oath without hardware.

This mirrors the parts of pico-fido's oath.c that the client depends on:
TLV parsing, the key blob layout ([type|alg, digits, secret...] with the HMAC
taken over key[2:]), the 0x72 list encoding, 61 00 chaining answered with
0xA5, and the P1=DE/P2=AD reset guard.

It is a TEST DOUBLE, not a reference implementation: it exists so the client's
framing can be checked, and any disagreement with real hardware wins.
"""

from __future__ import annotations

import hashlib
import os
import hmac
import struct

from . import oath as O

SW_OK = 0x9000


def _sw(sw):
    return [], sw >> 8, sw & 0xFF


class FakeOathDevice:
    """Implements transmit(apdu:list) -> (data, sw1, sw2)."""

    def __init__(self, max_chunk: int = 3):
        self.creds = {}          # name -> dict(key=bytes, imf=int|None)
        self.code = None
        self.validated = True
        self.selected = False
        self.max_chunk = max_chunk       # entries per LIST response
        self._chain = None
        self.reset_done = False
        self.challenge = b"\x01\x02\x03\x04\x05\x06\x07\x08"

    # ---------------------------------------------------------- transport

    def transmit(self, apdu):
        cla, ins, p1, p2 = apdu[0], apdu[1], apdu[2], apdu[3]
        body = bytes(apdu[5:]) if len(apdu) > 5 else b""
        if len(apdu) == 5:
            body = b""
        # strip Le
        if body and len(apdu) > 5:
            lc = apdu[4]
            body = bytes(apdu[5:5 + lc])

        if cla == 0x00 and ins == 0xA4 and p1 == 0x04 and p2 == 0x04:
            self.selected = True
            self.validated = self.code is None
            out = [O.TAG_T_VERSION, 0x03, 0x08, 0x00, 0x00]
            if self.code is not None:
                # Matches the firmware: the challenge is published here and
                # nowhere else, and only while a code is configured.
                self.challenge = os.urandom(8)
                out += list(O.tlv(O.TAG_CHALLENGE, self.challenge))
                out += list(O.tlv(O.TAG_ALGO, bytes([O.ALG_HMAC_SHA1])))
            return out, 0x90, 0x00
        if not self.selected:
            return _sw(0x6A82)

        if ins == 0xA1:                                   # LIST
            return self._list()
        if ins == 0xA5:                                   # SEND REMAINING
            if not self._chain:
                return _sw(0x6A81)
            chunk = self._chain.pop(0)
            # SW=61 00 means "more chunks follow". Returning 90 00 for every
            # chunk made the client stop after the second one, so a device
            # holding more than two chunks' worth of credentials silently
            # lost the rest. The real convention (SW_BYTES_REMAINING_00) is
            # what the client's loop is written against.
            if self._chain:
                return list(chunk), 0x61, 0x00
            self._chain = None
            return list(chunk), 0x90, 0x00
        if ins == 0xA3:                                   # VALIDATE
            return self._validate(body)
        if ins == 0x03:                                   # SET CODE
            return self._set_code(body)
        if ins == 0x01:                                   # PUT
            return self._put(body)
        if ins == 0x02:                                   # DELETE
            return self._delete(body)
        if ins == 0x05:                                   # RENAME
            return self._rename(body)
        if ins == 0x04:                                   # RESET
            if p1 != 0xDE or p2 != 0xAD:
                return _sw(0x6A86)
            self.creds.clear()
            self.code = None
            self.reset_done = True
            self.validated = True
            return _sw(SW_OK)
        if ins == 0xA2:                                   # CALCULATE
            return self._calculate(body, p2)
        if ins == 0xA4:                                   # CALCULATE ALL
            return self._calculate_all(body, p2)
        return _sw(0x6D00)

    # ------------------------------------------------------------ commands

    def _need_auth(self):
        if not self.validated:
            return _sw(0x6982)
        return None

    def _list(self):
        guard = self._need_auth()
        if guard:
            return guard
        if not self.creds:
            return _sw(SW_OK)
        names = sorted(self.creds)
        chunks = [names[i:i + self.max_chunk]
                  for i in range(0, len(names), self.max_chunk)]
        first, rest = chunks[0], chunks[1:]
        # Pending chunks are kept as a LIST and popped one at a time. Storing
        # them as (head, tail) pairs looked equivalent but made a 3-chunk
        # response impossible to drain, which is exactly the case the client's
        # 0xA5 loop has to get right.
        self._chain = [self._encode_list(c) for c in rest]
        payload = self._encode_list(first)
        if rest:
            return list(payload), 0x61, 0x00
        return list(payload), 0x90, 0x00

    def _encode_list(self, names):
        out = bytearray()
        for n in names:
            key = self.creds[n]["key"]
            out += bytes([O.TAG_NAME_LIST, len(n) + 1, key[0]]) + n.encode()
        return bytes(out)

    def _validate(self, body):
        chal = O.tlv_get(body, O.TAG_CHALLENGE)
        resp = O.tlv_get(body, O.TAG_RESPONSE)
        if chal is None or resp is None:
            return _sw(0x6A80)
        if self.code is None:
            # Matches the firmware: SW_DATA_INVALID, but the session is left
            # open because no code means no protection.
            self.validated = True
            return _sw(0x6A80)
        expected = hmac.new(self.code, self.challenge, hashlib.sha1).digest()
        if not hmac.compare_digest(resp, expected):
            return _sw(0x6A80)
        self.validated = True
        out = O.tlv(O.TAG_RESPONSE,
                    hmac.new(self.code, chal, hashlib.sha1).digest())
        return list(out), 0x90, 0x00

    def _set_code(self, body):
        guard = self._need_auth()
        if guard:
            return guard
        if not body:
            self.code = None
            self.validated = True
            return _sw(SW_OK)
        key = O.tlv_get(body, O.TAG_KEY)
        if key is None or len(key) < 2:
            return _sw(0x6A80)
        self.code = key[1:]
        self.validated = True
        return _sw(SW_OK)

    def _put(self, body):
        guard = self._need_auth()
        if guard:
            return guard
        name = O.tlv_get(body, O.TAG_NAME)
        key = O.tlv_get(body, O.TAG_KEY)
        if name is None or key is None or len(key) < 2:
            return _sw(0x6A80)
        imf = O.tlv_get(body, O.TAG_IMF)
        self.creds[name.decode()] = {
            "key": key,
            "imf": struct.unpack(">Q", imf)[0] if imf and len(imf) == 8 else 0,
        }
        return _sw(SW_OK)

    def _delete(self, body):
        guard = self._need_auth()
        if guard:
            return guard
        name = O.tlv_get(body, O.TAG_NAME)
        if name is None or name.decode() not in self.creds:
            return _sw(0x6A80)
        del self.creds[name.decode()]
        return _sw(SW_OK)

    def _rename(self, body):
        guard = self._need_auth()
        if guard:
            return guard
        new = O.tlv_get(body, O.TAG_NAME)
        old = O.tlv_get(body, O.TAG_NAME_LIST)
        if not new or not old or old.decode() not in self.creds:
            return _sw(0x6A80)
        self.creds[new.decode()] = self.creds.pop(old.decode())
        return _sw(SW_OK)

    def _hmac(self, name, challenge, p2):
        cred = self.creds[name]
        key = cred["key"]
        alg = key[0] & O.ALG_MASK
        md = {O.ALG_HMAC_SHA1: hashlib.sha1,
              O.ALG_HMAC_SHA256: hashlib.sha256,
              O.ALG_HMAC_SHA512: hashlib.sha512}[alg]
        secret = key[2:]
        digest = hmac.new(secret, challenge, md).digest()
        if p2 == 0x01:
            offset = digest[-1] & 0x0F
            code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
            return O.tlv(O.TAG_T_RESPONSE,
                         bytes([key[1]]) + struct.pack(">I", code))
        return O.tlv(O.TAG_RESPONSE, bytes([key[1]]) + digest)

    def _calculate(self, body, p2):
        guard = self._need_auth()
        if guard:
            return guard
        name = O.tlv_get(body, O.TAG_NAME)
        chal = O.tlv_get(body, O.TAG_CHALLENGE)
        if name is None or chal is None:
            return _sw(0x6A80)
        n = name.decode()
        if n not in self.creds:
            return _sw(0x6A80)
        cred = self.creds[n]
        if (cred["key"][0] & O.OATH_TYPE_MASK) == O.OATH_TYPE_HOTP:
            challenge = struct.pack(">Q", cred["imf"])
            cred["imf"] += 1
        else:
            challenge = chal
        return list(self._hmac(n, challenge, p2)), 0x90, 0x00

    def _calculate_all(self, body, p2):
        guard = self._need_auth()
        if guard:
            return guard
        chal = O.tlv_get(body, O.TAG_CHALLENGE)
        if chal is None:
            return _sw(0x6A80)
        out = bytearray()
        for n in sorted(self.creds):
            if (self.creds[n]["key"][0] & O.OATH_TYPE_MASK) == O.OATH_TYPE_HOTP:
                continue
            out += O.tlv(O.TAG_NAME, n.encode())
            out += self._hmac(n, chal, p2)
        return list(bytes(out)), 0x90, 0x00
