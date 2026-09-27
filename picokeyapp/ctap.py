"""
CTAPHID (FIDO over USB HID) transport for the FIDO channel.

Android has no HIDAPI and no /dev/hidraw, so the 64-byte FIDO reports are sent
with bulk transfers on the HID interface's interrupt endpoints (that works with
the Android USB Host API as long as the kernel HID driver has been detached,
which usbhost.Connection does by claiming with force=True).

Supported here:
  * CTAPHID_INIT  (0x86) - allocate a channel, read device capabilities
  * CTAPHID_WINK  (0x88) - blink the LED, the fastest "is it alive?" test
  * CTAPHID_CBOR  (0x90) - raw CTAP2 request/response (used for getInfo)
"""

from __future__ import annotations

import os
import struct
import time

from .cbor_mini import loads
from .pk.core.log import get_logger

logger = get_logger("ctap")

CTAPHID_PING = 0x81
CTAPHID_MSG = 0x83
CTAPHID_LOCK = 0x84
CTAPHID_INIT = 0x86
CTAPHID_WINK = 0x88
CTAPHID_CBOR = 0x90
CTAPHID_CANCEL = 0x91
CTAPHID_KEEPALIVE = 0xBB
CTAPHID_ERROR = 0xBF

BROADCAST_CID = 0xFFFFFFFF

CTAP2_GET_INFO = 0x04
CTAP2_RESET = 0x07

CAP_WINK = 0x01
CAP_CBOR = 0x04
CAP_NMSG = 0x08

# CTAPHID_ERROR payload carries one of these. Reporting "unexpected response
# command 0xBF" (which is what fell out before) threw away the only byte that
# says what actually went wrong.
HID_ERRORS = {
    0x01: "INVALID_CMD",
    0x02: "INVALID_PAR",
    0x03: "INVALID_LEN",
    0x04: "INVALID_SEQ",
    0x05: "MSG_TIMEOUT",
    0x06: "CHANNEL_BUSY",
    0x0A: "LOCK_REQUIRED",
    0x7F: "OTHER",
}

# CTAPHID_KEEPALIVE status byte - what the device is waiting for.
KA_PROCESSING = 0x01
KA_UPNEEDED = 0x02

# CTAP2 status codes that a cancelled request can come back with.
CTAP2_OK = 0x00
CTAP2_ERR_KEEPALIVE_CANCEL = 0x2D


class CTAPError(Exception):
    pass


_UNSET = object()      # distinguishes "not given" from a deliberate None


class CTAPHidError(CTAPError):
    """The transport answered with CTAPHID_ERROR instead of the command."""

    def __init__(self, code: int):
        self.code = code
        name = HID_ERRORS.get(code, "UNKNOWN")
        super().__init__(f"CTAPHID error 0x{code:02X} ({name})")


class CTAPCancel(CTAPError):
    """The request was cancelled (by us timing out, or the user giving up)."""


class CTAPHIDTransport:
    def __init__(self, connection, packet_size: int = 64):
        self._conn = connection
        self.packet_size = packet_size
        self.cid = BROADCAST_CID
        self._init_response = None

    # ------------------------------------------------------------- framing

    def _write_frame(self, cid: int, cmd: int, data: bytes):
        """Send one CTAPHID message, splitting it into INIT + CONT packets."""
        payload = bytes(data)
        frame = bytearray(self.packet_size)
        frame[0:4] = struct.pack(">I", cid & 0xFFFFFFFF)
        frame[4] = (cmd | 0x80) & 0xFF
        frame[5] = (len(payload) >> 8) & 0xFF
        frame[6] = len(payload) & 0xFF
        head = payload[:self.packet_size - 7]
        frame[7:7 + len(head)] = head
        written = self._conn.write(bytes(frame), timeout=3000)
        if written != self.packet_size:
            raise CTAPError(f"short HID write: {written}/{self.packet_size}")

        rest = payload[self.packet_size - 7:]
        seq = 0
        while rest:
            cont = bytearray(self.packet_size)
            cont[0:4] = struct.pack(">I", cid & 0xFFFFFFFF)
            cont[4] = seq & 0x7F
            chunk = rest[:self.packet_size - 5]
            cont[5:5 + len(chunk)] = chunk
            written = self._conn.write(bytes(cont), timeout=3000)
            if written != self.packet_size:
                raise CTAPError(f"short HID continuation write: {written}")
            rest = rest[self.packet_size - 5:]
            seq += 1

    def _read_frame(self, deadline: float, expect_cid: int = None):
        """Read one CTAPHID response. Returns (cmd, payload).

        Per spec BCNTH/BCNTL counts the data only - the command byte lives at
        offset 4 of the INIT packet and is NOT part of the counted length.

        `deadline` is absolute: it bounds the WHOLE exchange, not this one
        read. A device that keeps sending KEEPALIVE (waiting for a touch) used
        to reset the timeout on every report and hang forever.

        `expect_cid=None` accepts any channel, which is what CTAPHID_INIT
        needs: it is sent on the broadcast CID and answered with a newly
        allocated one.
        """
        first = self._read(self.packet_size, deadline)
        if len(first) < 7:
            raise CTAPError("short HID report")
        cid = struct.unpack(">I", bytes(first[0:4]))[0]
        if expect_cid is None:
            return_cid = cid
        else:
            return_cid = expect_cid
        if cid != return_cid:
            # A different authenticator (or a stale frame from a previous
            # session) answering on the same endpoint.
            raise CTAPError(f"HID response from another channel "
                            f"(0x{cid:08X}, expected 0x{self.cid:08X})")
        resp_cmd = first[4]                        # 0x86 INIT, 0x90 CBOR, 0xBB KEEPALIVE
        bcnt = (first[5] << 8) | first[6]
        data = bytearray(first[7:])
        seq = 0
        while len(data) < bcnt:
            cont = self._read(self.packet_size, deadline)
            if len(cont) < 5:
                raise CTAPError("short continuation report")
            if struct.unpack(">I", bytes(cont[0:4]))[0] != return_cid:
                raise CTAPError("continuation report from another channel")
            if cont[4] != seq:
                raise CTAPError(f"continuation sequence mismatch (got {cont[4]}, want {seq})")
            data += cont[5:]
            seq = (seq + 1) & 0x7F
        return resp_cmd, bytes(data[:bcnt])

    def _read(self, length: int, deadline: float) -> bytes:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise CTAPError("timed out waiting for the device")
        return self._conn.read(length=length, timeout=int(remaining * 1000))

    def _exchange(self, cmd: int, payload: bytes = b"", timeout: int = 3000,
                  on_keepalive=None, cancel_on_timeout: bool = True,
                  expect_cid: int = _UNSET):
        """Send one command and wait for its response.

        Mirrors python-fido2's CtapHidDevice.call: KEEPALIVE keeps us waiting
        but does NOT extend the deadline, ERROR carries a real error code, and
        running out of time sends CTAPHID_CANCEL so the authenticator stops
        waiting for a touch that will never come.

        `expect_cid` defaults to the current channel; pass None to accept any
        (only CTAPHID_INIT needs that).
        """
        if expect_cid is _UNSET:
            expect_cid = self.cid
        deadline = time.monotonic() + max(timeout, 100) / 1000.0
        self._write_frame(self.cid, cmd, payload)
        last_ka = None
        while True:
            try:
                resp_cmd, data = self._read_frame(deadline, expect_cid)
            except CTAPError:
                if cancel_on_timeout:
                    self._cancel()
                raise
            if resp_cmd == CTAPHID_KEEPALIVE:
                status = data[0] if data else 0
                if on_keepalive is not None and status != last_ka:
                    last_ka = status
                    on_keepalive(status)
                continue                       # device still busy, keep waiting
            if resp_cmd == CTAPHID_ERROR:
                raise CTAPHidError(data[0] if data else 0x7F)
            if resp_cmd != cmd:
                raise CTAPError(f"unexpected response command 0x{resp_cmd:02X}")
            return data

    def _cancel(self):
        """Tell the authenticator to drop the pending request."""
        try:
            self._write_frame(self.cid, CTAPHID_CANCEL, b"")
        except Exception as e:
            logger.debug("sending CTAPHID_CANCEL failed: " + str(e))

    # ------------------------------------------------------- public commands

    def init(self) -> dict:
        nonce = os.urandom(8)
        # INIT goes out on the broadcast channel and is answered with a fresh
        # CID, so this one exchange cannot insist on the current channel.
        resp = self._exchange(CTAPHID_INIT, nonce, expect_cid=None)
        if len(resp) < 17:
            raise CTAPError("truncated CTAPHID_INIT response")
        if resp[0:8] != nonce:
            # Someone else answered, or we read a stale frame: adopting that
            # CID would make every later command fail in a confusing way.
            raise CTAPError("CTAPHID_INIT echoed a different nonce "
                            "(another device answered)")
        self.cid = struct.unpack(">I", resp[8:12])[0]
        self._init_response = {
            "nonce_echo": resp[0:8],
            "cid": self.cid,
            "protocol_version": resp[12],
            "device_version": (resp[13], resp[14], resp[15]),
            "capabilities": resp[16],
        }
        return self._init_response

    @property
    def capabilities(self) -> dict:
        caps = (self._init_response or {}).get("capabilities", 0)
        return {"wink": bool(caps & CAP_WINK),
                "cbor": bool(caps & CAP_CBOR),
                "nmsg": bool(caps & CAP_NMSG)}

    def wink(self) -> bool:
        # WINK is a plain command with no touch prompt, so there is nothing to
        # cancel and nothing to report beyond the timeout itself.
        self._exchange(CTAPHID_WINK, b"", timeout=3000, cancel_on_timeout=False)
        return True

    def cbor(self, ctap_cmd: int, payload: bytes = b"", timeout: int = 5000,
             on_keepalive=None):
        """Send a CTAP2 command; returns (status_byte, response_bytes)."""
        resp = self._exchange(CTAPHID_CBOR, bytes([ctap_cmd]) + payload,
                              timeout=timeout, on_keepalive=on_keepalive)
        if not resp:
            raise CTAPError("empty CTAP2 response")
        return resp[0], resp[1:]

    def get_info(self, on_keepalive=None) -> dict:
        status, data = self.cbor(CTAP2_GET_INFO, on_keepalive=on_keepalive)
        if status != CTAP2_OK:
            raise CTAPError(f"authenticatorGetInfo failed, status 0x{status:02X}")
        info = loads(data)
        if not isinstance(info, dict):
            raise CTAPError("authenticatorGetInfo did not return a CBOR map")
        return info

    def reset(self, on_keepalive=None) -> bool:
        """Factory reset of the FIDO applet. Needs physical touch on the key."""
        status, _ = self.cbor(CTAP2_RESET, b"", timeout=30000,
                              on_keepalive=on_keepalive)
        if status == CTAP2_ERR_KEEPALIVE_CANCEL:
            raise CTAPCancel("the device stopped waiting for your touch")
        return status == CTAP2_OK

    # -------------------------------------------------------- lifecycle

    def reconnect(self):
        raise CTAPError("HID transport cannot be reopened; rescan the device")

    def close(self):
        try:
            self._conn.close()
        except Exception:
            pass


def describe(info: dict) -> dict:
    """Flatten the interesting parts of an authenticatorGetInfo response."""
    def s(v):
        return v.decode("utf-8", "replace") if isinstance(v, (bytes, bytearray)) else str(v)

    out = {}
    versions = info.get(1) or []
    out["versions"] = [s(v) for v in versions]
    if 2 in info:
        out["extensions"] = [s(v) for v in info[2]]
    aaguid = info.get(3)
    if isinstance(aaguid, (bytes, bytearray)):
        out["aaguid"] = aaguid.hex()
    opts = info.get(4) or {}
    out["options"] = {s(k): bool(v) for k, v in opts.items()} if isinstance(opts, dict) else {}
    if 5 in info:
        out["max_msg_size"] = info[5]
    pins = info.get(6) or []
    out["pin_uv_protocols"] = list(pins)
    if 7 in info:
        out["max_credential_count"] = info[7]
    if 8 in info:
        out["max_credential_id_length"] = info[8]
    if 9 in info:
        out["transports"] = [s(v) for v in info[9]]
    if 0x0A in info:
        out["algorithms"] = info[0x0A]
    return out
