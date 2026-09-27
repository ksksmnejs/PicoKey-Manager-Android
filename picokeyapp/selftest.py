"""
Protocol self-test that runs WITHOUT any hardware (and therefore also inside
the APK: "运行协议自检"). It feeds the real CCID / CTAPHID code with a fake USB
pipe, so a broken frame layout or a botched port shows up as a failure here and
not as an unexplainable timeout when a real PicoKey is plugged in.

Run from the shell:  python -m picokeyapp.selftest
"""

from __future__ import annotations

import struct
import time

from .i18n import t


def _now():
    return time.monotonic()


# --------------------------------------------------------------------- fakes

class _EP:
    max_packet_size = 64


class FakeConnection:
    """Minimal stand-in for usbhost.Connection: 64-byte chunks, like real USB."""

    def __init__(self, handler, packet_size: int = 64):
        self.handler = handler
        self.packet_size = packet_size
        self.ep_in = _EP()
        self.ep_out = _EP()
        self._queue = []
        self.closed = False
        self.written = []

    def write(self, data, timeout=None):
        data = bytes(data)
        self.written.append(data)
        response = self.handler(data) or b""
        self._queue = [response[i:i + self.packet_size]
                       for i in range(0, len(response), self.packet_size)] or [b""]
        return len(data)

    def read(self, length=None, timeout=None):
        if not self._queue:
            return b""
        return self._queue.pop(0)

    def control_in(self, *a, **kw):
        return bytes([0x06, 0xD0, 0xF1]) + b"\x00" * 8

    def close(self):
        self.closed = True


# ------------------------------------------------------- fake PicoKey (CCID)

ATR = bytes([0x3B, 0x80, 0x80, 0x01, 0x01])

PHY_TLV = bytes([
    0x00, 0x04, 0xFE, 0xFF, 0xFC, 0xFD,          # VIDPID
    0x04, 0x01, 0x19,                            # LED_GPIO = 25
    0x05, 0x01, 0x40,                            # LED brightness = 64
    0x06, 0x02, 0x00, 0x01,                      # OPTS = WCID
    0x08, 0x01, 0x0F,                            # UP_BTN (confirm button) = 15
    0x09, 0x08,                                  # USB product string, NUL terminated
]) + b"PicoKey\x00" + bytes([
    0x0A, 0x04, 0x00, 0x00, 0x00, 0x81,          # curves = SECP256R1 | ED25519
    0x0B, 0x01, 0x0F,                            # enabled USB interfaces = all
    0x0C, 0x01, 0x01,                            # LED driver = PICO
])


def _ccid_response(msg_type, data, seq, status=0x00, error=0x00):
    body = bytes(data)
    return (bytes([msg_type]) + len(body).to_bytes(4, "little")
            + bytes([0x00, seq, status, error, 0x00]) + body)


class FakePicoKey:
    """Speaks CCID bulk frames and answers the handful of APDUs we use."""

    def __init__(self):
        self.reset_state()

    def reset_state(self):
        self.selected = False
        self.phy_written = None
        self.rebooted = None
        self.secure = None
        self.secure_written = None

    # APDU layer -> (data, sw1, sw2)
    def apdu(self, apdu):
        apdu = bytes(apdu)
        if apdu[:5] == bytes([0x00, 0xA4, 0x04, 0x04, 0x08]):
            self.selected = True
            return bytes([0x01, 0x02, 0x07, 0x04]), 0x90, 0x00    # RP2350 / FIDO / 7.4
        if len(apdu) >= 4 and apdu[1] == 0x1E:
            p1 = apdu[2]                                   # CLA INS P1 P2
            if p1 == 0x01:
                return PHY_TLV, 0x90, 0x00
            if p1 == 0x02:
                vals = [1024, 2048, 4096, 7, 400384]
                out = b"".join(v.to_bytes(4, "big") for v in vals)
                return out, 0x90, 0x00
            if p1 == 0x03:
                return bytes([0x00, 0x00, 0x00]), 0x90, 0x00
            return b"", 0x6A, 0x86
        if len(apdu) >= 4 and apdu[1] == 0x1C:
            self.phy_written = apdu
            if apdu[2] == 0x02:                        # secure boot (p1 = 0x02)
                # Lc occupies apdu[5:7] here (1 pad byte + 2 length bytes),
                # so the data field starts at apdu[7].
                lc_len = (apdu[5] << 8) | apdu[6]
                body = list(apdu[7:7 + lc_len])
                self.secure_written = (body[0], body[1]) if len(body) >= 2 else tuple(body)
            return b"", 0x90, 0x00
        if len(apdu) >= 4 and apdu[1] == 0x1F:
            self.rebooted = apdu[2]
            return b"", 0x90, 0x00
        return b"", 0x6A, 0x82

    # CCID frame layer
    def __call__(self, frame):
        frame = bytes(frame)
        msg_type = frame[0]
        seq = frame[6]
        if msg_type == 0x62:                       # IccPowerOn
            return _ccid_response(0x80, ATR, seq)
        if msg_type == 0x63:                       # IccPowerOff
            return _ccid_response(0x81, b"", seq)
        if msg_type == 0x6F:                       # XfrBlock
            dw_length = int.from_bytes(frame[1:5], "little")
            apdu = frame[10:10 + dw_length]
            data, sw1, sw2 = self.apdu(apdu)
            return _ccid_response(0x80, bytes(data) + bytes([sw1, sw2]), seq)
        return _ccid_response(0x80, b"", seq, status=0x40, error=0x00)


# ---------------------------------------------------------- fake FIDO (HID)

class FakeFidoKey:
    def __init__(self):
        from .cbor_mini import dumps
        self.aaguid = bytes(range(16))
        self._pending = None                # (cid, cmd, bcnt, bytearray)
        self.info = dumps({
            1: ["U2F_V2", "FIDO_2_0"],
            3: self.aaguid,
            4: {"rk": True, "uv": False, "plat": False},
            5: 1200,
            6: [1],
            9: ["usb"],
        })
        self.winked = False

    def __call__(self, frame):
        """Consume one 64-byte HID report; returns b"" while a message is
        still incomplete (continuation packets carry no reply of their own)."""
        frame = bytes(frame)
        if len(frame) < 5:
            return b""
        cid = struct.unpack(">I", frame[0:4])[0]
        flags = frame[4]

        if flags & 0x80:                           # INIT packet: start of message
            cmd = flags & 0x7F
            bcnt = (frame[5] << 8) | frame[6]
            self._pending = [cid, cmd, bcnt, bytearray(frame[7:])]
        elif self._pending is not None:            # CONT packet
            self._pending[3] += frame[5:]

        if self._pending is None:
            return b""
        cid, cmd, bcnt, buf = self._pending
        if len(buf) < bcnt:
            return b""
        self._pending = None
        data = bytes(buf[:bcnt])

        if cmd == 0x06:                            # INIT
            out = (data[:8] + struct.pack(">I", 0x12345678)
                   + bytes([0x02, 0x07, 0x04, 0x00, 0x05]))
            return self._frame(cid, 0x86, out)
        if cmd == 0x08:                            # WINK
            self.winked = True
            return self._frame(cid, 0x88, b"")
        if cmd == 0x10:                            # CBOR
            ctap_cmd, payload = data[0], data[1:]
            if ctap_cmd == 0x04:
                return self._frame(cid, 0x90, bytes([0x00]) + self.info)
            return self._frame(cid, 0x90, bytes([0x01]))
        return self._frame(cid, 0xBF, bytes([0x01]))

    @staticmethod
    def _frame(cid, cmd, payload, packet_size: int = 64):
        """Build a spec-correct response: INIT packet + CONT packets (all 64B)."""
        payload = bytes(payload)
        bcnt = len(payload)
        out = bytearray()
        first = bytearray(packet_size)
        first[0:4] = struct.pack(">I", cid)
        first[4] = cmd | 0x80
        first[5] = (bcnt >> 8) & 0xFF
        first[6] = bcnt & 0xFF
        head = payload[:packet_size - 7]
        first[7:7 + len(head)] = head
        out += first
        rest = payload[len(head):]
        seq = 0
        while rest:
            cont = bytearray(packet_size)
            cont[0:4] = struct.pack(">I", cid)
            cont[4] = seq & 0x7F
            chunk = rest[:packet_size - 5]
            cont[5:5 + len(chunk)] = chunk
            out += cont
            rest = rest[len(chunk):]
            seq += 1
        return bytes(out)


# ------------------------------------------------------------------- checks

def _check(label, condition, detail=""):
    if not condition:
        raise AssertionError(f"{label} FAILED {detail}")
    return f"  [ok] {label}{(' - ' + detail) if detail else ''}"


def run() -> str:
    from . import ccid, ctap
    from .cbor_mini import loads, dumps
    from .pk import PicoKey, PhyData, PhyUsbItf, PhyLedDriver, PhyOpt, PhyCurve

    lines = [t("selftest_title"), ""]

    # 1. CBOR codec -----------------------------------------------------
    lines.append(t("selftest_cbor") + ":")
    lines.append(_check("map/array/int/bytes",
                        loads(bytes.fromhex("a26161016162820203")) == {"a": 1, "b": [2, 3]}))
    lines.append(_check("negative + text",
                        loads(bytes.fromhex("a1206a746573742d76616c7565"))
                        == {-1: "test-value"}))
    lines.append(_check("round trip", loads(dumps({"x": [1, b"\x00\xff"], "y": True})) ==
                        {"x": [1, b"\x00\xff"], "y": True}))

    # 2. CCID + PicoKey --------------------------------------------------
    lines.append("")
    lines.append(t("selftest_ccid") + ":")
    fake = FakePicoKey()
    conn = FakeConnection(fake)
    transport = ccid.CCIDTransport(conn, label="fake-ccid")
    pk = PicoKey(transport)

    summary = pk.summary()
    lines.append(_check("select applet -> platform", summary["platform"] == "RP2350", str(summary)))
    lines.append(_check("select applet -> product", summary["product"] == "FIDO"))
    lines.append(_check("select applet -> version", summary["version"] == "7.4"))

    flash = pk.flash_info()
    lines.append(_check("flash_info values",
                        (flash["free"], flash["used"], flash["total"], flash["nfiles"])
                        == (1024, 2048, 4096, 7), str(flash)))

    phy = pk.phy()
    lines.append(_check("PHY VID/PID", (phy.vid, phy.pid) == (0xFEFF, 0xFCFD), repr(phy)))
    lines.append(_check("PHY LED gpio/brightness",
                        (phy.led_gpio, phy.led_brightness) == (25, 64)))
    lines.append(_check("PHY usb interfaces",
                        phy.enabled_usb_itf == (int(PhyUsbItf.CCID) | int(PhyUsbItf.WCID)
                                                | int(PhyUsbItf.HID) | int(PhyUsbItf.KB))))
    lines.append(_check("PHY led driver", phy.led_driver == int(PhyLedDriver.PICO)))
    lines.append(_check("PHY usb product string", phy.usb_product == "PicoKey",
                        str(phy.usb_product)))
    lines.append(_check("PHY confirm-button GPIO", phy.up_btn == 15, str(phy.up_btn)))
    lines.append(_check("PHY opts (WCID)", phy.opts == int(PhyOpt.WCID), hex(phy.opts or 0)))
    lines.append(_check("PHY enabled curves",
                        phy.enabled_curves == (int(PhyCurve.SECP256R1) | int(PhyCurve.ED25519)),
                        hex(phy.enabled_curves or 0)))

    data = phy.serialize()
    pk.phy(data)
    lines.append(_check("PHY write reached the device", fake.phy_written is not None))

    # every commissioning field has to survive a write -> serialize round trip
    full = PhyData()
    full.vidpid = bytearray([0x2E, 0x8A, 0x10, 0xFE])
    full.led_gpio = 25
    full.led_brightness = 96
    full.led_driver = int(PhyLedDriver.WS2812)
    full.up_btn = 15
    full.usb_product = "My Board"
    full.opts = int(PhyOpt.WCID) | int(PhyOpt.LED_STEADY)
    full.enabled_curves = 0x00000081
    full.enabled_usb_itf = int(PhyUsbItf.CCID) | int(PhyUsbItf.HID)
    round_trip = PhyData.parse(full.serialize())
    lines.append(_check("PHY write -> parse round trip",
                        round_trip.vid == 0x2E8A and round_trip.pid == 0x10FE
                        and round_trip.usb_product == "My Board"
                        and round_trip.up_btn == 15
                        and round_trip.opts == full.opts
                        and round_trip.enabled_curves == full.enabled_curves
                        and round_trip.led_driver == full.led_driver,
                        repr(round_trip)))

    # ---------------------------------------------------------- secure boot
    lines.append("")
    lines.append(t("sec_security").strip("— ") + ":")
    sec = pk.secure_info()
    lines.append(_check("secure_info parsed",
                        set(sec) == {"enabled", "locked", "boot_key"}, str(sec)))
    pk.secure_boot(3, True)
    lines.append(_check("secure_boot reached the device",
                        fake.secure_written == (3, 1), str(fake.secure_written)))

    pk.reboot(True)
    lines.append(_check("reboot(BOOTSEL) reached the device", fake.rebooted == 0x01))

    # long response spanning several 64-byte USB packets
    class LongKey(FakePicoKey):
        def apdu(self, apdu):
            if len(apdu) >= 4 and apdu[1] == 0x1E:
                return bytes(range(256))[:200], 0x90, 0x00
            return super().apdu(apdu)

    long_pk = PicoKey(ccid.CCIDTransport(FakeConnection(LongKey()), label="long"))
    resp, sw = long_pk.send(0x1E, cla=0x80, p1=0x02, ne=256)
    lines.append(_check("multi-packet CCID reassembly", len(resp) == 200, f"{len(resp)} bytes"))

    transport.close()

    # 3. CTAPHID ---------------------------------------------------------
    lines.append("")
    lines.append(t("selftest_ctap") + ":")
    fake_fido = FakeFidoKey()
    hid = ctap.CTAPHIDTransport(FakeConnection(fake_fido))
    init = hid.init()
    lines.append(_check("INIT allocates a CID", init["cid"] == 0x12345678, str(init)))
    lines.append(_check("INIT capabilities", hid.capabilities["wink"] is True))
    lines.append(_check("WINK", hid.wink() and fake_fido.winked))
    info = hid.get_info()
    described = ctap.describe(info)
    lines.append(_check("getInfo versions", described["versions"] == ["U2F_V2", "FIDO_2_0"],
                        str(described.get("versions"))))
    lines.append(_check("getInfo aaguid", described["aaguid"] == fake_fido.aaguid.hex()))
    lines.append(_check("getInfo options", described["options"].get("rk") is True))
    hid.close()

    # 4. error handling --------------------------------------------------
    # These are the failures that used to reach the user as a bare ValueError
    # ("not enough values to unpack") or as a status word invented from
    # whatever happened to be sitting in the buffer.
    lines.append("")
    lines.append(t("selftest_errors").strip("— ") + ":")

    from .pk.ICCD import Icc_Error_Short_Frame, RDR_to_PC_DataBlock
    from .pk.APDU import APDUResponse
    from . import flasher

    # a) fewer bytes than the 10-byte CCID header
    try:
        RDR_to_PC_DataBlock(b"\x80\x00\x00\x00\x00")(0)
        lines.append(_check("short CCID frame -> named error", False, "no exception"))
    except Icc_Error_Short_Frame as e:
        lines.append(_check("short CCID frame -> named error",
                            "truncated" in str(e), str(e)))
    except Exception as e:
        lines.append(_check("short CCID frame -> named error", False,
                            type(e).__name__ + ": " + str(e)))

    # b) no SW bytes at all: must not invent a status word.
    #    The response has to echo the sequence number from the request's byte 6.
    def _echo_seq(msg_type, body=b""):
        return lambda d: _ccid_response(msg_type, body, d[6] if len(d) > 6 else 0)

    empty = ccid.CCIDTransport(FakeConnection(_echo_seq(0x80)),
                               label="empty", auto_power=False)
    try:
        empty.transmit([0x00, 0xA4, 0x04, 0x04])
        lines.append(_check("missing SW -> named error", False, "no exception"))
    except IOError as e:
        lines.append(_check("missing SW -> named error", "truncated" in str(e), str(e)))
    except Exception as e:
        lines.append(_check("missing SW -> named error", False,
                            type(e).__name__ + ": " + str(e)))

    # c) bytes past the declared frame end must not leak into the next read
    trailing = ccid.CCIDTransport(
        FakeConnection(lambda d: _echo_seq(0x81)(d) + b"\xAA" * 7),
        label="trailing", auto_power=False)
    frame = trailing.exchange(bytes([0x63]) + b"\x00" * 9)
    lines.append(_check("stray bytes after the frame are dropped",
                        len(frame) == 10, f"{len(frame)} bytes"))

    # d) a status word should explain itself
    lines.append(_check("SW 6A86 explains itself",
                        "P1/P2" in str(APDUResponse(0x6A, 0x86)),
                        str(APDUResponse(0x6A, 0x86))))

    # e) a late reply to the previous command: drop it, ask again, succeed
    class LateConn:
        """Answers the first read with a stale frame, then behaves."""

        def __init__(self, op):
            self.op = op
            self.written = []
            self._pending = [flasher.slip_encode(
                struct.pack("<BBHI", 0x01, 0x08, 0, 0))]

        def write(self, data, timeout=None):
            self.written.append(bytes(data))
            self._pending.append(flasher.slip_encode(
                struct.pack("<BBHI", 0x01, self.op, 0, 0)))
            return len(data)

        def read(self, length=None, timeout=None):
            if not self._pending:
                raise IOError("nothing to read")
            return self._pending.pop(0)

    late = LateConn(flasher.OP_FLASH_END)
    flasher.EspLoader(late).command(flasher.OP_FLASH_END, b"", 0, timeout=200)
    lines.append(_check("stale frame -> resync and retry", len(late.written) == 2,
                        f"{len(late.written)} write(s)"))

    # f) CTAPHID: a device that only ever sends KEEPALIVE must not hang us
    class NeverAnswers:
        ep_in = _EP()
        ep_out = _EP()

        def __init__(self):
            self.sent = []

        def write(self, data, timeout=None):
            self.sent.append(bytes(data))
            return len(data)

        def read(self, length=None, timeout=None):
            f = bytearray(64)
            f[0:4] = struct.pack(">I", 0x11223344)
            f[4] = ctap.CTAPHID_KEEPALIVE
            f[5], f[6] = 0, 1
            f[7] = 0x02                       # waiting for the user to touch
            return bytes(f)

        def close(self):
            pass

    stalled = NeverAnswers()
    hid_stall = ctap.CTAPHIDTransport(stalled)
    hid_stall.cid = 0x11223344
    seen = []
    started = _now()
    try:
        hid_stall.cbor(ctap.CTAP2_GET_INFO, b"", timeout=700,
                       on_keepalive=seen.append)
        lines.append(_check("KEEPALIVE loop respects the deadline", False,
                            "returned instead of timing out"))
    except ctap.CTAPError:
        elapsed = _now() - started
        lines.append(_check("KEEPALIVE loop respects the deadline",
                            elapsed < 5, f"{elapsed:.1f}s for a 0.7s timeout"))
    lines.append(_check("touch prompt reaches the caller", seen == [0x02], str(seen)))
    lines.append(_check("timeout sends CTAPHID_CANCEL",
                        any(d[4] == ctap.CTAPHID_CANCEL for d in stalled.sent)))

    # g) CTAPHID_ERROR used to surface as "unexpected response command 0xBF",
    #    which threw away the one byte saying what went wrong.
    class ErrorOnly:
        ep_in = _EP()
        ep_out = _EP()

        def __init__(self, code, cid=0x11223344):
            self.code = code
            self.cid = cid

        def write(self, data, timeout=None):
            return len(data)

        def read(self, length=None, timeout=None):
            f = bytearray(64)
            f[0:4] = struct.pack(">I", self.cid)
            f[4] = ctap.CTAPHID_ERROR
            f[5], f[6] = 0, 1
            f[7] = self.code
            return bytes(f)

        def close(self):
            pass

    try:
        err_dev = ctap.CTAPHIDTransport(ErrorOnly(0x06))
        err_dev.cid = 0x11223344
        err_dev.get_info()
        lines.append(_check("CTAPHID_ERROR reports its code", False, "no exception"))
    except ctap.CTAPHidError as e:
        lines.append(_check("CTAPHID_ERROR reports its code",
                            "CHANNEL_BUSY" in str(e), str(e)))

    # h) a frame from another channel must not be taken as our answer
    try:
        foreign = ctap.CTAPHIDTransport(ErrorOnly(0x06, cid=0xDEADBEEF))
        foreign.cid = 0x11223344
        foreign._read_frame(_now() + 1, expect_cid=0x11223344)
        lines.append(_check("foreign CID rejected", False, "accepted"))
    except ctap.CTAPError as e:
        lines.append(_check("foreign CID rejected", "another channel" in str(e), str(e)))

    # i) INIT nonce mismatch: do not adopt a CID from a stranger
    class WrongNonce:
        ep_in = _EP()
        ep_out = _EP()

        def write(self, data, timeout=None):
            return len(data)

        def read(self, length=None, timeout=None):
            body = bytearray(17)
            body[8:12] = struct.pack(">I", 0x11223344)
            f = bytearray(64)
            f[0:4] = struct.pack(">I", 0x11223344)
            f[4] = ctap.CTAPHID_INIT
            f[5], f[6] = 0, 17
            f[7:7 + 17] = body
            return bytes(f)

        def close(self):
            pass

    try:
        ctap.CTAPHIDTransport(WrongNonce()).init()
        lines.append(_check("INIT nonce mismatch rejected", False, "accepted"))
    except ctap.CTAPError as e:
        lines.append(_check("INIT nonce mismatch rejected",
                            "nonce" in str(e), str(e)))

    # f2) still wrong after the resync: say which ops were involved
    class AlwaysWrong:
        def __init__(self):
            self.written = []

        def write(self, data, timeout=None):
            self.written.append(bytes(data))
            return len(data)

        def read(self, length=None, timeout=None):
            return flasher.slip_encode(struct.pack("<BBHI", 0x01, 0x08, 0, 0))

    try:
        flasher.EspLoader(AlwaysWrong()).command(flasher.OP_FLASH_END, b"", 0,
                                                 timeout=200)
        lines.append(_check("mismatch after resync names both ops", False,
                            "no exception"))
    except flasher.FirmwareError as e:
        lines.append(_check("mismatch after resync names both ops",
                            "08" in str(e) and "04" in str(e), str(e)))
    except Exception as e:
        lines.append(_check("mismatch after resync names both ops", False,
                            type(e).__name__ + ": " + str(e)))

    lines.append("")
    lines.append(t("selftest_passed"))
    return "\n".join(lines)


if __name__ == "__main__":
    print(run())
