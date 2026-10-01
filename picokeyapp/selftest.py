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

# From the defining module rather than the package: the package __init__ is a
# separate file, and a partial upload that leaves it behind would turn the
# whole self test into an ImportError instead of a report.
try:
    from .pk.PicoKey import SecureBootError
except ImportError:                                     # pragma: no cover
    class SecureBootError(Exception):
        """Fallback when PicoKey.py has not caught up with selftest.py."""


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
        self.secure_reject = 0      # set to a SW (e.g. 0x6A86) to refuse

    # APDU layer -> (data, sw1, sw2)
    def apdu(self, apdu):
        apdu = bytes(apdu)
        if apdu[:5] == bytes([0x00, 0xA4, 0x04, 0x04, 0x08]):
            self.selected = True
            return bytes([0x01, 0x02, 0x07, 0x04]), 0x90, 0x00    # RP2350 / FIDO / 7.4
        # The rescue applet's real table: 0x1C writes object P1, 0x1E reads
        # object P1, 0x1D is the secure command, 0x1F reboots. Only object
        # 0x01 (PHY) and 0x02 (flash) are known to exist, which is why the
        # old "read object 3 / write object 2" attempt answered 6A86.
        if len(apdu) >= 4 and apdu[1] == 0x1E:
            p1 = apdu[2]                                   # CLA INS P1 P2
            if p1 == 0x01:
                return PHY_TLV, 0x90, 0x00
            if p1 == 0x02:
                vals = [1024, 2048, 4096, 7, 400384]
                out = b"".join(v.to_bytes(4, "big") for v in vals)
                return out, 0x90, 0x00
            return b"", 0x6A, 0x86          # unknown object
        if len(apdu) >= 4 and apdu[1] == 0x1C:
            if apdu[2] == 0x01:
                self.phy_written = apdu
                return b"", 0x90, 0x00
            return b"", 0x6A, 0x86          # no such writable object
        if len(apdu) >= 4 and apdu[1] == 0x1D:
            # Secure command: P1 = bootkey slot, P2 = lock flag, no data.
            self.secure_written = (apdu[2], apdu[3])
            if self.secure_reject:
                return b"", (self.secure_reject >> 8) & 0xFF, self.secure_reject & 0xFF
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
            4: {"rk": True, "uv": False, "plat": False, "up": True},
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
            if ctap_cmd == 0x0B:                   # SELECTION: user presence
                return self._frame(cid, 0x90, bytes([0x00]))
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


# Which device-screen button needs which channel. If a future edit adds a
# button and forgets the `disabled:` rule, it silently becomes tappable on the
# wrong channel again - and that failure only ever shows up as a stack trace
# after the tap.
_NEEDS_APDU = ("btn_refresh", "btn_read_phy", "btn_write_phy",
               "btn_read_secure", "btn_secure_boot", "btn_reboot",
               "btn_reboot_bootsel")
_NEEDS_CTAP = ("btn_wink", "btn_test_presence")


def _check_channel_gating():
    """Every channel-specific button must be greyed out on the other channel."""
    import os
    import re

    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(os.path.dirname(here), "main.py")
    try:
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
    except OSError:
        # Inside a built APK there is no main.py on disk to read. Skipping is
        # correct here: this check guards the source tree, not the running app,
        # and failing it would abort the whole self test on a phone.
        return ["  [skip] channel gating (source not available in a built app)"]

    kv = re.search(r'KV_DEVICE = """(.*?)"""', src, re.S)
    if not kv:
        return [_check("channel gating rules present", False, "KV_DEVICE not found")]

    # id: X ... disabled: app.busy or app.blocked_*
    rules = {}
    for block in re.split(r"\n(?=\s*(?:Menu|Primary|Danger)Button:)", kv.group(1)):
        mid = re.search(r"id:\s*(\w+)", block)
        mdis = re.search(r"disabled:\s*(.+)", block)
        if mid and mdis:
            rules[mid.group(1)] = mdis.group(1).strip()

    out = []
    missing = []
    for name in _NEEDS_APDU:
        if rules.get(name) != "app.busy or app.blocked_apdu":
            missing.append(f"{name} (CCID)")
    for name in _NEEDS_CTAP:
        if rules.get(name) != "app.busy or app.blocked_ctap":
            missing.append(f"{name} (HID)")
    out.append(_check("channel gating rules present", not missing,
                      "missing: " + ", ".join(missing) if missing else
                      f"{len(rules)} button(s) gated"))

    # The gating is driven by _sync_channel(); without it the bound properties
    # never change and every button stays enabled on both channels.
    sync = re.search(r"def _sync_channel\(self\):", src)
    called = len(re.findall(r"self\._sync_channel\(\)", src))
    out.append(_check("channel gating is applied on connect/disconnect",
                      bool(sync) and called >= 2,
                      f"_sync_channel defined={bool(sync)}, call sites={called}"))
    return out


def _write_object_rejected(pk, p1: int) -> bool:
    """True when writing object `p1` is refused.

    Guards the exact mistake that made secure boot look broken: asking the
    rescue applet to write an object that does not exist.
    """
    try:
        pk.send(0x1C, cla=0x80, p1=p1, data=[0x00, 0x00])
    except Exception:
        return True          # send() raises on any non-9000 status
    return False


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
    # Object 0x03 is not readable on a real board any more, so secure_info()
    # must simply report "unavailable" instead of raising.
    lines.append(_check("secure_info reports unavailable instead of raising",
                        pk.secure_info() is None))

    # The secure command is INS 0x1D with the slot in P1 and the lock flag in
    # P2, carrying no data - not a write to object 2.
    pk.secure_boot(3, True)
    lines.append(_check("secure_boot sends INS 1D, P1=slot, P2=lock",
                        fake.secure_written == (3, 1), str(fake.secure_written)))

    fake.reset_state()
    pk.secure_boot(0, False)
    lines.append(_check("secure_boot without lock sends P2=0",
                        fake.secure_written == (0, 0), str(fake.secure_written)))

    # A refusal has to name the cause instead of looking like success.
    fake.reset_state()
    fake.secure_reject = 0x6A86
    try:
        pk.secure_boot(0, True)
        lines.append(_check("a board that refuses reports it", False,
                            "no exception"))
    except SecureBootError as e:
        lines.append(_check("a board that refuses reports it",
                            "6A86" in str(e) and "written" in str(e).lower(),
                            str(e)))
    finally:
        fake.reset_state()

    # The old mistake: writing object 2 as if it were the secure command.
    lines.append(_check("writing object 2 is rejected by the device",
                        _write_object_rejected(pk, 0x02)))

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
    # `options.up` is what the device claims about requiring a physical press.
    lines.append(_check("getInfo reports user presence",
                        described["options"].get("up") is True,
                        str(described["options"])))

    # CTAP_SELECTION is how we tell a real presence button from none at all.
    elapsed = hid.selection()
    lines.append(_check("selection confirms presence", elapsed >= 0,
                        f"{elapsed * 1000:.0f} ms"))

    # A board that waits for a press sends KEEPALIVE first; the elapsed time
    # is what separates that from a device that granted presence instantly.
    class WaitsForButton(FakeFidoKey):
        def __init__(self):
            super().__init__()
            self.keepalives = 0

        def __call__(self, frame):
            data = bytes(frame)
            if len(data) >= 5 and (data[4] & 0x7F) == 0x10:
                ctap_cmd = data[7] if len(data) > 7 else 0
                if ctap_cmd == 0x0B:
                    # A device waiting for a press emits KEEPALIVE frames and
                    # only then the real answer, all on the same transfer.
                    cid = struct.unpack(">I", data[0:4])[0]
                    self.keepalives = 2
                    return (self._frame(cid, ctap.CTAPHID_KEEPALIVE,
                                        bytes([ctap.KA_UPNEEDED])) * 2
                            + self._frame(cid, 0x90, bytes([0x00])))
            return super().__call__(frame)

    waiting = WaitsForButton()
    hid_wait = ctap.CTAPHIDTransport(FakeConnection(waiting))
    hid_wait.init()
    seen = []
    took = hid_wait.selection(on_keepalive=seen.append)
    lines.append(_check("selection waits through KEEPALIVE",
                        waiting.keepalives == 2 and took >= 0,
                        f"{waiting.keepalives} keepalive(s)"))
    lines.append(_check("selection reports the touch prompt",
                        seen == [ctap.KA_UPNEEDED], str(seen)))
    hid_wait.close()

    hid.close()

    # 4. error handling --------------------------------------------------
    # These are the failures that used to reach the user as a bare ValueError
    # ("not enough values to unpack") or as a status word invented from
    # whatever happened to be sitting in the buffer.
    lines.append("")
    lines.append(t("selftest_errors").strip("— ") + ":")

    from .pk.ICCD import Icc_Error_Short_Frame, RDR_to_PC_DataBlock
    from .pk.APDU import APDUResponse
    from .pk import PicoKey
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

    # d2) a refused secure-boot write names the cause and says nothing was written
    class _Card:
        def __init__(self, sw): self.sw = sw
        def transmit(self, apdu): return b"", self.sw >> 8, self.sw & 0xFF

    def _secure_probe(sw):
        pk = PicoKey.__new__(PicoKey)
        object.__setattr__(pk, "_PicoKey__card", _Card(sw))
        object.__setattr__(pk, "_PicoKey__sc", None)
        pk.select_applet = lambda: None
        try:
            pk.secure_boot(0, True)
            return None
        except SecureBootError as e:
            return str(e)

    r = _secure_probe(0x6A86)
    lines.append(_check("refused secure boot names the cause",
                        r is not None and "6A86" in r and "nothing was written" in r,
                        str(r)))
    lines.append(_check("accepted secure boot does not raise",
                        _secure_probe(0x9000) is None, "ok"))

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

    # f3) sync must not take a running firmware's log for a ROM reply.
    # This is why the app said "fw_flash: done" on the same board where the web
    # tool reported "sync failed": the old check accepted any frame starting
    # with 0x01, and an ESP32-S3 keeps printing to that very same pipe.
    class LogNoise:
        """A firmware printing to USB Serial/JTAG, with an unlucky 0xC0 in it."""

        def __init__(self):
            self.data = bytearray(
                b"I (1234) app: start\xc0\x01\x08\x00\x00\x00\x00\x00\x00\x00\xc0")

        def write(self, data, timeout=None):
            return len(data)

        def read(self, length=None, timeout=None):
            if not self.data:
                return b""
            chunk = bytes(self.data[:length])
            del self.data[:length]
            return chunk

    lines.append(_check("running firmware is not mistaken for the ROM",
                        flasher.EspLoader(LogNoise()).sync() is False,
                        "reported a successful handshake"))

    class RealRom:
        def write(self, data, timeout=None):
            return len(data)

        def read(self, length=None, timeout=None):
            return flasher.slip_encode(struct.pack("<BBHI", 0x01, 0x08, 0, 0))

    lines.append(_check("a real ROM handshake still succeeds",
                        flasher.EspLoader(RealRom()).sync() is True,
                        "the board would never be detected"))

    # f4) the erase commands have to land in the 0xD0 block, not next to the
    # flash ones. Getting this wrong would send ERASE_FLASH where SPI_ATTACH
    # was meant, i.e. wiping the chip when the user asked to flash.
    class RecordingConn:
        def __init__(self, replies):
            self.replies = list(replies)
            self.written = []

        def write(self, data, timeout=None):
            self.written.append(bytes(data))
            return len(data)

        def read(self, length=None, timeout=None):
            if not self.replies:
                return b""
            return self.replies.pop(0)[:length]

        def close(self):
            pass

    def _ack(op, status=0):
        return flasher.slip_encode(
            struct.pack("<BBHI", 0x01, op, 0, 0) + bytes([status]))

    def _sent(conn):
        return [flasher.slip_decode(bytearray(w))[0] for w in conn.written]

    # Erase survives an SPI_ATTACH that answers with a non-zero status.
    c = RecordingConn([_ack(0x0D, status=1), _ack(0xD0)])
    flasher.EspLoader(c).erase_flash()
    frames = _sent(c)
    lines.append(_check("erase attaches to SPI first",
                        len(frames) >= 1 and frames[0][1] == flasher.OP_SPI_ATTACH,
                        "did not attach before erasing"))
    lines.append(_check("erase sends ERASE_FLASH (0xD0)",
                        len(frames) >= 2 and frames[1][1] == flasher.OP_ERASE_FLASH,
                        f"sent op {frames[1][1]:#04x}" if len(frames) >= 2
                        else "no erase command was sent"))

    c2 = RecordingConn([_ack(0x0D), _ack(0xD1)])
    flasher.EspLoader(c2).erase_region(0x10000, 0x100000)
    fr = _sent(c2)[1]
    size, offset = struct.unpack_from("<II", fr, 8)
    lines.append(_check("region erase sends (size, offset) in that order",
                        fr[1] == flasher.OP_ERASE_REGION
                        and size == 0x100000 and offset == 0x10000,
                        f"op {fr[1]:#04x} size {size:#x} offset {offset:#x}"))

    lines.append(_check("erase opcodes do not collide with the flash ones",
                        flasher.OP_ERASE_FLASH not in
                        (flasher.OP_SPI_ATTACH, flasher.OP_FLASH_BEGIN,
                         flasher.OP_FLASH_DATA, flasher.OP_FLASH_END),
                        f"ERASE_FLASH={flasher.OP_ERASE_FLASH:#04x}"))

    lines.append("")
    lines.append("")
    lines.append(t("selftest_ui") + ":")
    lines.extend(_check_channel_gating())

    lines.append("")
    lines.append(t("selftest_passed"))
    return "\n".join(lines)


if __name__ == "__main__":
    print(run())
