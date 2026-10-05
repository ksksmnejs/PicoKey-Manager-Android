"""
Protocol self-test that runs WITHOUT any hardware (and therefore also inside
the APK: "运行协议自检"). It feeds the real CCID / CTAPHID code with a fake USB
pipe, so a broken frame layout or a botched port shows up as a failure here and
not as an unexplainable timeout when a real PicoKey is plugged in.

Run from the shell:  python -m picokeyapp.selftest
"""

from __future__ import annotations

import hashlib
import io
import os
import re
import struct
import time

from .i18n import t
from . import uf2write

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
        # Upstream pypicokey's real table (picokey/PicoKey.py): 0x1C writes
        # object P1 (01=PHY, 02=secure boot), 0x1E reads object P1
        # (01=PHY, 02=flash, 03=secure info), 0x1F reboots. There is no 0x1D;
        # an earlier revision invented one and it was wrong.
        if len(apdu) >= 4 and apdu[1] == 0x1E:
            p1 = apdu[2]                                   # CLA INS P1 P2
            if p1 == 0x01:
                return PHY_TLV, 0x90, 0x00
            if p1 == 0x02:
                vals = [1024, 2048, 4096, 7, 400384]
                out = b"".join(v.to_bytes(4, "big") for v in vals)
                return out, 0x90, 0x00
            if p1 == 0x03:
                # Most boards in the field answer 6A86 here (the feature is not
                # compiled in), which is exactly the case that used to raise.
                if getattr(self, "secure_info_ok", False):
                    return bytes([0x01, 0x00, 0x03]), 0x90, 0x00
                return b"", 0x6A, 0x86
            return b"", 0x6A, 0x86          # unknown object
        if len(apdu) >= 4 and apdu[1] == 0x1C:
            if apdu[2] == 0x01:
                self.phy_written = apdu
                return b"", 0x90, 0x00
            if apdu[2] == 0x02:
                # Secure boot: P1=0x02, body is [bootkey slot, lock flag].
                body = apdu[7:9]
                self.secure_written = (body[0], body[1])
                if self.secure_reject:
                    return b"", ((self.secure_reject >> 8) & 0xFF,
                                 self.secure_reject & 0xFF)[0], \
                           self.secure_reject & 0xFF
                return b"", 0x90, 0x00
            return b"", 0x6A, 0x86          # no such writable object
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

_FAILURES = []


def _check(label, condition, detail=""):
    """Record one assertion without aborting the run.

    This used to raise on the first failure. That is why the self-test looked
    like it failed "forever": each run stopped at the first bad check, the fix
    went in, and the next run stopped at the next one. Reporting every failure
    in one pass means one run shows the whole picture.
    """
    if not condition:
        _FAILURES.append(f"{label} FAILED {detail}".strip())
        return f"  [FAIL] {label}{(' - ' + detail) if detail else ''}"
    return f"  [ok] {label}{(' - ' + detail) if detail else ''}"


# Which device-screen button needs which channel. If a future edit adds a
# button and forgets the `disabled:` rule, it silently becomes tappable on the
# wrong channel again - and that failure only ever shows up as a stack trace
# after the tap.
_NEEDS_APDU = ("btn_refresh", "btn_read_phy", "btn_write_phy",
               "btn_read_secure", "btn_secure_boot", "btn_reboot",
               "btn_reboot_bootsel")
_NEEDS_CTAP = ("btn_wink", "btn_test_presence",
               # authenticatorConfig is CTAP-only: it is unreachable over CCID,
               # and leaving these enabled on the CCID channel produces an error
               # that looks like a bug rather than a wrong channel.
               "btn_toggle_always_uv", "btn_set_min_pin")


# Project root: selftest.py lives in picokeyapp/, main.py one level up.
_SELFTEST_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _check_font_coverage() -> list:
    """The bundled font must be able to draw every glyph the UI can show.

    The font is shipped inside the APK, so a glyph it lacks is not rendered at
    all - it becomes a tofu box, and on a screen full of warnings that is worse
    than a plain ASCII label because it looks like decoration. The subset is
    built from the source files, so this only breaks when someone edits the
    strings afterwards without rebuilding it (or drops in a different font).
    """
    out = []
    try:
        from fontTools.ttLib import TTFont
    except Exception:
        out.append(_check("the font can be inspected", False,
                          "fontTools is not available here"))
        return out

    font_path = os.path.join(_SELFTEST_ROOT, "assets", "fonts",
                             "NotoSansSC-Regular-subset.ttf")
    if not os.path.exists(font_path):
        out.append(_check("the bundled font is present", False, font_path))
        return out

    cmap = TTFont(font_path).getBestCmap()
    shown = set()
    for name in ("main.py", "picokeyapp/i18n.py"):
        path = os.path.join(_SELFTEST_ROOT, name)
        if os.path.exists(path):
            shown |= set(open(path, encoding="utf-8").read())

    missing = sorted(c for c in shown
                     if ord(c) > 0x2000 and ord(c) not in cmap)
    out.append(_check("every shown glyph exists in the bundled font",
                      not missing,
                      "" if not missing else
                      "not drawable: " + "".join(missing[:40])))

    size = os.path.getsize(font_path)
    out.append(_check("the bundled font stays small enough to ship",
                      size < 900_000,
                      f"{size} bytes"))
    return out


def _check_row_height() -> list:
    """Rows must grow for a wrapped label instead of clipping it."""
    src = open(os.path.join(_SELFTEST_ROOT, "main.py"), encoding="utf-8").read()
    out = []
    out.append(_check("field rows size themselves to their text",
                      "height: self.minimum_height" in src,
                      "a fixed row height clips a wrapped English label"))
    return out


def _check_official_engine():
    """Checks on the optional esptool-js path in the single-file web flasher.

    The HTML is only present in a source checkout, so a packaged APK skips
    these rather than failing. Every rule here corresponds to a way this path
    can silently do the wrong thing: the most important is the hard reset,
    because skipping it leaves the chip in the bootloader, which looks exactly
    like a failed flash (no LED, a single USB interface).
    """
    lines = []
    here = os.path.dirname(os.path.abspath(__file__))   # .../picokeyapp
    root = os.path.dirname(here)                        # project root
    path = os.path.join(root, "picokey-commissioner.html")
    if not os.path.exists(path):
        lines.append("  [skip] official esptool-js engine in the web page "
                     "(source not available in a built app)")
        return lines
    src = io.open(path, encoding="utf-8").read()

    def has(needle):
        return needle in src

    lines.append(_check("web page defines its own MD5 (no second CDN)",
                        has("function md5hex("),
                        "" if has("function md5hex(") else "md5hex() is gone"))

    two = has("esm.sh/esptool-js") and has("unpkg.com/esptool-js")
    lines.append(_check("official engine tries a second CDN before giving up",
                        two,
                        "" if two else "only one CDN source is configured"))

    imap = has('type="importmap"') and has('atob-lite')
    lines.append(_check("import map covers esptool-js bare specifiers",
                        imap,
                        "" if imap else
                        "pako/atob-lite are not mapped; the plain CDN build "
                        "cannot load"))

    reset = has('after("hard_reset")') or has("after('hard_reset')")
    lines.append(_check("official engine hard-resets the chip after writing",
                        reset,
                        "" if reset else
                        "no hard_reset: the chip stays in the bootloader and "
                        "looks like a failed flash"))

    baud = has("OFFICIAL_BAUD = 115200")
    lines.append(_check("official engine uses a conservative baud rate",
                        baud,
                        "" if baud else "OFFICIAL_BAUD is not 115200"))

    # A failed load must not strand the device: the modules are fetched
    # before the device is handed over, and a failure falls through.
    # Needle is the call site, not the dictionary entry: "officialFail" also
    # appears in the i18n tables, so matching that alone would keep passing
    # even after the fallback branch is deleted.
    safe = has("const mod = await loadOfficial()") and has("t('officialFail')")
    lines.append(_check("a failed engine load falls back to the built-in one",
                        safe,
                        "" if safe else
                        "the official path has no fallback when loading fails"))

    # The flasher stub drops the stream on the ESP32-S3's native USB
    # Serial/JTAG: flashing dies at the first command with "Invalid head of
    # packet (0x45)" because the chip already rebooted and is printing its
    # ROM log. Skipping it means main() must not upload one.
    nostub = has("loader.runStub = async function(){ return loader; };")
    lines.append(_check("the stub can be skipped (it dies on ESP32-S3 USB-JTAG)",
                        nostub,
                        "" if nostub else
                        "runStub is never overridden: the stub upload cannot "
                        "be skipped, which breaks ESP32-S3 native USB"))

    wired = has('id="chkNoStub"') and has("flashWithOfficial(list, mod, skipStub)")
    lines.append(_check("the skip-stub checkbox is wired to the engine call",
                        wired,
                        "" if wired else
                        "chkNoStub exists but its value never reaches "
                        "flashWithOfficial()"))

    dirty = has("t('officialDirty')")
    lines.append(_check("a failed official run warns that the board needs a replug",
                        dirty,
                        "" if dirty else
                        "no warning that a failed stub run leaves the chip "
                        "unusable until it is replugged"))

    # Espressif documents that --no-stub makes esptool ignore the flash pins
    # kept in eFuse. Chips with in-package flash therefore lose their flash
    # entirely (Flash ID ffffff), so skipping must be the exception, not the
    # default.
    default_on = re.search(r'id="chkNoStub"(?![\s\S]{0,40}?checked)', src) is not None
    lines.append(_check("skipping the stub is NOT the default (eFuse pins are ignored)",
                        default_on,
                        "" if default_on else
                        'chkNoStub is checked by default: --no-stub ignores the '
                        'eFuse flash pins, so in-package flash is unreachable'))

    # Without this, a board whose flash cannot be reached still gets 700 KB
    # compressed and sent before the write dies, and the reason is buried.
    # Needle is the guarded call site plus the dead-ID test, not just any
    # mention of readFlashId: the bare name also matches the line inside the
    # try block, so a looser needle passes even with the guard removed.
    preflight = (has("typeof loader.readFlashId === 'function'")
                 and has("fid === 0xFFFFFF")
                 and has("t('officialNoFlash'")
                 and has("t('officialNoFlashStub'"))
    lines.append(_check("the flash is probed before anything is written",
                        preflight,
                        "" if preflight else
                        "no flash-ID pre-flight: an unreachable flash is only "
                        "discovered when the write fails"))

    retry = (has("openOfficialLoader") and has("device.reset()")
             and has("_sleep(1500)"))
    lines.append(_check("connect + stub upload are retried with a reset between",
                        retry,
                        "" if retry else
                        "a dropped stream has no retry: the whole run fails on "
                        "the first bad packet"))

    # hard_reset pulls RTS, which USB Serial/JTAG does not expose at all.
    wd = has("loader.after('watchdog_reset')") and has("loader.after('hard_reset')")
    lines.append(_check("reset after flashing tries the watchdog reset first",
                        wd,
                        "" if wd else
                        "only hard_reset is used: there is no RTS line on "
                        "USB Serial/JTAG, so the chip may stay in the bootloader"))

    # Two open handles on one pipe eat each other's bytes.
    reopen = re.search(r'if \(device\)\{?\s*\n?\s*log\(', src) is not None \
        and has("await disconnect()")
    lines.append(_check("connecting twice releases the previous handle first",
                        reopen,
                        "" if reopen else
                        "connect() can open and claim the same device twice, "
                        "which corrupts the stream"))

    return lines


def _check_raw_listener():
    """Checks on the read-only listener in the single-file web flasher.

    "Uploading stub... Running stub... Invalid head of packet (0x45)" has two
    causes that look identical from the tool's side: the board is rebooting in
    a loop (Espressif documents that empty or invalid flash makes an ESP32-S3
    reboot every few seconds, re-enumerating USB each time), or it only resets
    once the stub is running (power). Listening without sending anything
    separates them, so these checks guard the parts that would silently give
    the wrong verdict.
    """
    here = os.path.dirname(os.path.abspath(__file__))   # .../picokeyapp
    root = os.path.dirname(here)                        # project root
    path = os.path.join(root, "picokey-commissioner.html")
    if not os.path.exists(path):
        return ["  [skip] raw listener in the web page (source not available "
                "in a built app)"]
    src = io.open(path, encoding="utf-8").read()
    lines = []

    has_raw = "async function listenRaw(" in src
    lines.append(_check(
        "the page can listen to the board without sending anything",
        has_raw,
        "" if has_raw else
        "listenRaw() is gone: a reboot loop can no longer be told apart from "
        "a power problem"))

    # A chip sitting quietly in download mode never completes transferIn, so
    # without a race the listener hangs and the "no reboot loop" verdict,
    # the useful half of the answer, never gets printed.
    raced = "Promise.race([" in src and "setTimeout(() => r(null), 1200)" in src
    lines.append(_check(
        "the listener gives up on a silent chip instead of hanging",
        raced,
        "" if raced else
        "transferIn is not raced against a timer: a quiet board hangs the page"))

    bannered = "/ESP-ROM/g" in src and "listenBootLoop" in src
    lines.append(_check(
        "repeated boot banners are reported as a reboot loop",
        bannered,
        "" if bannered else
        "no ESP-ROM banner counting: a reboot loop looks just like a healthy "
        "board"))

    gated = 'id="btnListen"' in src and "getElementById('btnListen')" in src
    lines.append(_check(
        "the listener is wired to a button and gated on a connection",
        gated,
        "" if gated else "btnListen is not wired: the diagnostic is unreachable"))

    return lines


def _dict_line_closed(line):
    """True if every `"key":"value"` pair on one dictionary line is intact.

    Walks the line instead of using one greedy match, because several keys
    share a line. A value that ends early (an unescaped quote inside it)
    leaves the closing quote followed by prose rather than a comma or the
    end of the line, which is exactly what the browser chokes on.
    """
    i, n = 0, len(line)
    while True:
        j = line.find(':"', i)
        if j < 0:
            return True
        k = j + 2
        while k < n:
            if line[k] == "\\":
                k += 2
                continue
            if line[k] == '"':
                break
            k += 1
        if k >= n:
            return False                      # value never closed
        m = k + 1
        while m < n and line[m] in " \t":
            m += 1
        if m >= n:
            return True
        if line[m] != ",":
            return False                      # prose where a comma belongs
        i = m + 1


def _check_dict_quotes():
    """Checks that no dictionary string carries an unescaped double quote.

    Every string in the translation dictionaries is delimited by `"`. One
    stray quote inside a value ends the string early and turns the whole
    inline script into a syntax error, which kills the page: the markup still
    renders, so it looks fine, but every button is dead. This is easy to do
    when writing English prose with quoted terms, and a browser is the only
    way to notice it otherwise.
    """
    here = os.path.dirname(os.path.abspath(__file__))   # .../picokeyapp
    root = os.path.dirname(here)                        # project root
    path = os.path.join(root, "picokey-commissioner.html")
    if not os.path.exists(path):
        return ["  [skip] quote check in the web page (source not available "
                "in a built app)"]
    src = io.open(path, encoding="utf-8").read()
    lines_src = src.split("\n")
    # 0-based slices for the two dictionary literals found by markers.
    starts = [i for i, ln in enumerate(lines_src) if ln.strip() in ("zh: {", "en: {")]
    bad = []
    for s in starts:
        for ln in lines_src[s + 1:]:
            if ln.rstrip() in ("};", "  };"):
                break
            if not _dict_line_closed(ln):
                bad.append(ln.strip()[:60])
    lines = []
    lines.append(_check(
        "no dictionary string breaks out of its quotes",
        not bad,
        "" if not bad else
        "unescaped \" in: " + "; ".join(bad[:3]) +
        " — the inline script will not parse and every button goes dead"))
    return lines


def _check_reload_note():
    """Checks the hint shown after a forced reload.

    Reloading drops the USBDevice object, so the page comes back with every
    button grey except "connect". That is correct, but it reads as a broken
    page, which sends people hunting for a bug that is not there.
    """
    here = os.path.dirname(os.path.abspath(__file__))   # .../picokeyapp
    root = os.path.dirname(here)                        # project root
    path = os.path.join(root, "picokey-commissioner.html")
    if not os.path.exists(path):
        return ["  [skip] reload hint in the web page (source not available "
                "in a built app)"]
    src = io.open(path, encoding="utf-8").read()
    lines = []

    # The hint has to survive the reload it is describing, hence sessionStorage
    # rather than a plain variable.
    flagged = "sessionStorage.setItem('pkReloaded','1')" in src
    lines.append(_check(
        "a reload leaves a marker the next page load can see",
        flagged,
        "" if flagged else
        "forceReload() sets no marker: the hint can never be shown"))

    # Anchored: a substring match also hits the commented-out copy and the
    # definition, so a disabled call would still read as wired.
    shown = ("function noteReload()" in src
             and re.search(r"^\s*noteReload\(\);", src, re.M) is not None)
    lines.append(_check(
        "the reload hint is actually called at startup",
        shown,
        "" if shown else
        "noteReload() is never called: a reload still looks like a failure"))

    # Both dictionaries, otherwise the English page logs an empty line.
    zh = 'reloadHint:"刷新后需要重新点' in src
    en = 'reloadHint:"Reloading clears the connection' in src
    lines.append(_check(
        "the reload hint is translated in both languages",
        zh and en,
        "" if (zh and en) else
        "reloadHint is missing from %s dictionary"
        % ("the English" if zh else ("the Chinese" if en else "each"))))

    return lines


def _mk_uf2(n: int) -> bytes:
    """n well-formed 512 byte UF2 blocks.

    The block number is stamped into each block. Identical blocks would make
    the sequence invisible: writing them back to front produced a byte stream
    that compared equal to the original, so a genuine ordering bug passed this
    suite unnoticed.
    """
    from . import flasher
    out = bytearray()
    for i in range(n):
        blk = bytearray(512)
        struct.pack_into("<I", blk, 0, flasher.UF2_MAGIC_START0)
        struct.pack_into("<I", blk, 4, flasher.UF2_MAGIC_START1)
        struct.pack_into("<I", blk, 8, i)          # makes each block unique
        struct.pack_into("<I", blk, 508, flasher.UF2_MAGIC_END)
        out += blk
    return bytes(out)


class _BotDrive:
    """A fake BOOTSEL drive that speaks Bulk-Only Transport.

    `skip_csw` holds the block indices whose status packet never arrives -
    which is exactly what a real board does on its last block, because it
    reboots before replying.
    """

    def __init__(self, skip_csw=()):
        self.skip_csw = set(skip_csw)
        self.cbws = []
        self.payloads = []
        self._tag = None
        self._lba = None

    def write(self, data, timeout=None):
        b = bytes(data)
        if len(b) == 31 and b[:4] == b"USBC":
            self._tag = struct.unpack_from("<I", b, 4)[0]
            # CBW layout: sig(4) tag(4) len(4) flags(1) lun(1) cblen(1) = 15,
            # so the CDB - and therefore the opcode - starts at byte 15.
            if b[15] == uf2write.SCSI_WRITE_10:
                self._lba = struct.unpack_from(">I", b, 17)[0]
            else:
                self._lba = None
            self.cbws.append(b)
            return len(b)
        self.payloads.append((self._lba, b))
        return len(b)

    def read(self, length=None, timeout=None):
        if self._lba is not None and self._lba in self.skip_csw:
            raise OSError("no reply - the board rebooted")
        return struct.pack("<IIIB", uf2write.CSW_SIGNATURE, self._tag or 0, 0, 0)


def _attempt(drive, payload):
    """Run write_uf2 without letting an exception abort the whole self-test.

    A broken writer must be *reported*, not thrown out of run(): an uncaught
    error here takes the entire report down with it, which is the same "one
    failure at a time" behaviour this suite deliberately moved away from.
    """
    try:
        return uf2write.write_uf2(drive, payload), None
    except Exception as exc:
        return None, exc


def _check_uf2_write():
    """Checks the direct UF2 download (RP2040 / RP2350, no mounted drive).

    These boards are usually flashed by copying a file onto a USB drive.
    Phones often cannot mount that drive, so the app speaks USB mass storage
    itself. Everything here runs against a fake drive, so the wire format is
    what is being checked rather than any particular board.
    """
    lines = ["UF2 direct write (RP2040 / RP2350):"]
    data = _mk_uf2(4)

    drive = _BotDrive()
    result, err = _attempt(drive, data)
    ok = err is None and result is not None
    lines.append(_check("a well-formed UF2 is written without error", ok,
                        "" if ok else f"write_uf2 raised: {err}"))

    signed = bool(drive.cbws) and all(
        len(c) == 31 and c[:4] == b"USBC" for c in drive.cbws)
    lines.append(_check("every command goes out inside a signed 31 byte CBW",
                        signed,
                        "" if signed else
                        f"{len(drive.cbws)} wrapper(s), all signed={signed}"))

    writes = [c for c in drive.cbws if c[15] == uf2write.SCSI_WRITE_10]
    lines.append(_check("one WRITE(10) per UF2 block", len(writes) == 4,
                        "" if len(writes) == 4
                        else f"WRITE(10) went out {len(writes)}x, expected 4"))

    lbas = [lba for lba, _ in drive.payloads]
    lines.append(_check("blocks are written one per command, from LBA 0 up",
                        lbas == [0, 1, 2, 3],
                        "" if lbas == [0, 1, 2, 3]
                        else f"LBA order was {lbas}"))

    joined = b"".join(p for _, p in drive.payloads)
    lines.append(_check("the bytes on the wire are the UF2 itself",
                        joined == data,
                        "" if joined == data else "payload differs from the file"))

    lines.append(_check("a normal write reports the board answered",
                        ok and result["final_csw"] is True,
                        "" if ok and result["final_csw"] is True
                        else "final_csw should be true when nothing is skipped"))

    # The board reboots on the final block, before its status packet can be
    # read. That is success, and must not be turned into an error.
    last = _BotDrive(skip_csw={3})
    res_last, err_last = _attempt(last, data)
    ok_last = (err_last is None and res_last is not None
               and res_last["final_csw"] is False and len(last.payloads) == 4)
    lines.append(_check("a missing reply on the last block counts as success",
                        ok_last,
                        "" if ok_last else
                        f"last block was treated as a failure ({err_last})"))

    # The same silence anywhere else is a real fault and must surface.
    mid = _BotDrive(skip_csw={1})
    _, err_mid = _attempt(mid, data)
    lines.append(_check("a missing reply mid-way is still an error",
                        err_mid is not None,
                        "" if err_mid is not None
                        else "silence on block 1 was swallowed"))

    # A truncated file would silently write a partial image.
    _, err_ragged = _attempt(_BotDrive(), data + b"\x00" * 7)
    lines.append(_check("a file that is not a whole number of blocks is "
                        "refused", err_ragged is not None,
                        "" if err_ragged is not None
                        else "a ragged UF2 was accepted"))

    # Copying onto an already mounted drive: the file must reach the disk,
    # not just Python's buffer, before the board is unplugged.
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        target = uf2write.write_uf2_mounted(tmp, data)
        same = io.open(target, "rb").read() == data
    lines.append(_check("copying onto a mounted drive writes the file",
                        same,
                        "" if same else "the copy did not match the source"))

    gone = False
    try:
        uf2write.write_uf2_mounted("/nonexistent/picokey-selftest", data)
    except Exception:
        gone = True
    lines.append(_check("a vanished mount point is reported, not ignored",
                        gone,
                        "" if gone
                        else "writing to a missing directory 'succeeded'"))

    return lines


def _check_uf2_web():
    """Checks the WebUSB UF2 path in the single-file web page.

    The page used to tell people a browser simply cannot write a UF2. It can:
    a BOOTSEL board is a mass-storage device and Bulk-Only Transport works
    over WebUSB. What the page cannot do is force a browser to hand over a
    protected interface, so that case has to be reported honestly rather than
    surfacing as a bare error.
    """
    here = os.path.dirname(os.path.abspath(__file__))   # .../picokeyapp
    root = os.path.dirname(here)                        # project root
    path = os.path.join(root, "picokey-commissioner.html")
    if not os.path.exists(path):
        return ["  [skip] UF2 write in the web page (source not available "
                "in a built app)"]
    src = io.open(path, encoding="utf-8").read()
    lines = ["UF2 write in the web page:"]

    wired = ('id="btnUf2" onclick="doWriteUf2()"' in src
             and re.search(r"^\s*async function doWriteUf2\(\)", src, re.M)
             is not None)
    lines.append(_check("the UF2 button is wired to a handler", wired,
                        "" if wired else "btnUf2 has no doWriteUf2() to call"))

    # Class 0x08 only. Matching any interface would happily try to speak SCSI
    # to a CDC port and fail in a way that says nothing.
    msc = ("alt.interfaceClass !== 0x08" in src
           and "function pickMscInterface" in src)
    lines.append(_check("only a mass-storage interface is used", msc,
                        "" if msc else
                        "pickMscInterface does not filter on class 0x08"))

    # Refusal is expected, not exceptional: browsers protect this class.
    guarded = ("catch(e){\n      // Protected class" in src
               or "Protected class" in src) and "t('uf2Blocked')" in src
    lines.append(_check("a refused interface gets its own explanation", guarded,
                        "" if guarded else
                        "a blocked claim shows a bare error instead"))

    # The board reboots before answering the last block.
    tolerant = "i === total - 1" in src and "lastCsw = false" in src
    lines.append(_check("the last block needs no reply", tolerant,
                        "" if tolerant else
                        "a missing reply on the final block becomes a failure"))

    signed = "0x43425355" in src and "0x53425355" in src
    lines.append(_check("the wrappers carry the USBC / USBS signatures", signed,
                        "" if signed else "CBW / CSW signatures are missing"))

    # Only a UF2 may take this path; an ESP image is not a disk image.
    kind_guard = "fwKind !== 'uf2'" in src or 'fwKind !== \"uf2\"' in src
    lines.append(_check("the button only accepts a UF2 image", kind_guard,
                        "" if kind_guard else
                        "any picked file could be pushed as a UF2"))

    # The handler has to read the variables this page actually has. Writing it
    # against a name that does not exist throws a ReferenceError the moment the
    # button is pressed, which looks like "nothing happened".
    start = src.index("async function doWriteUf2()")
    body = src[start:src.index("\nfunction ", start)] if "\nfunction " in src[start:] \
        else src[start:start + 4000]
    uses_real = "fwData" in body and "fwBytes" not in body
    lines.append(_check("the handler reads the picked image by its real name",
                        uses_real,
                        "" if uses_real else
                        "doWriteUf2 refers to a variable that does not exist"))
    declared = "let fwKind = null;" in src
    lines.append(_check("the image kind is kept where the button can see it",
                        declared,
                        "" if declared else
                        "fwKind is never declared: the guard cannot work"))

    # Every key, in both dictionaries - one language missing a key logs an
    # empty line at exactly the moment something went wrong.
    keys = ["btnUf2", "hintUf2", "uf2NeedFile", "uf2NoMsc", "uf2NoMscBody",
            "uf2Using", "uf2Blocked", "uf2BlockedBody", "uf2Writing",
            "uf2LastNoReply", "uf2Done", "uf2DoneBody", "uf2Failed",
            "mUf2Title"]
    thin = [k for k in keys if src.count("    " + k + ':"') != 2]
    lines.append(_check("every new string exists in both languages", not thin,
                        "" if not thin else "missing from one dictionary: "
                                            + ", ".join(thin)))
    return lines


def _check_no_hang_no_false_alarm():
    """Three bugs that all present as "it just sits there" or "it lies".

    A board in a reboot loop prints its ROM banner forever. Every banner
    arrived before the per-frame deadline expired, which reset the deadline,
    so an erase that could never be answered waited forever: the app hangs on
    "erasing the whole chip" with no error and no way out.

    Separately, the module check looked for .py files next to __file__. In a
    packaged APK there are none, so it reported all eleven modules missing on
    a build that was plainly running - the app cannot import them and be
    broken at the same time.

    And a single fixed log name meant each run overwrote the last, so a crash
    on startup destroyed the log of the run before it.
    """
    import re as _re
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)
    lines = []

    try:
        with open(os.path.join(here, "flasher.py"), encoding="utf-8") as fh:
            fsrc = fh.read()
    except OSError:
        return ["  [skip] erase/import/log guards (source not available "
                "in a built app)"]

    # One wall-clock budget, shared: the loop must consult remaining time
    # rather than handing each _read_frame the full timeout again.
    budget = ("budget = _now() + (timeout or self.timeout) / 1000.0" in fsrc
              and "remaining = budget - _now()" in fsrc
              and "self._read_frame(timeout=max(1, int(remaining * 1000)))" in fsrc)
    lines.append(_check(
        "an endless banner cannot extend the erase wait",
        budget,
        "" if budget else
        "_await_op re-arms a full timeout per frame: a rebooting board hangs "
        "the flash instead of failing"))

    try:
        with open(os.path.join(root, "main.py"), encoding="utf-8") as fh:
            msrc = fh.read()
    except OSError:
        msrc = ""
    if not msrc:
        lines.append("  [skip] log naming (source not available in a built app)")
        return lines

    dated = ('_LOG_PREFIX = "picokey_"' in msrc
             and '_log_name = _LOG_PREFIX + time.strftime("%Y%m%d-%H%M%S")' in msrc)
    lines.append(_check(
        "each run gets its own dated log file",
        dated,
        "" if dated else
        "the log name is fixed again: a crash on open destroys the previous "
        "run's log"))

    # The prefix already owns one underscore, so a second one glues three
    # fields into "picokey_20261003_091636" and the stamp stops being
    # readable at a glance. A dash keeps date and time visibly separate.
    stamp = re.search(r'_LOG_PREFIX \+ time\.strftime\("([^"]+)"\)', msrc)
    glued = bool(stamp) and "_%H" in stamp.group(1)
    lines.append(_check(
        "date and time are separated by a dash, not an underscore",
        bool(stamp) and not glued,
        "" if (bool(stamp) and not glued) else
        "the stamp glues three fields together: picokey_20261003_091636.log"))

    # The false alarm: importing is the only honest test for a packaged build.
    # This check lives in the same file as the code it guards, so it reads
    # itself - a guard that inspects the wrong file passes no matter what.
    try:
        with open(os.path.abspath(__file__), encoding="utf-8") as fh:
            ssrc = fh.read()
    except OSError:
        ssrc = ""
    # Both needles appear in this very check, so a plain `in` test would be
    # satisfied by the guard itself and could never fail. Counting is what
    # makes it meaningful: one hit is the guard, two mean real code.
    imported = ssrc.count('__import__("picokeyapp." + m)') >= 2
    stale = ssrc.count('os.path.exists(os.path.join(here, m + ".py"))') > 1
    lines.append(_check(
        "module completeness is decided by importing, not by file lookup",
        imported and not stale,
        "" if imported and not stale else
        "the check looks for .py files, which do not exist in an APK - it "
        "reports every module missing on a build that runs fine"))

    return lines


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


def _check_uv_config() -> list:
    """The PIN/UV handshake that gates authenticatorConfig.

    These run against a fake authenticator that performs the device side for
    real - its own ECDH, its own PIN check, its own verification of the auth
    param. That is the point: a unit test of each half would pass while the two
    halves disagreed about the key schedule, and the failure on real hardware
    would look like "wrong PIN" forever.

    `uvcrypto` is cross-checked against a known-answer vector because a bug in
    the AES inverse column mix still encrypts correctly - it only shows up when
    decrypting the token, which is the step that unlocks everything else.
    """
    from . import ctapcfg as C
    from . import uvcrypto as U
    from .cbor_mini import dumps, loads

    out = []

    # --- the primitives, against published vectors ------------------------
    key = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    ref = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
    rk = U._key_expansion(key)
    out.append(_check("AES-256 matches the FIPS-197 known-answer vector",
                      U._encrypt_block(pt, rk) == ref,
                      U._encrypt_block(pt, rk).hex()))
    out.append(_check("AES-256 decrypts its own output",
                      U._decrypt_block(ref, rk) == pt,
                      "the inverse column mix is wrong"))

    secret = U.protocol1_shared_secret(b"\x01" * 32)
    out.append(_check("PIN/UV protocol one derives SHA-256(x)",
                      secret == hashlib.sha256(b"\x01" * 32).digest()))
    out.append(_check("pinHashEnc survives a round trip",
                      U.protocol1_decrypt(
                          secret, U.protocol1_encrypt(
                              secret, U.pin_hash("1234"))) == U.pin_hash("1234")))
    out.append(_check("authenticate() truncates to 16 bytes",
                      len(U.protocol1_authenticate(secret, b"\x0d\x02")) == 16))

    # --- the handshake, end to end ---------------------------------------
    class Fake:
        """Device side of CTAP: real ECDH, real PIN check, real auth param."""

        def __init__(self, pin):
            self.pin = pin
            self.priv, self.pub = U.p256_keypair()
            self.secret = None
            self.token = os.urandom(32)
            self.always_uv = True
            self.min_pin = None

        def cbor(self, cmd, payload=b"", timeout=None, on_keepalive=None):
            req = loads(payload) if payload else {}
            if cmd == C.CMD_CLIENT_PIN:
                sub = req[C.PIN_PARAM_SUBCOMMAND]
                if sub == C.PIN_SUB_GET_KEY_AGREEMENT:
                    return 0x00, dumps({
                        C.PIN_RESP_KEY_AGREEMENT: C.encode_platform_pubkey(self.pub)})
                if sub == C.PIN_SUB_GET_TOKEN_USING_PIN:
                    peer = C.decode_device_pubkey(req[C.PIN_PARAM_KEY_AGREEMENT])
                    self.secret = U.protocol1_shared_secret(
                        U.p256_ecdh(self.priv, peer))
                    if U.protocol1_decrypt(
                            self.secret,
                            req[C.PIN_PARAM_PIN_HASH_ENC]) != U.pin_hash(self.pin):
                        return 0x31, b""
                    if req[C.PIN_PARAM_PERMISSIONS] != C.PERM_AUTHENTICATOR_CFG:
                        return 0x3E, b""
                    return 0x00, dumps({
                        C.PIN_RESP_PIN_TOKEN:
                            U.protocol1_encrypt(self.secret, self.token)})
                return 0x01, b""
            if cmd == C.CMD_CONFIG:
                sub = req[C.CFG_PARAM_SUBCOMMAND]
                body = bytes([sub])
                if C.CFG_PARAM_SUBCOMMAND_PARAMS in req:
                    body += dumps(req[C.CFG_PARAM_SUBCOMMAND_PARAMS])
                want = U.protocol1_authenticate(
                    self.token, bytes([C.CMD_CONFIG]) + body)
                if req[C.CFG_PARAM_AUTH_PARAM] != want:
                    return 0x31, b""
                if sub == C.CFG_SUB_TOGGLE_ALWAYS_UV:
                    self.always_uv = not self.always_uv
                elif sub == C.CFG_SUB_SET_MIN_PIN_LENGTH:
                    self.min_pin = req[C.CFG_PARAM_SUBCOMMAND_PARAMS][0x01]
                return 0x00, b""
            return 0x01, b""

    dev = Fake("123456")
    cfg = C.UvConfig(dev)
    try:
        cfg.obtain_token("123456")
        got_token = cfg._token == dev.token
        same_secret = cfg._secret == dev.secret
    except Exception as exc:                      # pragma: no cover
        got_token = same_secret = False
        out.append(_check("token exchange", False, f"{type(exc).__name__}: {exc}"))
    if got_token:
        out.append(_check("both sides derive the same shared secret", same_secret))
        out.append(_check("the token comes back and decrypts", got_token))

        before = dev.always_uv
        cfg.toggle_always_uv()
        out.append(_check("toggleAlwaysUv flips the authenticator's setting",
                          dev.always_uv != before,
                          f"{before} -> {dev.always_uv}"))
        cfg.toggle_always_uv()
        out.append(_check("toggling twice returns to the original state",
                          dev.always_uv == before))

    # A wrong PIN must be refused, and refused with a reason someone can act on.
    try:
        C.UvConfig(Fake("123456")).obtain_token("000000")
        out.append(_check("a wrong PIN is refused", False, "it was accepted"))
    except C.ConfigError as exc:
        out.append(_check("a wrong PIN is refused, with a readable reason",
                          "PIN" in str(exc), str(exc)))

    # Tampering with the token must be caught by the authenticator: this is
    # what stops a config change being applied under a token we never owned.
    d2 = Fake("123456")
    c2 = C.UvConfig(d2)
    c2.obtain_token("123456")
    c2._token = os.urandom(32)
    try:
        c2.toggle_always_uv()
        out.append(_check("a forged token is rejected", False, "it was accepted"))
    except C.ConfigError:
        out.append(_check("a forged token is rejected", True))

    # Configuring without a token at all is a programming error, not a device
    # one; it must fail loudly rather than send an unauthenticated command.
    try:
        C.UvConfig(Fake("123456")).toggle_always_uv()
        out.append(_check("config without a token is refused", False))
    except C.ConfigError:
        out.append(_check("config without a token is refused", True))

    # setMinPINLength is one-way; the range check is the last cheap guard.
    d3 = Fake("123456")
    c3 = C.UvConfig(d3)
    c3.obtain_token("123456")
    refused = 0
    for bad in (0, 3, 64, 100):
        try:
            c3.set_min_pin_length(bad)
        except C.ConfigError:
            refused += 1
    out.append(_check("setMinPINLength rejects out-of-range values",
                      refused == 4, f"refused {refused}/4"))

    # Feature detection must key off authnrCfg, not the CTAP version string.
    out.append(_check("config support is detected from authnrCfg",
                      C.config_supported({"options": {"authnrCfg": True}})
                      and not C.config_supported({"options": {}})))

    # The P-256 domain parameters are easy to mistype by one digit; a point
    # off the curve must be refused rather than silently used.
    try:
        U.p256_point_from_bytes(0, 0)
        out.append(_check("an off-curve public key is rejected", False))
    except U.EccError:
        out.append(_check("an off-curve public key is rejected", True))

    return out


def _check_ins_table() -> list:
    """Pin the rescue-applet command table to upstream pypicokey.

    Every INS here was at some point inferred from a documentation mirror
    rather than read from source, and one of them (a nonexistent 0x1D used
    for secure boot) was simply invented. The authoritative values come from
    pypicokey's picokey/PicoKey.py:

        0x1C P1=01  write PHY      0x1E P1=01  read PHY
        0x1C P1=02  secure boot    0x1E P1=02  flash info
        0x1F P1=..  reboot         0x1E P1=03  secure info

    Checking them statically means a future edit that "fixes" one of these
    from memory fails here instead of on real hardware.
    """
    import re
    out = [t("sec_security").strip("— ") + " (上游命令表):"]
    try:
        src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "pk", "PicoKey.py"), encoding="utf-8").read()
    except OSError:
        # Packaged APK: no source on disk. Not a failure, just uncheckable.
        out.append("  [skip] " + t("skip_no_source"))
        return out

    expected = [
        ("read PHY      -> 1E/P1=01",
         r"self\.send\(0x1E,\s*cla=0x80,\s*p1=0x01"),
        ("write PHY     -> 1C/P1=01",
         r"self\.send\(0x1C,\s*cla=0x80,\s*p1=0x01"),
        ("flash info    -> 1E/P1=02",
         r"self\.send\(0x1E,\s*cla=0x80,\s*p1=0x02"),
        ("secure info   -> 1E/P1=03",
         r"self\.send\(0x1E,\s*cla=0x80,\s*p1=0x03"),
        ("secure boot   -> 1C/P1=02",
         r"self\.send\(0x1C,\s*cla=0x80,\s*p1=0x02"),
        ("reboot        -> 1F",
         r"self\.send\(0x1F,\s*cla=0x80"),
    ]
    for label, pattern in expected:
        m = re.search(pattern, src)
        out.append(_check(label, m is not None,
                          "not found - diverged from upstream"
                          if m is None else m.group(0)))

    # 0x1D has never existed upstream. If it reappears, someone inferred it.
    out.append(_check("INS 0x1D is not used at all",
                      re.search(r"self\.send\(0x1D", src) is None,
                      "0x1D does not exist in the upstream command table"))

    # The on-screen text must not contradict the code. It once did: the probe
    # footer told the operator to use INS 1D for secure boot while the code
    # sent 1C/P1=02, and the difference matters most on the one irreversible
    # action this app can perform.
    try:
        from . import i18n
        footer = i18n.t("probe_footer")
    except Exception as exc:                       # pragma: no cover
        footer = ""
        out.append(_check("probe_footer is reachable", False, str(exc)))

    # Counted, not searched with a literal: this very check contains the
    # string it looks for, so a plain "in" test would always pass.
    out.append(_check("probe_footer agrees with the code (says INS 1C, P1=02)",
                      "INS 1C" in footer and "P1=02" in footer
                      and footer.count("INS 1D") == 1,
                      "footer and implementation disagree on the command"))
    out.append(_check("probe_footer mentions 1D once, as a does-not-exist warning",
                      footer.count("1D") == 1,
                      "1D should appear exactly once"))
    return out


def run() -> str:
    import inspect

    # Module completeness, before anything is imported from this package: a
    # missing file is the most common cause of "it crashes on open", and every
    # check below is pointless until the imports resolve.
    # Imported, not looked up on disk. In a packaged APK the sources are not
    # loose .py files next to __file__, so a file-existence check reports every
    # single module as missing while the app itself is plainly running - the
    # user then sees "missing modules" for a build that imports fine. Only an
    # import that actually raises is a missing module.
    here = os.path.dirname(os.path.abspath(__file__))
    _MAIN_IMPORTS = ["cbor_mini", "ccid", "ctap", "ctapcfg", "detect",
                     "flasher", "fonts", "i18n", "usbhost", "uvcrypto", "saf",
                     "uf2write"]
    gone = []
    for m in _MAIN_IMPORTS:
        try:
            __import__("picokeyapp." + m)
        except Exception:
            gone.append(m)
    if gone:
        return "\n".join([
            t("selftest_title"), "",
            "  [FAIL] " + t("selftest_missing_modules", default="missing modules"),
            "  - " + ", ".join(gone),
            "",
            t("selftest_hint_missing", default=
              "Upload picokeyapp/%s.py as well. A module missing at import "
              "time aborts before any window exists, which is what a crash on "
              "open actually is." % gone[0]),
        ])

    from . import ccid, ctap
    from .cbor_mini import loads, dumps
    from .pk import PicoKey, PhyData, PhyUsbItf, PhyLedDriver, PhyOpt, PhyCurve

    # A second run must not inherit the first one's failures.
    _FAILURES.clear()
    lines = [t("selftest_title"), ""]

    # Environment first. Most "it keeps failing" reports turn out to be a
    # half-uploaded build, and without this there is no way to tell: the same
    # checks pass in source and fail in a package that is missing one file.
    import sys
    import platform as _platform
    try:
        src_ok = os.path.exists(os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "main.py"))
    except Exception:
        src_ok = False
    lines.append("env: python %s | kivy %s | source on disk: %s" % (
        sys.version.split()[0],
        getattr(_platform, "python_implementation", lambda: "?")(),
        "yes" if src_ok else "no (built app - file-based checks are skipped)"))
    lines.append("")


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

    # And when the board does answer, the three fields have to be decoded.
    fake.secure_info_ok = True
    try:
        info = pk.secure_info()
        lines.append(_check("secure_info decodes enabled/locked/bootkey",
                            info is not None and info["enabled"] is True
                            and info["locked"] is False
                            and info["boot_key"] == 3, str(info)))
    finally:
        fake.secure_info_ok = False

    # Upstream: INS 0x1C, P1=0x02, body [slot, lock]. An earlier revision sent
    # INS 0x1D with the slot in P1 - invented from a doc mirror, and wrong.
    pk.secure_boot(3, True)
    lines.append(_check("secure_boot sends INS 1C P1=02 with [slot, lock]",
                        fake.secure_written == (3, 1), str(fake.secure_written)))

    fake.reset_state()
    pk.secure_boot(0, False)
    lines.append(_check("secure_boot without lock sends lock flag 0",
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

    # Guard against the mistake this file once locked in: INS 0x1D never
    # existed upstream. A device that does not implement it answers 6A82, so
    # sending it must fail loudly rather than being reported as success.
    try:
        pk.send(0x1D, cla=0x80, p1=0x00, p2=0x00)
        lines.append(_check("the invented INS 1D is not used", False,
                            "a command that does not exist upstream succeeded"))
    except Exception:
        lines.append(_check("the invented INS 1D is not used", True))

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

    # OP_READ_REG, not a flash op: only an idempotent command may be resent, and
    # this check is about the resync happening at all.
    late = LateConn(flasher.OP_READ_REG)
    flasher.EspLoader(late).command(flasher.OP_READ_REG, b"", 0, timeout=200)
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
    # FLASH_END is deliberately not resent, so the message has to say that it
    # stopped rather than claim a retry happened.
        lines.append(_check("mismatch names both ops and says it stopped", False,
                            "no exception"))
    except flasher.FirmwareError as e:
        lines.append(_check("mismatch names both ops and says it stopped",
                            "08" in str(e) and "04" in str(e)
                            and ("未执行第二次" in str(e)
                                 or "没有重复发送" in str(e)), str(e)))
    except Exception as e:
        lines.append(_check("mismatch names both ops and says it stopped", False,
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
    # drain is stubbed out here: the attach *did* answer, so there is nothing
    # stale in the pipe, and letting drain run would eat the erase reply and
    # then sit out the full 90s erase timeout.
    c = RecordingConn([_ack(0x0D, status=1), _ack(0xD0)])
    loader_e = flasher.EspLoader(c)
    loader_e.drain = lambda *a, **k: None
    loader_e.erase_flash(timeout=800)
    frames = _sent(c)
    lines.append(_check("erase attaches to SPI first",
                        len(frames) >= 1 and frames[0][1] == flasher.OP_SPI_ATTACH,
                        "did not attach before erasing"))
    lines.append(_check("erase sends ERASE_FLASH (0xD0)",
                        len(frames) >= 2 and frames[1][1] == flasher.OP_ERASE_FLASH,
                        f"sent op {frames[1][1]:#04x}" if len(frames) >= 2
                        else "no erase command was sent"))

    c2 = RecordingConn([_ack(0x0D), _ack(0xD1)])
    loader_r = flasher.EspLoader(c2)
    loader_r.drain = lambda *a, **k: None
    loader_r.erase_region(0x10000, 0x100000, timeout=800)
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

    # f4b) The pipe must be clean before the first real command. The ROM prints
    # a banner on the same USB Serial/JTAG line, and sync() skips over frames
    # that do not match, so whatever is left waits to be read back as the answer
    # to SPI_ATTACH. This is the "bootloader did not answer" / "got op 0D,
    # wanted D0" pair that showed up on a board that had actually synced fine.
    class BannerConn(RecordingConn):
        """Answers SYNC properly, but only after a banner has been printed."""

        def __init__(self):
            super().__init__([])
            self.banner = b"ESP-ROM:esp32s3-20210327 Build:Mar 27 2021\r\n"
            self.sync_seen = 0

        def read(self, length=None, timeout=None):
            if self.banner is not None:
                b, self.banner = self.banner, None
                return b
            return _ack(flasher.OP_SYNC)

    # What matters is that the *device* side is drained, not just the local
    # buffer: slip_decode already skips leading junk, so a buffer-only check
    # passes whether or not the cleanup runs. Count the drain instead.
    bc = BannerConn()
    ld_b = flasher.EspLoader(bc)
    drained = []
    ld_b.drain = lambda *a, **k: drained.append(1)
    synced = ld_b.sync()
    lines.append(_check("sync drains the device after the ROM banner",
                        synced and len(drained) >= 1,
                        f"synced={synced}, drain called {len(drained)}x"))

    # f4c) A timeout is not the same as a refusal. For an idempotent command,
    # asking again is free and it consumes the overdue reply instead of leaving
    # it for the next command - which is what an erase would otherwise read.
    class QuietConn(RecordingConn):
        """Never answers; used to count how many times a command goes out."""

        def read(self, length=None, timeout=None):
            return b""

    for label, op, want in (("an idempotent command is retried after a timeout",
                             flasher.OP_SPI_ATTACH, 2),
                            ("a destructive command is not retried on timeout",
                             flasher.OP_ERASE_FLASH, 1)):
        qc = QuietConn([])
        qc.drain = lambda *a, **k: None
        ld_q = flasher.EspLoader(qc)
        ld_q.timeout = 60
        try:
            ld_q.command(op, b"", timeout=60)
        except flasher.FirmwareError:
            pass
        n = sum(1 for w in qc.written
                if flasher.slip_decode(bytearray(w))[0][1] == op)
        lines.append(_check(label, n == want, f"sent {n}x, expected {want}x"))

    # f4e) Multi-image flashing: an ESP32-S3 needs bootloader, partition table
    # and app at three different offsets, and writing only the app at 0x0 is
    # the failure this exists to prevent. What must hold is that all three go
    # out over ONE connection - re-syncing between images is what lets the
    # previous command's reply answer the next one.
    class EchoConn(RecordingConn):
        """Answers every command with a well-formed reply for that command."""

        def __init__(self):
            super().__init__([])
            self.last = flasher.OP_SYNC
            self.pending = bytearray()

        def write(self, data, timeout=None):
            self.written.append(bytes(data))
            self.pending += bytes(data)
            frame, used = flasher.slip_decode(self.pending)
            if frame is not None:
                self.last = frame[1]
                del self.pending[:used]
            return len(data)

        def read(self, length=None, timeout=None):
            return _ack(self.last)

    three = [(0x0, b"\xe9" + b"\x00" * 63, "bootloader.bin"),
             (0x8000, b"\xe9" + b"\x00" * 63, "partition-table.bin"),
             (0x10000, b"\xe9" + b"\x00" * 63, "firmware.bin")]
    mc = EchoConn()
    seen_progress = []

    class _Dev:
        def interfaces_of_class(self, _cls):
            return [0]

    _real_usb = flasher.usbhost
    try:
        flasher.usbhost = type("U", (), {
            "Connection": staticmethod(lambda *a, **k: mc)})()
        flasher.flash_esp32_multi(
            _Dev(), three,
            progress=lambda i, n, d, b: seen_progress.append((i, n)))
    finally:
        flasher.usbhost = _real_usb

    # Writes are chopped into endpoint-sized chunks, so an individual entry in
    # `written` is often only part of a frame. Keep the ones that decode.
    m_ops = [f[1] for f in _sent(mc) if f is not None]
    n_begin = m_ops.count(flasher.OP_FLASH_BEGIN)
    n_sync = m_ops.count(flasher.OP_SYNC)
    lines.append(_check("three images are written over one connection",
                        n_sync == 2,
                        f"SYNC went out {n_sync} time(s), expected 2 (one sync)"))
    lines.append(_check("each image gets its own FLASH_BEGIN",
                        n_begin == 3, f"FLASH_BEGIN went out {n_begin}x"))
    lines.append(_check("progress reports which image is being written",
                        seen_progress and seen_progress[0][1] == 3,
                        f"first callback was {seen_progress[0] if seen_progress else None}"))

    # The offsets themselves. Getting these wrong is the whole reason the
    # board stays dark, so they are pinned rather than left to whoever edits
    # the guessing function next.
    lines.append(_check("offsets are guessed from file names",
                        (flasher.guess_offset("bootloader.bin") == 0x0
                         and flasher.guess_offset("partition-table.bin") == 0x8000
                         and flasher.guess_offset("pico_fido.bin") == 0x10000),
                        f"bootloader={flasher.guess_offset('bootloader.bin'):#x}, "
                        f"partition={flasher.guess_offset('partition-table.bin'):#x}, "
                        f"app={flasher.guess_offset('pico_fido.bin'):#x}"))

    # Upstream ships one .bin and does not say which kind it is. Getting this
    # wrong is the difference between a board that boots and one that flashes
    # "successfully" and then stays dark.
    merged = bytearray(0x20000)
    merged[0] = 0xE9
    merged[0x10000] = 0xE9
    app_only = bytearray(0x5000)
    app_only[0] = 0xE9
    lines.append(_check(
        "a whole-flash image is written to 0x0, an app-only one to 0x10000",
        flasher.guess_offset("pico.bin", bytes(merged)) == 0x0
        and flasher.guess_offset("pico.bin", bytes(app_only)) == 0x10000,
        f"merged={flasher.guess_offset('pico.bin', bytes(merged)):#x}, "
        f"app={flasher.guess_offset('pico.bin', bytes(app_only)):#x}"))
    class LateThenRight:
        """The reply to the previous command turns up instead of this one's.

        This is the real sequence on an ESP32-S3: SPI_ATTACH's answer arrives
        after ERASE_FLASH went out. The erase is already running, so it cannot
        be sent again - dropping the overdue frame and reading on is the only
        thing that ends well.
        """

        def __init__(self):
            self.written = []
            self._reads = 0

        def write(self, data, timeout=None):
            self.written.append(bytes(data))
            return len(data)

        def read(self, length=None, timeout=None):
            self._reads += 1
            if self._reads == 1:
                return flasher.slip_encode(
                    struct.pack("<BBHI", 0x01, 0x0D, 0, 0))   # late attach
            return flasher.slip_encode(
                struct.pack("<BBHI", 0x01, 0xD0, 0, 0))       # the real answer

        def close(self):
            pass

    late = LateThenRight()
    ldr = flasher.EspLoader(late)
    ldr.drain = lambda *a, **k: None
    try:
        ldr.command(flasher.OP_ERASE_FLASH, b"", timeout=500)
        ok_late = True
        detail = "erase completed"
    except Exception as exc:
        ok_late = False
        detail = str(exc)
    n_e = sum(1 for w in late.written
              if flasher.slip_decode(bytearray(w))[0][1] == 0xD0)
    lines.append(_check(
        "an overdue reply is dropped instead of failing the erase in flight",
        ok_late and n_e == 1,
        f"succeeded={ok_late}, ERASE_FLASH sent {n_e}x, {detail}"))

    lines.append(_check(
        "erase-first runs on the same connection as the write",
        "erase_first" in inspect.getsource(flasher.flash_esp32_multi)
        and "loader.erase_flash()" in inspect.getsource(flasher.flash_esp32_multi),
        "the erase must not open a second connection"))

    # f4d) flash() must clear the pipe just like erase_flash() does. It did
    # not, which is why the error surfaced during flashing while naming the
    # erase opcode - the two paths had drifted apart.
    import inspect
    _f_src = inspect.getsource(flasher.EspLoader.flash)
    _f_ok = "_clean_pipe" in _f_src
    lines.append(_check("flash() clears the pipe after a failed SPI_ATTACH",
                        _f_ok,
                        "" if _f_ok else
                        "flash() carries the failed reply over to FLASH_BEGIN"))

    # f5) A destructive command must never be retransmitted. The mismatch path
    # retries when a stale frame turns up, which is right for a read but not for
    # an erase: sending ERASE_FLASH a second time while the first is still
    # running is not a retry, it is a second erase. This is exactly the
    # "got op 0D, wanted D0" case - SPI_ATTACH's answer arriving late.
    #
    # Guard first: this property lives in flasher.py, not here. If only
    # selftest.py was uploaded, the count comes out 2 and the message says
    # nothing about why - the reported failure looks like a bug in the test
    # rather than a missing file.
    def _flasher_has_guard():
        import inspect
        cls = flasher.EspLoader
        if not hasattr(cls, "NON_IDEMPOTENT_OPS"):
            return False
        try:
            return "_retry" in inspect.signature(cls.command).parameters
        except (TypeError, ValueError):
            return False

    guard_ok = _flasher_has_guard()
    lines.append(_check("selftest_flasher_skew", guard_ok,
                        "" if guard_ok else t("selftest_flasher_skew")))

    def _count_sent(conn, op, drain_noop=True):
        loader = flasher.EspLoader(conn)
        if drain_noop:
            # Nothing left in the pipe, so draining must not consume the reply
            # we are about to read - otherwise the test measures the fake
            # connection's queue instead of the retry logic.
            loader.drain = lambda *a, **k: None
        try:
            loader.command(op, b"", timeout=800)
        except flasher.FirmwareError:
            pass
        return sum(1 for w in conn.written
                   if flasher.slip_decode(bytearray(w))[0][1] == op)

    # Counted once into a variable: calling it inside the message too would run
    # a second command against the same connection and report the total.
    if guard_ok:
        stale = RecordingConn([_ack(0x0D)])
        n_erase = _count_sent(stale, flasher.OP_ERASE_FLASH)
        lines.append(_check("a destructive command is not retransmitted",
                            n_erase == 1, f"ERASE_FLASH went out {n_erase} times"))

        stale2 = RecordingConn([_ack(0x0D)])
        n_data = _count_sent(stale2, flasher.OP_FLASH_DATA)
        lines.append(_check("a flash data block is not retransmitted",
                            n_data == 1, f"FLASH_DATA went out {n_data} times"))
    else:
        # Without the guard every mismatch is retried, so both counts would be
        # 2. That measures the missing file, not the property, so say so.
        lines.append("  [skip] a destructive command is not retransmitted")
        lines.append("  [skip] a flash data block is not retransmitted")

    # ...while an idempotent one still gets its retry.
    late = RecordingConn([_ack(0x08), _ack(flasher.OP_READ_REG)])
    loader_ro = flasher.EspLoader(late)
    loader_ro.drain = lambda *a, **k: None
    try:
        loader_ro.command(flasher.OP_READ_REG, b"", timeout=800)
        ok_ro = True
    except flasher.FirmwareError:
        ok_ro = False
    n_ro = sum(1 for w in late.written
               if flasher.slip_decode(bytearray(w))[0][1] == flasher.OP_READ_REG)
    lines.append(_check("a read is still retried after a stale frame",
                        ok_ro and n_ro == 2,
                        f"succeeded={ok_ro}, sent {n_ro}x"))

    # f6) FLASH_END has to ask the ROM to run the firmware. The argument reads
    # backwards - esptool sends 0 to reboot and 1 to stay in the bootloader -
    # and we used to send 1 always, so a freshly flashed board sat in download
    # mode: no LED (the LED is driven by firmware) and one USB interface, which
    # is indistinguishable from a flash that never happened.
    def _flash_end_arg(reboot):
        img = b"\xe9" + b"\x00" * 63          # one block at the default size
        replies = [_ack(flasher.OP_SPI_ATTACH), _ack(flasher.OP_FLASH_BEGIN),
                   _ack(flasher.OP_FLASH_DATA), _ack(flasher.OP_FLASH_END)]
        conn = RecordingConn(replies)
        loader = flasher.EspLoader(conn)
        loader.drain = lambda *a, **k: None
        loader.flash(img, reboot=reboot)
        for w in conn.written:
            frame = flasher.slip_decode(bytearray(w))[0]
            # A data block goes out in 64-byte writes, so most of what was
            # recorded is a partial frame. Only complete ones can be decoded.
            if not frame:
                continue
            if frame[1] == flasher.OP_FLASH_END:
                return struct.unpack_from("<I", frame, 8)[0]
        return None

    try:
        arg_on = _flash_end_arg(True)
        arg_off = _flash_end_arg(False)
    except Exception as exc:
        arg_on = arg_off = None
        lines.append(_check("FLASH_END reboots the chip", False,
                            f"{type(exc).__name__}: {exc}"))
    if arg_on is not None:
        lines.append(_check("FLASH_END reboots the chip", arg_on == 0,
                            f"sent {arg_on}, expected 0"))
        lines.append(_check("FLASH_END can be told to stay in the bootloader",
                            arg_off == 1, f"sent {arg_off}, expected 1"))

    # Rebooting in the middle of a multi-file write would drop the connection
    # with images still queued, so only the last file may carry the flag.
    import inspect as _inspect
    _multi_src = _inspect.getsource(flasher.flash_esp32_multi)
    _multi_ok = "reboot=reboot and idx == total" in _multi_src
    lines.append(_check("multi-file flashing reboots on the last file only",
                        _multi_ok,
                        "" if _multi_ok else
                        "the reboot flag is not tied to the last entry"))

    lines.append("")
    lines.append("")
    lines.extend(_check_ins_table())
    lines.extend(_check_uv_config())

    lines.append("")
    lines.append("")
    lines.append(t("selftest_ui") + ":")
    lines.extend(_check_channel_gating())

    lines.append("")
    lines.extend(_check_official_engine())
    lines.extend(_check_raw_listener())
    lines.extend(_check_reload_note())
    lines.append("")
    lines.extend(_check_uf2_write())
    lines.extend(_check_uf2_web())
    lines.extend(_check_dict_quotes())
    lines.extend(_check_no_hang_no_false_alarm())
    lines.append("")
    lines.extend(_check_font_coverage())
    lines.extend(_check_row_height())

    lines.append("")
    if _FAILURES:
        lines.append(t("selftest_failed", n=len(_FAILURES)))
        for item in _FAILURES:
            lines.append("  - " + item)
    else:
        lines.append(t("selftest_passed"))
    return "\n".join(lines)


if __name__ == "__main__":
    print(run())
