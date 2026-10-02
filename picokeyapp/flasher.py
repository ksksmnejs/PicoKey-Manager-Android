"""
Firmware flashing straight from the phone, over the Android USB host API.

Two boards, two completely unrelated mechanisms
-----------------------------------------------
RP2040 / RP2350
    BOOTSEL makes the Boot ROM expose the flash as a USB mass-storage device
    (USB class 8). You "flash" by copying a .uf2 file onto it; the ROM does the
    rest. There is no serial protocol to speak.

    Writing a file into that FAT filesystem from scratch would mean shipping a
    FAT12/16/32 writer - a lot of code with a lot of ways to corrupt a volume.
    Instead we hand the file to the system file manager through the Storage
    Access Framework, which already knows how to do this correctly.

ESP32-S2 / ESP32-S3
    These have no UF2 bootloader and no mass-storage mode. They boot a ROM
    serial loader that speaks esptool's SLIP-framed binary protocol over
    USB Serial/JTAG (a CDC ACM interface, USB class 10). This module
    implements that protocol directly, so no external tool is needed.

Provenance / testing status
---------------------------
The SLIP framing, command opcodes and packet layout follow the ROM serial
protocol, and the UF2 block layout is validated against the published magic
numbers. None of it has been exercised against real silicon - see the README.
Flashing is therefore treated as a destructive, opt-in action in the UI.
"""

from __future__ import annotations

import struct

from . import usbhost
from .i18n import t

# ---------------------------------------------------------------------------
# Firmware image sniffing
# ---------------------------------------------------------------------------

UF2_MAGIC_START0 = 0x0A324655      # "UF2\n"
UF2_MAGIC_START1 = 0x9E5D5157
UF2_MAGIC_END = 0x0AB16F30
UF2_BLOCK = 512

_ESP_IMAGE_MAGIC = 0xE9            # first byte of an ESP8266/ESP32 image
_ESP_CHIP_IDS = {0x09: "ESP32-S3"}


class FirmwareError(Exception):
    pass


def sniff(data: bytes) -> dict:
    """Identify a firmware blob. Never raises; 'unknown' is a valid answer."""
    if not data:
        return {"kind": "empty", "detail": t("fw_empty", default="empty file")}

    if len(data) >= 8:
        m0, m1 = struct.unpack_from("<II", data, 0)
        if m0 == UF2_MAGIC_START0 and m1 == UF2_MAGIC_START1:
            blocks = _uf2_block_count(data)
            return {"kind": "uf2", "blocks": blocks,
                    "detail": t("fw_uf2", n=blocks, default=f"UF2, {blocks} blocks")}

    if data[0] == _ESP_IMAGE_MAGIC and len(data) >= 4:
        # Byte 1 of a real image is the segment count (0..16); anything else
        # means the 0xE9 was a coincidence.
        segments = data[1]
        chip = _ESP_CHIP_IDS.get(data[3]) if len(data) > 3 else None
        if segments <= 16:
            return {"kind": "esp", "segments": segments, "chip": chip,
                    "detail": t("fw_esp", n=segments,
                                default=f"ESP image, {segments} segments")}

    if data[:2] == b"PK":
        return {"kind": "zip", "detail": t("fw_zip", default="ZIP archive - extract first")}
    if data[:2] == b"\x1f\x8b":
        return {"kind": "gzip", "detail": t("fw_gzip", default="gzip - decompress first")}
    if data[:6] in (b"<!DOCT", b"<html>", b"<?xml "):
        return {"kind": "html", "detail": t("fw_html", default="this is a web page, not firmware")}

    return {"kind": "unknown", "detail": t("fw_unknown", default="unrecognised format")}


def uf2_is_valid(data: bytes) -> bool:
    """True if every 512-byte block of this UF2 starts and ends correctly."""
    if len(data) < UF2_BLOCK or len(data) % UF2_BLOCK:
        return False
    for off in range(0, len(data), UF2_BLOCK):
        blk = data[off:off + UF2_BLOCK]
        m0, m1 = struct.unpack_from("<II", blk, 0)
        end, = struct.unpack_from("<I", blk, UF2_BLOCK - 4)
        if m0 != UF2_MAGIC_START0 or m1 != UF2_MAGIC_START1 or end != UF2_MAGIC_END:
            return False
    return True


def _uf2_block_count(data: bytes) -> int:
    if len(data) < UF2_BLOCK:
        return 0
    return len(data) // UF2_BLOCK


def uf2_target_family(data: bytes) -> str:
    """Which chip family a UF2 is built for, from the block flags."""
    if len(data) < UF2_BLOCK:
        return "unknown"
    flags, = struct.unpack_from("<I", data, 8)
    # bit 0 = "not main flash"; family IDs live in the upper bits
    fam = (flags >> 24) & 0xFF
    return {0x00: "unknown", 0x0A: "RP2040", 0x21: "RP2350"}.get(fam, hex(fam))


# ---------------------------------------------------------------------------
# Bootloader device detection
# ---------------------------------------------------------------------------

USB_CLASS_MASS_STORAGE = 0x08
USB_CLASS_CDC_DATA = 0x0A


def classify_bootloader(device) -> str | None:
    """Return 'uf2', 'esp32' or None for a device that is in bootloader mode.

    Detection is deliberately based on interface class, not VID/PID: boards in
    ROM mode show the silicon vendor's ID, and clone boards vary wildly.
    """
    try:
        if device.interfaces_of_class(USB_CLASS_MASS_STORAGE):
            return "uf2"
        if device.interfaces_of_class(USB_CLASS_CDC_DATA):
            return "esp32"
    except Exception:
        return None
    return None


# ---------------------------------------------------------------------------
# ESP32: SLIP framing + ROM serial loader
# ---------------------------------------------------------------------------

SLIP_END = 0xC0
SLIP_ESC = 0xDB
SLIP_ESC_END = 0xDC
SLIP_ESC_ESC = 0xDD

# ROM command opcodes
OP_FLASH_BEGIN = 0x02
OP_FLASH_DATA = 0x03
OP_FLASH_END = 0x04
OP_MEM_BEGIN = 0x05
OP_MEM_END = 0x06
OP_MEM_DATA = 0x07
OP_SYNC = 0x08
OP_READ_REG = 0x09
OP_WRITE_REG = 0x0A
OP_SPI_ATTACH = 0x0D
OP_CHANGE_BAUDRATE = 0x0F
OP_SPI_FLASH_MD5 = 0x13
# Erase commands live in the 0xD0 block, not next to the flash ones.
OP_ERASE_FLASH = 0xD0
OP_ERASE_REGION = 0xD1

CHECKSUM_MAGIC = 0xEF


def slip_encode(data: bytes) -> bytes:
    out = bytearray([SLIP_END])
    for b in data:
        if b == SLIP_END:
            out += bytes([SLIP_ESC, SLIP_ESC_END])
        elif b == SLIP_ESC:
            out += bytes([SLIP_ESC, SLIP_ESC_ESC])
        else:
            out.append(b)
    out.append(SLIP_END)
    return bytes(out)


def slip_decode(buf: bytearray):
    """Pull the first complete SLIP frame out of `buf`.

    Returns (payload, consumed_bytes) or (None, 0) when the frame is
    incomplete. Leading garbage before the first 0xC0 is dropped rather than
    treated as an error, because a freshly opened port can hold stale bytes.
    """
    start = buf.find(bytes([SLIP_END]))
    if start < 0:
        return None, 0
    i = start + 1
    out = bytearray()
    while i < len(buf):
        b = buf[i]
        if b == SLIP_END:
            return bytes(out), i + 1
        if b == SLIP_ESC:
            if i + 1 >= len(buf):
                return None, 0
            nxt = buf[i + 1]
            # Put back the ORIGINAL byte, not the escape token: 0xDB 0xDC
            # means 0xC0 and 0xDB 0xDD means 0xDB. Appending the token itself
            # silently corrupts every escaped byte in the frame.
            if nxt == SLIP_ESC_END:
                out.append(SLIP_END)
            elif nxt == SLIP_ESC_ESC:
                out.append(SLIP_ESC)
            else:
                out.append(nxt)
            i += 2
            continue
        out.append(b)
        i += 1
    return None, 0


def rom_checksum(data: bytes, state: int = CHECKSUM_MAGIC) -> int:
    """The XOR-of-dwords checksum the ROM loader expects."""
    MASK = 0x3FFFFFFF
    state &= MASK
    full = len(data) - (len(data) % 4)
    for i in range(0, full, 4):
        (word,) = struct.unpack_from("<I", data, i)
        state ^= word & MASK
    tail = data[full:]
    if tail:
        (word,) = struct.unpack("<I", tail.ljust(4, b"\x00"))
        state ^= word & MASK
    return state


class EspLoader:
    """esptool ROM serial loader over an Android CDC-ACM bulk interface."""

    def __init__(self, connection, timeout: int = 3000):
        self.conn = connection
        self.timeout = timeout
        self._buf = bytearray()

    # ------------------------------------------------------------ raw I/O

    def _write(self, data: bytes):
        # USB Serial/JTAG has no baud rate to configure, and the bulk endpoint
        # is 64 bytes, so long frames must be split or the transfer stalls.
        ep_size = 64
        for i in range(0, len(data), ep_size):
            self.conn.write(data[i:i + ep_size], timeout=self.timeout)

    def _read_frame(self, timeout: int = None) -> bytes:
        """Read one SLIP frame, buffering whatever the endpoint returns."""
        timeout = timeout or self.timeout
        deadline = _now() + timeout / 1000.0
        while True:
            payload, used = slip_decode(self._buf)
            if payload is not None:
                del self._buf[:used]
                return payload
            chunk = self.conn.read(64, timeout=max(200, int((deadline - _now()) * 1000)))
            if chunk:
                self._buf += chunk
            if _now() > deadline:
                raise FirmwareError(t("fw_esp_timeout", default="no response from the bootloader"))

    # ------------------------------------------------------------ commands

    def sync(self, attempts: int = 5) -> bool:
        """Send SYNC until the ROM answers or we run out of attempts.

        The response is checked properly - direction *and* opcode *and* length.
        It used to accept anything whose first byte was 0x01, which made a
        running firmware look like a ready bootloader: ESP32-S3 keeps printing
        to the same USB Serial/JTAG pipe, so its log output was being read back
        as a ROM reply and the app reported success while the web tool, which
        does a real handshake, correctly said "sync failed". Same board, two
        answers - the difference was who checked.
        """
        payload = struct.pack("<I", 0) + b"\x07\x07\x12\x20" + b"\x55" * 32

        def one_round() -> bool:
            for _ in range(attempts):
                try:
                    self._write(slip_encode(self._packet(OP_SYNC, payload)))
                    resp = self._read_frame(timeout=500)
                    if not resp or len(resp) < 8:
                        continue
                    if resp[0] != 0x01:            # not a response
                        continue
                    if resp[1] != OP_SYNC:         # an answer to something else
                        continue
                    return True
                except Exception:
                    continue
            return False

        # Twice, deliberately. A ROM answers every time; a stray byte sequence
        # in a firmware log that happens to look like one reply will not also
        # look like a second. This is what separates "a real bootloader" from
        # "noise we got lucky with".
        ok = one_round() and one_round()
        if ok:
            # The ESP32-S3 ROM prints a banner ("ESP-ROM:esp32s3-...") on the
            # same USB Serial/JTAG pipe, and sync() deliberately skipped over
            # frames that did not match. Whatever survived is now sitting in
            # the buffer waiting to be read as the answer to the first real
            # command. Throw it away before anything is sent.
            self._clean_pipe(timeout=200)
        return ok

    def drain(self, timeout: int = 150) -> None:
        """Throw away anything the endpoint still holds from an earlier command.

        Only called when a response came back garbled: a stale frame sitting in
        the pipe is the usual reason the next answer does not match the op we
        just sent. A timeout here means nothing is left, which is success.
        """
        deadline = _now() + timeout / 1000.0
        while _now() < deadline:
            try:
                chunk = self.conn.read(64, timeout=max(50, int((deadline - _now()) * 1000)))
            except Exception:
                return
            if not chunk:
                return

    # Commands that must never be sent twice. The mismatch path below retransmits
    # when a stale frame shows up, which is right for a read but destructive for
    # these: a second ERASE_FLASH while the first is still running, or a repeated
    # FLASH_DATA block, is exactly the kind of thing that leaves the board in a
    # state nobody asked for.
    NON_IDEMPOTENT_OPS = frozenset((OP_ERASE_FLASH, OP_ERASE_REGION,
                                    OP_FLASH_BEGIN, OP_FLASH_DATA, OP_FLASH_END))

    def _clean_pipe(self, timeout: int = 150) -> None:
        """Drop everything the endpoint still holds from an earlier command.

        Both the buffer we have already read and whatever is still queued in the
        device. Clearing only one of the two leaves the other to turn up as the
        answer to the next command, which is what "got op 0D, wanted D0" is:
        SPI_ATTACH timed out, we carried on, and its reply arrived late and was
        read as the erase's answer.

        Every caller used to do this by hand, and erase_flash() had it while
        flash() did not - the inconsistency that made flashing fail with an
        error that only made sense for erasing.
        """
        self._buf = bytearray()
        self.drain(timeout=timeout)

    def command(self, op: int, data: bytes = b"", checksum: int = 0,
                timeout: int = None, _retry: bool = True) -> tuple:
        """Send one command and return (value, body)."""
        if op in self.NON_IDEMPOTENT_OPS:
            # These cannot be resent, so a stale frame arriving late is not a
            # retry opportunity - it is a failed command. Clear before sending
            # rather than after discovering the mismatch.
            self._clean_pipe()
        self._write(slip_encode(self._packet(op, data, checksum)))
        try:
            resp = self._await_op(op, timeout) if op in self.NON_IDEMPOTENT_OPS \
                else self._read_frame(timeout=timeout)
        except FirmwareError:
            # A timeout is not proof the command never ran - only that its reply
            # had not arrived yet. For an idempotent command, asking again costs
            # nothing and it consumes that late reply, instead of leaving it to
            # be read as the answer to the next command. That is precisely how
            # SPI_ATTACH's overdue reply ended up answering an ERASE_FLASH.
            if _retry and op not in self.NON_IDEMPOTENT_OPS:
                self._clean_pipe()
                return self.command(op, data, checksum, timeout, _retry=False)
            raise
        if len(resp) < 8:
            raise FirmwareError(t("fw_esp_short", default="truncated response"))
        direction, r_op = resp[0], resp[1]
        size = struct.unpack_from("<H", resp, 2)[0]
        (value,) = struct.unpack_from("<I", resp, 4)
        if direction != 0x01 or r_op != op:
            # A late reply from the previous command. Retrying is only safe for
            # commands where a second send does the same thing as the first; for
            # the rest we drop the stale frame and fail, because resending an
            # erase or a flash block does something extra rather than the same
            # thing again.
            self._buf = bytearray()
            self.drain()
            if _retry and op not in self.NON_IDEMPOTENT_OPS:
                return self.command(op, data, checksum, timeout, _retry=False)
            # Saying "retried and still wrong" would be a lie for a command we
            # deliberately refused to resend, and it is the difference between
            # "the board is confused" and "we stopped before doing it twice".
            key = ("fw_esp_mismatch_stale" if op in self.NON_IDEMPOTENT_OPS
                   else "fw_esp_mismatch_retried")
            raise FirmwareError(t(key, got=f"{r_op:02X}", want=f"{op:02X}",
                                  default=f"unexpected response (got op {r_op:#02x}, "
                                          f"wanted {op:#02x})"))
        body = resp[8:8 + size]
        status = resp[8 + size] if len(resp) > 8 + size else 0
        if status:
            raise FirmwareError(t("fw_esp_status", code=status,
                                  default=f"bootloader returned status {status}"))
        return value, body

    def _await_op(self, op: int, timeout: int = None,
                  max_stale: int = 4) -> bytes:
        """Read frames until one belongs to `op`, dropping overdue ones.

        A command that was already sent cannot be unsent. While an erase runs
        the ROM is busy for tens of seconds, and whatever reply was still in
        flight from the previous command arrives first - reading it used to end
        the operation right there, with the board erasing anyway and the app
        reporting failure. For a command that must not go out twice, dropping
        those frames and carrying on is the only correct answer.
        """
        stale = 0
        while True:
            resp = self._read_frame(timeout=timeout)
            if len(resp) >= 8 and resp[0] == 0x01 and resp[1] == op:
                return resp
            stale += 1
            if stale > max_stale:
                return resp

    @staticmethod
    def _packet(op: int, data: bytes, checksum: int = None) -> bytes:
        if checksum is None:
            checksum = rom_checksum(data)
        return struct.pack("<BBHI", 0x00, op, len(data), checksum) + data

    # ------------------------------------------------------------ flashing

    def flash(self, image: bytes, offset: int = 0,
              progress=None, block_size: int = 0x4000) -> None:
        """Write a raw ESP image to flash using the ROM's own commands.

        No flasher stub is uploaded: the ROM's FLASH_BEGIN/DATA/END commands
        are enough for a plain write, which keeps this independent of any
        binary blob we would otherwise have to ship.
        """
        total = len(image)
        blocks = (total + block_size - 1) // block_size

        # Attach to the SPI flash before touching it.
        try:
            self.command(OP_SPI_ATTACH, struct.pack("<I", 0), timeout=4000)
        except FirmwareError:
            # Some ROMs answer with a non-zero status here but are still ready.
            # What must not survive is a reply that never arrived: it turns up
            # later and gets read as the answer to FLASH_BEGIN, which then
            # fails with an error naming the wrong operation.
            self._clean_pipe()

        self.command(OP_FLASH_BEGIN,
                     struct.pack("<IIII", total, blocks, block_size, offset),
                     timeout=20000)

        seq = 0
        for i in range(blocks):
            chunk = image[i * block_size:(i + 1) * block_size]
            padded = chunk + b"\xff" * (block_size - len(chunk))
            self.command(OP_FLASH_DATA,
                         struct.pack("<II", len(padded), seq) + padded,
                         timeout=8000)
            seq += 1
            if progress:
                progress(i + 1, blocks)

        self.command(OP_FLASH_END, struct.pack("<I", 1), timeout=4000)

    def erase_flash(self, timeout: int = 90000) -> None:
        """Erase the whole flash chip.

        This is the recovery step for a board whose firmware will not start:
        re-flashing alone leaves whatever bad configuration was already there,
        so the board comes back up in exactly the same broken state. Erasing
        first is what actually clears it.

        The ROM holds the line while it works, so the timeout has to be long -
        90s is generous for a 16MB chip and still bounded, which matters
        because a command that never answers would otherwise hang the worker
        thread forever.
        """
        try:
            self.command(OP_SPI_ATTACH, struct.pack("<I", 0), timeout=4000)
        except FirmwareError:
            # Some ROMs answer with a non-zero status here but are still ready.
            # What must NOT be carried over is a reply that never arrived: it
            # turns up later and gets read as the answer to the erase, which is
            # how "got op 0D, wanted D0" happens. Clear the pipe before sending
            # a command that cannot be sent twice.
            self._clean_pipe()
        self.command(OP_ERASE_FLASH, b"", timeout=timeout)

    def erase_region(self, offset: int, size: int, timeout: int = 60000) -> None:
        """Erase [offset, offset+size)."""
        try:
            self.command(OP_SPI_ATTACH, struct.pack("<I", 0), timeout=4000)
        except FirmwareError:
            self._buf = bytearray()
            self.drain()
        self.command(OP_ERASE_REGION, struct.pack("<II", size, offset),
                     timeout=timeout)


def _now():
    import time
    return time.time()


# ---------------------------------------------------------------------------
# High level entry point
# ---------------------------------------------------------------------------

def verify_download_mode(device) -> bool:
    """Open the CDC interface and actually shake hands with the ROM.

    classify_bootloader() only looks at whether a CDC data interface exists,
    and an ESP32-S3 exposes one whether or not its firmware is running - so a
    perfectly healthy board gets listed as "in download mode". This opens the
    interface and syncs for real, which is the only question that matters.
    """
    intfs = device.interfaces_of_class(USB_CLASS_CDC_DATA)
    if not intfs:
        return False
    conn = None
    try:
        conn = usbhost.Connection(device, intfs[0], force=True)
        return EspLoader(conn).sync()
    except Exception:
        return False
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def erase_esp32(device, region: tuple = None) -> None:
    """Erase an ESP32 in download mode - the whole chip by default.

    `region` is an optional (offset, size) pair for a partial erase.

    The ROM download mode lives in mask ROM and cannot be bricked, so this is
    always safe to attempt; it just destroys the contents, which is the point.
    """
    intfs = device.interfaces_of_class(USB_CLASS_CDC_DATA)
    if not intfs:
        raise FirmwareError(t("fw_no_cdc", default="no serial interface found"))
    conn = usbhost.Connection(device, intfs[0], force=True)
    try:
        loader = EspLoader(conn)
        if not loader.sync():
            raise FirmwareError(t("fw_esp_nosync",
                                  default="bootloader did not answer - is the board in download mode?"))
        if region:
            loader.erase_region(region[0], region[1])
        else:
            loader.erase_flash()
    finally:
        try:
            conn.close()
        except Exception:
            pass


def flash_esp32(device, image: bytes, progress=None, erase_first=False):
    """Open the CDC data interface of an ESP32 in download mode and flash it.

    `erase_first` wipes the whole chip before writing. It has to happen on the
    same connection as the write: erasing through a second connection leaves the
    ROM free to answer late, and the erase reply is then read as the first
    flash command's - the "got op 0D, wanted D0" failure.
    """
    intfs = device.interfaces_of_class(USB_CLASS_CDC_DATA)
    if not intfs:
        raise FirmwareError(t("fw_no_cdc", default="no serial interface found"))
    conn = usbhost.Connection(device, intfs[0], force=True)
    try:
        loader = EspLoader(conn)
        if not loader.sync():
            raise FirmwareError(t("fw_esp_nosync",
                                  default="bootloader did not answer - is the board in download mode?"))
        if erase_first:
            loader.erase_flash()
        loader.flash(image, progress=progress)
    finally:
        try:
            conn.close()
        except Exception:
            pass


APP_OFFSET = 0x10000
ESP_MAGIC = 0xE9


def is_merged_image(data: bytes) -> bool:
    """True when this is a whole-flash image, not just the application.

    Upstream ships a single .bin for the ESP32. There is no filename to tell
    whether it is the app alone (which belongs at 0x10000) or everything merged
    into one (which belongs at 0x0) - and writing either to the wrong address
    produces a board that flashes "successfully" and then never starts.

    The merged form is unambiguous though: esptool's merge_bin pads the gap up
    to the app partition with 0xFF, so a real application image header sits at
    0x10000 inside the file. An app-only image is not that long, and its own
    header is at 0x0.
    """
    if not data or len(data) <= APP_OFFSET:
        return False
    return data[APP_OFFSET] == ESP_MAGIC


def guess_offset(name: str, data: bytes = None) -> int:
    """Pick a plausible flash offset from a firmware file name.

    An ESP32-S3 boots from three separate images, and getting the offsets wrong
    is the single most common reason a freshly flashed board stays dark: the app
    image written at 0x0 is loaded as if it were a bootloader, so nothing ever
    runs and - because the LED is driven by firmware - no LED ever lights up
    either. Guessing here means the common case needs no typing at all.
    """
    # A whole-flash image wins over the file name: it goes at 0x0 whatever it
    # is called, and the name frequently says nothing useful anyway.
    if data and is_merged_image(data):
        return 0x0
    low = (name or "").lower()
    if "bootloader" in low:
        return 0x0
    if "partition" in low:
        return 0x8000
    if low.endswith(".uf2"):
        return 0x0            # UF2 is self-describing; offset is not used
    return 0x10000            # the application image


def flash_esp32_multi(device, entries, progress=None, erase_first=False):
    """Write several images at their own offsets, over one connection.

    `entries` is a list of (offset, image, name). Opening the interface once
    matters: re-syncing between files gives the ROM a chance to answer late and
    leaves the previous command's reply to be read as the next one's - the
    "got op 0D, wanted D0" failure.

    `progress` is called with (file_index, file_count, blocks_done, blocks_total).
    """
    intfs = device.interfaces_of_class(USB_CLASS_CDC_DATA)
    if not intfs:
        raise FirmwareError(t("fw_no_cdc", default="no serial interface found"))
    conn = usbhost.Connection(device, intfs[0], force=True)
    try:
        loader = EspLoader(conn)
        if not loader.sync():
            raise FirmwareError(t("fw_esp_nosync",
                                  default="bootloader did not answer - is the board in download mode?"))
        if erase_first:
            loader.erase_flash()
        total = len(entries)
        for idx, (offset, image, name) in enumerate(entries, start=1):
            def _sub(done, blocks, _i=idx, _n=name):
                if progress:
                    progress(_i, total, done, blocks)
            loader.flash(image, offset=offset, progress=_sub)
    finally:
        try:
            conn.close()
        except Exception:
            pass


def save_via_saf(filename: str, mime: str = "application/octet-stream") -> bool:
    """Hand a UF2 to the system file manager so the user can drop it on the
    RPI-RP2 / RP2350 drive.

    Returns True if the picker was launched. This is the RP2040/RP2350 path:
    the mass-storage Boot ROM does the real work once the file lands.
    """
    try:
        from jnius import autoclass
        from android import activity

        Intent = autoclass("android.content.Intent")
        act = activity._activity if hasattr(activity, "_activity") else None
        if act is None:
            act = autoclass("org.kivy.android.PythonActivity").mActivity

        intent = Intent(Intent.ACTION_CREATE_DOCUMENT)
        intent.addCategory(Intent.CATEGORY_OPENABLE)
        intent.setType(mime)
        intent.putExtra(Intent.EXTRA_TITLE, filename)
        act.startActivity(intent)
        return True
    except Exception as exc:
        raise FirmwareError(t("fw_saf_failed", err=str(exc),
                              default=f"could not open the file picker: {exc}"))
