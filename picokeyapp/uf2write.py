"""
Write a UF2 straight onto an RP2040 / RP2350 board in BOOTSEL mode.

Why this module exists
----------------------
The normal RP2040/RP2350 ritual is: the board appears as a tiny USB drive,
drag a .uf2 onto it, the drive vanishes, the board reboots. That depends on
the *host* being able to mount the drive. A phone often cannot:

  * the boot ROM's drive is a synthetic FAT volume - it only accepts UF2
    blocks and answers very few SCSI commands, so some kernels refuse it;
  * scoped storage hides the mount from apps even when the kernel accepted it;
  * some phones simply never mount USB mass storage over OTG.

Talking USB Mass Storage ourselves removes the kernel and the file manager
from the picture entirely: claim the interface and speak Bulk-Only Transport
(BOT) directly. No mount, no filesystem, no storage permission.

Protocol in one page
--------------------
Every SCSI command travels inside a 31 byte Command Block Wrapper, and the
device answers with a 13 byte Command Status Wrapper:

    CBW  'USBC' | tag | data length | flags | lun | cdb length | cdb[16]
    CSW  'USBS' | tag | residue     | status

Only three commands are needed: TEST UNIT READY (0x00), READ CAPACITY(10)
(0x25) and WRITE(10) (0x2A).

Two quirks of these boot ROMs that are easy to get wrong
--------------------------------------------------------
1. The ROM ignores the LBA and simply consumes UF2 blocks in the order they
   arrive, so blocks must be written sequentially from LBA 0. Sending one
   512 byte block per WRITE(10) is the most widely accepted shape and costs
   nothing measurable, so that is what this module does.

2. After the final block the ROM reboots the board immediately - the USB
   device disappears before the last CSW can be read. A missing CSW on the
   *last* block therefore means success, not failure, and has to be reported
   as such instead of being turned into an error.
"""

from __future__ import annotations

import os
import struct
import time

from .i18n import t
from .pk.core.log import get_logger

logger = get_logger("uf2write")

UF2_BLOCK = 512

# Bulk-Only Transport signatures
CBW_SIGNATURE = 0x43425355        # "USBC"
CSW_SIGNATURE = 0x53425355        # "USBS"

CBW_SIZE = 31
CSW_SIZE = 13

# SCSI opcodes
SCSI_TEST_UNIT_READY = 0x00
SCSI_READ_CAPACITY_10 = 0x25
SCSI_WRITE_10 = 0x2A

CSW_GOOD = 0x00

# The boot ROM keeps INFO_UF2.TXT / INDEX.HTM on its drive; finding that file
# is the reliable way to tell "this is a BOOTSEL drive" from any other FAT
# volume that happens to be plugged in.
BOOTSEL_MARKER = "INFO_UF2.TXT"


class UF2Error(Exception):
    """Raised when the UF2 could not be handed to the board."""


# ---------------------------------------------------------------------------
# Bulk-Only Transport
# ---------------------------------------------------------------------------

class BulkOnlyTransport:
    """Minimal USB Mass Storage BOT on top of an already claimed interface.

    `conn` is a `picokeyapp.usbhost.Connection`. Keeping BOT separate from the
    USB host layer matters: the transport is plain bytes, so it can be driven
    by a fake connection in the test suite with no Java anywhere near it.
    """

    def __init__(self, conn, lun: int = 0, timeout: int = 5000):
        self.conn = conn
        self.lun = lun
        self.timeout = timeout
        self._tag = 1

    # ------------------------------------------------------------------ CBW

    def _cbw(self, cdb: bytes, data_length: int, direction_in: bool) -> bytes:
        tag = self._tag
        self._tag = (self._tag + 1) & 0xFFFFFFFF
        head = struct.pack("<IIIBBB", CBW_SIGNATURE, tag, data_length,
                           0x80 if direction_in else 0x00, self.lun, len(cdb))
        cdb = bytes(cdb)[:16]
        return head + cdb + b"\x00" * (16 - len(cdb))

    def _next_tag(self) -> int:
        return (self._tag - 1) & 0xFFFFFFFF

    # ------------------------------------------------------------------ CSW

    def _read_csw(self, expected_tag: int) -> tuple[int, int]:
        """Read and validate one CSW. Returns (status, residue)."""
        data = self.conn.read(CSW_SIZE, timeout=self.timeout)
        if len(data) < CSW_SIZE:
            raise UF2Error(t("uf2_csw_short", n=len(data),
                             default=f"short CSW: {len(data)} bytes"))
        sig, tag, residue, status = struct.unpack_from("<IIIB", data, 0)
        if sig != CSW_SIGNATURE:
            raise UF2Error(t("uf2_csw_bad", default="CSW signature wrong"))
        if tag != expected_tag:
            # A stale tag means we are reading a reply to something else -
            # the classic symptom of two readers sharing one endpoint.
            raise UF2Error(t("uf2_csw_tag", got=tag, want=expected_tag,
                             default=f"CSW tag mismatch: {tag} != {expected_tag}"))
        return status, residue

    # --------------------------------------------------------------- commands

    def test_unit_ready(self, retries: int = 10, delay: float = 0.2) -> bool:
        """Poll until the drive stops reporting 'not ready'.

        A freshly attached BOOTSEL drive is often busy for a moment; without
        this the first WRITE(10) is the thing that fails, and the error it
        produces says nothing useful.
        """
        last = None
        for _ in range(max(1, retries)):
            try:
                cbw = self._cbw(bytes([SCSI_TEST_UNIT_READY, 0, 0, 0, 0, 0]),
                                0, False)
                self.conn.write(cbw, timeout=self.timeout)
                status, _ = self._read_csw(self._next_tag())
                if status == CSW_GOOD:
                    return True
                last = status
            except Exception as exc:
                last = str(exc)
            time.sleep(delay)
        logger.debug("test unit ready gave up: %s", last)
        return False

    def read_capacity(self) -> tuple[int, int]:
        """(last LBA, block size). Best effort - boot ROMs may refuse."""
        cbw = self._cbw(bytes([SCSI_READ_CAPACITY_10, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                        8, True)
        self.conn.write(cbw, timeout=self.timeout)
        data = self.conn.read(8, timeout=self.timeout)
        self._read_csw(self._next_tag())
        last_lba, block_len = struct.unpack(">II", data[:8])
        return last_lba, block_len

    def write_blocks(self, lba: int, payload: bytes) -> None:
        """WRITE(10) starting at `lba`. `payload` must be a block multiple."""
        if len(payload) % UF2_BLOCK:
            raise UF2Error(t("uf2_not_aligned", default="payload is not a "
                                                        "whole number of blocks"))
        count = len(payload) // UF2_BLOCK
        if count > 0xFFFF:
            count = 0xFFFF
            payload = payload[:count * UF2_BLOCK]
        cdb = bytes([SCSI_WRITE_10, 0x00]) + struct.pack(">I", lba) + \
              bytes([0x00]) + struct.pack(">H", count) + bytes([0x00])
        self.conn.write(self._cbw(cdb, len(payload), False), timeout=self.timeout)
        self.conn.write(payload, timeout=self.timeout)
        status, _ = self._read_csw(self._next_tag())
        if status != CSW_GOOD:
            raise UF2Error(t("uf2_write_status", status=status,
                             default=f"WRITE(10) status 0x{status:02X}"))


# ---------------------------------------------------------------------------
# The actual UF2 download
# ---------------------------------------------------------------------------

def write_uf2(conn, data: bytes, progress=None, timeout: int = 5000) -> dict:
    """Push a complete UF2 image to a BOOTSEL drive over BOT.

    Returns a small dict describing what happened, so the caller can log it
    honestly - in particular whether the final CSW arrived, which is the one
    piece of information that distinguishes "written" from "written, and the
    board already rebooted".
    """
    if not data or len(data) % UF2_BLOCK:
        raise UF2Error(t("uf2_not_aligned", default="UF2 is not a whole "
                                                   "number of 512 byte blocks"))
    total = len(data) // UF2_BLOCK
    bot = BulkOnlyTransport(conn, timeout=timeout)

    ready = bot.test_unit_ready()
    if not ready:
        # Not fatal on its own: some boot ROMs never answer this command but
        # accept writes anyway. Log it and carry on so the real error, if
        # there is one, comes from the write itself.
        logger.debug("drive never reported ready; continuing anyway")

    capacity = None
    try:
        capacity = bot.read_capacity()
        logger.debug("read capacity: last lba=%d block=%d", *capacity)
    except Exception as exc:
        logger.debug("read capacity unavailable: %s", exc)

    final_csw = True
    for index in range(total):
        block = data[index * UF2_BLOCK:(index + 1) * UF2_BLOCK]
        last = index == total - 1
        try:
            bot.write_blocks(index, block)
        except Exception as exc:
            if last:
                # The board reboots the instant the last block lands, so the
                # reply to that block legitimately never arrives.
                logger.debug("last block: no CSW (board rebooted): %s", exc)
                final_csw = False
            else:
                raise
        if progress:
            progress(index + 1, total)

    return {"blocks": total, "bytes": len(data),
            "capacity": capacity, "final_csw": final_csw,
            "unit_ready": ready}


# ---------------------------------------------------------------------------
# Fallback: a BOOTSEL drive the phone did manage to mount
# ---------------------------------------------------------------------------

def _candidate_mounts() -> list[str]:
    """Mount points worth probing for a BOOTSEL drive.

    Reading /proc/mounts is the only way to see volumes an app has not been
    granted access to. Scoped storage usually denies reads into these paths,
    which is fine - a probe that fails simply is not a BOOTSEL drive from the
    app's point of view, and the raw BOT path does not need any of it.
    """
    points = []
    try:
        with open("/proc/mounts", "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2:
                    points.append(parts[1])
    except Exception:
        pass
    for root in ("/storage", "/mnt/media_rw", "/mnt/usb_storage"):
        try:
            for name in os.listdir(root):
                points.append(os.path.join(root, name))
        except Exception:
            pass
    seen, out = set(), []
    for p in points:
        if p and p not in seen:
            seen.add(p)
            out.append(p)
    return out


def find_mounted_bootsel() -> str | None:
    """Return the mount point of a mounted BOOTSEL drive, or None.

    The probe looks for INFO_UF2.TXT - a file only these boot ROMs put on
    their drive, so an ordinary USB stick never matches.
    """
    for point in _candidate_mounts():
        try:
            if not os.path.isdir(point):
                continue
            if os.path.isfile(os.path.join(point, BOOTSEL_MARKER)):
                return point
        except Exception:
            continue
    return None


def write_uf2_mounted(mount: str, data: bytes,
                      filename: str = "firmware.uf2") -> str:
    """Copy a UF2 onto an already mounted BOOTSEL drive. Returns the path."""
    if not os.path.isdir(mount):
        raise UF2Error(t("uf2_mount_gone", default="the drive disappeared"))
    target = os.path.join(mount, filename)
    with open(target, "wb") as fh:
        fh.write(data)
        try:
            fh.flush()
            os.fsync(fh.fileno())
        except Exception:
            pass
    return target
