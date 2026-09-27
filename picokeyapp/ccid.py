"""
CCID transport over the Android USB Host API.

Upstream pypicokey reaches the device either through PC/SC (pyscard) or, in
"rescue" mode, through pyusb + libusb. Both end up sending CCID bulk frames
(`PC_to_RDR_XfrBlock` / `RDR_to_PC_DataBlock`), so on Android we keep the
upstream ICCD framing (pk.ICCD) and only replace the byte pipe: bulk OUT/IN on
a claimed interface. The very same class serves

  * the CCID interface   (bInterfaceClass = 0x0B)  -> ConnectionType.SMARTCARD
  * the rescue interface (bInterfaceClass = 0xFF)  -> ConnectionType.RESCUE
"""

from __future__ import annotations

from .pk.ICCD import ICCD, Icc_Error_Base, Icc_Error_Power_Off
from .pk.core.log import get_logger

logger = get_logger("ccid")


class CCIDTransport:
    """Object with the same duck-type as upstream's smartcard connection."""

    def __init__(self, connection, label: str = "CCID", auto_power: bool = True,
                 reopener=None, connection_type: int = None):
        self._conn = connection
        self._label = label
        from .pk import ConnectionType
        self.connection_type = (connection_type if connection_type is not None
                                else ConnectionType.SMARTCARD)
        self._reopener = reopener      # callable() -> fresh usbhost.Connection
        self._iccd = ICCD(self)
        self._active = False
        if auto_power:
            try:
                self.power_off()            # start from a clean slot, like upstream
            except Exception as e:
                logger.debug("initial power off failed: " + str(e))

    # ------------------------------------------------------- raw pipe (ICCD)

    def exchange(self, data, timeout: int = 3000) -> bytes:
        """Write one CCID command frame, read back a complete response frame."""
        self._conn.write(bytes(data), timeout=timeout)
        buf = bytearray()
        need = None
        maxpkt = int(self._conn.ep_in.max_packet_size or 64)
        while True:
            chunk = self._conn.read(timeout=timeout)
            if not chunk:
                break
            buf += chunk
            if need is None and len(buf) >= 5:
                need = 10 + int.from_bytes(bytes(buf[1:5]), "little")
            if need is not None and len(buf) >= need:
                break
            if len(chunk) < maxpkt:         # short packet == end of transfer
                break
        if need is not None and len(buf) > need:
            # Anything past the declared frame belongs to an earlier command;
            # keeping it would desync every exchange after this one.
            logger.debug("dropping %d stray byte(s) after the CCID frame",
                         len(buf) - need)
            buf = buf[:need]
        return bytes(buf)

    # ---------------------------------------------------------- card-ish API

    def power_on(self):
        if not self._active:
            self._active = True
            return self._iccd.IccPowerOn()
        return None

    def power_off(self):
        if self._active or self._active is None:
            try:
                self._iccd.IccPowerOff()
            except Icc_Error_Power_Off:
                pass
        self._active = False

    def transmit(self, apdu):
        """APDU in -> (data, sw1, sw2), exactly like pyscard / RescuePicoKey."""
        if not self._active:
            self.power_on()
        try:
            return self._iccd.transmit(list(apdu))
        except Icc_Error_Base as e:
            raise IOError(f"{self._label}: {e}")

    # ---------------------------------------------------------- lifecycle

    def reconnect(self):
        logger.debug("reconnecting CCID transport")
        self.close()
        if self._reopener is None:
            raise IOError("this transport cannot be reopened; rescan the device")
        try:
            self._conn = self._reopener()
        except Exception as e:
            raise IOError(f"reconnect failed: {e}")
        self._iccd = ICCD(self)
        self._active = False
        self.power_on()
        return self

    def close(self):
        try:
            self.power_off()
        except Exception:
            pass
        try:
            self._conn.close()
        except Exception:
            pass

    @property
    def label(self):
        return self._label


def open(connection, label: str = "CCID", reopener=None) -> CCIDTransport:
    return CCIDTransport(connection, label=label, reopener=reopener)
