"""
/*
 * This file is part of the pypicokey distribution (https://github.com/polhenarejos/pypicokey).
 * Copyright (c) 2025 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * ---------------------------------------------------------------------------
 * Android port notes (picokey-android):
 *   - removed every pyscard (PC/SC) and pyusb (libusb) dependency: Android has
 *     neither pcscd nor raw libusb access, so the transport is injected from
 *     outside (picokeyapp.ccid / picokeyapp.ctap build it on top of the
 *     Android USB Host API).
 *   - removed CardMonitor / RescueMonitor: hot-plug is handled by polling in
 *     the UI layer, which keeps the app alive when the device goes away.
 *   - the APDU level logic (send/resend/0x61 chaining/secure channel wrapping)
 *     is unchanged from upstream.
 */
"""

from typing import Optional
from .APDU import APDUResponse
from .PhyData import PhyData
from .core.exceptions import PicoKeyNotFoundError, PicoKeyInvalidStateError
from .core.log import get_logger

logger = get_logger("PicoKey")

try:                                    # optional: only needed for DKEK / secure channel
    from .SecureChannel import SecureChannel
except Exception:                       # pragma: no cover - pycvc/cryptography absent
    SecureChannel = None


class Platform:
    """Kept as plain ints so the enum never breaks on stripped-down builds."""
    RP2040 = 0
    RP2350 = 1
    ESP32 = 2
    EMULATION = 3

    NAMES = {0: 'RP2040', 1: 'RP2350', 2: 'ESP32', 3: 'EMULATION'}

    @classmethod
    def name_of(cls, value: int) -> str:
        return cls.NAMES.get(value, f'UNKNOWN({value})')


class Product:
    UNKNOWN = 0
    HSM = 1
    FIDO = 2
    OPENPGP = 3

    NAMES = {0: 'UNKNOWN', 1: 'HSM', 2: 'FIDO', 3: 'OpenPGP'}

    @classmethod
    def name_of(cls, value: int) -> str:
        return cls.NAMES.get(value, f'UNKNOWN({value})')


class ConnectionType:
    UNKNOWN = 0
    SMARTCARD = 1
    RESCUE = 2
    HID = 3

    NAMES = {0: 'UNKNOWN', 1: 'SMARTCARD/CCID', 2: 'RESCUE', 3: 'HID/FIDO'}

    @classmethod
    def name_of(cls, value: int) -> str:
        return cls.NAMES.get(value, f'UNKNOWN({value})')


class PicoKey:
    """High level PicoKey command set on top of an arbitrary APDU transport.

    `card` must expose:
        transmit(apdu: list[int]) -> (response: list[int], sw1: int, sw2: int)
        reconnect()               -> self
        close()                   -> None
    """

    def __init__(self, card, connection_type: int = ConnectionType.UNKNOWN):
        if card is None:
            raise PicoKeyNotFoundError('No PicoKey transport given')
        if connection_type in (None, ConnectionType.UNKNOWN):
            # let the transport tell us which pipe we are on
            connection_type = getattr(card, "connection_type", ConnectionType.UNKNOWN)
        logger.debug("Initializing PicoKey...")
        self.__card = card
        self.__apdu = []
        self.__connection_type = connection_type
        self.__sc = None
        self.platform = 0
        self.product = 0
        self.version = (0, 0)

        try:
            resp, sw1, sw2 = self.select_applet()
            logger.debug(f"Applet selected with response code: 0x{sw1:02X}{sw2:02X}")
            if (sw1 == 0x90 and sw2 == 0x00):
                self.platform = resp[0]
                self.product = resp[1]
                self.version = (resp[2], resp[3])
        except Exception:
            logger.error("APDU response error during applet selection")
            self.platform = Platform.RP2040
            self.product = Product.UNKNOWN
            self.version = (0, 0)

    # ------------------------------------------------------------------ info

    @property
    def device(self):
        return self.__card

    def has_device(self) -> bool:
        return self.__card is not None

    @property
    def connection_type(self) -> int:
        return self.__connection_type

    def summary(self) -> dict:
        return {
            'platform': Platform.name_of(self.platform),
            'product': Product.name_of(self.product),
            'version': f'{self.version[0]}.{self.version[1]}',
            'connection': ConnectionType.name_of(self.__connection_type),
        }

    # ------------------------------------------------------------ lifecycle

    def close(self):
        if not self.__card:
            return
        try:
            self.__card.close()
        except Exception as e:
            logger.error("Error while closing: " + str(e))
        self.__card = None

    def reconnect(self):
        if not self.__card:
            raise PicoKeyNotFoundError('No device connected')
        self.__card = self.__card.reconnect()
        return self.__card

    # --------------------------------------------------------------- APDUs

    def transmit(self, apdu: list):
        if not self.__card:
            raise PicoKeyNotFoundError('No device connected')
        try:
            return self.__card.transmit(apdu)
        except Exception as e:
            raise PicoKeyInvalidStateError("Transmission error: " + str(e))

    def send(self, command, cla: int = 0x00, p1: int = 0x00, p2: int = 0x00,
             ne: Optional[int] = None, data=None, codes: list = []):
        if not self.__card:
            raise PicoKeyNotFoundError('No device connected')

        data = list(data) if data else []
        if data:
            lc = [0x00] + list(len(data).to_bytes(2, 'big'))
        else:
            lc = [0x00]                      # upstream used [0x00*3]; keep 1 byte Lc=0
        le = [0x00, 0x00] if ne is None else list(ne.to_bytes(2, 'big'))

        if isinstance(command, (list, tuple)) and len(command) > 1:
            apdu = list(command)
        else:
            apdu = [cla, command]
        apdu = apdu + [p1, p2] + lc + data + le
        self.__apdu = apdu
        logger.trace(f"APDU -> {' '.join([f'{x:02X}' for x in apdu])}")

        if self.__sc:
            apdu = self.__sc.wrap_apdu(apdu)

        try:
            response, sw1, sw2 = self.__card.transmit(apdu)
        except Exception:
            logger.debug("Reconnecting card after transmit failure")
            try:
                self.__card = self.__card.reconnect()
            except Exception as e:
                self.close()
                raise PicoKeyNotFoundError('Reconnection failed: ' + str(e))
            try:
                response, sw1, sw2 = self.__card.transmit(apdu)
            except Exception as e:
                raise PicoKeyInvalidStateError("APDU transmission error after reconnect: " + str(e))

        code = (sw1 << 8 | sw2)
        if sw1 != 0x90:
            if sw1 == 0x61:                  # T=0 style GET RESPONSE chaining
                response = list(response)
                while sw1 == 0x61:
                    rapdu = [0x00, 0xC0, 0x00, 0x00, sw2]
                    if self.__sc:
                        rapdu = self.__sc.wrap_apdu(rapdu)
                    resp, sw1, sw2 = self.__card.transmit(rapdu)
                    if self.__sc:
                        resp, _ = self.__sc.unwrap_rapdu(resp)
                    response += list(resp)
                code = (sw1 << 8 | sw2)
            if code not in codes and code != 0x9000:
                raise APDUResponse(sw1, sw2)

        logger.trace(f"Response APDU <- {' '.join([f'{x:02X}' for x in response])}"
                     f", SW1={sw1:02X}, SW2={sw2:02X}")

        if self.__sc:
            response, code = self.__sc.unwrap_rapdu(response)
            if code not in codes and code != 0x9000:
                raise APDUResponse(code >> 8, code & 0xFF)
        return bytes(response), code

    def resend(self):
        apdu = self.__apdu
        if self.__sc:
            apdu = self.__sc.wrap_apdu(apdu)
        response, sw1, sw2 = self.__card.transmit(apdu)
        return bytes(response), sw1, sw2

    def open_secure_channel(self, shared: bytes, nonce: bytes, token: bytes, pbkeyBytes: bytes):
        if SecureChannel is None:
            raise PicoKeyInvalidStateError('SecureChannel unavailable (pycvc/cryptography missing)')
        sc = SecureChannel(shared=shared, nonce=nonce)
        if not sc.verify_token(token, pbkeyBytes):
            raise Exception('Secure Channel token verification failed')
        self.__sc = sc

    def select_applet(self):
        return self.transmit([0x00, 0xA4, 0x04, 0x04, 0x08,
                              0xA0, 0x58, 0x3F, 0xC1, 0x9B, 0x7E, 0x4F, 0x21, 0x00])

    # ------------------------------------------------------------ commands

    def phy(self, data=None):
        if data is None:
            try:
                self.select_applet()
                resp, sw = self.send(0x1E, cla=0x80, p1=0x01, ne=256)
                return PhyData.parse(resp)
            except Exception:
                return None
        else:
            self.select_applet()
            self.send(0x1C, cla=0x80, p1=0x01, data=data)
            return None

    def flash_info(self):
        free = used = total = nfiles = size = 0
        try:
            self.select_applet()
            resp, sw = self.send(0x1E, cla=0x80, p1=0x02, ne=256)
            if len(resp) >= 20:
                free = int.from_bytes(resp[0:4], 'big')
                used = int.from_bytes(resp[4:8], 'big')
                total = int.from_bytes(resp[8:12], 'big')
                nfiles = int.from_bytes(resp[12:16], 'big')
                size = int.from_bytes(resp[16:20], 'big')
        except Exception as e:
            logger.error("flash_info failed: " + str(e))
        return {'free': free, 'used': used, 'total': total, 'nfiles': nfiles, 'size': size}

    def secure_info(self):
        """Read the secure-boot state, or None if the device cannot report it.

        Indexing resp[0..2] unconditionally raised IndexError whenever the
        device answered with an error status (0x6A86 "wrong P1/P2" is what an
        ESP32-S3 without the OTP feature returns) and an empty body. That
        surfaced as a traceback instead of "this board does not support it",
        which is both untrue to the actual cause and alarming next to a
        feature that burns fuses.
        """
        try:
            self.select_applet()
            resp, sw = self.send(0x1E, cla=0x80, p1=0x03, ne=256)
        except Exception as e:
            logger.error("secure_info failed: " + str(e))
            return None
        if sw != 0x9000:
            logger.error("secure_info: device answered SW=%04X" % sw)
            return None
        if len(resp) < 3:
            logger.error("secure_info: short response (%d bytes)" % len(resp))
            return None
        return {
            'enabled': resp[0] != 0,
            'locked': resp[1] != 0,
            'boot_key': resp[2],
        }

    def secure_boot(self, bootkey_index: int = 0, lock: bool = False):
        self.select_applet()
        data = [bootkey_index & 0xFF, 1 if lock else 0]
        self.send(0x1C, cla=0x80, p1=0x02, data=data)

    def reboot(self, bootsel: bool = False):
        self.select_applet()
        self.send(0x1F, cla=0x80, p1=0x01 if bootsel else 0x00)
