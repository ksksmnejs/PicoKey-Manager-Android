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
 */
"""

class PC_to_RDR_Base:
    bSlot = 0x00

    def __call__(self, dwLength=0, bSeq=0):
        return bytearray([self.bMessageType]) + bytearray(dwLength.to_bytes(4, 'little')) + bytearray([self.bSlot, bSeq]) + bytearray(self.bReserved)

class Icc_Error_Base(Exception):
    def __init__(self, eCode=None):
        if (eCode):
            self.eCode = eCode
        self.message = f'ICCD Error code: {hex(self.eCode)}'
        super().__init__(self.message)

class Icc_Error_Icc_Mute(Icc_Error_Base):
    eCode = 0xFE

class Icc_Error_Xfr_Overrun(Icc_Error_Base):
    eCode = 0xFC

class Icc_Error_Hw_Error(Icc_Error_Base):
    eCode = 0xFB

class Icc_Error_User_Defined(Icc_Error_Base):
    def __init__(self, eCode):
        assert(eCode >= 0x81 and eCode <= 0xC0)
        super().__init__(eCode)

class Icc_Error_Not_Used(Icc_Error_Base):
    def __init__(self, eCode):
        assert(eCode in [0xFD, 0xF0, 0xEF, 0xE0, *list(range(0xF2,0xF9))])
        super().__init__(eCode)

class Icc_Error_Reserved(Icc_Error_Base):
    def __init__(self, eCode):
        super().__init__(eCode)

class Icc_Error_Time_Extension(Icc_Error_Base):
    eCode = 0 # Not an error really

class Icc_Error_Power_Off(Icc_Error_Base):
    def __init__(self, bmIccStatus):
        super().__init__(bmIccStatus)

# Every RDR_to_PC frame (DataBlock, SlotStatus, ...) begins with this header:
# bMessageType, dwLength(4), bSlot, bSeq, bStatus, bError, bReserved.
RDR_HEADER_SIZE = 10


class Icc_Error_Short_Frame(Icc_Error_Base):
    """The device answered with fewer bytes than a CCID response needs.

    Without this guard the slice assignment `bStatus, bError = msg[7:9]` raises
    a bare "not enough values to unpack", which says nothing about the actual
    cause - a truncated or empty USB transfer.
    """
    eCode = 0xFA

    def __init__(self, length, minimum):
        self.length = length
        self.minimum = minimum
        self.message = (f'truncated CCID response: got {length} byte(s), '
                        f'need at least {minimum}')
        Exception.__init__(self, self.message)


class Icc_Error_Protocol(Icc_Error_Base):
    """A structurally wrong response frame.

    These checks were `assert` statements. Python drops asserts under `-O`,
    which buildozer may well use, and that would have silently disabled the
    sequence-number check - the one thing keeping a stale or mixed-up response
    from being read as the answer to the current command.
    """
    eCode = 0xF9

    def __init__(self, what):
        self.what = what
        self.message = f'malformed CCID response: {what}'
        Exception.__init__(self, self.message)


class RDR_to_PC_Base:
    bSlot = 0x00

    def __init__(self, msg):
        self._msg = msg

    def __call__(self, bSeq):
        msg = self._msg
        if len(msg) < RDR_HEADER_SIZE:
            raise Icc_Error_Short_Frame(len(msg), RDR_HEADER_SIZE)
        if (msg[0] != self.bMessageType):
            raise Icc_Error_Protocol(
                f'wrong message type 0x{msg[0]:02X}, '
                f'expected 0x{self.bMessageType:02X}')
        self.dwLength = int.from_bytes(msg[1:5], 'little')
        if (msg[5] != self.bSlot):
            raise Icc_Error_Protocol(
                f'wrong slot 0x{msg[5]:02X}, expected 0x{self.bSlot:02X}')
        if (msg[6] != bSeq):
            # The sequence number is what stops a stale response from being
            # read as the answer to the command we just sent.
            raise Icc_Error_Protocol(
                f'wrong sequence number {msg[6]}, expected {bSeq}')
        bStatus, bError = msg[7:9]
        bmIccStatus = bStatus & 0x3
        bmCommandStatus = (bStatus >> 6) & 0x3
        if (bmIccStatus != 0):
            raise Icc_Error_Power_Off(bmIccStatus)
        if (msg[9] != 0x00):
            raise Icc_Error_Protocol(f'reserved byte 9 is 0x{msg[9]:02X}, expected 0x00')
        if (bmCommandStatus >= 3):
            raise Icc_Error_Protocol(f'invalid command status {bmCommandStatus}')
        if (bmCommandStatus == 1):
            if (bError == 0xFE):
                raise Icc_Error_Icc_Mute()
            elif (bError == 0xFC):
                raise Icc_Error_Xfr_Overrun()
            elif (bError == 0xFB):
                raise Icc_Error_Hw_Error()
            elif (bError >= 0x81 and bError <= 0xC0):
                raise Icc_Error_User_Defined(bError)
            elif (bError in [0xFD, 0xF0, 0xEF, 0xE0, *list(range(0xF2,0xF9))]):
                raise Icc_Error_Not_Used(bError)
            raise Icc_Error_Reserved(bError)
        elif (bmCommandStatus == 2):
            raise Icc_Error_Time_Extension()
        if (self.dwLength > 0):
            body = msg[RDR_HEADER_SIZE:]
            if len(body) < self.dwLength:
                raise Icc_Error_Short_Frame(len(msg),
                                            RDR_HEADER_SIZE + self.dwLength)
            # Trim to dwLength: trailing bytes belong to a previous command
            # and would desync every exchange after this one.
            return body[:self.dwLength]
        return b''

class PC_to_RDR_IccPowerOn(PC_to_RDR_Base):
    bMessageType = 0x62
    dwLength = 0
    bReserved = b'\x00'*3

    def __call__(self, bSeq):
        return super().__call__(dwLength=self.dwLength, bSeq=bSeq)

class RDR_to_PC_DataBlock(RDR_to_PC_Base):
    bMessageType = 0x80

    def __init__(self, msg):
        super().__init__(msg)

    def __call__(self, bSeq):
        return super().__call__(bSeq=bSeq)

class PC_to_RDR_IccPowerOff(PC_to_RDR_IccPowerOn):
    bMessageType = 0x63

class RDR_PC_SlotStatus(RDR_to_PC_Base):
    bMessageType = 0x81

    def __init__(self, msg):
        super().__init__(msg)

    def __call__(self, bSeq):
        super().__call__(bSeq=bSeq)

class PC_to_RDR_XfrBlock(PC_to_RDR_Base):
    bMessageType = 0x6F
    bReserved = b'\x00'*3

    def __init__(self, apdu):
        self.__apdu = apdu

    def __call__(self, bSeq):
        return super().__call__(dwLength=len(self.__apdu), bSeq=bSeq) + bytearray(self.__apdu)

class ICCD:
    def __init__(self, dev, bSeq=-1):
        self._bSeq = bSeq
        self._dev = dev

    def __get_request(self, cls):
        self._bSeq = (self._bSeq + 1) % 256
        return cls(self._bSeq)

    def __get_response(self, cls):
        while (True):
            try:
                response = cls(self._bSeq)
                return response
            except Icc_Error_Time_Extension:
                pass
            except Icc_Error_Base as e:
                raise e

    def _exchange(self, clsreq, clsresp):
        request = self.__get_request(clsreq)
        ret = self._dev.exchange(request)
        response = self.__get_response(clsresp(ret))
        return response

    def IccPowerOn(self):
        return self._exchange(PC_to_RDR_IccPowerOn(), RDR_to_PC_DataBlock)

    def IccPowerOff(self):
        try:
            self._exchange(PC_to_RDR_IccPowerOff(), RDR_PC_SlotStatus)
        except Icc_Error_Power_Off:
            pass

    def SendApdu(self, apdu):
        return self._exchange(PC_to_RDR_XfrBlock(apdu), RDR_to_PC_DataBlock)

    def transmit(self, apdu):
        response = self.SendApdu(apdu) or b''
        # An R-APDU always ends with SW1 SW2. A shorter frame is truncated,
        # and slicing it anyway would invent a status word out of whatever
        # bytes happened to be sitting in the buffer.
        if len(response) < 2:
            raise Icc_Error_Short_Frame(len(response), 2)
        return response[:-2], response[-2], response[-1]
