# Copyright (c) Nordic Semiconductor ASA
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form, except as embedded into a Nordic
#    Semiconductor ASA integrated circuit in a product or a software update for
#    such product, must reproduce the above copyright notice, this list of
#    conditions and the following disclaimer in the documentation and/or other
#    materials provided with the distribution.
#
# 3. Neither the name of Nordic Semiconductor ASA nor the names of its
#    contributors may be used to endorse or promote products derived from this
#    software without specific prior written permission.
#
# 4. This software, with or without modification, must only be used with a
#    Nordic Semiconductor ASA integrated circuit.
#
# 5. Any software provided in binary form under this license must not be reverse
#    engineered, decompiled, modified and/or disassembled.
#
# THIS SOFTWARE IS PROVIDED BY NORDIC SEMICONDUCTOR ASA "AS IS" AND ANY EXPRESS
# OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY, NONINFRINGEMENT, AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL NORDIC SEMICONDUCTOR ASA OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
# GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
# OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from __future__ import annotations

from collections.abc import Sequence

from .Types import *  # noqa: F401,F403


class BlePacket:
    def __init__(self, type: int, packetList: Sequence[int], phy: int) -> None:
        self.type: int = type

        offset = 0
        offset = self.extractAccessAddress(packetList, offset)
        offset = self.extractFormat(packetList, phy, offset)

        if self.type == PACKET_TYPE_ADVERTISING:
            offset = self.extractAdvHeader(packetList, offset)
        else:
            offset = self.extractConnHeader(packetList, offset)

        offset = self.extractLength(packetList, offset)
        self.payload: list[int] = list(packetList[offset:])

        if self.type == PACKET_TYPE_ADVERTISING:
            offset = self.extractAddresses(packetList, offset)
            self.extractName(packetList, offset)

    def __repr__(self) -> str:
        return "BLE packet, AAddr: " + str(self.accessAddress)

    def extractAccessAddress(self, packetList: Sequence[int], offset: int) -> int:
        self.accessAddress: list[int] = list(packetList[offset : offset + 4])
        return offset + 4

    def extractFormat(self, packetList: Sequence[int], phy: int, offset: int) -> int:
        self.coded: bool = phy == PHY_CODED
        if self.coded:
            self.codingIndicator: int = packetList[offset] & 0x03
            return offset + 1
        return offset

    def extractAdvHeader(self, packetList: Sequence[int], offset: int) -> int:
        hdr = packetList[offset]
        self.advType: int = hdr & 0x0F
        self.txAddrType: int = (hdr >> 6) & 0x01
        if self.advType in (1, 3, 5):
            self.rxAddrType: int = (hdr << 7) & 0x01
        return offset + 1

    def extractConnHeader(self, packetList: Sequence[int], offset: int) -> int:
        hdr = packetList[offset]
        self.llid: int = hdr & 0x03
        self.sn: int = (hdr >> 2) & 0x01
        self.nesn: int = (hdr >> 3) & 0x01
        self.md: int = (hdr >> 4) & 0x01
        return offset + 1

    def extractAddresses(self, packetList: Sequence[int], offset: int) -> int:
        addr: list[int] | None = None
        scanAddr: list[int] | None = None

        if self.advType in (0, 1, 2, 4, 6):
            addr = list(packetList[offset : offset + 6])
            addr.reverse()
            addr.append(self.txAddrType)
            offset += 6

        if self.advType in (3, 5):
            scanAddr = list(packetList[offset : offset + 6])
            scanAddr.reverse()
            scanAddr.append(self.txAddrType)
            offset += 6
            addr = list(packetList[offset : offset + 6])
            addr.reverse()
            addr.append(self.rxAddrType)
            offset += 6

        if self.advType == 1:
            scanAddr = list(packetList[offset : offset + 6])
            scanAddr.reverse()
            scanAddr.append(self.rxAddrType)
            offset += 6

        if self.advType == 7:
            ext_header_len = packetList[offset] & 0x3F
            offset += 1

            ext_header_offset = offset
            flags = packetList[ext_header_offset]
            ext_header_offset += 1

            if flags & 0x01:
                addr = list(packetList[ext_header_offset : ext_header_offset + 6])
                addr.reverse()
                addr.append(self.txAddrType)
                ext_header_offset += 6

            if flags & 0x02:
                scanAddr = list(packetList[ext_header_offset : ext_header_offset + 6])
                scanAddr.reverse()
                scanAddr.append(self.rxAddrType)
                ext_header_offset += 6

            offset += ext_header_len

        self.advAddress: list[int] | None = addr
        self.scanAddress: list[int] | None = scanAddr
        return offset

    def extractName(self, packetList: Sequence[int], offset: int) -> None:
        name = ""
        if self.advType in (0, 2, 4, 6, 7):
            i = offset
            while i < len(packetList):
                length = packetList[i]
                if (i + length + 1) > len(packetList) or length == 0:
                    break
                ad_type = packetList[i + 1]
                if ad_type in (8, 9):
                    nameList = packetList[i + 2 : i + length + 1]
                    name = "".join(chr(j) for j in nameList)
                i += length + 1
            name = '"' + name + '"'
        elif self.advType == 1:
            name = "[ADV_DIRECT_IND]"

        self.name: str = name

    def extractLength(self, packetList: Sequence[int], offset: int) -> int:
        self.length: int = packetList[offset]
        return offset + 1
