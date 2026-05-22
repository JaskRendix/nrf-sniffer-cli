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

import logging
import time
from collections.abc import Sequence
from typing import Any

import serial

from . import UART, BlePacket, Exceptions, Notifications
from .Types import *  # noqa: F401,F403

ADV_ACCESS_ADDRESS = [0xD6, 0xBE, 0x89, 0x8E]

SYNCWORD_POS = 0
PAYLOAD_LEN_POS_V1 = 1
PAYLOAD_LEN_POS = 0
PROTOVER_POS = PAYLOAD_LEN_POS + 2
PACKETCOUNTER_POS = PROTOVER_POS + 1
ID_POS = PACKETCOUNTER_POS + 2

BLE_HEADER_LEN_POS = ID_POS + 1
FLAGS_POS = BLE_HEADER_LEN_POS + 1
CHANNEL_POS = FLAGS_POS + 1
RSSI_POS = CHANNEL_POS + 1
EVENTCOUNTER_POS = RSSI_POS + 1
TIMESTAMP_POS = EVENTCOUNTER_POS + 2
BLEPACKET_POS = TIMESTAMP_POS + 4
TXADD_POS = BLEPACKET_POS + 4
TXADD_MSK = 0x40
PAYLOAD_POS = BLE_HEADER_LEN_POS

HEADER_LENGTH = 6
BLE_HEADER_LENGTH = 10

VALID_ADV_CHANS = [37, 38, 39]

PACKET_COUNTER_CAP = 2**16


class PacketReader(Notifications.Notifier):
    def __init__(
        self,
        portnum: str | None = None,
        callbacks: list[Any] | None = None,
        baudrate: int | None = None,
    ) -> None:
        super().__init__(callbacks or [])
        self.portnum: str | None = portnum
        try:
            self.uart = UART.Uart(portnum, baudrate)
        except serial.SerialException as e:
            logging.exception("Error opening UART %s", str(e))
            self.uart = UART.Uart()
        self.packetCounter: int = 0
        self.lastReceivedPacketCounter: int = 0
        self.lastReceivedPacket: Packet | None = None
        self.lastReceivedTimestampPacket: Packet | None = None
        self.supportedProtocolVersion: int = PROTOVER_V3

    def setup(self) -> None:
        pass

    def doExit(self) -> None:
        self.uart.close()
        self.clearCallbacks()

    def encodeToSLIP(self, byteList: Sequence[int]) -> list[int]:
        tempSLIPBuffer: list[int] = [SLIP_START]
        for b in byteList:
            if b == SLIP_START:
                tempSLIPBuffer.extend([SLIP_ESC, SLIP_ESC_START])
            elif b == SLIP_END:
                tempSLIPBuffer.extend([SLIP_ESC, SLIP_ESC_END])
            elif b == SLIP_ESC:
                tempSLIPBuffer.extend([SLIP_ESC, SLIP_ESC_ESC])
            else:
                tempSLIPBuffer.append(b)
        tempSLIPBuffer.append(SLIP_END)
        return tempSLIPBuffer

    def decodeFromSLIP(
        self, timeout: float | None = None, complete_timeout: float | None = None
    ) -> list[int]:
        dataBuffer: list[int] = []
        startOfPacket = False
        endOfPacket = False

        time_start: float = time.time()
        while not startOfPacket and (
            complete_timeout is None or (time.time() - time_start < complete_timeout)
        ):
            res = self.getSerialByte(timeout)
            startOfPacket = res == SLIP_START

        while not endOfPacket and (
            complete_timeout is None or (time.time() - time_start < complete_timeout)
        ):
            serialByte = self.getSerialByte(timeout)
            if serialByte == SLIP_END:
                endOfPacket = True
            elif serialByte == SLIP_ESC:
                serialByte = self.getSerialByte(timeout)
                if serialByte == SLIP_ESC_START:
                    dataBuffer.append(SLIP_START)
                elif serialByte == SLIP_ESC_END:
                    dataBuffer.append(SLIP_END)
                elif serialByte == SLIP_ESC_ESC:
                    dataBuffer.append(SLIP_ESC)
                else:
                    dataBuffer.append(SLIP_END)
            else:
                dataBuffer.append(serialByte)

        if not endOfPacket:
            raise Exceptions.UARTPacketError(
                "Exceeded max timeout of %f seconds." % (complete_timeout or 0.0)
            )
        return dataBuffer

    def getSerialByte(self, timeout: float | None = None) -> int:
        serialByte = self.uart.readByte(timeout)
        if serialByte is None:
            raise Exceptions.SnifferTimeout("Packet read timed out.")
        return serialByte

    def handlePacketHistory(self, packet: Packet) -> None:
        if (
            self.lastReceivedPacket is not None
            and packet.packetCounter
            != (self.lastReceivedPacket.packetCounter + 1) % PACKET_COUNTER_CAP
            and self.lastReceivedPacket.packetCounter != 0
        ):
            logging.info(
                "gap in packets, between %s and %s packet before: %s packet after: %s",
                self.lastReceivedPacket.packetCounter,
                packet.packetCounter,
                self.lastReceivedPacket.packetList,
                packet.packetList,
            )

        self.lastReceivedPacket = packet
        if packet.id in (EVENT_PACKET_DATA_PDU, EVENT_PACKET_ADV_PDU):
            self.lastReceivedTimestampPacket = packet

    def getPacketTime(self, packet: Packet) -> int:
        ble_payload_length = packet.payloadLength - BLE_HEADER_LENGTH

        if packet.phy == PHY_1M:
            return 8 * (1 + ble_payload_length)
        elif packet.phy == PHY_2M:
            return 4 * (2 + ble_payload_length)
        elif packet.phy == PHY_CODED:
            ci = packet.packetList[BLEPACKET_POS + 4]
            fec2_block_len = ble_payload_length - 4 - 1
            fec1_block_us = 80 + 256 + 16 + 24
            if ci == PHY_CODED_CI_S8:
                return fec1_block_us + 64 * fec2_block_len + 24
            elif ci == PHY_CODED_CI_S2:
                return fec1_block_us + 16 * fec2_block_len + 6
        return 0

    def convertPacketListProtoVer2(self, packet: Packet) -> None:
        packet.packetList[PROTOVER_POS] = PROTOVER_V2

        if packet.packetList[ID_POS] == EVENT_PACKET_ADV_PDU:
            packet.packetList[ID_POS] = EVENT_PACKET_DATA_PDU

        if packet.packetList[ID_POS] != EVENT_PACKET_DATA_PDU:
            return

        time_delta = 0
        if (
            self.lastReceivedTimestampPacket is not None
            and self.lastReceivedTimestampPacket.valid
        ):
            time_delta = packet.timestamp - (
                self.lastReceivedTimestampPacket.timestamp
                + self.getPacketTime(self.lastReceivedTimestampPacket)
            )

        td = toLittleEndian(time_delta, 4)
        packet.packetList[TIMESTAMP_POS] = td[0]
        packet.packetList[TIMESTAMP_POS + 1] = td[1]
        packet.packetList[TIMESTAMP_POS + 2] = td[2]
        packet.packetList[TIMESTAMP_POS + 3] = td[3]

    def handlePacketCompatibility(self, packet: Packet) -> None:
        if (
            self.supportedProtocolVersion == PROTOVER_V2
            and packet.packetList[PROTOVER_POS] > PROTOVER_V2
        ):
            self.convertPacketListProtoVer2(packet)

    def setSupportedProtocolVersion(self, supportedProtocolVersion: int) -> None:
        if supportedProtocolVersion != PROTOVER_V3:
            logging.info(
                "Using packet compatibility, converting packets to protocol version %d",
                supportedProtocolVersion,
            )
        self.supportedProtocolVersion = supportedProtocolVersion

    def getPacket(self, timeout: float | None = None) -> Packet | None:
        try:
            packetList = self.decodeFromSLIP(timeout)
        except Exceptions.UARTPacketError:
            logging.exception("")
            return None
        else:
            packet = Packet(packetList)
            if packet.valid:
                self.handlePacketCompatibility(packet)
                self.handlePacketHistory(packet)
            return packet

    def sendPacket(self, id: int, payload: Sequence[int]) -> None:
        packetList: list[int] = (
            [HEADER_LENGTH]
            + [len(payload)]
            + [PROTOVER_V1]
            + toLittleEndian(self.packetCounter, 2)
            + [id]
            + list(payload)
        )
        packetList = self.encodeToSLIP(packetList)
        self.packetCounter += 1
        self.uart.writeList(packetList)

    def sendScan(
        self, findScanRsp: bool = False, findAux: bool = False, scanCoded: bool = False
    ) -> None:
        flags0 = (
            (1 if findScanRsp else 0)
            | ((1 if findAux else 0) << 1)
            | ((1 if scanCoded else 0) << 2)
        )
        self.sendPacket(REQ_SCAN_CONT, [flags0])
        logging.info("Scan flags: %s", bin(flags0))

    def sendFollow(
        self,
        addr: Sequence[int],
        followOnlyAdvertisements: bool = False,
        followOnlyLegacy: bool = False,
        followCoded: bool = False,
    ) -> None:
        flags0 = (
            (1 if followOnlyAdvertisements else 0)
            | ((1 if followOnlyLegacy else 0) << 1)
            | ((1 if followCoded else 0) << 2)
        )
        logging.info("Follow flags: %s", bin(flags0))
        self.sendPacket(REQ_FOLLOW, list(addr) + [flags0])

    def sendPingReq(self) -> None:
        self.sendPacket(PING_REQ, [])

    def getBytes(self, value: Sequence[int], size: int) -> list[int]:
        v = list(value)
        if len(v) < size:
            v = [0] * (size - len(v)) + v
        else:
            v = v[:size]
        return v

    def sendTK(self, TK: Sequence[int]) -> None:
        tk = self.getBytes(TK, 16)
        self.sendPacket(SET_TEMPORARY_KEY, tk)
        logging.info(f"Sent TK to sniffer: {tk}")

    def sendPrivateKey(self, pk: Sequence[int]) -> None:
        pk_bytes = self.getBytes(pk, 32)
        self.sendPacket(SET_PRIVATE_KEY, pk_bytes)
        logging.info(f"Sent private key to sniffer: {pk_bytes}")

    def sendLegacyLTK(self, ltk: Sequence[int]) -> None:
        ltk_bytes = self.getBytes(ltk, 16)
        self.sendPacket(SET_LEGACY_LONG_TERM_KEY, ltk_bytes)
        logging.info(f"Sent Legacy LTK to sniffer: {ltk_bytes}")

    def sendSCLTK(self, ltk: Sequence[int]) -> None:
        ltk_bytes = self.getBytes(ltk, 16)
        self.sendPacket(SET_SC_LONG_TERM_KEY, ltk_bytes)
        logging.info(f"Sent SC LTK to sniffer: {ltk_bytes}")

    def sendIRK(self, irk: Sequence[int]) -> None:
        irk_bytes = self.getBytes(irk, 16)
        self.sendPacket(SET_IDENTITY_RESOLVING_KEY, irk_bytes)
        logging.info(f"Sent IRK to sniffer: {irk_bytes}")

    def sendSwitchBaudRate(self, newBaudRate: int) -> None:
        self.sendPacket(SWITCH_BAUD_RATE_REQ, toLittleEndian(newBaudRate, 4))

    def switchBaudRate(self, newBaudRate: int) -> None:
        self.uart.switchBaudRate(newBaudRate)

    def sendHopSequence(self, hopSequence: Sequence[int]) -> None:
        for chan in hopSequence:
            if chan not in VALID_ADV_CHANS:
                raise Exceptions.InvalidAdvChannel(f"{chan} is not an adv channel")
        payload = [len(hopSequence)] + list(hopSequence) + [37] * (3 - len(hopSequence))
        self.sendPacket(SET_ADV_CHANNEL_HOP_SEQ, payload)
        self.notify("NEW_ADV_HOP_SEQ", {"hopSequence": list(hopSequence)})

    def sendVersionReq(self) -> None:
        self.sendPacket(REQ_VERSION, [])

    def sendTimestampReq(self) -> None:
        self.sendPacket(REQ_TIMESTAMP, [])

    def sendGoIdle(self) -> None:
        self.sendPacket(GO_IDLE, [])


class Packet:
    def __init__(self, packetList: list[int]) -> None:
        try:
            if not packetList:
                raise Exceptions.InvalidPacketException(
                    f"packet list not valid: {str(packetList)}"
                )

            self.protover: int = packetList[PROTOVER_POS]

            if self.protover > PROTOVER_V3:
                logging.exception(f"Unsupported protocol version {str(self.protover)}")
                raise RuntimeError(f"Unsupported protocol version {str(self.protover)}")

            self.packetCounter: int = parseLittleEndian(
                packetList[PACKETCOUNTER_POS : PACKETCOUNTER_POS + 2]
            )
            self.id: int = packetList[ID_POS]

            if int(self.protover) == PROTOVER_V1:
                self.payloadLength: int = packetList[PAYLOAD_LEN_POS_V1]
            else:
                self.payloadLength = parseLittleEndian(
                    packetList[PAYLOAD_LEN_POS : PAYLOAD_LEN_POS + 2]
                )

            self.packetList: list[int] = packetList
            self.valid: bool = False
            self.OK: bool = False
            self.readPayload(packetList)

        except Exceptions.InvalidPacketException as e:
            logging.error("Invalid packet: %s", str(e))
            self.OK = False
            self.valid = False
        except Exception as e:
            logging.exception("packet creation error %s", str(e))
            logging.info("packetList: %s", packetList)
            self.OK = False
            self.valid = False

    def __repr__(self) -> str:
        return f"UART packet, type: {self.id}, PC: {self.packetCounter}"

    def readPayload(self, packetList: list[int]) -> None:
        self.blePacket: BlePacket.BlePacket | None = None
        self.OK = False

        if not self.validatePacketList(packetList):
            raise Exceptions.InvalidPacketException(
                "packet list not valid: %s" % str(packetList)
            )
        else:
            self.valid = True

        self.payload: list[int] = packetList[
            PAYLOAD_POS : PAYLOAD_POS + self.payloadLength
        ]

        if self.id in (EVENT_PACKET_ADV_PDU, EVENT_PACKET_DATA_PDU):
            try:
                self.bleHeaderLength = packetList[BLE_HEADER_LEN_POS]
                if self.bleHeaderLength == BLE_HEADER_LENGTH:
                    self.flags = packetList[FLAGS_POS]
                    self.readFlags()
                    self.channel = packetList[CHANNEL_POS]
                    self.rawRSSI = packetList[RSSI_POS]
                    self.RSSI = -self.rawRSSI
                    self.eventCounter = parseLittleEndian(
                        packetList[EVENTCOUNTER_POS : EVENTCOUNTER_POS + 2]
                    )

                    self.timestamp = parseLittleEndian(
                        packetList[TIMESTAMP_POS : TIMESTAMP_POS + 4]
                    )

                    if self.phy == PHY_CODED:
                        self.packetList.pop(BLEPACKET_POS + 6 + 1)
                    else:
                        self.packetList.pop(BLEPACKET_POS + 6)
                    self.payloadLength -= 1
                    if self.protover >= PROTOVER_V2:
                        payloadLength = toLittleEndian(self.payloadLength, 2)
                        packetList[PAYLOAD_LEN_POS] = payloadLength[0]
                        packetList[PAYLOAD_LEN_POS + 1] = payloadLength[1]
                    else:
                        packetList[PAYLOAD_LEN_POS_V1] = self.payloadLength
                else:
                    logging.info("Invalid BLE Header Length %s", packetList)
                    self.valid = False

                if self.OK:
                    try:
                        if self.protover >= PROTOVER_V3:
                            packet_type = (
                                PACKET_TYPE_ADVERTISING
                                if self.id == EVENT_PACKET_ADV_PDU
                                else PACKET_TYPE_DATA
                            )
                        else:
                            packet_type = (
                                PACKET_TYPE_ADVERTISING
                                if packetList[BLEPACKET_POS : BLEPACKET_POS + 4]
                                == ADV_ACCESS_ADDRESS
                                else PACKET_TYPE_DATA
                            )

                        self.blePacket = BlePacket.BlePacket(
                            packet_type, packetList[BLEPACKET_POS:], self.phy
                        )
                    except Exception as e:
                        logging.exception("blePacket error %s", str(e))
            except Exception as e:
                logging.exception("packet error %s", str(e))
                self.OK = False
        elif self.id == PING_RESP:
            if self.protover < PROTOVER_V3:
                self.version = parseLittleEndian(
                    packetList[PAYLOAD_POS : PAYLOAD_POS + 2]
                )
        elif self.id == RESP_VERSION:
            self.version = "".join(chr(i) for i in packetList[PAYLOAD_POS:])
        elif self.id == RESP_TIMESTAMP:
            self.timestamp = parseLittleEndian(
                packetList[PAYLOAD_POS : PAYLOAD_POS + 4]
            )
        elif self.id in (SWITCH_BAUD_RATE_RESP, SWITCH_BAUD_RATE_REQ):
            self.baudRate = parseLittleEndian(packetList[PAYLOAD_POS : PAYLOAD_POS + 4])
        else:
            logging.info("Unknown packet ID")

    def readFlags(self) -> None:
        self.crcOK = bool(self.flags & 1)
        self.direction = bool(self.flags & 2)
        self.encrypted = bool(self.flags & 4)
        self.micOK = bool(self.flags & 8)
        self.phy = (self.flags >> 4) & 7
        self.OK = self.crcOK and (self.micOK or not self.encrypted)

    def getList(self) -> list[int]:
        return self.packetList

    def validatePacketList(self, packetList: list[int]) -> bool:
        try:
            return (self.payloadLength + HEADER_LENGTH) == len(packetList)
        except Exception:
            logging.exception("Invalid packet: %s", packetList)
            return False


def parseLittleEndian(values: Sequence[int]) -> int:
    total = 0
    for i, b in enumerate(values):
        total += b << (8 * i)
    return total


def toLittleEndian(value: int, size: int) -> list[int]:
    out = [0] * size
    for i in range(size):
        out[i] = (value >> (i * 8)) & 0xFF
    return
