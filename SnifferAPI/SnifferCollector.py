#!/usr/bin/env python3

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

import copy
import logging
import random
import sys
import threading
import time
from typing import Any

from serial import SerialException

from . import CaptureFiles, Devices, Exceptions, Notifications, Packet
from .Types import EVENT_DISCONNECT  # noqa: F401
from .Types import (
    EVENT_CONNECT,
    EVENT_FOLLOW,
    EVENT_PACKET_ADV_PDU,
    EVENT_PACKET_DATA_PDU,
    PACKET_TYPE_ADVERTISING,
    PING_RESP,
    PROTOVER_V3,
    RESP_TIMESTAMP,
    RESP_VERSION,
    SWITCH_BAUD_RATE_RESP,
)

STATE_INITIALIZING = 0
STATE_SCANNING = 1
STATE_FOLLOWING = 2


class SnifferCollector(Notifications.Notifier):
    """Central collector for packets, devices, and sniffer state."""

    def __init__(
        self,
        portnum: str | None = None,
        baudrate: int | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)

        self._portnum: str | None = portnum
        self._fwversion: str = "Unknown version"

        self._state_lock = threading.RLock()
        self._setState(STATE_INITIALIZING)

        self._captureHandler = CaptureFiles.CaptureFileHandler(
            capture_file_path=kwargs.get("capture_file_path", None)
        )

        self._exit: bool = False
        self._connectionAccessAddress: list[int] | None = None

        self._packetListLock = threading.RLock()
        with self._packetListLock:
            self._packets: list[Any] = []

        self._packetReader: Packet.PacketReader = Packet.PacketReader(
            self._portnum,
            baudrate=baudrate,
            callbacks=[("*", self.passOnNotification)],
        )
        self._devices: Devices.DeviceList = Devices.DeviceList(
            callbacks=[("*", self.passOnNotification)]
        )

        self._missedPackets: int = 0
        self._packetsInLastConnection: int | None = None
        self._connectEventPacketCounterValue: int | None = None
        self._inConnection: bool = False
        self._currentConnectRequest: Any | None = None

        self._nProcessedPackets: int = 0

        self._switchingBaudRate: bool = False
        self._proposedBaudRate: int | None = None
        self._attemptedBaudRates: list[int] = []

        self._last_time: float | None = None
        self._last_timestamp: int = 0
        self._boardId: int = self._makeBoardId()

    def __del__(self) -> None:
        # Be defensive: __del__ can run during interpreter shutdown
        try:
            self._doExit()
        except Exception:
            pass

    def _setup(self) -> None:
        self._packetReader.setup()

    def _makeBoardId(self) -> int:
        try:
            if sys.platform == "win32":
                boardId = int(self._packetReader.portnum.split("COM")[1])
                logging.info("board ID: %d", boardId)
            elif sys.platform == "linux":
                boardId = int(self._packetReader.portnum.split("ttyACM")[1])
                logging.info("board ID: %d", boardId)
            else:
                raise IndexError()
        except (IndexError, AttributeError, ValueError):
            random.seed()
            boardId = random.randint(0, 255)
            logging.info("board ID (random): %d", boardId)

        return boardId

    @property
    def state(self) -> int:
        with self._state_lock:
            return self._state

    def _setState(self, newState: int) -> None:
        with self._state_lock:
            self._state = newState
        self.notify("STATE_CHANGE", newState)

    def _switchBaudRate(self, newBaudRate: int) -> None:
        uart = getattr(self._packetReader, "uart", None)
        ser = getattr(uart, "ser", None)
        baudrates = getattr(ser, "BAUDRATES", None)

        if baudrates and newBaudRate in baudrates:
            self._packetReader.sendSwitchBaudRate(newBaudRate)
            self._switchingBaudRate = True
            self._proposedBaudRate = newBaudRate
            self._attemptedBaudRates.append(newBaudRate)

    def _addDevice(self, device: Devices.Device) -> None:
        self._devices.appendOrUpdate(device)

    def _processBLEPacket(self, packet: Any) -> None:
        packet.boardId = self._boardId

        if packet.protover >= PROTOVER_V3:
            if self._last_time is None:
                packet.time = time.time()
                self._last_time = packet.time
                self._last_timestamp = getattr(packet, "timestamp", 0)
            else:
                ts = getattr(packet, "timestamp", 0)
                if ts < self._last_timestamp:
                    time_diff = (1 << 32) - (self._last_timestamp - ts)
                else:
                    time_diff = ts - self._last_timestamp

                packet.time = self._last_time + (time_diff / 1_000_000)
                self._last_time = packet.time
                self._last_timestamp = ts
        else:
            packet.time = time.time()

        self._appendPacket(packet)
        self.notify("NEW_BLE_PACKET", {"packet": packet})
        self._captureHandler.writePacket(packet)

        self._nProcessedPackets += 1

        if not getattr(packet, "OK", False):
            return

        try:
            self._handleAdvertisingPacket(packet)
        except Exception as e:
            logging.exception("packet processing error %s", str(e))
            self.notify("PACKET_PROCESSING_ERROR", {"errorString": str(e)})

    def _handleAdvertisingPacket(self, packet: Any) -> None:
        ble = getattr(packet, "blePacket", None)
        if ble is None:
            return

        if ble.type != PACKET_TYPE_ADVERTISING:
            return

        if self.state == STATE_FOLLOWING and getattr(ble, "advType", None) == 5:
            self._connectionAccessAddress = ble.accessAddress

        if self.state == STATE_FOLLOWING and getattr(ble, "advType", None) == 4:
            newDevice = Devices.Device(
                address=ble.advAddress,
                name=ble.name,
                RSSI=packet.RSSI,
            )
            self._devices.appendOrUpdate(newDevice)

        if self.state == STATE_SCANNING:
            advType = getattr(ble, "advType", None)
            advAddress = getattr(ble, "advAddress", None)
            if (
                advType in [0, 1, 2, 4, 6, 7]
                and advAddress is not None
                and getattr(packet, "crcOK", False)
                and not getattr(packet, "direction", False)
            ):
                newDevice = Devices.Device(
                    address=advAddress,
                    name=ble.name,
                    RSSI=packet.RSSI,
                )
                self._devices.appendOrUpdate(newDevice)

    def _continuouslyPipe(self) -> None:
        while not self._exit:
            try:
                packet = self._packetReader.getPacket(timeout=12)
                if packet is None or not getattr(packet, "valid", False):
                    raise Exceptions.InvalidPacketException("")
            except Exceptions.SnifferTimeout as e:
                logging.info(str(e))
                packet = None
            except (SerialException, ValueError):
                logging.exception("UART read error")
                logging.error("Lost contact with sniffer hardware.")
                self._doExit()
            except Exceptions.InvalidPacketException:
                pass
            else:
                self._dispatchPacket(packet)

    def _dispatchPacket(self, packet: Any) -> None:
        pid = getattr(packet, "id", None)

        if pid in (EVENT_PACKET_DATA_PDU, EVENT_PACKET_ADV_PDU):
            self._processBLEPacket(packet)
        elif pid == EVENT_FOLLOW:
            # No user-visible value
            pass
        elif pid == EVENT_CONNECT:
            self._handleConnect(packet)
        elif pid == EVENT_DISCONNECT:
            self._handleDisconnect(packet)
        elif pid == SWITCH_BAUD_RATE_RESP and self._switchingBaudRate:
            self._handleSwitchBaudRateResp(packet)
        elif pid == PING_RESP:
            self._handlePingResp(packet)
        elif pid == RESP_VERSION:
            self._fwversion = packet.version
            logging.info("Firmware version %s", self._fwversion)
        elif pid == RESP_TIMESTAMP:
            self._handleTimestampResp(packet)
        else:
            logging.info("Unknown packet ID")

    def _handleConnect(self, packet: Any) -> None:
        self._connectEventPacketCounterValue = packet.packetCounter
        self._inConnection = True
        prev = self._findPacketByPacketCounter(self._connectEventPacketCounterValue - 1)
        self._currentConnectRequest = copy.copy(prev) if prev is not None else None

    def _handleDisconnect(self, packet: Any) -> None:
        if self._inConnection and self._connectEventPacketCounterValue is not None:
            self._packetsInLastConnection = (
                packet.packetCounter - self._connectEventPacketCounterValue
            )
            self._inConnection = False

    def _handleSwitchBaudRateResp(self, packet: Any) -> None:
        self._switchingBaudRate = False
        if getattr(packet, "baudRate", None) == self._proposedBaudRate:
            self._packetReader.switchBaudRate(self._proposedBaudRate)
        else:
            self._switchBaudRate(packet.baudRate)

    def _handlePingResp(self, packet: Any) -> None:
        if hasattr(packet, "version"):
            versions = {
                1116: "3.1.0",
                1115: "3.0.0",
                1114: "2.0.0",
                1113: "2.0.0-beta-3",
                1112: "2.0.0-beta-1",
            }
            self._fwversion = versions.get(
                packet.version, "SVN rev: %d" % packet.version
            )
            logging.info("Firmware version %s", self._fwversion)

    def _handleTimestampResp(self, packet: Any) -> None:
        self._last_time = time.time()
        self._last_timestamp = packet.timestamp

        lt = time.localtime(self._last_time)
        usecs = int((self._last_time - int(self._last_time)) * 1_000_000)
        logging.info(
            "Firmware timestamp %d reference: %s.%06d %s",
            self._last_timestamp,
            time.strftime("%b %d %Y %X", lt),
            usecs,
            time.strftime("%Z", lt),
        )

    def _findPacketByPacketCounter(self, packetCounterValue: int) -> Any | None:
        with self._packetListLock:
            for i in range(-1, -1 - len(self._packets), -1):
                if (
                    getattr(self._packets[i], "packetCounter", None)
                    == packetCounterValue
                ):
                    return self._packets[i]
        return None

    def _appendPacket(self, packet: Any) -> None:
        with self._packetListLock:
            if len(self._packets) > 100000:
                self._packets = self._packets[20000:]
            self._packets.append(packet)

    def _getPackets(self, number: int = -1) -> list[Any]:
        with self._packetListLock:
            returnList = self._packets[0:number]
            self._packets = self._packets[number:]
        return returnList

    def _clearPackets(self) -> None:
        with self._packetListLock:
            self._packets.clear()

    def _startScanning(
        self, findScanRsp: bool = False, findAux: bool = False, scanCoded: bool = False
    ) -> None:
        logging.info("starting scan")

        if self.state == STATE_FOLLOWING:
            logging.info("Stopped sniffing device")

        self._setState(STATE_SCANNING)
        self._packetReader.sendScan(findScanRsp, findAux, scanCoded)
        self._packetReader.sendTK([0])

    def _doExit(self) -> None:
        if self._exit:
            return
        self._exit = True
        self.notify("APP_EXIT")
        try:
            self._packetReader.doExit()
        except Exception:
            logging.exception("Error while exiting packet reader")

        # Clear method references to avoid uncollectable cyclic references
        try:
            self.clearCallbacks()
        except Exception:
            pass
        try:
            self._devices.clearCallbacks()
        except Exception:
            pass

    def _startFollowing(
        self,
        device: Devices.Device,
        followOnlyAdvertisements: bool = False,
        followOnlyLegacy: bool = False,
        followCoded: bool = False,
    ) -> None:
        self._devices.setFollowed(device)
        logging.info(
            'Sniffing device %d - "%s"',
            self._devices.index(device),
            device.name,
        )
        self._packetReader.sendFollow(
            device.address,
            followOnlyAdvertisements,
            followOnlyLegacy,
            followCoded,
        )
        self._setState(STATE_FOLLOWING)

    def _clearDevices(self) -> None:
        self._devices.clear()
