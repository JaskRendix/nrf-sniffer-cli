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
import os
import sys
import threading
from typing import Any

from . import UART, Logger, SnifferCollector
from .Types import *  # noqa: F401

try:
    from .version import VERSION_STRING
except Exception:
    VERSION_STRING = "Unknown Version"


def initLog() -> None:
    Logger.initLogger()
    logging.info("--------------------------------------------------------")
    logging.info(f"Software version: {VERSION_STRING}")


class Sniffer(threading.Thread, SnifferCollector.SnifferCollector):
    """Threaded wrapper around SnifferCollector providing the public API."""

    def __init__(
        self,
        portnum: str | None = None,
        baudrate: int = UART.SNIFFER_OLD_DEFAULT_BAUDRATE,
        **kwargs: Any,
    ) -> None:
        initLog()

        threading.Thread.__init__(self)
        SnifferCollector.SnifferCollector.__init__(
            self, portnum, baudrate=baudrate, **kwargs
        )

        self.daemon = True
        self.goodExit: bool = True

        # Notify when COM port is detected
        self.subscribe("COMPORT_FOUND", self.comPortFound)

    def getPackets(self, number: int = -1) -> list[Any]:
        """Return up to `number` packets since last fetch."""
        return self._getPackets(number)

    def getDevices(self):
        """Return the DeviceList of discovered devices."""
        return self._devices

    def addDevice(self, device) -> None:
        """Manually add a device to the device list."""
        self._addDevice(device)

    def follow(
        self,
        device=None,
        followOnlyAdvertisements: bool = False,
        followOnlyLegacy: bool = False,
        followCoded: bool = False,
    ) -> None:
        """Follow a specific BLE device."""
        self._startFollowing(
            device, followOnlyAdvertisements, followOnlyLegacy, followCoded
        )

    def clearDevices(self) -> None:
        """Clear the device list."""
        self._clearDevices()

    def scan(
        self, findScanRsp: bool = False, findAux: bool = False, scanCoded: bool = False
    ) -> None:
        """Start scanning for advertising devices."""
        self._startScanning(findScanRsp, findAux, scanCoded)

    def sendTK(self, TK) -> None:
        self._packetReader.sendTK(TK)

    def sendPrivateKey(self, pk) -> None:
        self._packetReader.sendPrivateKey(pk)

    def sendLegacyLTK(self, ltk) -> None:
        self._packetReader.sendLegacyLTK(ltk)

    def sendSCLTK(self, ltk) -> None:
        self._packetReader.sendSCLTK(ltk)

    def sendIRK(self, irk) -> None:
        self._packetReader.sendIRK(irk)

    def getFirmwareVersion(self) -> None:
        """Request firmware version from the sniffer."""
        self._packetReader.sendVersionReq()
        self._packetReader.sendPingReq()  # older firmware responds here

    def getTimestamp(self) -> None:
        self._packetReader.sendTimestampReq()

    def setPortnum(self, portnum: str | None) -> None:
        """Set COM port number before starting the sniffer."""
        self._portnum = portnum
        self._packetReader.portnum = portnum

    def setAdvHopSequence(self, hopSequence) -> None:
        self._packetReader.sendHopSequence(hopSequence)

    def setSupportedProtocolVersion(self, supportedProtocolVersion) -> None:
        self._packetReader.setSupportedProtocolVersion(supportedProtocolVersion)

    def doExit(self, join: bool = False) -> None:
        """Gracefully shut down the sniffer."""
        self._doExit()
        if join:
            self.join()

    @property
    def missedPackets(self) -> int:
        return self._missedPackets

    @property
    def packetsInLastConnection(self) -> int | None:
        return self._packetsInLastConnection

    @property
    def connectEventPacketCounterValue(self) -> int | None:
        return self._connectEventPacketCounterValue

    @property
    def currentConnectRequest(self):
        return self._currentConnectRequest

    @property
    def inConnection(self) -> bool:
        return self._inConnection

    @property
    def state(self) -> int:
        return self._state

    @property
    def portnum(self) -> str | None:
        return self._portnum

    @property
    def swversion(self) -> str:
        return VERSION_STRING

    @property
    def fwversion(self) -> str:
        return self._fwversion

    def run(self) -> None:
        try:
            self._setup()
            self.runSniffer()
        except KeyboardInterrupt as e:
            _, _, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            lineno = exc_tb.tb_lineno
            logging.info(
                "exiting (%s in %s at %d): %s",
                type(e),
                fname,
                lineno,
                str(e),
            )
            self.goodExit = False
        except (BrokenPipeError, OSError):
            logging.info("capture pipe closed before sniffer thread was stopped")
            self.goodExit = True
        except Exception as e:
            import traceback

            logging.exception("CRASH: %s", e)
            logging.exception(traceback.format_exc())
            self.goodExit = False
        else:
            self.goodExit = True

    def comPortFound(self, notification) -> None:
        """Callback when COM port is detected."""
        self._portnum = notification.msg["comPort"]
        self._boardId = self._makeBoardId()

    def runSniffer(self) -> None:
        """Main sniffer loop."""
        if not self._exit:
            self._continuouslyPipe()
        else:
            self.goodExit = False
