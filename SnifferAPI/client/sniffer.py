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

import logging
import sys
import time

# Only imported for typing; avoids runtime dependency
from typing import IO, TYPE_CHECKING

from SnifferAPI.client.tools import (
    address_to_string,
    format_packet,
    normalize_address,
    record_packet_json,
)
from SnifferAPI.Devices import Device
from SnifferAPI.Sniffer import Sniffer
from SnifferAPI.UART import find_sniffer

if TYPE_CHECKING:
    from SnifferAPI.client.sniffer import FilterSet


logger = logging.getLogger(__name__)

DEFAULT_BAUDRATE: int = 1_000_000
PROTOCOL_VERSION: int = 2
LOOP_SLEEP_S: float = 0.1
DIAG_EVERY_N_LOOPS: int = 20


class SnifferClient:
    """High‑level wrapper around Nordic's Sniffer API with strong typing."""

    def __init__(self, capture_file: str) -> None:
        ports: list[str] = find_sniffer()
        if not ports:
            logger.error("No sniffer dongles found. Is the device plugged in?")
            sys.exit(1)

        logger.debug("Using sniffer on port %s", ports[0])

        self._sniffer = Sniffer(
            portnum=ports[0],
            baudrate=DEFAULT_BAUDRATE,
            capture_file_path=capture_file,
        )
        self._sniffer.setSupportedProtocolVersion(PROTOCOL_VERSION)
        self._sniffer.start()

    def stop(self) -> None:
        """Stop the sniffer safely."""
        try:
            self._sniffer.stop()
        except Exception:
            pass

    def scan(
        self,
        timeout: float,
        *,
        address: str | None = None,
        name: str | None = None,
    ) -> list[Device]:
        """Scan for BLE devices.

        Returns:
            A list of matching Device objects, or all discovered devices if
            no filter is provided. Returns an empty list on timeout.
        """
        self._sniffer.scan()
        target_addr: str | None = normalize_address(address) if address else None
        deadline: float = time.monotonic() + timeout

        while time.monotonic() < deadline:
            time.sleep(0.2)
            devices: list[Device] = self._sniffer.getDevices().asList()

            if target_addr:
                found: list[Device] = [
                    d for d in devices if address_to_string(d) == target_addr
                ]
                if found:
                    return found

            elif name:
                found = [d for d in devices if d.name.replace('"', "") == name]
                if found:
                    return found

        # No filter → return everything collected so far.
        if not (target_addr or name):
            return self._sniffer.getDevices().asList()

        return []

    def follow(
        self,
        device: Device,
        *,
        irk: list[int] | None = None,
        filters: FilterSet,
        live: bool,
        decode: bool,
        json_fh: IO[str] | None,
    ) -> None:
        """Follow a specific BLE device."""
        self._sniffer.follow(device)

        if irk is not None:
            self._sniffer.sendIRK(irk)

        self._loop(filters=filters, live=live, decode=decode, json_fh=json_fh)

    def follow_by_irk(
        self,
        irk: list[int],
        *,
        filters: FilterSet,
        live: bool,
        decode: bool,
        json_fh: IO[str] | None,
    ) -> None:
        """Follow an anonymised device using only its IRK (no prior scan)."""
        placeholder = Device(address=[], name='""', RSSI=0)

        self._sniffer.scan()
        self._sniffer.follow(placeholder)
        self._sniffer.sendIRK(irk)

        self._loop(filters=filters, live=live, decode=decode, json_fh=json_fh)

    def _loop(
        self,
        *,
        filters: FilterSet,
        live: bool,
        decode: bool,
        json_fh: IO[str] | None,
    ) -> None:
        """Main packet processing loop."""
        loops: int = 0
        packet_count: int = 0

        while True:
            time.sleep(LOOP_SLEEP_S)
            packets = self._sniffer.getPackets()

            for p in packets:
                if not filters.match(p):
                    continue

                packet_count += 1

                if live:
                    print(format_packet(p, decode=decode))

                if json_fh is not None:
                    record_packet_json(p, json_fh)

            loops += 1
            if loops % DIAG_EVERY_N_LOOPS == 0:
                logger.debug(
                    "inConnection=%s  packets=%d",
                    self._sniffer.inConnection,
                    packet_count,
                )
