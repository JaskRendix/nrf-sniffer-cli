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

import json
import logging
from typing import IO, Any

from SnifferAPI import Devices
from SnifferAPI.Devices import Device
from SnifferAPI.Types import PACKET_TYPE_ADVERTISING, PACKET_TYPE_DATA

logger = logging.getLogger(__name__)


def format_packet(p: Any, *, decode: bool) -> str:
    """Return a human‑readable representation of a sniffer packet."""

    # RSSI handling
    rssi: int = int(getattr(p, "RSSI", -100))

    # Map RSSI (-100 to -20) into a 20-character bar
    # -100 dBm → empty bar
    # -20 dBm → full bar
    bar_length: int = int(max(0, min(20, (rssi + 100) / 4)))
    signal_bar: str = f"|{'█' * bar_length}{'-' * (20 - bar_length)}|"

    base: str = (
        f"[{getattr(p, 'timestamp', 0.0):.3f}] "
        f"{signal_bar} {rssi:4} dBm "
        f"CH={getattr(p, 'channel', '?')}"
    )

    if not decode:
        return base

    bp: Any = getattr(p, "blePacket", None)
    if bp is None:
        return base

    extra: list[str] = []
    pkt_type: Any = getattr(bp, "type", None)

    if pkt_type == PACKET_TYPE_ADVERTISING:
        adv_addr: list[int] | None = getattr(bp, "advAddress", None)
        if adv_addr:
            dev: Device = Devices.Device(address=adv_addr, name="", RSSI=0)
            extra.append(f"addr={address_to_string(dev)}")
        name: str | None = getattr(bp, "name", None)
        if name:
            extra.append(f"name={name.strip(chr(34))}")
        extra.append(f"adv_type={getattr(bp, 'advType', '?')}")

    elif pkt_type == PACKET_TYPE_DATA:
        extra.append(f"llid={getattr(bp, 'llid', '?')}")
        extra.append(f"len={getattr(bp, 'length', '?')}")

    return base + (" " + " ".join(extra) if extra else "")


def record_packet_json(p: Any, fh: IO[str]) -> None:
    """Write a single packet as NDJSON to *fh*."""
    obj: dict[str, Any] = {
        "timestamp": getattr(p, "timestamp", None),
        "rssi": getattr(p, "RSSI", None),
        "channel": getattr(p, "channel", None),
    }

    bp: Any = getattr(p, "blePacket", None)
    if bp is not None:
        adv_addr: list[int] | None = getattr(bp, "advAddress", None)
        ble_obj: dict[str, Any] = {
            "type": getattr(bp, "type", None),
            "adv_type": getattr(bp, "advType", None),
            "name": getattr(bp, "name", None),
            "adv_address": (
                address_to_string(Devices.Device(address=adv_addr, name="", RSSI=0))
                if adv_addr
                else None
            ),
        }
        obj["ble"] = ble_obj

    fh.write(json.dumps(obj) + "\n")
    fh.flush()


def normalize_address(addr: str) -> str:
    """Normalize a BLE address by removing separators and lowercasing."""
    return addr.replace(":", "").replace("-", "").lower()


def address_to_string(dev: Device) -> str:
    """Return a normalized hex string (no separators) for a Device address."""
    return "".join(f"{b:02x}" for b in dev.address[:6])


def hex_to_bytes(value: str) -> list[int]:
    """Convert a hex string (optionally prefixed with 0x) into a list of bytes."""
    value = value.lower().removeprefix("0x")
    if any(c not in "0123456789abcdef" for c in value):
        raise ValueError(f"IRK must be hexadecimal, got: {value!r}")
    if len(value) % 2:
        value = "0" + value
    return [int(value[i : i + 2], 16) for i in range(0, len(value), 2)]
