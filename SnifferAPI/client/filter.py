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
from dataclasses import dataclass
from typing import Any

from SnifferAPI.client.tools import address_to_string, normalize_address
from SnifferAPI.Devices import Device
from SnifferAPI.Types import EVENT_PACKET_ADV_PDU, EVENT_PACKET_DATA_PDU

logger = logging.getLogger(__name__)


@dataclass
class FilterSet:
    """Typed filter configuration for packet selection."""

    channel: int | None = None
    min_rssi: int | None = None
    pdu_type: str = "all"  # "adv" | "data" | "all"
    adv_address: str | None = None  # normalized, no colons

    def match(self, p: Any) -> bool:
        """Return True if packet *p* matches all filter conditions."""

        # Channel filter
        if self.channel is not None:
            pkt_channel = getattr(p, "channel", None)
            if pkt_channel != self.channel:
                return False

        # RSSI filter
        pkt_rssi = getattr(p, "RSSI", None)
        if self.min_rssi is not None and pkt_rssi is not None:
            if pkt_rssi < self.min_rssi:
                return False

        # PDU type filter
        pkt_id = getattr(p, "id", None)
        if self.pdu_type == "adv" and pkt_id != EVENT_PACKET_ADV_PDU:
            return False
        if self.pdu_type == "data" and pkt_id != EVENT_PACKET_DATA_PDU:
            return False

        # Advertiser address filter
        if self.adv_address is not None:
            bp = getattr(p, "blePacket", None)
            adv_addr = getattr(bp, "advAddress", None) if bp else None
            if not adv_addr:
                return False

            dev = Device(address=adv_addr, name="", RSSI=0)
            if address_to_string(dev) != self.adv_address:
                return False

        return True

    @classmethod
    def from_args(cls, args: Any) -> FilterSet:
        """Construct a FilterSet from argparse arguments."""
        adv_address: str | None = None

        raw_addr = getattr(args, "addr", None)
        if raw_addr:
            adv_address = normalize_address(raw_addr)

        return cls(
            channel=getattr(args, "channel", None),
            min_rssi=getattr(args, "min_rssi", None),
            pdu_type=getattr(args, "type", "all"),
            adv_address=adv_address,
        )
