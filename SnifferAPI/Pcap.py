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

import struct

# PCAP packet header: ts_sec, ts_usec, incl_len, orig_len
PACKET_HEADER = struct.Struct("<LLLL")

# PCAP global header for Nordic BLE link type (272)
GLOBAL_HEADER: bytes = struct.pack(
    "<LHHIILL",
    0xA1B2C3D4,  # Magic number
    2,  # Major version
    4,  # Minor version
    0,  # Reserved
    0,  # Reserved
    0x0000FFFF,  # Max capture length
    272,  # LINKTYPE_NORDIC_BLE
)

__all__ = ["get_global_header", "create_packet"]


def get_global_header() -> bytes:
    """Return the PCAP global header."""
    return GLOBAL_HEADER


def create_packet(packet: bytes | bytearray, timestamp_seconds: float) -> bytes:
    """Create a PCAP packet record.

    Args:
        packet: Raw Nordic BLE packet bytes.
        timestamp_seconds: Relative timestamp in seconds.

    Returns:
        A PCAP-formatted packet record.
    """
    if not isinstance(packet, (bytes, bytearray)):
        raise TypeError("packet must be bytes or bytearray")

    ts_sec = int(timestamp_seconds)
    ts_usec = int((timestamp_seconds - ts_sec) * 1_000_000)

    header = PACKET_HEADER.pack(ts_sec, ts_usec, len(packet), len(packet))
    return header + bytes(packet)
