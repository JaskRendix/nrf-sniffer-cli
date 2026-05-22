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

import argparse
import json
import logging
import sys
from typing import IO, Any

from SnifferAPI import UART
from SnifferAPI.client.filter import FilterSet
from SnifferAPI.client.sniffer import SnifferClient
from SnifferAPI.client.tools import address_to_string, hex_to_bytes
from SnifferAPI.Devices import Device

logger = logging.getLogger(__name__)

DEFAULT_CAPTURE_FILE: str = "capture.pcap"


def configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(message)s",
    )


def _capture_flags() -> argparse.ArgumentParser:
    """Shared flags for subcommands that capture packets."""
    p: argparse.ArgumentParser = argparse.ArgumentParser(add_help=False)
    p.add_argument("--live", action="store_true", help="Print packets to stdout.")
    p.add_argument(
        "--decode", action="store_true", help="Decode BLE fields in live output."
    )
    p.add_argument(
        "--record-json", metavar="FILE", help="Append packets as NDJSON to FILE."
    )
    p.add_argument(
        "--channel",
        type=int,
        metavar="N",
        help="Only process packets on BLE channel N.",
    )
    p.add_argument(
        "--min-rssi",
        type=int,
        metavar="DBM",
        help="Drop packets below this RSSI (dBm).",
    )
    p.add_argument(
        "--type",
        choices=["adv", "data", "all"],
        default="all",
        help="Filter by PDU type (default: all).",
    )
    p.add_argument(
        "--addr",
        metavar="AA:BB:CC:DD:EE:FF",
        help="Only show packets from this advertiser.",
    )
    return p


def build_parser() -> argparse.ArgumentParser:
    shared: argparse.ArgumentParser = _capture_flags()

    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        description="Sniff Bluetooth LE traffic over the air."
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable debug logging."
    )
    parser.add_argument(
        "--capture-file",
        "-c",
        default=DEFAULT_CAPTURE_FILE,
        metavar="FILE",
        help=f"Pcap output file (default: {DEFAULT_CAPTURE_FILE}).",
    )
    parser.add_argument(
        "--timeout",
        "-t",
        type=float,
        default=5.0,
        metavar="SEC",
        help="Scan timeout in seconds (default: 5).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="List connected sniffer serial ports.")
    scan_parser = sub.add_parser("scan", help="Scan for advertising BLE devices.")
    scan_parser.add_argument(
        "--json", action="store_true", help="Output scan results as JSON."
    )

    sniff = sub.add_parser(
        "sniff", parents=[shared], help="Follow a specific BLE device."
    )
    group = sniff.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--address", "-a", metavar="AA:BB:CC:DD:EE:FF", help="Target by address."
    )
    group.add_argument(
        "--name", "-n", metavar="NAME", help="Target by advertised name."
    )
    group.add_argument("--irk", metavar="HEX", help="Follow by IRK (big-endian hex).")

    return parser


def _handle_list() -> int:
    ports: list[str] = UART.find_sniffer()
    if not ports:
        print("No sniffers found.")
        return 1
    for p in ports:
        print(p)
    return 0


def _handle_scan(client: SnifferClient, timeout: float, as_json: bool) -> int:
    devices: list[Device] = client.scan(timeout)
    if as_json:
        payload: list[dict[str, Any]] = [
            {
                "address": address_to_string(d),
                "name": d.name.replace('"', ""),
                "rssi": d.RSSI,
            }
            for d in devices
        ]
        print(json.dumps(payload, indent=2))
    else:
        for d in devices:
            print(f"{address_to_string(d)}  {d.name.replace(chr(34), '')}")
    return 0


def _open_json_file(path: str | None) -> IO[str] | None:
    if path is None:
        return None
    return open(path, "a", encoding="utf-8")


def main() -> int:
    parser: argparse.ArgumentParser = build_parser()
    args = parser.parse_args()
    configure_logging(args.verbose)

    if args.command == "list":
        return _handle_list()

    client: SnifferClient = SnifferClient(args.capture_file)

    if args.command == "scan":
        return _handle_scan(client, float(args.timeout), bool(args.json))

    filters: FilterSet = FilterSet.from_args(args)
    live: bool = bool(args.live)
    decode: bool = bool(args.decode)
    json_fh: IO[str] | None = _open_json_file(args.record_json)

    try:
        if args.irk:
            try:
                irk: bytes = hex_to_bytes(args.irk)
            except ValueError as exc:
                logger.error("Invalid IRK: %s", exc)
                return 1
            client.follow_by_irk(
                irk, filters=filters, live=live, decode=decode, json_fh=json_fh
            )
        else:
            devices: list[Device] = client.scan(
                float(args.timeout), address=args.address, name=args.name
            )
            if not devices:
                logger.error("Device not found within %.0f s.", float(args.timeout))
                return 2
            target: Device = devices[0]
            client.follow(
                target, filters=filters, live=live, decode=decode, json_fh=json_fh
            )

    except KeyboardInterrupt:
        logger.info("Interrupted — stopping.")
        client.stop()
    finally:
        if json_fh is not None:
            json_fh.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
