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

import argparse
import json
import logging
import sys
import time
from dataclasses import dataclass

from SnifferAPI import UART, Devices, Sniffer
from SnifferAPI.Types import (
    EVENT_PACKET_ADV_PDU,
    EVENT_PACKET_DATA_PDU,
    PACKET_TYPE_ADVERTISING,
    PACKET_TYPE_DATA,
)

logger = logging.getLogger(__name__)


DEFAULT_CAPTURE_FILE = "capture.pcap"
DEFAULT_BAUDRATE = 1_000_000
PROTOCOL_VERSION = 2
LOOP_SLEEP_S = 0.1
DIAG_EVERY_N_LOOPS = 20


def configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(message)s",
    )


def normalize_address(addr: str) -> str:
    return addr.replace(":", "").replace("-", "").lower()


def address_to_string(dev) -> str:
    return "".join(f"{b:02x}" for b in dev.address[:6])


def hex_to_bytes(value: str) -> list[int]:
    value = value.lower().removeprefix("0x")
    if any(c not in "0123456789abcdef" for c in value):
        raise ValueError(f"IRK must be hexadecimal, got: {value!r}")
    if len(value) % 2:
        value = "0" + value
    return [int(value[i : i + 2], 16) for i in range(0, len(value), 2)]


def format_packet(p, *, decode: bool) -> str:
    # RSSI handling
    rssi = getattr(p, "RSSI", -100)

    # Map RSSI (-100 to -20) into a 20-character bar
    # -100 dBm → empty bar
    # -20 dBm → full bar
    bar_length = int(max(0, min(20, (rssi + 100) / 4)))
    signal_bar = f"|{'█' * bar_length}{'-' * (20 - bar_length)}|"

    base = (
        f"[{getattr(p, 'timestamp', 0):.3f}] "
        f"{signal_bar} {rssi:4} dBm "
        f"CH={getattr(p, 'channel', '?')}"
    )

    if not decode:
        return base

    bp = getattr(p, "blePacket", None)
    if bp is None:
        return base

    extra: list[str] = []
    pkt_type = getattr(bp, "type", None)

    if pkt_type == PACKET_TYPE_ADVERTISING:
        adv_addr = getattr(bp, "advAddress", None)
        if adv_addr:
            dev = Devices.Device(address=adv_addr, name="", RSSI=0)
            extra.append(f"addr={address_to_string(dev)}")
        if name := getattr(bp, "name", None):
            extra.append(f"name={name.strip(chr(34))}")
        extra.append(f"adv_type={getattr(bp, 'advType', '?')}")

    elif pkt_type == PACKET_TYPE_DATA:
        extra.append(f"llid={getattr(bp, 'llid', '?')}")
        extra.append(f"len={getattr(bp, 'length', '?')}")

    return base + (" " + " ".join(extra) if extra else "")


def record_packet_json(p, fh) -> None:
    obj: dict = {
        "timestamp": getattr(p, "timestamp", None),
        "rssi": getattr(p, "RSSI", None),
        "channel": getattr(p, "channel", None),
    }
    bp = getattr(p, "blePacket", None)
    if bp is not None:
        adv_addr = getattr(bp, "advAddress", None)
        obj["ble"] = {
            "type": getattr(bp, "type", None),
            "adv_type": getattr(bp, "advType", None),
            "name": getattr(bp, "name", None),
            "adv_address": (
                address_to_string(Devices.Device(address=adv_addr, name="", RSSI=0))
                if adv_addr
                else None
            ),
        }
    fh.write(json.dumps(obj) + "\n")
    fh.flush()


@dataclass
class FilterSet:
    channel: int | None = None
    min_rssi: int | None = None
    pdu_type: str = "all"  # "adv" | "data" | "all"
    adv_address: str | None = None  # normalised, no colons

    def match(self, p) -> bool:
        if self.channel is not None and getattr(p, "channel", None) != self.channel:
            return False

        rssi = getattr(p, "RSSI", None)
        if self.min_rssi is not None and rssi is not None and rssi < self.min_rssi:
            return False

        pkt_id = getattr(p, "id", None)
        if self.pdu_type == "adv" and pkt_id != EVENT_PACKET_ADV_PDU:
            return False
        if self.pdu_type == "data" and pkt_id != EVENT_PACKET_DATA_PDU:
            return False

        if self.adv_address is not None:
            bp = getattr(p, "blePacket", None)
            adv_addr = bp and getattr(bp, "advAddress", None)
            if not adv_addr:
                return False
            dev = Devices.Device(address=adv_addr, name="", RSSI=0)
            if address_to_string(dev) != self.adv_address:
                return False

        return True

    @classmethod
    def from_args(cls, args) -> "FilterSet":
        adv_address = None
        if raw := getattr(args, "addr", None):
            adv_address = normalize_address(raw)
        return cls(
            channel=getattr(args, "channel", None),
            min_rssi=getattr(args, "min_rssi", None),
            pdu_type=getattr(args, "type", "all"),
            adv_address=adv_address,
        )


class SnifferClient:
    def __init__(self, capture_file: str) -> None:
        ports = UART.find_sniffer()
        if not ports:
            logger.error("No sniffer dongles found. Is the device plugged in?")
            sys.exit(1)

        logger.debug("Using sniffer on port %s", ports[0])
        self._sniffer = Sniffer.Sniffer(
            portnum=ports[0],
            baudrate=DEFAULT_BAUDRATE,
            capture_file_path=capture_file,
        )
        self._sniffer.setSupportedProtocolVersion(PROTOCOL_VERSION)
        self._sniffer.start()

    def stop(self) -> None:
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
    ) -> list:
        """Scan for BLE devices.

        Returns a list of matching Device objects, or all found devices when
        neither *address* nor *name* is given.  Returns an empty list on
        timeout.
        """
        self._sniffer.scan()
        target_addr = normalize_address(address) if address else None
        deadline = time.monotonic() + timeout

        while time.monotonic() < deadline:
            time.sleep(0.2)
            devices = self._sniffer.getDevices().asList()

            if target_addr:
                found = [d for d in devices if address_to_string(d) == target_addr]
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
        device,
        *,
        irk: list[int] | None = None,
        filters: FilterSet,
        live: bool,
        decode: bool,
        json_fh,
    ) -> None:
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
        json_fh,
    ) -> None:
        """Follow an anonymised device using only its IRK (no prior scan)."""
        placeholder = Devices.Device(address=[], name='""', RSSI=0)
        self._sniffer.scan()
        self._sniffer.follow(placeholder)
        self._sniffer.sendIRK(irk)
        self._loop(filters=filters, live=live, decode=decode, json_fh=json_fh)

    def _loop(self, *, filters: FilterSet, live: bool, decode: bool, json_fh) -> None:
        loops = 0
        packet_count = 0

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


def _capture_flags() -> argparse.ArgumentParser:
    """Shared flags for subcommands that capture packets."""
    p = argparse.ArgumentParser(add_help=False)
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
    shared = _capture_flags()

    parser = argparse.ArgumentParser(
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


def main() -> int:
    args = build_parser().parse_args()
    configure_logging(args.verbose)

    if args.command == "list":
        ports = UART.find_sniffer()
        if not ports:
            print("No sniffers found.")
            return 1
        for p in ports:
            print(p)
        return 0

    client = SnifferClient(args.capture_file)

    if args.command == "scan":
        devices = client.scan(args.timeout)
        if args.json:
            print(
                json.dumps(
                    [
                        {
                            "address": address_to_string(d),
                            "name": d.name.replace('"', ""),
                            "rssi": d.RSSI,
                        }
                        for d in devices
                    ],
                    indent=2,
                )
            )
        else:
            for d in devices:
                print(f"{address_to_string(d)}  {d.name.replace(chr(34), '')}")
        return 0

    filters = FilterSet.from_args(args)
    live = args.live
    decode = args.decode
    json_fh = (
        open(args.record_json, "a", encoding="utf-8") if args.record_json else None
    )

    try:
        if args.irk:
            try:
                irk = hex_to_bytes(args.irk)
            except ValueError as exc:
                logger.error("Invalid IRK: %s", exc)
                return 1
            client.follow_by_irk(
                irk, filters=filters, live=live, decode=decode, json_fh=json_fh
            )
        else:
            devices = client.scan(args.timeout, address=args.address, name=args.name)
            if not devices:
                logger.error("Device not found within %.0f s.", args.timeout)
                return 2
            client.follow(
                devices[0], filters=filters, live=live, decode=decode, json_fh=json_fh
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
