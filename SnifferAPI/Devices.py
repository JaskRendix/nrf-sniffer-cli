# Copyright (c) 2017, Nordic Semiconductor ASA
#
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
import threading
from collections.abc import Iterable

from . import Notifications


class DeviceList(Notifications.Notifier):
    """Thread‑safe list of discovered BLE devices with update notifications."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._deviceListLock = threading.RLock()
        self.devices: list[Device] = []

    def __len__(self) -> int:
        return len(self.devices)

    def __repr__(self) -> str:
        return f"Sniffer Device List: {self.asList()}"

    def clear(self) -> None:
        logging.info("Clearing device list")
        with self._deviceListLock:
            self.devices.clear()
            self.notify("DEVICES_CLEARED")

    def appendOrUpdate(self, newDevice: Device) -> None:
        """Insert a new device or update an existing one."""
        with self._deviceListLock:
            existing = self.find(newDevice)

            if existing is None:
                self.append(newDevice)
                return

            updated = False

            # Update name if previously unknown
            if newDevice.name != '""' and existing.name == '""':
                existing.name = newDevice.name
                updated = True

            # Update RSSI if significantly changed
            if newDevice.RSSI != 0 and (
                existing.RSSI < (newDevice.RSSI - 5)
                or existing.RSSI > (newDevice.RSSI + 2)
            ):
                existing.RSSI = newDevice.RSSI
                updated = True

            if updated:
                self.notify("DEVICE_UPDATED", existing)

    def append(self, device: Device) -> None:
        with self._deviceListLock:
            self.devices.append(device)
            self.notify("DEVICE_ADDED", device)

    def find(self, key: list[int] | int | str | Device) -> Device | None:
        """Find a device by address list, index, name, or Device instance."""
        with self._deviceListLock:
            if isinstance(key, list):
                return next((d for d in self.devices if d.address == key), None)

            if isinstance(key, int):
                return self.devices[key] if 0 <= key < len(self.devices) else None

            if isinstance(key, str):
                return next(
                    (d for d in self.devices if d.name in (key, f'"{key}"')),
                    None,
                )

            if isinstance(key, Device):
                return self.find(key.address)

        return None

    def remove(self, key: list[int] | int | Device) -> None:
        with self._deviceListLock:
            if isinstance(key, list):
                device = self.find(key)
                if device:
                    self.devices.remove(device)

            elif isinstance(key, int):
                device = self.devices.pop(key)

            elif isinstance(key, Device):
                device = self.find(key.address)
                if device:
                    self.devices.remove(device)

            else:
                return

            self.notify("DEVICE_REMOVED", device)

    def index(self, device: Device) -> int | None:
        with self._deviceListLock:
            for idx, dev in enumerate(self.devices):
                if dev.address == device.address:
                    return idx
        return None

    def setFollowed(self, device: Device) -> None:
        with self._deviceListLock:
            if device in self.devices:
                for dev in self.devices:
                    dev.followed = False
                device.followed = True

        self.notify("DEVICE_FOLLOWED", device)

    def asList(self) -> list[Device]:
        with self._deviceListLock:
            return list(self.devices)


class Device:
    """Simple BLE device representation."""

    def __init__(self, address: list[int], name: str, RSSI: int):
        self.address: list[int] = address
        self.name: str = name
        self.RSSI: int = RSSI
        self.followed: bool = False

    def __repr__(self) -> str:
        return f'Bluetooth LE device "{self.name}" ({self.address})'


def listToString(values: Iterable[int]) -> str:
    """Convert a list of byte values to a string."""
    return bytes(values).decode("latin1")
