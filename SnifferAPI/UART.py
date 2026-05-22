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

import collections
import logging
import os
from threading import Event, Thread
from typing import Deque

import serial
import serial.tools.list_ports as list_ports

from . import Exceptions, Filelock, Packet

if os.name == "posix":
    import termios


SNIFFER_OLD_DEFAULT_BAUDRATE: int = 460800
SNIFFER_BAUDRATES: list[int] = [1_000_000, 460_800]


def find_sniffer(write_data: bool = False) -> list[str]:
    """Scan all serial ports and return those that respond like a Nordic sniffer."""
    open_ports = list_ports.comports()
    sniffers: list[str] = []

    for port in (x.device for x in open_ports):
        for rate in SNIFFER_BAUDRATES:
            reader: Packet.PacketReader | None = None

            error_types = [
                serial.SerialException,
                ValueError,
                Exceptions.LockedException,
            ]
            if os.name == "posix":
                error_types.append(termios.error)

            try:
                reader = Packet.PacketReader(portnum=port, baudrate=rate)
                try:
                    if write_data:
                        reader.sendPingReq()
                        reader.decodeFromSLIP(0.1, complete_timeout=0.1)
                    else:
                        reader.decodeFromSLIP(0.3, complete_timeout=0.3)

                    sniffers.append(port)
                    break
                except (Exceptions.SnifferTimeout, Exceptions.UARTPacketError):
                    pass

            except tuple(error_types):
                continue

            finally:
                if reader is not None:
                    reader.doExit()

    return sniffers


def find_sniffer_baudrates(
    port: str, write_data: bool = False
) -> dict[str, list[int]] | None:
    """Return the working baudrate for a sniffer port, or None if none match."""
    for rate in SNIFFER_BAUDRATES:
        reader: Packet.PacketReader | None = None
        try:
            reader = Packet.PacketReader(portnum=port, baudrate=rate)
            try:
                if write_data:
                    reader.sendPingReq()
                    reader.decodeFromSLIP(0.1, complete_timeout=0.1)
                else:
                    reader.decodeFromSLIP(0.3, complete_timeout=0.3)

                return {"default": rate, "other": []}

            except (Exceptions.SnifferTimeout, Exceptions.UARTPacketError):
                pass

        finally:
            if reader is not None:
                reader.doExit()

    return None


class Uart:
    """UART wrapper with background read thread and safe shutdown."""

    def __init__(self, portnum: str | None = None, baudrate: int | None = None):
        self.ser: serial.Serial | None = None

        try:
            if baudrate is not None and baudrate not in SNIFFER_BAUDRATES:
                raise ValueError(f"Invalid baudrate: {baudrate}")

            logging.info(f"Opening serial port {portnum}")

            self.portnum = portnum
            if self.portnum:
                Filelock.lock(portnum)

            self.ser = serial.Serial(
                port=portnum,
                baudrate=9600,
                rtscts=True,
                exclusive=True,
            )
            self.ser.baudrate = baudrate

        except Exception:
            if self.ser:
                self.ser.close()
                self.ser = None
            raise

        self.read_queue: Deque[int] = collections.deque()
        self.read_queue_has_data: Event = Event()

        self.reading: bool = True
        self.worker_thread: Thread = Thread(target=self._read_worker, daemon=True)
        self.worker_thread.start()

    def _read_worker(self) -> None:
        assert self.ser is not None
        self.ser.reset_input_buffer()

        while self.reading:
            try:
                data = self.ser.read(self.ser.in_waiting or 1)
                self._read_queue_extend(data)
            except serial.SerialException as exc:
                logging.info(f"Unable to read UART: {exc}")
                self.reading = False
                return

    def close(self) -> None:
        """Stop the worker thread and close the serial port."""
        if self.ser:
            logging.info("closing UART")
            self.reading = False
            self.read_queue_has_data.set()

            if hasattr(self.ser, "cancel_read"):
                self.ser.cancel_read()

            self.worker_thread.join()
            self.ser.close()
            self.ser = None

        if getattr(self, "portnum", None):
            Filelock.unlock(self.portnum)

    def __del__(self):
        if hasattr(self, "ser") or hasattr(self, "portnum"):
            try:
                self.close()
            except Exception:
                pass

    def switchBaudRate(self, newBaudRate: int) -> None:
        assert self.ser is not None
        self.ser.baudrate = newBaudRate

    def readByte(self, timeout: float | None = None) -> int | None:
        return self._read_queue_get(timeout)

    def writeList(self, array: bytes | bytearray | list[int]) -> None:
        assert self.ser is not None
        try:
            self.ser.write(array)
        except serial.SerialTimeoutException:
            logging.info("Got write timeout, ignoring error")
        except serial.SerialException as exc:
            self.ser.close()
            raise exc

    def _read_queue_extend(self, data: bytes) -> None:
        if data:
            self.read_queue.extend(data)
            self.read_queue_has_data.set()

    def _read_queue_get(self, timeout: float | None) -> int | None:
        if self.read_queue_has_data.wait(timeout):
            self.read_queue_has_data.clear()
            try:
                value = self.read_queue.popleft()
            except IndexError:
                return None

            if self.read_queue:
                self.read_queue_has_data.set()

            return value

        return None


def list_serial_ports():
    """Return available serial ports."""
    return list_ports.comports()


if __name__ == "__main__":
    import time

    t_start = time.time()
    ports = find_sniffer()
    t_mid = time.time()
    print(ports)
    print(f"find_sniffer took {t_mid - t_start:.3f} seconds")

    for p in ports:
        t = time.time()
        print(find_sniffer_baudrates(p))
        print(f"find_sniffer_baudrate took {time.time() - t:.3f} seconds")

    print(f"total runtime {time.time() - t_start:.3f}")
