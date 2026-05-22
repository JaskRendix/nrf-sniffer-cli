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
from pathlib import Path

from . import Logger, Pcap

DEFAULT_CAPTURE_FILE_DIR: str = Logger.DEFAULT_LOG_FILE_DIR
DEFAULT_CAPTURE_FILE_NAME: str = "capture.pcap"


def get_capture_file_path(capture_file_path: str | None = None) -> str:
    """Return a valid .pcap file path, falling back to the default."""
    default_path = Path(DEFAULT_CAPTURE_FILE_DIR) / DEFAULT_CAPTURE_FILE_NAME

    if capture_file_path is None:
        return str(default_path)

    path = Path(capture_file_path)
    if path.suffix != ".pcap":
        return str(default_path)

    return str(path.resolve())


class CaptureFileHandler:
    """Manage capture file creation, rollover, and packet writing."""

    def __init__(self, capture_file_path: str | None = None, clear: bool = False):
        filename = Path(get_capture_file_path(capture_file_path))
        directory = filename.parent

        directory.mkdir(parents=True, exist_ok=True)

        self.filename: Path = filename
        self.backupFilename: Path = filename.with_suffix(filename.suffix + ".1")

        if not self.filename.exists():
            self.startNewFile()
        elif self.filename.stat().st_size > 20_000_000:
            self.doRollover()

        if clear:
            self.startNewFile()

    def startNewFile(self) -> None:
        """Create a new capture file with a global PCAP header."""
        with self.filename.open("wb") as f:
            f.write(Pcap.get_global_header())

    def doRollover(self) -> None:
        """Rotate the capture file, keeping a single backup."""
        try:
            if self.backupFilename.exists():
                self.backupFilename.unlink()
        except Exception:
            logging.exception("capture file rollover remove backup failed")

        try:
            self.filename.rename(self.backupFilename)
            self.startNewFile()
        except Exception:
            logging.exception("capture file rollover failed")

    def writePacket(self, packet) -> None:
        """Append a packet to the capture file."""
        with self.filename.open("ab") as f:
            raw = bytes([packet.boardId] + packet.getList())
            pcap_packet = Pcap.create_packet(raw, packet.time)
            f.write(pcap_packet)
