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

import threading
from collections.abc import Callable
from typing import Any


class Notification:
    """Simple notification object carrying a key and optional message."""

    def __init__(self, key: str, msg: Any = None):
        if not isinstance(key, str):
            raise TypeError(f"Invalid notification key: {key!r}")
        self.key: str = key
        self.msg: Any = msg

    def __repr__(self) -> str:
        return f"Notification(key={self.key!r}, msg={self.msg!r})"


Callback = Callable[[Notification], None]


class Notifier:
    """Thread‑safe publish/subscribe notification dispatcher."""

    def __init__(
        self,
        callbacks: list[tuple[str, Callback]] | None = None,
        **kwargs: Any,
    ):
        self._callbacks: dict[str, list[Callback]] = {}
        self._lock = threading.RLock()

        if callbacks:
            for key, cb in callbacks:
                self.subscribe(key, cb)

    def clearCallbacks(self) -> None:
        with self._lock:
            self._callbacks.clear()

    def subscribe(self, key: str, callback: Callback) -> None:
        with self._lock:
            lst = self._callbacks.setdefault(key, [])
            if callback not in lst:
                lst.append(callback)

    def unSubscribe(self, key: str, callback: Callback) -> None:
        with self._lock:
            lst = self._callbacks.get(key)
            if lst and callback in lst:
                lst.remove(callback)

    def getCallbacks(self, key: str) -> list[Callback]:
        with self._lock:
            return self._callbacks.setdefault(key, [])

    def notify(
        self,
        key: str | None = None,
        msg: Any = None,
        notification: Notification | None = None,
    ) -> None:
        """Send a notification to all subscribers of the key and '*'."""
        with self._lock:
            if notification is None:
                notification = Notification(key, msg)

            # Call specific listeners
            for cb in self._callbacks.get(notification.key, []):
                try:
                    cb(notification)
                except Exception as e:
                    # Never let one callback break the dispatcher
                    import logging

                    logging.exception(f"Notifier callback failed: {e}")

            # Call wildcard listeners
            for cb in self._callbacks.get("*", []):
                try:
                    cb(notification)
                except Exception as e:
                    import logging

                    logging.exception(f"Notifier wildcard callback failed: {e}")

    def passOnNotification(self, notification: Notification) -> None:
        """Forward an existing notification."""
        self.notify(notification=notification)
