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
import logging.handlers as logHandlers
import os
import threading
import time
import traceback

#################################################################
# This file contains the logger. To log a line, simply write    #
# 'logging.[level]("whatever you want to log")'                 #
# [level] is one of {info, debug, warning, error, critical,     #
#     exception}                                                #
# See python logging documentation                              #
# As long as Logger.initLogger has been called beforehand, this #
# will result in the line being appended to the log file        #
#################################################################

appdata = os.getenv("appdata")
if appdata:
    DEFAULT_LOG_FILE_DIR = os.path.join(
        appdata, "Nordic Semiconductor", "Sniffer", "logs"
    )
else:
    DEFAULT_LOG_FILE_DIR = "/tmp/logs"

DEFAULT_LOG_FILE_NAME = "log.txt"

logFileName: str | None = None
logHandler: logHandlers.RotatingFileHandler | None = None
logHandlerArray: list[logging.Handler] = []
logFlusher: "LogFlusher" | None = None

myMaxBytes: int = 1_000_000


def setLogFileName(log_file_path: str) -> None:
    """Set the absolute path of the log file to use."""
    global logFileName
    logFileName = os.path.abspath(log_file_path)


def initLogger() -> None:
    """Initialize the global logger and start the flusher thread."""
    try:
        global logFileName, logHandler, logFlusher, logHandlerArray

        if logFileName is None:
            logFileName = os.path.join(DEFAULT_LOG_FILE_DIR, DEFAULT_LOG_FILE_NAME)

        log_dir = os.path.dirname(logFileName)
        if not os.path.isdir(log_dir):
            os.makedirs(log_dir, exist_ok=True)

        if not os.path.isfile(logFileName):
            with open(logFileName, "w", encoding="utf-8") as f:
                f.write(f"{time.time()}{os.linesep}")

        logHandler = MyRotatingFileHandler(
            logFileName, mode="a", maxBytes=myMaxBytes, backupCount=3
        )
        logFormatter = logging.Formatter(
            "%(asctime)s %(levelname)s: %(message)s",
            datefmt="%d-%b-%Y %H:%M:%S (%z)",
        )
        logHandler.setFormatter(logFormatter)

        logger = logging.getLogger()
        logger.addHandler(logHandler)
        logger.setLevel(logging.INFO)

        logFlusher = LogFlusher(logHandler)
        logHandlerArray.append(logHandler)
    except Exception:
        print("LOGGING FAILED")
        print(traceback.format_exc())
        raise


def shutdownLogger() -> None:
    """Stop the flusher thread and shut down logging."""
    global logFlusher
    if logFlusher is not None:
        logFlusher.stop()
        logFlusher = None
    logging.shutdown()


def clearLog() -> None:
    """Clear the log by forcing a rollover."""
    try:
        if logHandler is not None:
            logHandler.doRollover()
    except Exception:
        print("LOGGING FAILED")
        raise


def getTimestamp() -> str | None:
    """Return the timestamp on the first line of the logfile."""
    if logFileName is None:
        return None
    try:
        with open(logFileName, "r", encoding="utf-8") as f:
            f.seek(0)
            return f.readline()
    except Exception:
        print("LOGGING FAILED")
        return None


def addTimestamp() -> None:
    """Append a timestamp line to the logfile."""
    if logFileName is None:
        return
    try:
        with open(logFileName, "a", encoding="utf-8") as f:
            f.write(f"{time.time()}{os.linesep}")
    except Exception:
        print("LOGGING FAILED")


def readAll() -> str:
    """Return the entire content of the logfile."""
    if logFileName is None:
        return ""
    try:
        with open(logFileName, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        print("LOGGING FAILED")
        return ""


def addLogHandler(handler: logging.Handler) -> None:
    """Add an extra logging handler and track it in the global list."""
    global logHandlerArray
    logger = logging.getLogger()
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logHandlerArray.append(handler)


def removeLogHandler(handler: logging.Handler) -> None:
    """Remove a logging handler previously added."""
    global logHandlerArray
    logger = logging.getLogger()
    logger.removeHandler(handler)
    if handler in logHandlerArray:
        logHandlerArray.remove(handler)


class MyRotatingFileHandler(logHandlers.RotatingFileHandler):
    """Custom rotating file handler that appends a timestamp after rollover."""

    def doRollover(self) -> None:
        try:
            super().doRollover()
            addTimestamp()
            self.maxBytes = myMaxBytes
        except Exception:
            # There have been permissions issues with the log files.
            self.maxBytes += int(myMaxBytes / 2)


class LogFlusher(threading.Thread):
    """Background thread that periodically flushes the log handler."""

    def __init__(self, logHandler: logging.Handler) -> None:
        super().__init__()
        self.daemon = True
        self.handler = logHandler
        self.exit = threading.Event()
        self.start()

    def run(self) -> None:
        while True:
            if self.exit.wait(10):
                try:
                    self.doFlush()
                except AttributeError as e:
                    print(e)
                break
            self.doFlush()

    def doFlush(self) -> None:
        self.handler.flush()
        stream = getattr(self.handler, "stream", None)
        if stream is not None and hasattr(stream, "fileno"):
            try:
                os.fsync(stream.fileno())
            except OSError:
                # If fsync fails (e.g. closed file), ignore and continue.
                pass

    def stop(self) -> None:
        self.exit.set()


if __name__ == "__main__":
    initLogger()
    for i in range(50):
        logging.info(f"test log no. {i}")
        print("test log no. ", i)
