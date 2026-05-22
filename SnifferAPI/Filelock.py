from __future__ import annotations

import logging
import os
from pathlib import Path
from sys import platform

from . import Exceptions

if platform == "linux":
    import psutil


LOCK_DIR = Path("/var/lock")


def lockpid(lockfile: Path) -> int:
    """Return PID stored in lockfile, or 0 if invalid or missing."""
    if lockfile.is_file():
        try:
            content = lockfile.read_text().strip()
            return int(content)
        except Exception:
            logging.info("Lockfile is invalid. Overriding it..")
            try:
                lockfile.unlink()
            except Exception:
                pass
            return 0
    return 0


def lock(port: str) -> None:
    """Create a UUCP-style lockfile for a serial port on Linux."""
    if platform != "linux":
        return

    tty = os.path.basename(port)
    lockfile = LOCK_DIR / f"LCK..{tty}"

    pid = lockpid(lockfile)
    if pid:
        if pid == os.getpid():
            return

        if psutil.pid_exists(pid):
            raise Exceptions.LockedException(f"Device {port} is locked")
        else:
            logging.info("Lockfile is stale. Overriding it..")
            try:
                lockfile.unlink()
            except Exception:
                pass

    # Write our PID as a 10-byte decimal number with newline
    try:
        lockfile.write_text(f"{os.getpid():10}\n")
    except Exception as exc:
        logging.exception(f"Failed to create lockfile {lockfile}: {exc}")


def unlock(port: str) -> None:
    """Remove lockfile if owned by this process."""
    if platform != "linux":
        return

    tty = os.path.basename(port)
    lockfile = LOCK_DIR / f"LCK..{tty}"

    pid = lockpid(lockfile)
    if pid == os.getpid():
        try:
            lockfile.unlink()
        except Exception:
            logging.exception(f"Failed to remove lockfile {lockfile}")
