from __future__ import annotations

import ctypes
import getpass
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .utils import safe_collect


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


def collect() -> dict:
    def inner() -> dict:
        return {
            "windows": platform.platform(),
            "release": platform.release(),
            "version": platform.version(),
            "architecture": platform.machine(),
            "username": getpass.getuser(),
            "isAdmin": _is_admin(),
            "python": sys.version.split()[0],
            "executable": str(Path(sys.executable)),
            "cwd": str(Path.cwd()),
            "time": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
            "toolVersion": __version__,
        }

    return safe_collect(inner)

