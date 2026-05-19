from __future__ import annotations

import ipaddress
import json
import locale
import os
import platform
import subprocess
import sys
from collections.abc import Callable
from typing import Any


Result = dict[str, Any]


def section(ok: bool, data: Any = None, error: str | None = None) -> Result:
    return {"ok": ok, "data": data, "error": error}


def safe_collect(fn: Callable[[], Any]) -> Result:
    try:
        return section(True, fn(), None)
    except Exception as exc:  # noqa: BLE001 - every diagnostic must be isolated.
        return section(False, None, str(exc))


def run_command(args: list[str], timeout: int = 10) -> Result:
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            encoding=locale.getpreferredencoding(False),
            errors="replace",
            timeout=timeout,
            shell=False,
        )
        return section(
            completed.returncode == 0,
            {
                "args": args,
                "returncode": completed.returncode,
                "stdout": completed.stdout.strip(),
                "stderr": completed.stderr.strip(),
            },
            None if completed.returncode == 0 else completed.stderr.strip() or completed.stdout.strip(),
        )
    except FileNotFoundError as exc:
        return section(False, {"args": args}, f"command not found: {exc.filename}")
    except subprocess.TimeoutExpired:
        return section(False, {"args": args}, f"command timed out after {timeout}s")
    except Exception as exc:  # noqa: BLE001
        return section(False, {"args": args}, str(exc))


def run_powershell(command: str, timeout: int = 10) -> Result:
    exe = "powershell.exe" if platform.system().lower() == "windows" else "powershell"
    return run_command(
        [exe, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
        timeout=timeout,
    )


def parse_json_output(result: Result) -> Any:
    stdout = ((result.get("data") or {}).get("stdout") or "").strip()
    if not stdout:
        raise ValueError("PowerShell output is empty")
    return json.loads(stdout)


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def add_risk(risks: list[dict[str, str]], level: str, category: str, message: str, evidence: str = "") -> None:
    risks.append({"level": level, "category": category, "message": message, "evidence": evidence})


def is_private_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return ip.is_private and not ip.is_loopback and not ip.is_unspecified
    except ValueError:
        return False


def is_loopback_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def safe_json_dumps(data: Any, indent: int | None = 2) -> str:
    return json.dumps(data, ensure_ascii=False, indent=indent)


def safe_print(text: str) -> None:
    try:
        print(text)
    except UnicodeEncodeError:
        encoding = sys.stdout.encoding or "utf-8"
        payload = (text + "\n").encode(encoding, errors="replace")
        try:
            sys.stdout.buffer.write(payload)
            sys.stdout.buffer.flush()
        except Exception:
            sys.stdout.write(payload.decode(encoding, errors="replace"))
            sys.stdout.write("\n")


def getenv(name: str) -> str | None:
    value = os.environ.get(name)
    return value if value else None
