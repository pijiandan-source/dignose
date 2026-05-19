from __future__ import annotations

import os
import re

from .utils import add_risk, is_loopback_ip, is_private_ip, run_command, safe_collect

PROXY_ENV_NAMES = ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy"]
REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
HOST_RE = re.compile(r"(?:(?:https?|socks5?)://)?(?:[^@/\s]+@)?\[?([A-Za-z0-9_.:-]+)\]?")


def _host_hint(value: str) -> dict:
    match = HOST_RE.search(value)
    host = match.group(1).split(":", 1)[0] if match else ""
    return {"host": host, "isLoopback": is_loopback_ip(host), "isPrivate": is_private_ip(host)}


def _read_internet_settings() -> dict:
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH) as key:
            values = {}
            for name in ("ProxyEnable", "ProxyServer", "AutoConfigURL", "AutoDetect"):
                try:
                    values[name], _ = winreg.QueryValueEx(key, name)
                except FileNotFoundError:
                    values[name] = None
            return values
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


def collect(risks: list[dict[str, str]]) -> dict:
    def inner() -> dict:
        internet = _read_internet_settings()
        if internet.get("ProxyEnable") or internet.get("ProxyServer") or internet.get("AutoConfigURL"):
            add_risk(
                risks,
                "medium",
                "proxy",
                "系统 Internet 代理配置已启用或存在自动配置，可能影响加速器流量路径。",
                f"ProxyEnable={internet.get('ProxyEnable')} ProxyServer={internet.get('ProxyServer')} AutoConfigURL={internet.get('AutoConfigURL')}",
            )

        winhttp = run_command(["netsh", "winhttp", "show", "proxy"], timeout=8)
        winhttp_text = (winhttp.get("data") or {}).get("stdout", "")
        if winhttp.get("ok") and winhttp_text and "Direct access" not in winhttp_text and "直接访问" not in winhttp_text:
            add_risk(risks, "medium", "proxy", "检测到 WinHTTP 代理配置。", winhttp_text[:200])

        env = []
        for name in PROXY_ENV_NAMES:
            value = os.environ.get(name)
            if value:
                hint = _host_hint(value)
                env.append({"name": name, "value": value, **hint})
                add_risk(risks, "medium", "proxy", f"检测到 {name} 环境变量，可能影响部分应用流量。", f"{name}={value}")

        return {"internetSettings": internet, "winhttp": winhttp, "environment": env}

    return safe_collect(inner)

