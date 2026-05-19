from __future__ import annotations

import csv
import io
import json

from .utils import add_risk, as_list, run_command, run_powershell, safe_collect

WATCH_PORTS = {53, 80, 443, 7890, 7891, 7892, 1080, 10808, 8080, 8888, 9090, 51820, 1194, 500, 4500}
PROCESS_HINTS = ("clash", "v2ray", "xray", "sing-box", "mihomo", "openvpn", "wireguard", "tailscale", "zerotier")


def collect(risks: list[dict[str, str]]) -> dict:
    def inner() -> list[dict]:
        command = (
            "Get-NetTCPConnection -State Listen | "
            "Select-Object LocalAddress,LocalPort,OwningProcess,"
            "@{Name='ProcessName';Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} "
            "| ConvertTo-Json -Depth 3"
        )
        result = run_powershell(command, timeout=15)
        rows: list[dict] = []
        if result.get("ok"):
            raw = json.loads((result.get("data") or {}).get("stdout") or "[]")
            for item in as_list(raw):
                port = int(item.get("LocalPort") or 0)
                if port in WATCH_PORTS:
                    rows.append(
                        {
                            "protocol": "TCP",
                            "localAddress": item.get("LocalAddress"),
                            "localPort": port,
                            "pid": item.get("OwningProcess"),
                            "processName": item.get("ProcessName"),
                        }
                    )
        else:
            fallback = run_command(["netstat", "-ano"], timeout=12)
            for line in ((fallback.get("data") or {}).get("stdout") or "").splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[0].upper() == "TCP" and parts[3].upper() == "LISTENING":
                    address = parts[1]
                    try:
                        port = int(address.rsplit(":", 1)[1])
                    except ValueError:
                        continue
                    if port in WATCH_PORTS:
                        rows.append({"protocol": "TCP", "localAddress": address, "localPort": port, "pid": parts[-1], "processName": None})

        for row in rows:
            process = (row.get("processName") or "").lower()
            if row["localPort"] in {7890, 7891, 7892, 1080, 10808, 8080, 8888, 9090} or any(h in process for h in PROCESS_HINTS):
                add_risk(
                    risks,
                    "info",
                    "ports",
                    "检测到常见代理、VPN 或调试端口正在监听。",
                    f"{row.get('localAddress')}:{row.get('localPort')} PID={row.get('pid')} Process={row.get('processName')}",
                )
        return rows

    return safe_collect(inner)

