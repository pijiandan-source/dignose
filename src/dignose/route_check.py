from __future__ import annotations

import json
import re

from .utils import add_risk, as_list, run_command, run_powershell, safe_collect


IPV4_DEFAULT_ROW = re.compile(
    r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(?P<gateway>\S+)\s+(?P<interface>\S+)\s+(?P<metric>\d+)\s*$"
)
IPV6_DEFAULT_ROW = re.compile(r"^\s*(?P<ifindex>\d+)\s+(?P<metric>\d+)\s+::/0\s+(?P<gateway>.+?)\s*$")


def _parse_route_print(text: str) -> list[dict]:
    routes: list[dict] = []
    for line in text.splitlines():
        ipv4 = IPV4_DEFAULT_ROW.match(line)
        if ipv4:
            routes.append(
                {
                    "destination": "0.0.0.0/0",
                    "nextHop": ipv4.group("gateway"),
                    "routeMetric": int(ipv4.group("metric")),
                    "interfaceMetric": None,
                    "interfaceAlias": None,
                    "interfaceIndex": None,
                    "interfaceAddress": ipv4.group("interface"),
                }
            )
            continue
        ipv6 = IPV6_DEFAULT_ROW.match(line)
        if ipv6:
            routes.append(
                {
                    "destination": "::/0",
                    "nextHop": ipv6.group("gateway").strip(),
                    "routeMetric": int(ipv6.group("metric")),
                    "interfaceMetric": None,
                    "interfaceAlias": None,
                    "interfaceIndex": int(ipv6.group("ifindex")),
                }
            )
    return routes


def collect(risks: list[dict[str, str]]) -> dict:
    def inner() -> dict:
        result = run_powershell(
            "Get-NetRoute | Where-Object {$_.DestinationPrefix -eq '0.0.0.0/0' -or $_.DestinationPrefix -eq '::/0'} "
            "| Select-Object DestinationPrefix,NextHop,RouteMetric,InterfaceMetric,InterfaceAlias,InterfaceIndex "
            "| ConvertTo-Json -Depth 3",
            timeout=12,
        )
        routes: list[dict] = []
        if result.get("ok"):
            raw = json.loads((result.get("data") or {}).get("stdout") or "[]")
            for item in as_list(raw):
                routes.append(
                    {
                        "destination": item.get("DestinationPrefix"),
                        "nextHop": item.get("NextHop"),
                        "routeMetric": item.get("RouteMetric"),
                        "interfaceMetric": item.get("InterfaceMetric"),
                        "interfaceAlias": item.get("InterfaceAlias"),
                        "interfaceIndex": item.get("InterfaceIndex"),
                    }
                )
        else:
            fallback = run_command(["route", "print"], timeout=12)
            raw_text = (fallback.get("data") or {}).get("stdout", "")
            routes = _parse_route_print(raw_text)
            if not routes:
                routes.append({"raw": raw_text, "error": result.get("error")})

        ipv4_defaults = [r for r in routes if r.get("destination") == "0.0.0.0/0"]
        ipv6_defaults = [r for r in routes if r.get("destination") == "::/0"]
        if len(ipv4_defaults) > 1:
            add_risk(risks, "medium", "routes", "检测到多个 IPv4 默认路由，可能影响流量出口选择。", str(ipv4_defaults[:3]))
        if len(ipv6_defaults) > 1:
            add_risk(risks, "low", "routes", "检测到多个 IPv6 默认路由。", str(ipv6_defaults[:3]))
        if not ipv4_defaults and not ipv6_defaults and routes and not routes[0].get("raw"):
            add_risk(risks, "high", "routes", "未检测到默认路由，网络访问可能异常。", "")
        return {"defaultRoutes": routes, "ipv4DefaultCount": len(ipv4_defaults), "ipv6DefaultCount": len(ipv6_defaults)}

    return safe_collect(inner)
