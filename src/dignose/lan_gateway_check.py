from __future__ import annotations

import http.client
import socket
from urllib.parse import urlsplit

from .utils import add_risk, is_private_ip, run_command, safe_collect

IGNORED_GATEWAYS = {"", "::", "0.0.0.0", "On-link", "on-link"}


def _tcp_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=1.5):
            return True
    except Exception:  # noqa: BLE001
        return False


def _http_headers(host: str, port: int) -> dict:
    try:
        conn_cls = http.client.HTTPSConnection if port == 443 else http.client.HTTPConnection
        conn = conn_cls(host, port=port, timeout=2)
        conn.request("HEAD", "/")
        response = conn.getresponse()
        headers = {key: value for key, value in response.getheaders()}
        conn.close()
        return {"ok": True, "status": response.status, "headers": headers}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)}


def collect(risks: list[dict[str, str]], adapters: dict | None = None, routes: dict | None = None, dns: dict | None = None) -> dict:
    def inner() -> dict:
        gateways: list[str] = []
        local_ips: list[str] = []
        if adapters and adapters.get("ok"):
            for adapter in adapters.get("data") or []:
                local_ips.extend(adapter.get("ipv4") or [])
                for gateway in adapter.get("defaultGateways") or []:
                    if gateway not in IGNORED_GATEWAYS and gateway not in gateways:
                        gateways.append(gateway)
        if routes and routes.get("ok"):
            for route in (routes.get("data") or {}).get("defaultRoutes") or []:
                hop = route.get("nextHop")
                if hop not in IGNORED_GATEWAYS and hop not in gateways:
                    gateways.append(hop)

        private_local = [ip for ip in local_ips if is_private_ip(ip)]
        private_gateways = [gateway for gateway in gateways if is_private_ip(gateway)]
        dns_servers = (dns.get("data") or {}).get("servers") if dns and dns.get("ok") else []
        dns_is_gateway = [server for server in dns_servers or [] if server in gateways]
        dns_lan_other = [server for server in dns_servers or [] if is_private_ip(server) and server not in gateways]
        ports = []
        headers = []
        for gateway in private_gateways[:3]:
            for port in (80, 443, 8080, 8443):
                open_ = _tcp_open(gateway, port)
                ports.append({"gateway": gateway, "port": port, "open": open_})
                if open_ and port in {80, 443, 8080, 8443}:
                    header = _http_headers(gateway, port)
                    headers.append({"gateway": gateway, "port": port, **header})

        text = " ".join(
            str(header.get("headers", {})).lower()
            for header in headers
            if header.get("ok")
        )
        openwrt_signs = [token for token in ("openwrt", "luci", "uhttpd") if token in text]
        if dns_lan_other:
            add_risk(risks, "medium", "lanGateway", "DNS 指向非默认网关的局域网地址，检测到可能的旁路由迹象。", ", ".join(dns_lan_other))
        if len(private_gateways) > 1:
            add_risk(risks, "medium", "lanGateway", "检测到多个私有默认网关，可能存在二级路由或 VPN 路由影响。", ", ".join(private_gateways))
        if openwrt_signs:
            add_risk(risks, "medium", "lanGateway", "默认网关 Web 响应检测到疑似 OpenWrt / LuCI / uhttpd 迹象。", ", ".join(openwrt_signs))

        arp = run_command(["arp", "-a"], timeout=6)
        return {
            "localPrivateAddresses": private_local,
            "defaultGateways": gateways,
            "privateGateways": private_gateways,
            "dnsIsGateway": dns_is_gateway,
            "dnsLanOther": dns_lan_other,
            "gatewayPorts": ports,
            "gatewayHttpHeaders": headers,
            "openwrtSigns": openwrt_signs,
            "arp": arp,
            "suspectedLan": bool(private_local and private_gateways),
            "suspectedSecondaryRouter": len(private_gateways) > 1,
            "suspectedSideRouter": bool(dns_lan_other),
            "suspectedOpenWrt": bool(openwrt_signs),
        }

    return safe_collect(inner)
