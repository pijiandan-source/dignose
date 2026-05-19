from __future__ import annotations

import socket
import time

from .utils import add_risk, is_loopback_ip, is_private_ip, run_powershell, safe_collect

PUBLIC_DNS = {
    "8.8.8.8": "Google Public DNS",
    "8.8.4.4": "Google Public DNS",
    "1.1.1.1": "Cloudflare DNS",
    "1.0.0.1": "Cloudflare DNS",
    "9.9.9.9": "Quad9 DNS",
    "114.114.114.114": "114DNS",
    "223.5.5.5": "AliDNS",
    "223.6.6.6": "AliDNS",
}
TEST_DOMAINS = ["example.com", "cloudflare.com", "openai.com", "steamcommunity.com"]


def collect(risks: list[dict[str, str]], adapters: dict | None = None, skip_queries: bool = False) -> dict:
    def inner() -> dict:
        servers: list[str] = []
        if adapters and adapters.get("ok"):
            for adapter in adapters.get("data") or []:
                for server in adapter.get("dnsServers") or []:
                    if server and server not in servers:
                        servers.append(server)
        if not servers:
            ps = run_powershell("Get-DnsClientServerAddress -AddressFamily IPv4,IPv6 | ConvertTo-Json -Depth 4")
            if ps.get("ok"):
                import json

                raw = json.loads((ps.get("data") or {}).get("stdout") or "[]")
                for item in raw if isinstance(raw, list) else [raw]:
                    for server in item.get("ServerAddresses") or []:
                        if server not in servers:
                            servers.append(server)

        loopback = [item for item in servers if is_loopback_ip(item)]
        private = [item for item in servers if is_private_ip(item) and not is_loopback_ip(item)]
        public = [{"address": item, "name": PUBLIC_DNS[item]} for item in servers if item in PUBLIC_DNS]
        if loopback:
            add_risk(risks, "medium", "dns", "DNS 指向本机，可能由本地代理或 DNS 服务接管。", ", ".join(loopback))
        if private:
            add_risk(risks, "low", "dns", "DNS 指向局域网地址，可能由路由器或旁路由接管。", ", ".join(private))
        if public:
            add_risk(risks, "info", "dns", "检测到常见公共 DNS。", ", ".join(item["address"] for item in public))

        queries = []
        if not skip_queries:
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(3)
            try:
                for domain in TEST_DOMAINS:
                    started = time.perf_counter()
                    try:
                        records = sorted({info[4][0] for info in socket.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP)})
                        queries.append(
                            {
                                "domain": domain,
                                "ok": True,
                                "addresses": records[:10],
                                "elapsedMs": round((time.perf_counter() - started) * 1000),
                                "error": None,
                            }
                        )
                    except Exception as exc:  # noqa: BLE001
                        queries.append(
                            {
                                "domain": domain,
                                "ok": False,
                                "addresses": [],
                                "elapsedMs": round((time.perf_counter() - started) * 1000),
                                "error": str(exc),
                            }
                        )
            finally:
                socket.setdefaulttimeout(old_timeout)

        return {
            "servers": servers,
            "loopbackServers": loopback,
            "privateServers": private,
            "publicServers": public,
            "queries": queries,
        }

    return safe_collect(inner)

