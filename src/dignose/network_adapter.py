from __future__ import annotations

import json
import re

from .utils import as_list, run_command, run_powershell, safe_collect

ADAPTER_HEADER = re.compile(r"^\S.* adapter (?P<name>.+):$")
PROPERTY_LINE = re.compile(r"^\s{3}(?P<key>[^:]+?)\s*:\s*(?P<value>.*)$")


def _classify(name: str, description: str) -> str:
    text = f"{name} {description}".lower()
    if any(token in text for token in ("wi-fi", "wifi", "wireless", "802.11")):
        return "Wi-Fi"
    if any(token in text for token in ("vpn", "tap", "tun", "wireguard", "openvpn")):
        return "VPN"
    if any(token in text for token in ("hyper-v", "wsl", "vmware", "virtualbox", "virtual", "veth")):
        return "Virtual"
    if any(token in text for token in ("ethernet", "gbe", "realtek", "intel")):
        return "Ethernet"
    return "Unknown"


def _parse_ipconfig(text: str) -> list[dict]:
    adapters: list[dict] = []
    current: dict | None = None
    last_key: str | None = None
    for line in text.splitlines():
        header = ADAPTER_HEADER.match(line)
        if header:
            if current:
                adapters.append(current)
            name = header.group("name").strip()
            current = {
                "name": name,
                "description": "",
                "status": "Disconnected" if "disconnected" in line.lower() else None,
                "type": "Unknown",
                "macAddress": None,
                "ipv4": [],
                "ipv6": [],
                "defaultGateways": [],
                "dnsServers": [],
                "dhcp": None,
            }
            last_key = None
            continue
        if not current:
            continue
        prop = PROPERTY_LINE.match(line)
        if prop:
            key = " ".join(prop.group("key").replace(".", " ").split()).lower()
            value = prop.group("value").strip()
            last_key = key
        elif last_key and line.startswith(" ") and line.strip():
            key = last_key
            value = line.strip()
        else:
            continue

        value = value.replace("(Preferred)", "").strip()
        if not value:
            continue
        if key.startswith("description"):
            current["description"] = value
            current["type"] = _classify(current["name"], value)
        elif key.startswith("physical address"):
            current["macAddress"] = value
        elif key.startswith("dhcp enabled"):
            current["dhcp"] = value.lower().startswith("yes")
        elif key.startswith("media state") and "disconnected" in value.lower():
            current["status"] = "Disconnected"
        elif key.startswith("ipv4 address"):
            current["ipv4"].append(value)
            current["status"] = current["status"] or "Up"
        elif "ipv6 address" in key:
            current["ipv6"].append(value)
            current["status"] = current["status"] or "Up"
        elif key.startswith("default gateway"):
            current["defaultGateways"].append(value)
        elif key.startswith("dns servers"):
            current["dnsServers"].append(value)

    if current:
        adapters.append(current)
    return adapters


def collect() -> dict:
    def inner() -> list[dict]:
        command = (
            "Get-NetIPConfiguration | Select-Object InterfaceAlias,InterfaceDescription,NetAdapter,IPv4Address,"
            "IPv6Address,IPv4DefaultGateway,IPv6DefaultGateway,DNSServer | ConvertTo-Json -Depth 6"
        )
        result = run_powershell(command, timeout=12)
        if result.get("ok"):
            raw = json.loads((result.get("data") or {}).get("stdout") or "[]")
            adapters: list[dict] = []
            for item in as_list(raw):
                net_adapter = item.get("NetAdapter") or {}
                name = item.get("InterfaceAlias") or net_adapter.get("Name") or ""
                description = item.get("InterfaceDescription") or net_adapter.get("InterfaceDescription") or ""
                dns = item.get("DNSServer") or {}
                adapters.append(
                    {
                        "name": name,
                        "description": description,
                        "status": net_adapter.get("Status"),
                        "type": _classify(name, description),
                        "macAddress": net_adapter.get("MacAddress"),
                        "ipv4": [x.get("IPAddress") for x in as_list(item.get("IPv4Address")) if x.get("IPAddress")],
                        "ipv6": [x.get("IPAddress") for x in as_list(item.get("IPv6Address")) if x.get("IPAddress")],
                        "defaultGateways": [
                            x.get("NextHop")
                            for x in as_list(item.get("IPv4DefaultGateway")) + as_list(item.get("IPv6DefaultGateway"))
                            if x.get("NextHop")
                        ],
                        "dnsServers": dns.get("ServerAddresses") or [],
                        "dhcp": None,
                    }
                )
            if adapters:
                return adapters

        cim = run_powershell(
            "Get-CimInstance Win32_NetworkAdapterConfiguration -Filter \"IPEnabled=True\" | "
            "Select-Object Description,IPAddress,DefaultIPGateway,DNSServerSearchOrder,DHCPEnabled,MACAddress "
            "| ConvertTo-Json -Depth 4",
            timeout=12,
        )
        if cim.get("ok"):
            raw = json.loads((cim.get("data") or {}).get("stdout") or "[]")
            adapters = []
            for item in as_list(raw):
                description = item.get("Description") or ""
                addresses = item.get("IPAddress") or []
                ipv4 = [value for value in addresses if "." in value]
                ipv6 = [value for value in addresses if ":" in value]
                adapters.append(
                    {
                        "name": description,
                        "description": description,
                        "status": "Up",
                        "type": _classify(description, description),
                        "macAddress": item.get("MACAddress"),
                        "ipv4": ipv4,
                        "ipv6": ipv6,
                        "defaultGateways": item.get("DefaultIPGateway") or [],
                        "dnsServers": item.get("DNSServerSearchOrder") or [],
                        "dhcp": item.get("DHCPEnabled"),
                    }
                )
            if adapters:
                return adapters

        fallback = run_command(["ipconfig", "/all"], timeout=12)
        parsed = _parse_ipconfig((fallback.get("data") or {}).get("stdout", ""))
        if parsed:
            return parsed
        return [
            {
                "name": "ipconfig /all fallback",
                "description": "PowerShell Get-NetIPConfiguration failed",
                "status": None,
                "type": "Unknown",
                "raw": (fallback.get("data") or {}).get("stdout", ""),
                "error": result.get("error"),
            }
        ]

    return safe_collect(inner)
