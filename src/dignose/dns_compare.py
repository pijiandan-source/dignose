from __future__ import annotations

import ipaddress
import json
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from .utils import add_risk, safe_collect

DEFAULT_DOMAINS = [
    ("www.baidu.com", "basic_china"),
    ("www.qq.com", "basic_china"),
    ("www.163.com", "netease"),
    ("uu.163.com", "netease_accelerator"),
    ("adl.netease.com", "netease_accelerator"),
    ("steampowered.com", "gaming"),
    ("steamcommunity.com", "gaming"),
    ("github.com", "ai_dev"),
    ("openai.com", "ai_dev"),
    ("dns.alidns.com", "dns_provider"),
    ("doh.pub", "dns_provider"),
]

FULL_DOMAINS = DEFAULT_DOMAINS + [
    ("www.aliyun.com", "basic_china"),
    ("www.microsoft.com", "basic"),
    ("163.com", "netease"),
    ("netease.com", "netease"),
    ("www.netease.com", "netease"),
    ("uu.163.com.cn", "netease_accelerator"),
    ("uu.163.cn", "netease_accelerator"),
    ("uu.163.com/api", "netease_accelerator"),
    ("uu.163.com/client", "netease_accelerator"),
    ("nie.netease.com", "netease"),
    ("epicgames.com", "gaming"),
    ("riotgames.com", "gaming"),
    ("battle.net", "gaming"),
    ("blizzard.com", "gaming"),
    ("chatgpt.com", "ai_dev"),
    ("api.openai.com", "ai_dev"),
    ("api.github.com", "ai_dev"),
    ("doh.360.cn", "dns_provider"),
]

CHINA_UDP_DNS_PROVIDERS = [
    {"name": "AliDNS", "server": "223.5.5.5"},
    {"name": "AliDNS Secondary", "server": "223.6.6.6"},
    {"name": "DNSPod Tencent", "server": "119.29.29.29"},
    {"name": "DNSPod Tencent Secondary", "server": "182.254.116.116"},
    {"name": "Baidu DNS", "server": "180.76.76.76"},
    {"name": "114DNS", "server": "114.114.114.114"},
    {"name": "114DNS Secondary", "server": "114.114.115.115"},
]

DEFAULT_CHINA_UDP_DNS_PROVIDERS = [
    CHINA_UDP_DNS_PROVIDERS[0],
    CHINA_UDP_DNS_PROVIDERS[2],
    CHINA_UDP_DNS_PROVIDERS[5],
    CHINA_UDP_DNS_PROVIDERS[4],
]

GLOBAL_UDP_DNS_PROVIDERS = [
    {"name": "Cloudflare", "server": "1.1.1.1"},
    {"name": "Cloudflare Secondary", "server": "1.0.0.1"},
    {"name": "Google", "server": "8.8.8.8"},
    {"name": "Google Secondary", "server": "8.8.4.4"},
    {"name": "Quad9", "server": "9.9.9.9"},
]

CHINA_DOH_PROVIDERS = [
    {"name": "AliDNS DoH", "endpoint": "https://dns.alidns.com/resolve", "mode": "json_get"},
    {"name": "DNSPod DoH", "endpoint": "https://doh.pub/dns-query", "mode": "json_get"},
    {"name": "360 DoH", "endpoint": "https://doh.360.cn/dns-query", "mode": "json_get"},
]

GLOBAL_DOH_PROVIDERS = [
    {"name": "Cloudflare DoH", "endpoint": "https://cloudflare-dns.com/dns-query", "mode": "json_get"},
    {"name": "Google DoH", "endpoint": "https://dns.google/resolve", "mode": "json_get"},
    {"name": "Quad9 DoH", "endpoint": "https://dns.quad9.net/dns-query", "mode": "json_get"},
]

DNS_TYPES = ("A", "AAAA")


def normalize_hostname(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    parsed = urllib.parse.urlparse(value if "://" in value else f"dummy://{value}")
    return (parsed.hostname or "").lower().rstrip(".")


def classify_ip(value: str) -> str:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return "invalid"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link_local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_reserved or ip.is_unspecified:
        return "reserved"
    if ip.is_private:
        if ip.version == 6 and value.lower().startswith(("fc", "fd")):
            return "unique_local"
        return "private"
    return "public"


def _empty_records() -> dict[str, list[str]]:
    return {"A": [], "AAAA": [], "CNAME": []}


def _unique_sorted(values: list[str]) -> list[str]:
    return sorted({value for value in values if value})


def _flatten_ips(records: dict[str, list[str]]) -> list[str]:
    return _unique_sorted((records.get("A") or []) + (records.get("AAAA") or []))


def _result(ok: bool, elapsed_ms: int, records: dict[str, list[str]], error: str | None, **extra: Any) -> dict[str, Any]:
    return {"ok": ok, "elapsedMs": elapsed_ms, "records": records, "error": error, **extra}


def query_system(domain: str, timeout: float) -> dict[str, Any]:
    started = time.perf_counter()
    records = _empty_records()
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP)
        for info in infos:
            ip = info[4][0]
            records["AAAA" if ":" in ip else "A"].append(ip)
        records["A"] = _unique_sorted(records["A"])
        records["AAAA"] = _unique_sorted(records["AAAA"])
        return _result(True, round((time.perf_counter() - started) * 1000), records, None, source="system")
    except Exception as exc:  # noqa: BLE001
        return _result(False, round((time.perf_counter() - started) * 1000), records, str(exc), source="system")
    finally:
        socket.setdefaulttimeout(old_timeout)


def query_udp(domain: str, provider: dict[str, str], timeout: float, group: str) -> dict[str, Any]:
    started = time.perf_counter()
    records = _empty_records()
    try:
        import dns.exception
        import dns.resolver

        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [provider["server"]]
        per_type_timeout = max(0.5, timeout / 2)
        resolver.timeout = per_type_timeout
        resolver.lifetime = per_type_timeout
        errors = []
        for record_type in DNS_TYPES:
            try:
                answers = resolver.resolve(domain, record_type)
                records[record_type] = _unique_sorted([answer.to_text().rstrip(".") for answer in answers])
                for answer in answers.response.answer:
                    if answer.rdtype == 5:
                        records["CNAME"].extend(item.to_text().rstrip(".") for item in answer.items)
            except dns.resolver.NXDOMAIN:
                errors.append(f"{record_type}: nxdomain")
            except dns.resolver.NoAnswer:
                pass
            except dns.exception.Timeout:
                errors.append(f"{record_type}: timeout")
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{record_type}: {exc}")
        records["CNAME"] = _unique_sorted(records["CNAME"])
        ok = bool(records["A"] or records["AAAA"] or records["CNAME"]) or not errors
        return _result(
            ok,
            round((time.perf_counter() - started) * 1000),
            records,
            "; ".join(errors) or None,
            provider=provider["name"],
            server=provider["server"],
            group=group,
        )
    except ImportError:
        return _result(
            False,
            round((time.perf_counter() - started) * 1000),
            records,
            "dnspython dependency is not installed",
            provider=provider["name"],
            server=provider["server"],
            group=group,
        )
    except Exception as exc:  # noqa: BLE001
        return _result(
            False,
            round((time.perf_counter() - started) * 1000),
            records,
            str(exc),
            provider=provider["name"],
            server=provider["server"],
            group=group,
        )


def query_doh(domain: str, provider: dict[str, str], timeout: float, group: str) -> dict[str, Any]:
    started = time.perf_counter()
    records = _empty_records()
    statuses: list[int] = []
    errors: list[str] = []
    for record_type in DNS_TYPES:
        query = urllib.parse.urlencode({"name": domain, "type": record_type})
        url = f"{provider['endpoint']}?{query}"
        request = urllib.request.Request(
            url,
            headers={"Accept": "application/dns-json", "User-Agent": "dignose/0.1.0"},
        )
        try:
            with urllib.request.urlopen(request, timeout=max(0.5, timeout / 2)) as response:
                statuses.append(response.status)
                payload = json.loads(response.read().decode("utf-8", errors="replace"))
                for answer in payload.get("Answer") or []:
                    answer_type = answer.get("type")
                    data = str(answer.get("data", "")).rstrip(".")
                    if answer_type == 1:
                        records["A"].append(data)
                    elif answer_type == 28:
                        records["AAAA"].append(data)
                    elif answer_type == 5:
                        records["CNAME"].append(data)
                if payload.get("Status") not in (0, None):
                    errors.append(f"{record_type}: dns_status={payload.get('Status')}")
        except urllib.error.HTTPError as exc:
            statuses.append(exc.code)
            errors.append(f"{record_type}: http {exc.code}")
        except urllib.error.URLError as exc:
            errors.append(f"{record_type}: {exc.reason}")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{record_type}: {exc}")
    for key in records:
        records[key] = _unique_sorted(records[key])
    ok = bool(records["A"] or records["AAAA"] or records["CNAME"]) and any(status == 200 for status in statuses)
    return _result(
        ok,
        round((time.perf_counter() - started) * 1000),
        records,
        "; ".join(errors) or None,
        provider=provider["name"],
        endpoint=provider["endpoint"],
        mode=provider.get("mode", "json_get"),
        group=group,
        httpStatus=statuses[-1] if statuses else None,
    )


def _majority_ips(items: list[dict[str, Any]]) -> set[str]:
    sets = [set(_flatten_ips(item["records"])) for item in items if item.get("ok") and _flatten_ips(item["records"])]
    counts: dict[str, int] = {}
    for values in sets:
        for value in values:
            counts[value] = counts.get(value, 0) + 1
    threshold = max(2, (len(sets) // 2) + 1) if sets else 2
    return {ip for ip, count in counts.items() if count >= threshold}


def analyze_domain(
    system: dict[str, Any],
    udp_china: list[dict[str, Any]],
    doh_china: list[dict[str, Any]],
    udp_global: list[dict[str, Any]],
    doh_global: list[dict[str, Any]],
) -> dict[str, Any]:
    local_ips = set(_flatten_ips(system.get("records") or {}))
    china_items = udp_china + doh_china
    global_items = udp_global + doh_global
    china_majority = _majority_ips(china_items)
    global_majority = _majority_ips(global_items)
    local_classes = {ip: classify_ip(ip) for ip in local_ips}
    local_private = any(value in {"private", "unique_local"} for value in local_classes.values())
    local_loopback = any(value == "loopback" for value in local_classes.values())
    local_reserved = any(value in {"reserved", "multicast", "link_local", "invalid"} for value in local_classes.values())
    udp_china_success = sum(1 for item in udp_china if item.get("ok"))
    doh_china_success = sum(1 for item in doh_china if item.get("ok"))
    udp_china_mostly_failed = bool(udp_china) and udp_china_success < (len(udp_china) / 2)
    doh_china_mostly_failed = bool(doh_china) and doh_china_success < (len(doh_china) / 2)
    china_success = udp_china_success + doh_china_success
    local_differs_china = bool(system.get("ok") and local_ips and china_majority and local_ips.isdisjoint(china_majority))
    local_failed_china_ok = bool(not system.get("ok") and china_success >= 2)
    udp_failed_doh_ok = bool(udp_china_mostly_failed and doh_china_success >= max(1, len(doh_china) / 2))
    doh_failed_udp_ok = bool(doh_china_mostly_failed and udp_china_success >= max(1, len(udp_china) / 2))
    global_differs_only = bool(
        system.get("ok")
        and local_ips
        and global_majority
        and local_ips.isdisjoint(global_majority)
        and not local_differs_china
    )
    consistent = bool(
        system.get("ok")
        and local_ips
        and china_majority
        and not local_differs_china
        and not (local_private or local_loopback or local_reserved)
    )

    if local_loopback:
        summary = "本地系统 DNS 返回回环地址，疑似被本机代理、Hosts 或 DNS 服务接管。"
    elif local_private:
        summary = "本地系统 DNS 返回内网地址，检测到疑似内网接管迹象。"
    elif local_reserved:
        summary = "本地系统 DNS 返回保留、链路本地或多播地址，可能存在解析异常。"
    elif local_failed_china_ok:
        summary = "本地系统 DNS 失败，但多个中国大陆公共 DNS / DoH 成功，疑似本机 DNS、路由器 DNS、校园网/公司网 DNS 策略或运营商 DNS 异常。"
    elif local_differs_china:
        summary = "本地系统 DNS 与多数中国大陆公共 DNS / DoH 结果明显不一致，疑似 DNS 劫持、污染或路由器 DNS 接管。"
    elif udp_failed_doh_ok:
        summary = "多个中国大陆 UDP DNS 查询失败，但 DoH 查询成功，疑似 UDP DNS 被阻断或限制。"
    elif doh_failed_udp_ok:
        summary = "中国大陆 UDP DNS 查询成功，但多个 DoH 查询失败，疑似 HTTPS / DoH 被拦截或证书异常。"
    elif global_differs_only:
        summary = "仅国际 DNS 对照与本地结果不同，可能是 CDN 地域调度或跨境解析差异，默认不作为强异常。"
    elif consistent:
        summary = "本地系统 DNS、中国大陆公共 UDP DNS、DoH 结果基本一致。"
    else:
        summary = "解析结果存在差异或部分通道失败，请结合网络策略、CDN 地域调度和代理环境判断。"

    return {
        "consistent": consistent,
        "localDiffersFromChinaMajority": local_differs_china,
        "localDiffersFromMajority": local_differs_china,
        "localDiffersOnlyFromGlobal": global_differs_only,
        "localReturnedPrivateIp": local_private,
        "localReturnedLoopback": local_loopback,
        "localReturnedReservedIp": local_reserved,
        "localFailedChinaSucceeded": local_failed_china_ok,
        "localFailedPublicSucceeded": local_failed_china_ok,
        "udpChinaMostlyFailed": udp_china_mostly_failed,
        "dohChinaMostlyFailed": doh_china_mostly_failed,
        "udpMostlyFailed": udp_china_mostly_failed,
        "dohMostlyFailed": doh_china_mostly_failed,
        "udpFailedDohSucceeded": udp_failed_doh_ok,
        "dohFailedUdpSucceeded": doh_failed_udp_ok,
        "localIpClasses": local_classes,
        "chinaMajorityIps": sorted(china_majority),
        "globalMajorityIps": sorted(global_majority),
        "summary": summary,
    }


def _risk_for(domain: str, analysis: dict[str, Any]) -> tuple[str, str] | None:
    if analysis["localReturnedLoopback"] or analysis["localReturnedPrivateIp"] or analysis["localReturnedReservedIp"]:
        return "medium", f"{domain}: {analysis['summary']}"
    if analysis["localDiffersFromChinaMajority"] or analysis["localFailedChinaSucceeded"]:
        return "medium", f"{domain}: {analysis['summary']}"
    if analysis["udpFailedDohSucceeded"]:
        return "medium", f"{domain}: {analysis['summary']}"
    if analysis["dohFailedUdpSucceeded"]:
        return "low", f"{domain}: {analysis['summary']}"
    if analysis["localDiffersOnlyFromGlobal"]:
        return "info", f"{domain}: {analysis['summary']}"
    return None


def _domain_entries(custom_domains: list[str] | None, full: bool) -> list[tuple[str, str]]:
    base = FULL_DOMAINS if full else DEFAULT_DOMAINS
    entries = [(normalize_hostname(domain), category) for domain, category in base]
    for domain in custom_domains or []:
        entries.append((normalize_hostname(domain), "custom"))
    seen = set()
    normalized = []
    for domain, category in entries:
        if domain and domain not in seen:
            seen.add(domain)
            normalized.append((domain, category))
    return normalized


def _custom_udp_providers(values: list[str] | None) -> list[dict[str, str]]:
    providers = []
    for value in values or []:
        server = value.strip()
        if server:
            providers.append({"name": f"Custom UDP {server}", "server": server})
    return providers


def _custom_doh_providers(values: list[str] | None) -> list[dict[str, str]]:
    providers = []
    for value in values or []:
        endpoint = value.strip()
        if endpoint:
            providers.append({"name": f"Custom DoH {urllib.parse.urlparse(endpoint).netloc or endpoint}", "endpoint": endpoint, "mode": "json_get"})
    return providers


def collect(
    risks: list[dict[str, str]],
    *,
    enabled: bool = True,
    skip_udp: bool = False,
    skip_doh: bool = False,
    full: bool = False,
    include_global_dns: bool = False,
    include_global_doh: bool = False,
    timeout: float = 2.0,
    custom_domains: list[str] | None = None,
    custom_udp_providers: list[str] | None = None,
    custom_doh_providers: list[str] | None = None,
) -> dict[str, Any]:
    if not enabled:
        return {
            "ok": True,
            "data": {"enabled": False, "profile": "skipped", "domains": []},
            "error": "skipped by --skip-dns-compare",
        }

    def inner() -> dict[str, Any]:
        domains = _domain_entries(custom_domains, full)
        udp_china_providers = list(CHINA_UDP_DNS_PROVIDERS if full else DEFAULT_CHINA_UDP_DNS_PROVIDERS)
        udp_china_providers.extend(_custom_udp_providers(custom_udp_providers))
        udp_global_providers = list(GLOBAL_UDP_DNS_PROVIDERS if (full or include_global_dns) else [])
        doh_china_providers = list(CHINA_DOH_PROVIDERS)
        doh_global_providers = list(GLOBAL_DOH_PROVIDERS if (full or include_global_doh) else [])
        doh_china_providers.extend(_custom_doh_providers(custom_doh_providers))

        def collect_one(domain: str, category: str) -> dict[str, Any]:
            system = query_system(domain, timeout)
            udp_china: list[dict[str, Any]] = []
            udp_global: list[dict[str, Any]] = []
            doh_china: list[dict[str, Any]] = []
            doh_global: list[dict[str, Any]] = []
            tasks = {}
            with ThreadPoolExecutor(max_workers=10) as executor:
                if not skip_udp:
                    for provider in udp_china_providers:
                        tasks[executor.submit(query_udp, domain, provider, timeout, "china")] = "udpChina"
                    for provider in udp_global_providers:
                        tasks[executor.submit(query_udp, domain, provider, timeout, "global")] = "udpGlobal"
                if not skip_doh:
                    for provider in doh_china_providers:
                        tasks[executor.submit(query_doh, domain, provider, timeout, "china")] = "dohChina"
                    for provider in doh_global_providers:
                        tasks[executor.submit(query_doh, domain, provider, timeout, "global")] = "dohGlobal"
                for future in as_completed(tasks):
                    kind = tasks[future]
                    item = future.result()
                    if kind == "udpChina":
                        udp_china.append(item)
                    elif kind == "udpGlobal":
                        udp_global.append(item)
                    elif kind == "dohChina":
                        doh_china.append(item)
                    else:
                        doh_global.append(item)
            udp_china.sort(key=lambda item: item.get("provider", ""))
            udp_global.sort(key=lambda item: item.get("provider", ""))
            doh_china.sort(key=lambda item: item.get("provider", ""))
            doh_global.sort(key=lambda item: item.get("provider", ""))
            analysis = analyze_domain(system, udp_china, doh_china, udp_global, doh_global)
            return {
                "domain": domain,
                "category": category,
                "queries": {
                    "system": system,
                    "udpChina": udp_china,
                    "dohChina": doh_china,
                    "udpGlobal": udp_global,
                    "dohGlobal": doh_global,
                    "udp": udp_china + udp_global,
                    "doh": doh_china + doh_global,
                },
                "analysis": analysis,
            }

        output = []
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(collect_one, domain, category) for domain, category in domains]
            for future in as_completed(futures):
                output.append(future.result())
        domain_order = [domain for domain, _category in domains]
        output.sort(key=lambda item: domain_order.index(item["domain"]))
        for item in output:
            risk = _risk_for(item["domain"], item["analysis"])
            if risk:
                system_records = item.get("queries", {}).get("system", {}).get("records") or {}
                add_risk(risks, risk[0], "dnsCompare", risk[1], ", ".join(_flatten_ips(system_records)))

        return {
            "enabled": True,
            "profile": "china_full" if full else "china_default",
            "timeoutSeconds": timeout,
            "providers": {
                "system": True,
                "udpChina": [] if skip_udp else udp_china_providers,
                "dohChina": [] if skip_doh else doh_china_providers,
                "udpGlobal": [] if skip_udp else udp_global_providers,
                "dohGlobal": [] if skip_doh else doh_global_providers,
            },
            "domains": output,
        }

    return safe_collect(inner)

