from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from . import connectivity_check, devtool_proxy_check, dns_check, dns_compare, hosts_check, lan_gateway_check
from . import network_adapter, port_check, proxy_check, report as report_render, route_check, system_info
from .utils import safe_print


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dignose", description="Windows 网络环境只读诊断工具")
    parser.add_argument("--json", action="store_true", help="输出 JSON 到控制台")
    parser.add_argument("--output", help="输出 JSON 报告文件路径")
    parser.add_argument("--txt", help="输出文本摘要文件路径")
    parser.add_argument("--skip-connectivity", action="store_true", help="跳过连通性检测")
    parser.add_argument("--dns-compare", action="store_true", help="启用 DNS 多通道解析对比。默认已启用，保留用于显式声明")
    parser.add_argument("--skip-dns-compare", action="store_true", help="跳过 DNS 多通道解析对比")
    parser.add_argument("--dns-compare-full", action="store_true", help="使用完整域名列表和完整中国大陆 DNS provider 列表")
    parser.add_argument("--include-global-dns", action="store_true", help="加入国际 UDP DNS 对照组")
    parser.add_argument("--include-global-doh", action="store_true", help="加入国际 DoH 对照组")
    parser.add_argument("--dns-timeout", type=float, default=2.0, help="单个 DNS 查询超时时间，默认 2 秒")
    parser.add_argument("--dns-domain", action="append", default=[], help="额外 DNS 对比域名或 URL，可重复指定")
    parser.add_argument("--dns-provider", action="append", default=[], help="额外 UDP DNS provider IP，可重复指定")
    parser.add_argument("--doh-provider", action="append", default=[], help="额外 DoH endpoint，可重复指定")
    parser.add_argument("--skip-doh", action="store_true", help="跳过 DoH 查询")
    parser.add_argument("--skip-udp-dns", action="store_true", help="跳过第三方 UDP DNS 查询")
    parser.add_argument("--verbose", action="store_true", help="显示更详细的控制台信息")
    parser.add_argument("--version", action="version", version=f"dignose {__version__}")
    return parser


def collect_report(
    *,
    skip_connectivity: bool = False,
    skip_dns_compare: bool = False,
    dns_compare_full: bool = False,
    include_global_dns: bool = False,
    include_global_doh: bool = False,
    dns_timeout: float = 2.0,
    dns_domains: list[str] | None = None,
    dns_providers: list[str] | None = None,
    doh_providers: list[str] | None = None,
    skip_doh: bool = False,
    skip_udp_dns: bool = False,
) -> dict:
    risks: list[dict[str, str]] = []
    system = system_info.collect()
    adapters = network_adapter.collect()
    hosts = hosts_check.collect(risks)
    dns = dns_check.collect(risks, adapters=adapters, skip_queries=skip_connectivity)
    dns_compare_result = dns_compare.collect(
        risks,
        enabled=not skip_dns_compare,
        skip_udp=skip_udp_dns,
        skip_doh=skip_doh,
        full=dns_compare_full,
        include_global_dns=include_global_dns,
        include_global_doh=include_global_doh,
        timeout=max(0.5, min(dns_timeout, 10.0)),
        custom_domains=dns_domains or [],
        custom_udp_providers=dns_providers or [],
        custom_doh_providers=doh_providers or [],
    )
    proxy = proxy_check.collect(risks)
    ports = port_check.collect(risks)
    routes = route_check.collect(risks)
    default_gateways = []
    if adapters.get("ok"):
        for adapter in adapters.get("data") or []:
            default_gateways.extend(adapter.get("defaultGateways") or [])
    connectivity = (
        {"ok": True, "data": [], "error": "skipped by --skip-connectivity"}
        if skip_connectivity
        else connectivity_check.collect(default_gateways)
    )
    lan_gateway = lan_gateway_check.collect(risks, adapters=adapters, routes=routes, dns=dns)
    devtool_proxy = devtool_proxy_check.collect(risks)
    return {
        "meta": {"tool": "dignose", "version": __version__, "readonly": True},
        "system": system,
        "adapters": adapters,
        "hosts": hosts,
        "dns": dns,
        "dnsCompare": dns_compare_result,
        "proxy": proxy,
        "ports": ports,
        "routes": routes,
        "connectivity": connectivity,
        "lanGateway": lan_gateway,
        "devToolProxy": devtool_proxy,
        "risks": risks,
    }


def write_text(path: str, text: str) -> None:
    Path(path).write_text(text, encoding="utf-8", errors="replace")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    data = collect_report(
        skip_connectivity=args.skip_connectivity,
        skip_dns_compare=args.skip_dns_compare,
        dns_compare_full=args.dns_compare_full,
        include_global_dns=args.include_global_dns,
        include_global_doh=args.include_global_doh,
        dns_timeout=args.dns_timeout,
        dns_domains=args.dns_domain,
        dns_providers=args.dns_provider,
        doh_providers=args.doh_provider,
        skip_doh=args.skip_doh,
        skip_udp_dns=args.skip_udp_dns,
    )
    json_text = report_render.render_json(data)
    summary_text = report_render.render_summary(data)

    if args.output:
        write_text(args.output, json_text)
    if args.txt:
        write_text(args.txt, summary_text)

    if args.json:
        safe_print(json_text)
    else:
        safe_print(summary_text)
        if args.output:
            safe_print(f"\nJSON 报告已保存: {args.output}")
        if args.txt:
            safe_print(f"文本报告已保存: {args.txt}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

