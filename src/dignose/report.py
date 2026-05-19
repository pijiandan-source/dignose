from __future__ import annotations

from .utils import safe_json_dumps


def _ips(records: dict) -> str:
    values = (records or {}).get("A", []) + (records or {}).get("AAAA", [])
    return ", ".join(values) if values else "无"


def _line_for_result(item: dict, include_server: bool = True) -> str:
    status = "成功" if item.get("ok") else f"失败: {item.get('error') or 'unknown'}"
    target = item.get("server") if include_server else item.get("endpoint")
    suffix = f" {target}" if target and include_server else ""
    return f"  {item.get('provider')}{suffix}: {status}，{_ips(item.get('records') or {})}"


def _dns_compare_lines(report: dict) -> list[str]:
    dns_compare = (report.get("dnsCompare") or {}).get("data") or {}
    if not dns_compare.get("enabled"):
        return ["[DNS 多通道解析对比]", "已跳过。"]
    domains = dns_compare.get("domains") or []
    lines = ["[DNS 多通道解析对比]"]
    abnormal = [item for item in domains if not item.get("analysis", {}).get("consistent")]
    sample = abnormal[:5] if abnormal else domains[:3]
    if not sample:
        lines.append("未执行 DNS 对比。")
        return lines
    for item in sample:
        system = item.get("queries", {}).get("system", {})
        analysis = item.get("analysis", {})
        system_status = "成功" if system.get("ok") else f"失败: {system.get('error') or 'unknown'}"
        lines.append(f"域名: {item.get('domain')}")
        lines.append(f"本地系统 DNS: {system_status}: {_ips(system.get('records') or {})}")
        udp_china = item.get("queries", {}).get("udpChina") or []
        doh_china = item.get("queries", {}).get("dohChina") or []
        udp_global = item.get("queries", {}).get("udpGlobal") or []
        doh_global = item.get("queries", {}).get("dohGlobal") or []
        if udp_china:
            lines.append("中国大陆 UDP DNS:")
            lines.extend(_line_for_result(udp) for udp in udp_china[:4])
        if doh_china:
            lines.append("中国大陆 DoH:")
            lines.extend(_line_for_result(doh, include_server=False) for doh in doh_china[:3])
        if udp_global:
            lines.append("国际 UDP DNS 对照:")
            lines.extend(_line_for_result(udp) for udp in udp_global[:3])
        if doh_global:
            lines.append("国际 DoH 对照:")
            lines.extend(_line_for_result(doh, include_server=False) for doh in doh_global[:2])
        lines.append(f"判断: {analysis.get('summary')}")
    return lines


def render_summary(report: dict) -> str:
    system = (report.get("system") or {}).get("data") or {}
    adapters = (report.get("adapters") or {}).get("data") or []
    dns = (report.get("dns") or {}).get("data") or {}
    routes = (report.get("routes") or {}).get("data") or {}
    lan = (report.get("lanGateway") or {}).get("data") or {}
    risks = report.get("risks") or []

    primary = next((item for item in adapters if item.get("ipv4") or item.get("defaultGateways")), adapters[0] if adapters else {})
    lines = [
        "Windows 网络环境只读诊断报告",
        f"工具: dignose {report.get('meta', {}).get('version')}",
        "说明: 本工具只读取诊断信息，不修改 Hosts/DNS/代理/路由/注册表，不执行修复操作，不上传数据。",
        "",
        "[系统信息]",
        f"Windows: {system.get('windows') or '未知'}",
        f"管理员权限: {'是' if system.get('isAdmin') else '否'}",
        f"程序版本: {system.get('toolVersion')}",
        f"当前时间: {system.get('time')}",
        "",
        "[网络摘要]",
        f"当前网卡: {primary.get('name') or '未检测到'} ({primary.get('type') or 'Unknown'})",
        f"IPv4: {', '.join(primary.get('ipv4') or []) or '未检测到'}",
        f"默认网关: {', '.join(primary.get('defaultGateways') or lan.get('defaultGateways') or []) or '未检测到'}",
        f"DNS: {', '.join(dns.get('servers') or []) or '未检测到'}",
        f"IPv4 默认路由数量: {routes.get('ipv4DefaultCount', 0)}",
        "",
        *_dns_compare_lines(report),
        "",
        "[风险摘要]",
    ]
    if risks:
        lines.extend(f"- {item.get('level')}: {item.get('message')} {item.get('evidence') or ''}".rstrip() for item in risks)
    else:
        lines.append("- 未检测到明显风险项。")
    return "\n".join(lines)


def render_json(report: dict) -> str:
    return safe_json_dumps(report, indent=2)

