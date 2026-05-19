from __future__ import annotations

import re
from pathlib import Path

from .utils import add_risk, safe_collect

HOSTS_PATH = Path(r"C:\Windows\System32\drivers\etc\hosts")
HOSTS_LINE = re.compile(r"^\s*(\S+)\s+(.+?)\s*$")
KEYWORDS = (
    "openai",
    "chatgpt",
    "google",
    "youtube",
    "cloudflare",
    "steam",
    "steamcommunity",
    "epic",
    "riot",
    "battle.net",
    "github",
)


def collect(risks: list[dict[str, str]]) -> dict:
    def inner() -> dict:
        exists = HOSTS_PATH.exists()
        readable = False
        entries: list[dict] = []
        keyword_hits: list[dict] = []
        if exists:
            text = HOSTS_PATH.read_text(encoding="utf-8", errors="replace")
            readable = True
            for number, raw_line in enumerate(text.splitlines(), start=1):
                line = raw_line.split("#", 1)[0].strip()
                if not line:
                    continue
                match = HOSTS_LINE.match(line)
                if not match:
                    continue
                address, names = match.groups()
                for name in re.split(r"\s+", names.strip()):
                    if not name:
                        continue
                    entry = {"line": number, "address": address, "hostname": name}
                    entries.append(entry)
                    if any(keyword in name.lower() for keyword in KEYWORDS):
                        keyword_hits.append(entry)

        non_localhost = [
            item for item in entries if item["hostname"].lower() not in {"localhost", "localhost.localdomain"}
        ]
        if non_localhost:
            add_risk(
                risks,
                "medium",
                "hosts",
                f"Hosts 文件存在 {len(non_localhost)} 条非默认映射，可能影响域名访问路径。",
                f"{non_localhost[0]['address']} -> {non_localhost[0]['hostname']}",
            )
        if keyword_hits:
            add_risk(
                risks,
                "medium",
                "hosts",
                "Hosts 文件存在 AI、游戏平台、CDN 或常见网络服务相关域名映射。",
                f"{keyword_hits[0]['address']} -> {keyword_hits[0]['hostname']}",
            )
        return {
            "path": str(HOSTS_PATH),
            "exists": exists,
            "readable": readable,
            "entryCount": len(entries),
            "nonLocalhostCount": len(non_localhost),
            "keywordHitCount": len(keyword_hits),
            "entries": entries[:100],
            "keywordHits": keyword_hits[:50],
            "truncated": len(entries) > 100,
        }

    return safe_collect(inner)

