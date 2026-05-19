from __future__ import annotations

import configparser
import json
import os
from pathlib import Path

from .utils import add_risk, run_command, safe_collect


def _config_value(command: list[str]) -> str | None:
    result = run_command(command, timeout=6)
    value = ((result.get("data") or {}).get("stdout") or "").strip()
    if not result.get("ok") or value.lower() in {"", "null", "undefined", "none"}:
        return None
    return value


def collect(risks: list[dict[str, str]]) -> dict:
    def inner() -> dict:
        git = {
            "http.proxy": _config_value(["git", "config", "--global", "--get", "http.proxy"]),
            "https.proxy": _config_value(["git", "config", "--global", "--get", "https.proxy"]),
        }
        npm = {
            "proxy": _config_value(["npm", "config", "get", "proxy"]),
            "https-proxy": _config_value(["npm", "config", "get", "https-proxy"]),
        }
        pip_files = []
        for path in [
            Path(os.environ.get("APPDATA", "")) / "pip" / "pip.ini",
            Path.home() / "pip" / "pip.ini",
        ]:
            if path.exists():
                parser = configparser.ConfigParser()
                try:
                    parser.read(path, encoding="utf-8")
                    pip_files.append({"path": str(path), "proxy": parser.get("global", "proxy", fallback=None)})
                except Exception as exc:  # noqa: BLE001
                    pip_files.append({"path": str(path), "error": str(exc)})
        docker_config = Path.home() / ".docker" / "config.json"
        docker = {"path": str(docker_config), "exists": docker_config.exists(), "proxies": None}
        if docker_config.exists():
            try:
                docker["proxies"] = json.loads(docker_config.read_text(encoding="utf-8", errors="replace")).get("proxies")
            except Exception as exc:  # noqa: BLE001
                docker["error"] = str(exc)
        wsl_status = run_command(["wsl", "-l", "-v"], timeout=8)

        for group, values in {"git": git, "npm": npm}.items():
            for key, value in values.items():
                if value:
                    add_risk(risks, "low", "devToolProxy", f"{group} 配置了代理，可能影响开发工具流量。", f"{key}={value}")
        for item in pip_files:
            if item.get("proxy"):
                add_risk(risks, "low", "devToolProxy", "pip 配置了代理，可能影响 Python 包下载。", f"{item['path']} proxy={item['proxy']}")
        if docker.get("proxies"):
            add_risk(risks, "low", "devToolProxy", "Docker Desktop 配置中检测到代理字段。", str(docker.get("proxies"))[:200])
        return {"git": git, "npm": npm, "pip": pip_files, "docker": docker, "wsl": wsl_status}

    return safe_collect(inner)

