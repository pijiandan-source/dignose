from __future__ import annotations

import socket
import time

from .utils import run_command, safe_collect

PING_TARGETS = ["127.0.0.1", "1.1.1.1", "8.8.8.8", "example.com", "cloudflare.com", "openai.com", "steamcommunity.com"]
TCP_TARGETS = [("1.1.1.1", 53), ("8.8.8.8", 53), ("cloudflare.com", 443), ("openai.com", 443), ("steamcommunity.com", 443)]


def collect(default_gateways: list[str] | None = None) -> dict:
    def inner() -> list[dict]:
        results = []
        targets = list(PING_TARGETS)
        for gateway in default_gateways or []:
            if gateway and gateway not in targets and ":" not in gateway:
                targets.insert(1, gateway)
        for target in targets:
            started = time.perf_counter()
            result = run_command(["ping", "-n", "1", "-w", "1500", target], timeout=3)
            results.append(
                {
                    "type": "ping",
                    "target": target,
                    "ok": bool(result.get("ok")),
                    "elapsedMs": round((time.perf_counter() - started) * 1000),
                    "error": result.get("error"),
                }
            )
        for host, port in TCP_TARGETS:
            started = time.perf_counter()
            try:
                with socket.create_connection((host, port), timeout=3):
                    ok = True
                    error = None
            except Exception as exc:  # noqa: BLE001
                ok = False
                error = str(exc)
            results.append({"type": "tcp", "target": f"{host}:{port}", "ok": ok, "elapsedMs": round((time.perf_counter() - started) * 1000), "error": error})
        return results

    return safe_collect(inner)

