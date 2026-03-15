from __future__ import annotations

import os
import statistics
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    psutil = None


class HealthMonitor:
    def __init__(self, latency_window: int = 100) -> None:
        self._latencies = deque(maxlen=max(10, latency_window))
        self._connectivity: dict[str, bool] = {}
        self._boot_ts = time.time()
        self._last_cpu_time = time.process_time()
        self._last_wall = time.time()

    def record_inference_latency(self, latency_ms: float) -> None:
        if latency_ms >= 0:
            self._latencies.append(float(latency_ms))

    def set_connectivity(self, intersection_id: str, is_online: bool) -> None:
        self._connectivity[intersection_id] = bool(is_online)

    def mark_batch_connectivity(self, ids: list[str]) -> None:
        known = set(ids)
        for intersection_id in known:
            self._connectivity[intersection_id] = True
        for old_id in list(self._connectivity.keys()):
            if old_id not in known:
                self._connectivity[old_id] = False

    def _cpu_snapshot(self) -> dict[str, Any]:
        if psutil is not None:
            return {
                "cpu_percent": psutil.cpu_percent(interval=None),
                "logical_cores": psutil.cpu_count(logical=True),
                "physical_cores": psutil.cpu_count(logical=False),
            }

        now_wall = time.time()
        now_cpu = time.process_time()
        wall_delta = max(1e-6, now_wall - self._last_wall)
        cpu_delta = max(0.0, now_cpu - self._last_cpu_time)
        self._last_wall = now_wall
        self._last_cpu_time = now_cpu
        return {
            "cpu_percent": min(100.0, (cpu_delta / wall_delta) * 100.0),
            "logical_cores": os.cpu_count() or 1,
            "physical_cores": None,
        }

    def _ram_snapshot(self) -> dict[str, Any]:
        if psutil is not None:
            vm = psutil.virtual_memory()
            return {
                "ram_percent": vm.percent,
                "ram_used_mb": round(vm.used / (1024 * 1024), 2),
                "ram_total_mb": round(vm.total / (1024 * 1024), 2),
            }
        return {
            "ram_percent": None,
            "ram_used_mb": None,
            "ram_total_mb": None,
        }

    def snapshot(self) -> dict[str, Any]:
        latencies = list(self._latencies)
        cpu = self._cpu_snapshot()
        ram = self._ram_snapshot()
        online = [k for k, v in self._connectivity.items() if v]
        offline = [k for k, v in self._connectivity.items() if not v]

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "uptime_sec": round(max(0.0, time.time() - self._boot_ts), 2),
            **cpu,
            **ram,
            "inference_latency_ms": {
                "count": len(latencies),
                "avg": round(statistics.fmean(latencies), 3) if latencies else 0.0,
                "p95": round(sorted(latencies)[int(0.95 * (len(latencies) - 1))], 3) if len(latencies) > 1 else (latencies[0] if latencies else 0.0),
                "max": round(max(latencies), 3) if latencies else 0.0,
            },
            "intersection_connectivity": {
                "online": online,
                "offline": offline,
                "online_count": len(online),
                "offline_count": len(offline),
            },
        }
