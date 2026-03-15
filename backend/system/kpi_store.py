from __future__ import annotations

import asyncio
from collections import deque
from datetime import datetime, timezone
from typing import Any


class KPIStore:
    """Stores rolling intersection KPI snapshots and computes global summary metrics."""

    def __init__(self, history_size: int = 600) -> None:
        self._history_size = max(10, int(history_size))
        self._by_intersection: dict[str, deque[dict[str, Any]]] = {}
        self._lock = asyncio.Lock()
        self._last_reset_at = self._now()

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    async def ingest(self, intersection_id: str, snapshot: dict[str, Any]) -> None:
        async with self._lock:
            queue = self._by_intersection.setdefault(
                intersection_id, deque(maxlen=self._history_size)
            )
            queue.append(
                {
                    "timestamp": self._now(),
                    "intersection_id": intersection_id,
                    **snapshot,
                }
            )

    async def reset(self) -> None:
        async with self._lock:
            self._by_intersection = {}
            self._last_reset_at = self._now()

    async def summary(self) -> dict[str, Any]:
        async with self._lock:
            latest: dict[str, dict[str, Any]] = {}
            for intersection_id, items in self._by_intersection.items():
                if items:
                    latest[intersection_id] = dict(items[-1])

            intersections = sorted(latest.keys())
            samples = [latest[k] for k in intersections]

        def _num(sample: dict[str, Any], key: str, default: float = 0.0) -> float:
            value = sample.get(key, default)
            try:
                return float(value)
            except Exception:
                return default

        count = len(samples)
        if count == 0:
            return {
                "captured_at": self._now(),
                "last_reset_at": self._last_reset_at,
                "intersection_count": 0,
                "totals": {
                    "throughput_veh_per_min": 0.0,
                    "active_waiting_vehicles": 0,
                    "cleared_vehicles_total": 0,
                },
                "averages": {
                    "avg_wait_sec": 0.0,
                    "p95_wait_sec": 0.0,
                    "queue_length": 0.0,
                    "occupancy_ratio": 0.0,
                },
                "by_intersection": {},
            }

        throughput = sum(_num(item, "throughput_veh_per_min") for item in samples)
        waiting = int(sum(_num(item, "active_waiting_vehicles") for item in samples))
        cleared = int(sum(_num(item, "cleared_vehicles_total") for item in samples))
        avg_wait = sum(_num(item, "avg_wait_sec") for item in samples) / count
        p95_wait = sum(_num(item, "p95_wait_sec") for item in samples) / count
        queue_length = sum(_num(item, "queue_length") for item in samples) / count
        occupancy = sum(_num(item, "occupancy_ratio") for item in samples) / count

        return {
            "captured_at": self._now(),
            "last_reset_at": self._last_reset_at,
            "intersection_count": count,
            "totals": {
                "throughput_veh_per_min": round(throughput, 3),
                "active_waiting_vehicles": waiting,
                "cleared_vehicles_total": cleared,
            },
            "averages": {
                "avg_wait_sec": round(avg_wait, 3),
                "p95_wait_sec": round(p95_wait, 3),
                "queue_length": round(queue_length, 3),
                "occupancy_ratio": round(occupancy, 4),
            },
            "by_intersection": latest,
        }

