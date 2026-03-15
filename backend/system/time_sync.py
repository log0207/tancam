from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict


@dataclass
class NodeClock:
    node_id: str
    drift_ms: float = 0.0
    last_sync: str | None = None


class TimeSyncManager:
    def __init__(self, drift_threshold_ms: float = 250.0, tick_seconds: float = 2.0) -> None:
        self._nodes: Dict[str, NodeClock] = {}
        self._threshold_ms = float(drift_threshold_ms)
        self._tick_seconds = float(tick_seconds)
        self._lock = asyncio.Lock()
        self._running = False

    @property
    def threshold_ms(self) -> float:
        return self._threshold_ms

    async def register_nodes(self, node_ids: list[str]) -> None:
        async with self._lock:
            for node_id in node_ids:
                self._nodes.setdefault(node_id, NodeClock(node_id=node_id, last_sync=self._now()))

    async def set_drift(self, node_id: str, drift_ms: float) -> None:
        async with self._lock:
            node = self._nodes.setdefault(node_id, NodeClock(node_id=node_id, last_sync=self._now()))
            node.drift_ms = drift_ms

    async def apply_ntp_sync(self) -> None:
        async with self._lock:
            for node in self._nodes.values():
                node.drift_ms *= 0.35
                node.last_sync = self._now()

    async def simulate_tick(self) -> None:
        async with self._lock:
            for node in self._nodes.values():
                noise = random.uniform(-25.0, 25.0)
                node.drift_ms += noise
                node.drift_ms *= 0.98

    async def run(self, stop_event: asyncio.Event) -> None:
        self._running = True
        while not stop_event.is_set():
            await self.simulate_tick()
            await asyncio.sleep(self._tick_seconds)
        self._running = False

    async def status(self) -> dict:
        async with self._lock:
            nodes = {
                node_id: {
                    "drift_ms": round(node.drift_ms, 2),
                    "last_sync": node.last_sync,
                    "within_threshold": abs(node.drift_ms) <= self._threshold_ms,
                }
                for node_id, node in self._nodes.items()
            }

        max_drift = max((abs(item["drift_ms"]) for item in nodes.values()), default=0.0)
        coordination_allowed = max_drift <= self._threshold_ms
        return {
            "timestamp": self._now(),
            "drift_threshold_ms": self._threshold_ms,
            "max_abs_drift_ms": round(max_drift, 2),
            "coordination_allowed": coordination_allowed,
            "nodes": nodes,
            "running": self._running,
        }

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()
