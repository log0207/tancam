from __future__ import annotations

import asyncio
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Any

from backend.corridor.corridor_controller import CorridorController
from backend.messaging.message_bus import MessageBus


class EmergencyManager:
    def __init__(
        self,
        corridor_controller: CorridorController,
        message_bus: MessageBus,
        timeout_sec: int = 120,
    ) -> None:
        self._corridor = corridor_controller
        self._bus = message_bus
        self._timeout_sec = timeout_sec
        self._active: dict[str, dict[str, Any]] = {}
        self._lock = asyncio.Lock()

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    async def _build_adjacency(self) -> dict[str, list[str]]:
        topology = await self._corridor.get_topology()
        adjacency: dict[str, list[str]] = {}
        for link in topology.get("links", []):
            frm = str(link["from"])
            to = str(link["to"])
            adjacency.setdefault(frm, []).append(to)
            adjacency.setdefault(to, [])
        for item in topology.get("intersections", []):
            adjacency.setdefault(str(item["intersection_id"]), [])
        return adjacency

    async def compute_path(self, start_intersection: str, end_intersection: str | None = None) -> list[str]:
        """
        Computes the shortest path for an emergency vehicle through the corridor using
        Breadth-First Search (BFS) over the intersection topology graph.
        """
        adjacency = await self._build_adjacency()
        if start_intersection not in adjacency:
            raise ValueError(f"Unknown start intersection: {start_intersection}")

        if end_intersection is None:
            # Default to the very last intersection in the corridor if no end is specified.
            topology = await self._corridor.get_topology()
            end_intersection = str(topology["intersections"][-1]["intersection_id"])

        if end_intersection not in adjacency:
            raise ValueError(f"Unknown end intersection: {end_intersection}")

        queue = deque([start_intersection])
        parent: dict[str, str | None] = {start_intersection: None}
        visited = {start_intersection}

        while queue:
            node = queue.popleft()
            if node == end_intersection:
                break
            for nxt in adjacency.get(node, []):
                # Bug fix: use a dedicated `visited` set to properly prevent infinite loops
                # in cyclic topologies (like roundabouts or grids).
                if nxt in visited:
                    continue
                visited.add(nxt)
                parent[nxt] = node
                queue.append(nxt)

        if end_intersection not in parent:
            raise ValueError(
                f"No route from {start_intersection} to {end_intersection}"
            )

        path = []
        cursor: str | None = end_intersection
        while cursor is not None:
            path.append(cursor)
            cursor = parent[cursor]
        path.reverse()
        return path

    async def activate(
        self,
        event_id: str,
        start_intersection: str,
        end_intersection: str | None = None,
    ) -> dict[str, Any]:
        path = await self.compute_path(start_intersection, end_intersection)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=self._timeout_sec)
        event = {
            "event_id": event_id,
            "path": path,
            "status": "ACTIVE",
            "started_at": self._now(),
            "expires_at": expires_at.isoformat(),
        }

        async with self._lock:
            self._active[event_id] = event

        await self._bus.publish(
            "alerts",
            {
                "type": "emergency_corridor_activated",
                "event_id": event_id,
                "path": path,
            },
        )
        return event

    async def complete(self, event_id: str) -> dict[str, Any] | None:
        async with self._lock:
            event = self._active.pop(event_id, None)

        if event is not None:
            event["status"] = "COMPLETED"
            event["completed_at"] = self._now()
            await self._bus.publish(
                "system_events",
                {
                    "event": "emergency_corridor_restored",
                    "event_id": event_id,
                    "path": event.get("path", []),
                },
            )
        return event

    async def active_events(self) -> dict[str, dict[str, Any]]:
        async with self._lock:
            return {k: dict(v) for k, v in self._active.items()}

    async def prune_expired(self) -> None:
        now = datetime.now(timezone.utc)
        expired: list[str] = []
        async with self._lock:
            for event_id, event in self._active.items():
                expires = datetime.fromisoformat(event["expires_at"])
                if now >= expires:
                    expired.append(event_id)
            for event_id in expired:
                self._active.pop(event_id, None)

        for event_id in expired:
            await self._bus.publish(
                "system_events",
                {
                    "event": "emergency_corridor_timeout",
                    "event_id": event_id,
                },
            )
