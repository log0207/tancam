from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from backend.messaging.message_bus import MessageBus


@dataclass
class IntersectionMetric:
    intersection_id: str
    queue_count: float
    lane_density: float
    vehicle_type_weight: float
    occupancy_ratio: float
    arrival_rate: float
    timestamp: str


class CorridorController:
    def __init__(
        self,
        message_bus: MessageBus,
        topology_path: Path,
        update_interval_sec: float = 10.0,
    ) -> None:
        self._message_bus = message_bus
        self._topology_path = topology_path
        self._update_interval_sec = float(update_interval_sec)
        self._lock = asyncio.Lock()
        self._metrics: Dict[str, IntersectionMetric] = {}
        self._last_plan: dict[str, Any] | None = None
        self._last_plan_at_monotonic: float = 0.0
        self._last_metrics_signature: tuple[Any, ...] = ()
        self._metrics_changed = True
        self._topology_changed = True
        self._failures_changed = True
        self._strategy = "ADAPTIVE"
        self._link_speed_ema: dict[str, float] = {}
        self._speed_ema_alpha = 0.25
        self._offset_quantum_sec = 1.0
        self._max_plan_stale_sec = max(30.0, self._update_interval_sec * 3.0)
        self._phase_score_ema: dict[str, list[float]] = {}
        self._phase_ema_alpha = 0.3
        self._phase_starvation_ticks: dict[str, list[int]] = {}
        self._starvation_soft_limit = 3
        self._starvation_boost = 0.18
        self._last_cycle_diagnostics: dict[str, float] = {
            "mean_pressure": 0.0,
            "failure_ratio": 0.0,
            "degraded_pressure": 0.0,
        }
        self._failures: dict[str, set[str]] = {
            "network_outage": set(),
            "camera_failure": set(),
            "low_visibility": set(),
            "node_crash": set(),
        }
        self._topology = self._load_topology_from_disk()

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _load_topology_from_disk(self) -> dict[str, Any]:
        if not self._topology_path.exists():
            self._topology_path.parent.mkdir(parents=True, exist_ok=True)
            default = {
                "corridor_id": "C1",
                "priority_direction": "NORTHBOUND",
                "average_vehicle_speed_mps": 11.11,
                "intersections": [{"intersection_id": "J01", "distance_to_next_m": 0}],
                "links": [],
            }
            self._topology_path.write_text(json.dumps(default, indent=2), encoding="utf-8")
            return default

        with self._topology_path.open("r", encoding="utf-8") as fp:
            data = json.load(fp)
        self._validate_topology(data)
        return data

    def _validate_topology(self, data: dict[str, Any]) -> None:
        id_pattern = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
        intersections = data.get("intersections", [])
        if not isinstance(intersections, list) or not intersections:
            raise ValueError("Topology must include a non-empty intersections list")
        if len(intersections) > 20:
            raise ValueError("Topology supports at most 20 intersections")

        ids = []
        for item in intersections:
            intersection_id = item.get("intersection_id")
            if not intersection_id:
                raise ValueError("Each intersection requires intersection_id")
            text_id = str(intersection_id)
            if not id_pattern.fullmatch(text_id):
                raise ValueError(
                    "intersection_id must match ^[A-Za-z0-9_-]{1,32}$"
                )
            ids.append(text_id)

        if len(set(ids)) != len(ids):
            raise ValueError("intersection_id values must be unique")

        links = data.get("links", [])
        id_set = set(ids)
        for link in links:
            frm = link.get("from")
            to = link.get("to")
            if frm not in id_set or to not in id_set:
                raise ValueError("links must reference valid intersection_ids")
            if float(link.get("distance_m", 0)) < 0:
                raise ValueError("link distance_m cannot be negative")

    async def get_topology(self) -> dict[str, Any]:
        async with self._lock:
            return json.loads(json.dumps(self._topology))

    async def set_topology(self, data: dict[str, Any]) -> dict[str, Any]:
        self._validate_topology(data)
        async with self._lock:
            self._topology = data
            self._topology_changed = True
            self._metrics_changed = True
            self._link_speed_ema = {}
            self._topology_path.parent.mkdir(parents=True, exist_ok=True)
            with self._topology_path.open("w", encoding="utf-8") as fp:
                json.dump(data, fp, indent=2)
        await self._message_bus.publish(
            "system_events",
            {
                "event": "topology_updated",
                "corridor_id": data.get("corridor_id", "C1"),
                "intersection_count": len(data.get("intersections", [])),
            },
        )
        return data

    async def ingest_metrics(self, payload: dict[str, Any]) -> None:
        metric = IntersectionMetric(
            intersection_id=str(payload["intersection_id"]),
            queue_count=float(payload.get("queue_count", 0.0)),
            lane_density=float(payload.get("lane_density", 0.0)),
            vehicle_type_weight=float(payload.get("vehicle_type_weight", 0.0)),
            occupancy_ratio=float(payload.get("occupancy_ratio", 0.0)),
            arrival_rate=float(payload.get("arrival_rate", 0.0)),
            timestamp=str(payload.get("timestamp") or self._now()),
        )
        async with self._lock:
            self._metrics[metric.intersection_id] = metric
            self._metrics_changed = True

    async def set_failure(self, failure_type: str, intersection_id: str, active: bool) -> None:
        if failure_type not in self._failures:
            raise ValueError(f"Unsupported failure type: {failure_type}")
        async with self._lock:
            bucket = self._failures[failure_type]
            changed = False
            if active:
                if intersection_id not in bucket:
                    changed = True
                bucket.add(intersection_id)
            else:
                if intersection_id in bucket:
                    changed = True
                bucket.discard(intersection_id)
            if changed:
                self._failures_changed = True

    async def failure_status(self) -> dict[str, list[str]]:
        async with self._lock:
            return {k: sorted(v) for k, v in self._failures.items()}

    async def get_strategy(self) -> str:
        async with self._lock:
            return self._strategy

    async def set_strategy(self, strategy: str) -> str:
        normalized = str(strategy or "").strip().upper()
        if normalized not in {"ADAPTIVE", "FIXED"}:
            raise ValueError("strategy must be ADAPTIVE or FIXED")
        async with self._lock:
            self._strategy = normalized
            self._metrics_changed = True
        return normalized

    @staticmethod
    def _clamp(value: float, lo: float, hi: float) -> float:
        return max(lo, min(hi, value))

    def _safe_metric(self, metric: IntersectionMetric | None) -> IntersectionMetric | None:
        if metric is None:
            return None
        return IntersectionMetric(
            intersection_id=metric.intersection_id,
            queue_count=self._clamp(metric.queue_count, 0.0, 200.0),
            lane_density=self._clamp(metric.lane_density, 0.0, 1.0),
            vehicle_type_weight=self._clamp(metric.vehicle_type_weight, 0.0, 6.0),
            occupancy_ratio=self._clamp(metric.occupancy_ratio, 0.0, 1.0),
            arrival_rate=self._clamp(metric.arrival_rate, 0.0, 25.0),
            timestamp=metric.timestamp,
        )

    def _phase_scores(self, metric: IntersectionMetric | None) -> list[float]:
        if metric is None:
            return [1.0, 1.0, 1.0, 1.0]
        m = self._safe_metric(metric)
        assert m is not None

        # Phase-specific pressure construction. This avoids overfitting a single scalar
        # while still operating with limited per-intersection telemetry.
        ns_through = (0.55 * m.queue_count) + (28.0 * m.occupancy_ratio) + (8.0 * m.arrival_rate)
        ew_through = (0.42 * m.queue_count) + (30.0 * m.lane_density) + (7.0 * m.arrival_rate)
        ns_turn = (0.30 * m.queue_count) + (24.0 * m.vehicle_type_weight) + (6.0 * m.arrival_rate)
        ew_turn = (0.22 * m.queue_count) + (26.0 * m.lane_density) + (6.5 * m.vehicle_type_weight)
        base = [ns_through, ew_through, ns_turn, ew_turn]
        return [max(1.0, score) for score in base]

    def _update_phase_ema(self, intersection_id: str, scores: list[float]) -> list[float]:
        prev = self._phase_score_ema.get(intersection_id, [scores[0], scores[1], scores[2], scores[3]])
        smoothed = []
        for idx, value in enumerate(scores):
            smooth = prev[idx] + (self._phase_ema_alpha * (value - prev[idx]))
            smoothed.append(max(1.0, smooth))
        self._phase_score_ema[intersection_id] = smoothed
        return smoothed

    def _update_starvation(self, intersection_id: str, split: dict[str, int], cycle_length: int) -> dict[str, int]:
        ticks = self._phase_starvation_ticks.get(intersection_id, [0, 0, 0, 0])
        avg_share = cycle_length / 4.0
        for idx in range(4):
            phase_key = str(idx)
            if split[phase_key] < (avg_share * 0.72):
                ticks[idx] += 1
            else:
                ticks[idx] = 0
        self._phase_starvation_ticks[intersection_id] = ticks
        return split

    def _apply_starvation_boost(self, intersection_id: str, split: dict[str, int], cycle_length: int) -> dict[str, int]:
        ticks = self._phase_starvation_ticks.get(intersection_id, [0, 0, 0, 0])
        if not any(t >= self._starvation_soft_limit for t in ticks):
            return split

        boosted = dict(split)
        budget = 0
        for idx, t in enumerate(ticks):
            if t >= self._starvation_soft_limit:
                extra = int(round(cycle_length * self._starvation_boost))
                boosted[str(idx)] += extra
                budget += extra

        if budget <= 0:
            return boosted

        # Recover budget from the currently longest phases first.
        for phase_key, _ in sorted(boosted.items(), key=lambda x: x[1], reverse=True):
            if budget <= 0:
                break
            min_floor = max(8, int(round(cycle_length * 0.08)))
            available = max(0, boosted[phase_key] - min_floor)
            if available <= 0:
                continue
            take = min(available, budget)
            boosted[phase_key] -= take
            budget -= take
        return boosted

    def _rebalance_split(self, split: dict[str, int], cycle_length: int) -> dict[str, int]:
        min_green = max(8, int(round(cycle_length * 0.08)))
        max_green = int(cycle_length * 0.5)
        normalized = {k: int(self._clamp(v, min_green, max_green)) for k, v in split.items()}

        diff = cycle_length - sum(normalized.values())
        if diff == 0:
            return normalized

        # Add time to shortest phases first; remove from longest first.
        while diff > 0:
            progressed = False
            for key, _ in sorted(normalized.items(), key=lambda item: item[1]):
                if normalized[key] < max_green:
                    normalized[key] += 1
                    diff -= 1
                    progressed = True
                    if diff == 0:
                        break
            if not progressed:
                break

        while diff < 0:
            progressed = False
            for key, _ in sorted(normalized.items(), key=lambda item: item[1], reverse=True):
                if normalized[key] > min_green:
                    normalized[key] -= 1
                    diff += 1
                    progressed = True
                    if diff == 0:
                        break
            if not progressed:
                break

        return normalized

    def _phase_split(
        self,
        intersection_id: str,
        metric: IntersectionMetric | None,
        cycle_length: int,
    ) -> dict[str, int]:
        """
        Dynamically allocates the total cycle_length across 4 phases based on proportional demand.
        Unlike fixed-timers, this strictly divides the green time relative to the calculated weights
        of each phase, enforcing min/max boundaries to prevent starvation or excessive wait times.
        """
        if metric is None:
            even = max(8, int(round(cycle_length / 4.0)))
            fallback_split = {"0": even, "1": even, "2": even, "3": even}
            split = self._rebalance_split(fallback_split, cycle_length)
            split = self._update_starvation(intersection_id, split, cycle_length)
            split = self._apply_starvation_boost(intersection_id, split, cycle_length)
            return self._rebalance_split(split, cycle_length)

        raw_scores = self._phase_scores(metric)
        scores = self._update_phase_ema(intersection_id, raw_scores)

        total_weight = sum(scores)
        if total_weight <= 0:
            total_weight = 1.0

        min_green = max(8, int(round(cycle_length * 0.08)))
        max_green = int(cycle_length * 0.5)

        p0 = int(round((scores[0] / total_weight) * cycle_length))
        p1 = int(round((scores[1] / total_weight) * cycle_length))
        p2 = int(round((scores[2] / total_weight) * cycle_length))
        p3 = int(round((scores[3] / total_weight) * cycle_length))

        p0 = max(min_green, min(p0, max_green))
        p1 = max(min_green, min(p1, max_green))
        p2 = max(min_green, min(p2, max_green))
        p3 = max(min_green, min(p3, max_green))

        split = {"0": p0, "1": p1, "2": p2, "3": p3}
        split = self._rebalance_split(split, cycle_length)

        split = self._update_starvation(intersection_id, split, cycle_length)
        split = self._apply_starvation_boost(intersection_id, split, cycle_length)
        return self._rebalance_split(split, cycle_length)

    def _metric_signature(self, metrics: dict[str, IntersectionMetric]) -> tuple[Any, ...]:
        rows: list[tuple[Any, ...]] = []
        for intersection_id in sorted(metrics.keys()):
            metric = metrics[intersection_id]
            rows.append(
                (
                    intersection_id,
                    int(round(metric.queue_count / 2.0)),
                    round(metric.occupancy_ratio, 1),
                    round(metric.arrival_rate, 1),
                )
            )
        return tuple(rows)

    def _estimate_link_speed(self, base_speed: float, metric: IntersectionMetric | None) -> float:
        """
        Estimates the actual travel speed of a vehicle on a road link between two intersections.
        As traffic density and queue lengths increase, the effective speed drops.
        """
        if metric is None:
            return base_speed

        # Calculate congestion pressures using softer scaling for better accuracy across varying road sizes
        queue_pressure = min(1.0, max(0.0, metric.queue_count / 50.0))
        occupancy_pressure = min(1.0, max(0.0, metric.occupancy_ratio))
        density_pressure = min(1.0, max(0.0, metric.lane_density))

        # Weighted blend of pressures. Density and Occupancy are highly indicative of slow-moving traffic.
        pressure = (0.3 * queue_pressure) + (0.4 * occupancy_pressure) + (0.3 * density_pressure)

        # The higher the pressure, the slower the traffic.
        # Max reduction is 70% of base speed (heavy traffic).
        speed_reduction_factor = 1.0 - (0.7 * pressure)
        target = base_speed * speed_reduction_factor

        # Absolute minimum speed floor (e.g., bumper-to-bumper crawl at 2.0 m/s)
        return max(2.0, target)

    def _compute_offsets(self, topology: dict[str, Any], metrics: dict[str, IntersectionMetric]) -> dict[str, int]:
        base_speed = max(1.0, float(topology.get("average_vehicle_speed_mps", 11.11)))
        links = topology.get("links", [])
        intersections = [item["intersection_id"] for item in topology.get("intersections", [])]

        offsets: dict[str, int] = {}
        if not intersections:
            return offsets

        offsets[intersections[0]] = 0
        offset_acc = 0.0

        for idx in range(len(intersections) - 1):
            current = intersections[idx]
            nxt = intersections[idx + 1]

            distance = None
            for link in links:
                if str(link.get("from")) == current and str(link.get("to")) == nxt:
                    distance = float(link.get("distance_m", 0))
                    break
            if distance is None:
                fallback_item = topology.get("intersections", [])[idx]
                distance = float(fallback_item.get("distance_to_next_m", 0))
            dist = max(0.0, float(distance))

            metric = self._safe_metric(metrics.get(current))
            target_speed = self._estimate_link_speed(base_speed, metric)
            link_key = f"{current}->{nxt}"
            prev_speed = self._link_speed_ema.get(link_key, target_speed)
            speed = prev_speed + (self._speed_ema_alpha * (target_speed - prev_speed))
            self._link_speed_ema[link_key] = speed
            link_travel_time_sec = dist / max(1.0, speed)
            offset_acc += link_travel_time_sec
            node_offset = round(offset_acc / self._offset_quantum_sec) * self._offset_quantum_sec
            offsets[nxt] = int(round(node_offset))

        for intersection_id in intersections:
            offsets.setdefault(intersection_id, 0)

        return offsets

    def _compute_cycle_length(
        self,
        topology: dict[str, Any],
        metrics: dict[str, IntersectionMetric],
        failures: dict[str, set[str]],
    ) -> int:
        intersections = [str(item["intersection_id"]) for item in topology.get("intersections", [])]
        if not intersections:
            return 90

        pressure_values: list[float] = []
        for intersection_id in intersections:
            metric = self._safe_metric(metrics.get(intersection_id))
            if metric is None:
                pressure_values.append(0.45)
                continue
            queue_factor = self._clamp(metric.queue_count / 25.0, 0.0, 1.0)
            arrival_factor = self._clamp(metric.arrival_rate / 12.0, 0.0, 1.0)
            pressure = (
                (0.42 * queue_factor)
                + (0.26 * metric.occupancy_ratio)
                + (0.20 * metric.lane_density)
                + (0.12 * arrival_factor)
            )
            pressure_values.append(self._clamp(pressure, 0.0, 1.0))

        mean_pressure = sum(pressure_values) / max(1, len(pressure_values))
        failed_nodes = len({x for s in failures.values() for x in s})
        failure_ratio = failed_nodes / max(1, len(intersections))
        degraded = self._clamp(mean_pressure - (0.22 * failure_ratio), 0.0, 1.0)
        self._last_cycle_diagnostics = {
            "mean_pressure": round(mean_pressure, 4),
            "failure_ratio": round(failure_ratio, 4),
            "degraded_pressure": round(degraded, 4),
        }

        # Adaptive cycle (70..140) with failure dampening to avoid overcoordination.
        cycle = int(round(70 + (degraded * 70)))
        return int(self._clamp(cycle, 70, 140))

    async def compute_plan(self) -> dict[str, Any]:
        async with self._lock:
            topology = json.loads(json.dumps(self._topology))
            metrics = dict(self._metrics)
            failures = {k: set(v) for k, v in self._failures.items()}
            strategy = self._strategy

        cycle_length = 90 if strategy == "FIXED" else self._compute_cycle_length(topology, metrics, failures)
        offsets = self._compute_offsets(topology, metrics)
        phase_split: dict[str, dict[str, int]] = {}
        modes: dict[str, str] = {}

        for intersection in topology.get("intersections", []):
            intersection_id = str(intersection["intersection_id"])
            metric = metrics.get(intersection_id)
            if strategy == "FIXED":
                phase_split[intersection_id] = {"0": 25, "1": 20, "2": 25, "3": 20}
            else:
                phase_split[intersection_id] = self._phase_split(
                    intersection_id=intersection_id,
                    metric=metric,
                    cycle_length=cycle_length,
                )

            failed = any(intersection_id in group for group in failures.values())
            modes[intersection_id] = "FIXED" if failed else "COORDINATED"

        plan = {
            "corridor_id": topology.get("corridor_id", "C1"),
            "cycle_length": cycle_length,
            "phase_split": phase_split,
            "offset": offsets,
            "priority_direction": topology.get("priority_direction", "NORTHBOUND"),
            "modes": modes,
            "strategy": strategy,
            "diagnostics": {
                "intersection_count": len(topology.get("intersections", [])),
                "failure_count": len({x for s in failures.values() for x in s}),
                **self._last_cycle_diagnostics,
            },
            "generated_at": self._now(),
        }

        async with self._lock:
            self._last_plan = plan
            self._last_plan_at_monotonic = time.monotonic()
            self._last_metrics_signature = self._metric_signature(metrics)
            self._metrics_changed = False
            self._topology_changed = False
            self._failures_changed = False

        return plan

    async def compute_plan_if_needed(self) -> dict[str, Any] | None:
        now = time.monotonic()
        async with self._lock:
            metrics = dict(self._metrics)
            signature = self._metric_signature(metrics)
            stale = (now - self._last_plan_at_monotonic) >= self._max_plan_stale_sec
            needs = (
                self._last_plan is None
                or self._metrics_changed
                or self._topology_changed
                or self._failures_changed
                or signature != self._last_metrics_signature
                or stale
            )
        if not needs:
            return None
        return await self.compute_plan()

    async def latest_plan(self) -> dict[str, Any]:
        async with self._lock:
            cached = json.loads(json.dumps(self._last_plan)) if self._last_plan is not None else None
        if cached is not None:
            return cached
        return await self.compute_plan()

    async def run(self, stop_event: asyncio.Event) -> None:
        while not stop_event.is_set():
            plan = await self.compute_plan_if_needed()
            if plan is not None:
                await self._message_bus.publish("signal_plans", plan)
            await asyncio.sleep(self._update_interval_sec)
