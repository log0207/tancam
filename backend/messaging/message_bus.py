import asyncio
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any, Deque, Dict, Iterable, List


class MessageBus:
    """In-process MQTT-style pub/sub with bounded queues and topic history."""

    def __init__(self, topics: Iterable[str] | None = None, history_size: int = 200) -> None:
        base_topics = topics or ("traffic_metrics", "signal_plans", "system_events", "alerts")
        self._history_size = max(1, history_size)
        self._topics = set(base_topics)
        self._history: Dict[str, Deque[dict[str, Any]]] = {
            topic: deque(maxlen=self._history_size) for topic in self._topics
        }
        self._subscribers: Dict[str, set[asyncio.Queue]] = defaultdict(set)
        self._lock = asyncio.Lock()

    def _ensure_topic(self, topic: str) -> None:
        if topic in self._topics:
            return
        self._topics.add(topic)
        self._history[topic] = deque(maxlen=self._history_size)

    async def publish(self, topic: str, payload: dict[str, Any]) -> dict[str, Any]:
        self._ensure_topic(topic)
        event = {
            "topic": topic,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "payload": payload,
        }

        async with self._lock:
            self._history[topic].append(event)
            subscribers = list(self._subscribers.get(topic, set()))

        for queue in subscribers:
            if queue.full():
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                # If still full after dropping one, skip this subscriber to keep publish non-blocking.
                continue
        return event

    async def subscribe(self, topics: Iterable[str], max_queue: int = 256) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=max(8, max_queue))
        async with self._lock:
            for topic in topics:
                self._ensure_topic(topic)
                self._subscribers[topic].add(queue)
        return queue

    async def unsubscribe(self, queue: asyncio.Queue, topics: Iterable[str]) -> None:
        async with self._lock:
            for topic in topics:
                subs = self._subscribers.get(topic)
                if not subs:
                    continue
                subs.discard(queue)
                if not subs:
                    self._subscribers.pop(topic, None)

    async def snapshot(self, topic: str, limit: int = 20) -> List[dict[str, Any]]:
        self._ensure_topic(topic)
        async with self._lock:
            events = list(self._history[topic])
        if limit <= 0:
            return []
        return events[-limit:]

    async def multi_snapshot(self, topics: Iterable[str], limit: int = 20) -> Dict[str, List[dict[str, Any]]]:
        result: Dict[str, List[dict[str, Any]]] = {}
        for topic in topics:
            result[topic] = await self.snapshot(topic, limit=limit)
        return result
