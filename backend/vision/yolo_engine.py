from __future__ import annotations

import asyncio
import os
import random
import time
from dataclasses import dataclass
from typing import Any


@dataclass
class DetectionTask:
    request_id: str
    camera_id: str
    frame: Any
    roi_zones: list[dict[str, Any]]
    future: asyncio.Future


class YOLOEngine:
    _instance: "YOLOEngine | None" = None

    @classmethod
    def get_instance(cls) -> "YOLOEngine":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self) -> None:
        if YOLOEngine._instance is not None:
            raise RuntimeError("Use YOLOEngine.get_instance() for singleton access")

        self.backend = os.getenv("YOLO_BACKEND", "mock").lower()
        self.model_path = os.getenv("YOLO_MODEL_PATH", "")
        self.max_fps = 5.0
        self._min_interval = 1.0 / self.max_fps
        self._frame_queue: asyncio.Queue[DetectionTask] = asyncio.Queue(maxsize=64)
        self._workers: list[asyncio.Task] = []
        self._running = False
        self._last_infer = 0.0
        self._latencies_ms: list[float] = []
        self._model = None

    async def start(self, worker_count: int = 2) -> None:
        if self._running:
            return
        self._running = True
        await self._load_model_if_needed()
        self._workers = [asyncio.create_task(self._worker_loop(f"det-worker-{i}")) for i in range(max(1, worker_count))]

    async def stop(self) -> None:
        self._running = False
        for task in self._workers:
            task.cancel()
        self._workers.clear()

    async def _load_model_if_needed(self) -> None:
        if self.backend != "real" or self._model is not None:
            return

        try:
            from ultralytics import YOLO  # type: ignore

            model_name = self.model_path or "yolov8n.pt"
            self._model = YOLO(model_name)
        except Exception as exc:  # pragma: no cover - optional runtime integration
            raise RuntimeError(
                "YOLO_BACKEND=real requested but ultralytics model could not be loaded"
            ) from exc

    async def submit_frame(
        self,
        request_id: str,
        camera_id: str,
        frame: Any,
        roi_zones: list[dict[str, Any]] | None = None,
        timeout_sec: float = 1.5,
    ) -> list[dict[str, Any]]:
        if not self._running:
            await self.start()

        future: asyncio.Future = asyncio.get_running_loop().create_future()
        task = DetectionTask(
            request_id=request_id,
            camera_id=camera_id,
            frame=frame,
            roi_zones=roi_zones or [],
            future=future,
        )

        if self._frame_queue.full():
            try:
                dropped = self._frame_queue.get_nowait()
                if not dropped.future.done():
                    dropped.future.set_result([])
            except asyncio.QueueEmpty:
                pass

        await self._frame_queue.put(task)
        return await asyncio.wait_for(future, timeout=timeout_sec)

    async def submit_batch(
        self,
        batch_items: list[dict[str, Any]],
        timeout_sec: float = 2.0,
    ) -> dict[str, list[dict[str, Any]]]:
        tasks = []
        for item in batch_items:
            request_id = str(item.get("request_id") or f"batch-{time.time_ns()}")
            camera_id = str(item.get("camera_id", "cam-0"))
            frame = item.get("frame", {})
            roi_zones = item.get("roi_zones", [])
            tasks.append(
                self.submit_frame(
                    request_id=request_id,
                    camera_id=camera_id,
                    frame=frame,
                    roi_zones=roi_zones,
                    timeout_sec=timeout_sec,
                )
            )

        detections = await asyncio.gather(*tasks, return_exceptions=True)
        result: dict[str, list[dict[str, Any]]] = {}
        for item, detection_result in zip(batch_items, detections):
            camera_id = str(item.get("camera_id", "cam-0"))
            if isinstance(detection_result, Exception):
                result[camera_id] = []
            else:
                result[camera_id] = detection_result
        return result

    async def _worker_loop(self, worker_name: str) -> None:
        while self._running:
            task = await self._frame_queue.get()
            try:
                now = time.perf_counter()
                sleep_for = self._min_interval - (now - self._last_infer)
                if sleep_for > 0:
                    await asyncio.sleep(sleep_for)

                start = time.perf_counter()
                detections = await self._detect(task.camera_id, task.frame, task.roi_zones)
                latency = (time.perf_counter() - start) * 1000.0
                self._latencies_ms.append(latency)
                if len(self._latencies_ms) > 500:
                    self._latencies_ms = self._latencies_ms[-500:]

                self._last_infer = time.perf_counter()
                if not task.future.done():
                    task.future.set_result(detections)
            except Exception:
                if not task.future.done():
                    task.future.set_result([])

    async def _detect(
        self,
        camera_id: str,
        frame: Any,
        roi_zones: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        if self.backend == "real" and self._model is not None:
            return await self._real_detect(frame, roi_zones)
        return self._mock_detect(camera_id, frame, roi_zones)

    async def _real_detect(self, frame: Any, roi_zones: list[dict[str, Any]]) -> list[dict[str, Any]]:
        # Real model execution path is optional and only active when YOLO_BACKEND=real.
        # Frame pre-processing and ROI cropping can be handled by client before submit.
        results = self._model.predict(frame, verbose=False)
        detections: list[dict[str, Any]] = []
        for result in results:
            names = result.names
            for box in result.boxes:
                cls_idx = int(box.cls.item())
                conf = float(box.conf.item())
                x1, y1, x2, y2 = box.xyxy[0].tolist()
                bbox = [float(x1), float(y1), float(x2 - x1), float(y2 - y1)]
                if roi_zones and not self._bbox_in_any_roi(bbox, roi_zones):
                    continue
                detections.append(
                    {
                        "class": names.get(cls_idx, str(cls_idx)),
                        "bbox": bbox,
                        "confidence": round(conf, 4),
                        "lane_id": "L0",
                    }
                )
        return detections

    def _mock_detect(self, camera_id: str, frame: Any, roi_zones: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Mock detection routine for running without physical cameras or GPU constraints.
        Extracts vehicles from the simulated physics payload and applies realistic confidence jitter.
        """
        vehicles = []
        if isinstance(frame, dict):
            vehicles = frame.get("vehicles", []) or []

        detections: list[dict[str, Any]] = []
        for item in vehicles:
            bbox = item.get("bbox", [0, 0, 0, 0])
            if roi_zones and not self._bbox_in_any_roi(bbox, roi_zones):
                continue
            detections.append(
                {
                    "class": item.get("type", "car"),
                    "bbox": bbox,
                    # Add jitter to mock confidence mimicking CV instability
                    "confidence": round(max(0.55, min(0.99, item.get("confidence", 0.78) + random.uniform(-0.05, 0.05))), 3),
                    "lane_id": item.get("lane_id", "L0"),
                    "camera_id": camera_id,
                }
            )

        if not detections and not vehicles:
            # Light fallback so the CV pipeline stays actively emitting in an empty demo mode.
            for _ in range(random.randint(0, 2)):
                bbox = [random.randint(0, 320), random.randint(0, 180), random.randint(25, 80), random.randint(20, 70)]
                if roi_zones and not self._bbox_in_any_roi(bbox, roi_zones):
                    continue

                # BUG FIX: Assign safe lane index instead of randomizing out-of-bounds lanes.
                # If there are predefined ROIs, grab an ID from those, else fallback to 'L0'
                fallback_lane = "L0"
                if roi_zones:
                    # Pick a random valid ROI zone id
                    valid_zone = random.choice(roi_zones)
                    fallback_lane = valid_zone.get("id", "L0")

                detections.append(
                    {
                        "class": random.choice(["car", "bus", "bike", "ambulance"]),
                        "bbox": bbox,
                        "confidence": round(random.uniform(0.6, 0.92), 3),
                        "lane_id": fallback_lane,
                        "camera_id": camera_id,
                    }
                )

        return detections

    @staticmethod
    def _bbox_in_any_roi(bbox: list[float], roi_zones: list[dict[str, Any]]) -> bool:
        x, y, w, h = bbox
        cx = x + (w / 2.0)
        cy = y + (h / 2.0)
        for roi in roi_zones:
            rx = float(roi.get("x", 0))
            ry = float(roi.get("y", 0))
            rw = float(roi.get("w", 0))
            rh = float(roi.get("h", 0))
            if rx <= cx <= rx + rw and ry <= cy <= ry + rh:
                return True
        return False

    def stats(self) -> dict[str, Any]:
        lat = self._latencies_ms
        avg = sum(lat) / len(lat) if lat else 0.0
        return {
            "backend": self.backend,
            "running": self._running,
            "queue_depth": self._frame_queue.qsize(),
            "max_fps": self.max_fps,
            "avg_latency_ms": round(avg, 3),
            "sample_count": len(lat),
            "worker_count": len(self._workers),
        }
