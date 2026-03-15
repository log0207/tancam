import asyncio
import os
import re
import time
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from backend.corridor.corridor_controller import CorridorController
from backend.corridor.emergency_manager import EmergencyManager
from backend.messaging.message_bus import MessageBus
from backend.system.health_monitor import HealthMonitor
from backend.system.kpi_store import KPIStore
from backend.system.time_sync import TimeSyncManager
from backend.vision.yolo_engine import YOLOEngine

BASE_DIR = Path(__file__).resolve().parent
TOPOLOGY_PATH = BASE_DIR / "backend" / "system" / "data" / "corridor_topology.json"
INTERSECTION_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,32}$")


def env_flag(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


FEATURE_FLAGS = {
    "MULTI_INTERSECTION": env_flag("MULTI_INTERSECTION", True),
    "YOLO_ENABLED": env_flag("YOLO_ENABLED", False),
    "CORRIDOR_ENABLED": env_flag("CORRIDOR_ENABLED", False),
    "TWO_TIER_ENABLED": env_flag("TWO_TIER_ENABLED", True), # Enables Edge/Raspberry Pi Hardware integration
}


class TrafficMetricsPayload(BaseModel):
    intersection_id: str | None = None
    queue_count: float = Field(default=0.0, ge=0.0)
    lane_density: float = Field(default=0.0, ge=0.0)
    vehicle_type_weight: float = Field(default=0.0, ge=0.0)
    occupancy_ratio: float = Field(default=0.0, ge=0.0)
    arrival_rate: float = Field(default=0.0, ge=0.0)
    timestamp: str | None = None


class ControlCommandPayload(BaseModel):
    action: str
    intersection_id: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)


class IntersectionStatePayload(BaseModel):
    intersection_id: str | None = None
    signal_state: str = "RED"
    phase: int = 0
    queue_length: int = 0
    occupancy: float = 0.0
    confidence: float = 0.0
    mode: str = "LOCAL_ADAPTIVE"
    last_update: str | None = None


class VisionDetectionRequest(BaseModel):
    request_id: str | None = None
    camera_id: str
    frame: dict[str, Any] = Field(default_factory=dict)
    roi_zones: list[dict[str, Any]] = Field(default_factory=list)


class VisionBatchRequest(BaseModel):
    items: list[VisionDetectionRequest] = Field(default_factory=list)


class StrategyPayload(BaseModel):
    strategy: str = "ADAPTIVE"


class IntersectionKPIPayload(BaseModel):
    queue_length: float = Field(default=0.0, ge=0.0)
    occupancy_ratio: float = Field(default=0.0, ge=0.0)
    avg_wait_sec: float = Field(default=0.0, ge=0.0)
    p95_wait_sec: float = Field(default=0.0, ge=0.0)
    throughput_veh_per_min: float = Field(default=0.0, ge=0.0)
    active_waiting_vehicles: int = Field(default=0, ge=0)
    cleared_vehicles_total: int = Field(default=0, ge=0)


app = FastAPI(title="Adaptive Traffic 3D Web")
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

message_bus = MessageBus()
health_monitor = HealthMonitor()
time_sync = TimeSyncManager(drift_threshold_ms=250.0)
corridor_controller = CorridorController(
    message_bus=message_bus,
    topology_path=TOPOLOGY_PATH,
    update_interval_sec=2.0,
)
emergency_manager = EmergencyManager(corridor_controller, message_bus)
yolo_engine = YOLOEngine.get_instance()
kpi_store = KPIStore()

_background_tasks: list[asyncio.Task] = []
_stop_event = asyncio.Event()
_latest_intersection_states: dict[str, dict[str, Any]] = {}


def _validate_intersection_id(intersection_id: str) -> None:
    if not INTERSECTION_ID_PATTERN.fullmatch(intersection_id):
        raise HTTPException(
            status_code=400,
            detail="Invalid intersection_id format",
        )


async def _periodic_system_loop() -> None:
    while not _stop_event.is_set():
        await emergency_manager.prune_expired()
        status = {
            "health": health_monitor.snapshot(),
            "time_sync": await time_sync.status(),
            "yolo": yolo_engine.stats(),
        }
        await message_bus.publish("system_events", {"event": "system_tick", **status})
        await asyncio.sleep(5.0)


@app.on_event("startup")
async def startup_event() -> None:
    topology = await corridor_controller.get_topology()
    node_ids = [item["intersection_id"] for item in topology.get("intersections", [])]
    await time_sync.register_nodes(node_ids)
    health_monitor.mark_batch_connectivity(node_ids)

    _stop_event.clear()
    await yolo_engine.start(worker_count=2)
    _background_tasks.clear()
    _background_tasks.append(asyncio.create_task(corridor_controller.run(_stop_event)))
    _background_tasks.append(asyncio.create_task(time_sync.run(_stop_event)))
    _background_tasks.append(asyncio.create_task(_periodic_system_loop()))


@app.on_event("shutdown")
async def shutdown_event() -> None:
    _stop_event.set()
    for task in _background_tasks:
        task.cancel()
    _background_tasks.clear()
    await yolo_engine.stop()


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "feature_flags": FEATURE_FLAGS,
        },
    )


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "feature_flags": FEATURE_FLAGS,
        },
    )


@app.get("/api/health")
async def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "features": FEATURE_FLAGS,
        "yolo": yolo_engine.stats(),
    }


@app.get("/api/system/health")
async def system_health() -> dict[str, Any]:
    return {
        **health_monitor.snapshot(),
        "time_sync": await time_sync.status(),
        "yolo": yolo_engine.stats(),
    }


@app.get("/api/topology")
async def get_topology() -> dict[str, Any]:
    return await corridor_controller.get_topology()


@app.put("/api/topology")
async def put_topology(payload: dict[str, Any]) -> dict[str, Any]:
    try:
        topology = await corridor_controller.set_topology(payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    node_ids = [item["intersection_id"] for item in topology.get("intersections", [])]
    await time_sync.register_nodes(node_ids)
    health_monitor.mark_batch_connectivity(node_ids)
    return topology


@app.post("/api/intersections/{intersection_id}/metrics")
async def ingest_metrics(
    intersection_id: str,
    payload: TrafficMetricsPayload,
) -> dict[str, Any]:
    _validate_intersection_id(intersection_id)
    data = payload.model_dump()
    if data.get("intersection_id") and data["intersection_id"] != intersection_id:
        raise HTTPException(status_code=400, detail="intersection_id mismatch")

    data["intersection_id"] = intersection_id
    if not data.get("timestamp"):
        data["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    await corridor_controller.ingest_metrics(data)
    health_monitor.set_connectivity(intersection_id, True)
    await message_bus.publish("traffic_metrics", data)
    return {"status": "accepted", "intersection_id": intersection_id}


@app.post("/api/intersections/{intersection_id}/state")
async def ingest_intersection_state(
    intersection_id: str,
    payload: IntersectionStatePayload,
) -> dict[str, Any]:
    _validate_intersection_id(intersection_id)
    data = payload.model_dump()
    if data.get("intersection_id") and data["intersection_id"] != intersection_id:
        raise HTTPException(status_code=400, detail="intersection_id mismatch")

    data["intersection_id"] = intersection_id
    if not data.get("last_update"):
        data["last_update"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    _latest_intersection_states[intersection_id] = data
    await message_bus.publish("system_events", {"event": "intersection_state", "state": data})
    return {"status": "accepted", "intersection_id": intersection_id}


@app.get("/api/intersections/state")
async def get_intersection_states() -> dict[str, Any]:
    return {
        "items": list(_latest_intersection_states.values()),
        "count": len(_latest_intersection_states),
    }


@app.get("/api/corridor/plan")
async def get_corridor_plan() -> dict[str, Any]:
    sync = await time_sync.status()
    plan = await corridor_controller.latest_plan()
    if not sync.get("coordination_allowed", True):
        plan = {**plan, "coordination_disabled": True, "disable_reason": "clock_drift_exceeded"}
    return plan


@app.get("/api/control/strategy")
async def get_control_strategy() -> dict[str, Any]:
    return {"strategy": await corridor_controller.get_strategy()}


@app.put("/api/control/strategy")
async def put_control_strategy(
    payload: StrategyPayload
) -> dict[str, Any]:
    try:
        strategy = await corridor_controller.set_strategy(payload.strategy)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"strategy": strategy}


@app.get("/api/emergency/active")
async def get_emergency_active() -> dict[str, Any]:
    return await emergency_manager.active_events()


@app.post("/api/vision/detect")
async def vision_detect(payload: VisionDetectionRequest) -> dict[str, Any]:
    request_id = payload.request_id or str(uuid.uuid4())
    started = time.perf_counter()
    detections = await yolo_engine.submit_frame(
        request_id=request_id,
        camera_id=payload.camera_id,
        frame=payload.frame,
        roi_zones=payload.roi_zones,
    )
    latency_ms = (time.perf_counter() - started) * 1000.0
    health_monitor.record_inference_latency(latency_ms)

    result = {
        "request_id": request_id,
        "camera_id": payload.camera_id,
        "detections": detections,
        "latency_ms": round(latency_ms, 3),
    }
    await message_bus.publish("system_events", {"event": "vision_inference", **result})
    return result


@app.post("/api/vision/detect/batch")
async def vision_detect_batch(payload: VisionBatchRequest) -> dict[str, Any]:
    started = time.perf_counter()
    batch_items = [item.model_dump() for item in payload.items]
    detections = await yolo_engine.submit_batch(batch_items)
    latency_ms = (time.perf_counter() - started) * 1000.0
    health_monitor.record_inference_latency(latency_ms)
    result = {
        "camera_results": detections,
        "latency_ms": round(latency_ms, 3),
        "batch_size": len(batch_items),
    }
    await message_bus.publish("system_events", {"event": "vision_batch_inference", **result})
    return result


@app.post("/api/control/command")
async def control_command(payload: ControlCommandPayload) -> dict[str, Any]:
    action = payload.action.strip().lower()
    intersection_id = payload.intersection_id or payload.payload.get("intersection_id")

    if action == "inject_emergency":
        if not intersection_id:
            raise HTTPException(status_code=400, detail="intersection_id is required for inject_emergency")
        end_id = payload.payload.get("end_intersection")
        event_id = payload.payload.get("event_id") or f"emg-{uuid.uuid4().hex[:8]}"
        try:
            event = await emergency_manager.activate(event_id, intersection_id, end_id)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        await message_bus.publish(
            "system_events",
            {
                "event": "inject_emergency",
                "intersection_id": intersection_id,
                "payload": payload.payload,
                "result": event,
            },
        )
        await message_bus.publish("alerts", {"type": "inject_emergency", **event})
        return {"status": "ok", "result": event}

    if action == "clear_emergency":
        event_id = payload.payload.get("event_id")
        if not event_id:
            raise HTTPException(status_code=400, detail="event_id is required for clear_emergency")
        event = await emergency_manager.complete(event_id)
        await message_bus.publish(
            "system_events",
            {
                "event": "clear_emergency",
                "payload": payload.payload,
                "result": event,
            },
        )
        return {"status": "ok", "result": event}

    if action == "ntp_sync":
        await time_sync.apply_ntp_sync()
        await message_bus.publish("system_events", {"event": "ntp_sync_applied"})
        return {"status": "ok", "result": await time_sync.status()}

    if action in {"force_green", "activate_corridor", "free_traffic"}:
        event = {
            "event": action,
            "intersection_id": intersection_id,
            "payload": payload.payload,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        await message_bus.publish("system_events", event)
        return {"status": "ok", "result": event}

    failure_actions = {"network_outage", "camera_failure", "low_visibility", "node_crash"}
    if action in failure_actions:
        active = bool(payload.payload.get("active", True))
        topology = await corridor_controller.get_topology()
        if intersection_id:
            targets = [intersection_id]
        else:
            targets = [item["intersection_id"] for item in topology.get("intersections", [])]

        for target in targets:
            await corridor_controller.set_failure(action, target, active)
            if action in {"network_outage", "node_crash"}:
                health_monitor.set_connectivity(target, not active)

        alert_payload = {
            "type": action,
            "active": active,
            "targets": targets,
        }
        await message_bus.publish("alerts", alert_payload)
        await message_bus.publish(
            "system_events",
            {
                "event": action,
                "payload": payload.payload,
                "targets": targets,
                "active": active,
            },
        )
        return {
            "status": "ok",
            "result": alert_payload,
            "failure_status": await corridor_controller.failure_status(),
        }

    raise HTTPException(status_code=400, detail=f"Unsupported action '{action}'")


@app.get("/api/control/commands")
async def get_control_commands(limit: int = 50) -> dict[str, Any]:
    events = await message_bus.snapshot("system_events", limit=max(1, min(500, limit)))
    command_names = {
        "force_green",
        "activate_corridor",
        "free_traffic",
        "inject_emergency",
        "clear_emergency",
        "network_outage",
        "camera_failure",
        "low_visibility",
        "node_crash",
        "ntp_sync_applied",
    }

    command_events = []
    for event in events:
        payload = event.get("payload", {})
        event_name = payload.get("event")
        if event_name in command_names:
            command_events.append(event)
            continue
        event_type = payload.get("type")
        if event_type in command_names:
            command_events.append(event)

    return {"items": command_events}


@app.post("/api/intersections/{intersection_id}/kpi")
async def ingest_intersection_kpi(
    intersection_id: str,
    payload: IntersectionKPIPayload,
) -> dict[str, Any]:
    _validate_intersection_id(intersection_id)
    await kpi_store.ingest(intersection_id, payload.model_dump())
    return {"status": "accepted", "intersection_id": intersection_id}


@app.get("/api/kpi/summary")
async def get_kpi_summary() -> dict[str, Any]:
    strategy = await corridor_controller.get_strategy()
    summary = await kpi_store.summary()
    return {"strategy": strategy, **summary}


@app.post("/api/kpi/reset")
async def reset_kpi() -> dict[str, Any]:
    await kpi_store.reset()
    return {"status": "ok", "reset_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


@app.websocket("/ws/monitor")
async def websocket_monitor(websocket: WebSocket) -> None:
    topics = ["traffic_metrics", "signal_plans", "system_events", "alerts"]
    await websocket.accept()

    queue = await message_bus.subscribe(topics, max_queue=256)
    try:
        bootstrap_payload = {
            "topic": "bootstrap",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "payload": {
                "plan": await corridor_controller.latest_plan(),
                "topology": await corridor_controller.get_topology(),
                "health": health_monitor.snapshot(),
                "time_sync": await time_sync.status(),
                "failures": await corridor_controller.failure_status(),
                "states": list(_latest_intersection_states.values()),
            },
        }
        await websocket.send_json(bootstrap_payload)

        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=10.0)
                await websocket.send_json(event)
            except asyncio.TimeoutError:
                await websocket.send_json(
                    {
                        "topic": "heartbeat",
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "payload": {"status": "alive"},
                    }
                )
    except WebSocketDisconnect:
        pass
    finally:
        await message_bus.unsubscribe(queue, topics)
