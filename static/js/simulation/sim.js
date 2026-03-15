import * as THREE from "three";
import { OrbitControls } from "three/addons/controls/OrbitControls.js";
import {
  ROAD_W, STOP_DIST, SPAWN_DIST, WORLD_LIMIT, FPS_STEP, ROAD_TOP_Y, INBOUND_SUBLANES,
  MAX_PER_LANE, SUBLANE_OFFSETS, SIGNAL_TIMINGS, CONTROL_THRESHOLDS, SPAWN_CONTROL, TYPE, USE_CASES,
} from "../constants.js";
import { JUNCTIONS } from "../junctions.js";
import { initVehicleModels, cloneVehicleModelOrFallback, randColor } from "../models.js";
import { IntersectionController, INTERSECTION_MODES } from "../intersection/intersection_controller.js";
import { computeTrafficMetrics, publishTrafficMetrics } from "../intersection/traffic_metrics.js";
import { CorridorClient } from "../corridor/corridor_controller.js";

const corridorClient = new CorridorClient({ baseUrl: "" });
const DEFAULT_RENDER_JUNCTIONS = 10;
const HARD_MAX_RENDER_JUNCTIONS = 20;
const SIM_STEP = 1 / 30;
const MAX_FRAME_DELTA = 0.25;
const MAX_SUBSTEPS = 8;
const MAX_ACTIVE_VEHICLES = 64;
const OVERLAY_INTERVAL = 0.4;
const MAX_OVERLAY_BOXES = 36;

const ui = {
  nodeCount: document.getElementById("sim-node-count"),
  vehicleCount: document.getElementById("sim-vehicle-count"),
  followStatus: document.getElementById("sim-follow-status"),
  camButtons: {
    1: document.getElementById("sim-cam-1"),
    2: document.getElementById("sim-cam-2"),
    3: document.getElementById("sim-cam-3"),
    4: document.getElementById("sim-cam-4"),
  },
  aiToggle: document.getElementById("sim-ai-toggle"),
  junctionView: document.getElementById("sim-junction-view"),
  prevJunction: document.getElementById("sim-prev-junction"),
  nextJunction: document.getElementById("sim-next-junction"),
  cvOverlay: document.getElementById("cv-overlay"),
  auditPanel: null,
};

const canvas = document.getElementById("sim-canvas");
const scene = new THREE.Scene();
scene.background = new THREE.Color(0x95b296);
const renderer = new THREE.WebGLRenderer({ canvas, antialias: true });
renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1.2));
renderer.setSize(window.innerWidth, window.innerHeight);
renderer.outputColorSpace = THREE.SRGBColorSpace;
renderer.shadowMap.enabled = true;
renderer.shadowMap.type = THREE.PCFSoftShadowMap;

const camera = new THREE.PerspectiveCamera(56, window.innerWidth / window.innerHeight, 0.1, 2200);
camera.position.set(0, 74, 120);
camera.lookAt(0, 0, -80);
const controls = new OrbitControls(camera, renderer.domElement);
controls.enableDamping = true;
controls.dampingFactor = 0.06;
controls.minDistance = 10;
controls.maxDistance = 1400;
controls.maxPolarAngle = Math.PI * 0.49;
controls.target.set(0, 0, -80);

const hemi = new THREE.HemisphereLight(0xffffff, 0x7f8c72, 0.9);
scene.add(hemi);
const dir = new THREE.DirectionalLight(0xffffff, 0.45);
dir.position.set(35, 50, 28);
dir.castShadow = true;
dir.shadow.camera.near = 0.5;
dir.shadow.camera.far = 2400;
dir.shadow.camera.left = -300;
dir.shadow.camera.right = 300;
dir.shadow.camera.top = 300;
dir.shadow.camera.bottom = -300;
dir.shadow.mapSize.width = 512;
dir.shadow.mapSize.height = 512;
scene.add(dir);

const clock = new THREE.Clock();
const runtime = {
  topology: null,
  plan: null,
  intersections: [],
  intersectionsById: new Map(),
  intersectionIndexById: new Map(),
  intersectionIds: [],
  focusNodeId: null,
  vehicles: [],
  lastVehicleIndex: null,
  nextVehicleId: 1,
  minZ: -320,
  maxZ: 120,
  laneCooldown: new Map(),
  metricCache: new Map(),
  processedCommands: new Set(),
  processedCommandOrder: [],
  simMinutes: 8 * 60,
  metricTimer: 0,
  planTimer: 0,
  commandTimer: 0,
  uiTimer: 0,
  followEnabled: false,
  followVehicleId: null,
  followPinned: false,
  followRetargetTimer: 0,
  cameraMode: 1,
  aiVisionEnabled: false,
  overlayTimer: 0,
  simAccumulator: 0,
  useCase: "BALANCED",
  currentProfileLabel: "Normal",
  kpiByNode: new Map(),
  emergencyPathSet: new Set(),
  audit: {
    removed: 0,
    violations: 0,
    byReason: {},
    recent: [],
  },
};

const keyState = {};
const TMP_FORWARD = new THREE.Vector3();
const TMP_RIGHT = new THREE.Vector3();
const raycaster = new THREE.Raycaster();
const pointer = new THREE.Vector2();

function laneTemplate(centerZ) {
  const lanes = {
    0: { dir: new THREE.Vector3(0, 0, -1), rotY: Math.PI, spawn: new THREE.Vector3(0, 0, centerZ + SPAWN_DIST), hasSignal: true },
    1: { dir: new THREE.Vector3(-1, 0, 0), rotY: -Math.PI / 2, spawn: new THREE.Vector3(SPAWN_DIST, 0, centerZ), hasSignal: true },
    2: { dir: new THREE.Vector3(0, 0, 1), rotY: 0, spawn: new THREE.Vector3(0, 0, centerZ - SPAWN_DIST), hasSignal: true },
    3: { dir: new THREE.Vector3(1, 0, 0), rotY: Math.PI / 2, spawn: new THREE.Vector3(-SPAWN_DIST, 0, centerZ), hasSignal: true },
  };
  Object.values(lanes).forEach((lane) => {
    lane.left = new THREE.Vector3(-lane.dir.z, 0, lane.dir.x).normalize();
    lane.center = new THREE.Vector3(0, 0, centerZ);
  });
  return lanes;
}

function laneKey(nodeId, lane) {
  return `${nodeId}:${lane}`;
}

function getNodeKPI(nodeId) {
  if (!runtime.kpiByNode.has(nodeId)) {
    runtime.kpiByNode.set(nodeId, {
      clearedVehiclesTotal: 0,
      totalWaitSec: 0,
      waitSamples: [],
      clearedTimestampsSec: [],
      servedVehiclesTotal: 0,
      servedTotalWaitSec: 0,
      servedWaitSamples: [],
      servedTimestampsSec: [],
    });
  }
  return runtime.kpiByNode.get(nodeId);
}

function createVehicleIndex() {
  return {
    nodeVehicles: new Map(),
    nodeLaneCounts: new Map(),
    laneGroups: new Map(),
  };
}

function buildVehicleIndex() {
  const index = createVehicleIndex();
  for (let i = 0; i < runtime.vehicles.length; i += 1) {
    const v = runtime.vehicles[i];
    const nodeId = v.nodeId;
    if (!v.hasCrossed) {
      if (!index.nodeVehicles.has(nodeId)) index.nodeVehicles.set(nodeId, []);
      index.nodeVehicles.get(nodeId).push(v);
      const key = laneKey(nodeId, v.lane);
      index.nodeLaneCounts.set(key, (index.nodeLaneCounts.get(key) ?? 0) + 1);
    }

    const groupKey = `${nodeId}:${v.lane}:${v.subLane}`;
    if (!index.laneGroups.has(groupKey)) index.laneGroups.set(groupKey, []);
    index.laneGroups.get(groupKey).push(v);
  }
  return index;
}

function getLaneLoad(index, nodeId, lane) {
  if (!index) return 0;
  return index.nodeLaneCounts.get(laneKey(nodeId, lane)) ?? 0;
}

function addCorridorSurface() {
  const ground = new THREE.Mesh(new THREE.PlaneGeometry(280, (runtime.maxZ - runtime.minZ) + 260), new THREE.MeshPhongMaterial({ color: 0x8ca88b }));
  ground.rotation.x = -Math.PI / 2;
  ground.position.z = (runtime.maxZ + runtime.minZ) / 2;
  ground.receiveShadow = true;
  scene.add(ground);
  const road = new THREE.Mesh(new THREE.BoxGeometry(ROAD_W, 0.1, (runtime.maxZ - runtime.minZ) + 220), new THREE.MeshPhongMaterial({ color: 0x777a81 }));
  road.position.y = 0.05;
  road.position.z = (runtime.maxZ + runtime.minZ) / 2;
  road.receiveShadow = true;
  scene.add(road);
}

function addCrossing(z) {
  const roadB = new THREE.Mesh(new THREE.BoxGeometry(220, 0.1, ROAD_W), new THREE.MeshPhongMaterial({ color: 0x777a81 }));
  roadB.position.set(0, 0.06, z);
  roadB.receiveShadow = true;
  scene.add(roadB);
  const white = new THREE.MeshBasicMaterial({ color: 0xf2f2f2 });
  const zebra = ROAD_W / 2 + 3;
  for (let i = -7; i <= 7; i += 2) {
    const a = new THREE.Mesh(new THREE.BoxGeometry(1, 0.1, 4), white); a.position.set(i, 0.13, z + zebra);
    const b = new THREE.Mesh(new THREE.BoxGeometry(1, 0.1, 4), white); b.position.set(i, 0.13, z - zebra);
    const c = new THREE.Mesh(new THREE.BoxGeometry(4, 0.1, 1), white); c.position.set(zebra, 0.13, z + i);
    const d = new THREE.Mesh(new THREE.BoxGeometry(4, 0.1, 1), white); d.position.set(-zebra, 0.13, z + i);
    scene.add(a, b, c, d);
  }
}

function buildWorld(topology) {
  runtime.intersections = [];
  runtime.intersectionsById.clear();
  runtime.intersectionIndexById.clear();
  runtime.intersectionIds = [];
  runtime.laneCooldown.clear();
  runtime.kpiByNode.clear();
  const sourceNodes = Array.isArray(topology?.intersections) && topology.intersections.length
    ? topology.intersections
    : [{ intersection_id: "J01", distance_to_next_m: 0 }];
  const renderLimit = Math.max(1, Math.min(HARD_MAX_RENDER_JUNCTIONS, DEFAULT_RENDER_JUNCTIONS));
  const nodes = sourceNodes.slice(0, renderLimit);
  let z = 0;
  const centers = [];
  nodes.forEach((node, i) => {
    if (i > 0) {
      const prev = nodes[i - 1];
      const link = (topology?.links || []).find((l) => l.from === prev.intersection_id && l.to === node.intersection_id);
      z -= Math.max(90, Number(link?.distance_m ?? prev.distance_to_next_m ?? 120));
    }
    centers.push({ id: String(node.intersection_id), z });
  });
  runtime.maxZ = (centers[0]?.z ?? 0) + SPAWN_DIST + 30;
  runtime.minZ = (centers[centers.length - 1]?.z ?? 0) - SPAWN_DIST - 30;

  addCorridorSurface();
  centers.forEach((entry) => {
    addCrossing(entry.z);
    const lanes = laneTemplate(entry.z);
    Object.entries(lanes).forEach(([laneId, lane]) => {
      const fromCenter = lane.spawn.clone().sub(lane.center).normalize();
      const labelPos = lane.center.clone().addScaledVector(fromCenter, STOP_DIST + 5.5);
      addLaneBadge(Number(laneId) + 1, labelPos, lane.rotY);
    });
    const lights = {};
    JUNCTIONS.FOUR_WAY.buildSignals(scene, lights, lanes);
    const controller = new IntersectionController({ intersectionId: entry.id, phases: [0, 1, 2, 3], mode: INTERSECTION_MODES.COORDINATED });
    const node = {
      id: entry.id,
      centerZ: entry.z,
      lanes,
      lights,
      controller,
      etaCache: {},
      offsetSec: 0,
      offsetCurrentSec: 0,
      offsetTargetSec: 0,
      offsetInitialized: false,
      failureStates: new Set(),
      freeTraffic: false,
      runwayMats: addRunwayGuides(entry.z),
      prevPhase: 0,
      prevPhaseState: "GREEN",
    };
    runtime.intersections.push(node);
    runtime.intersectionsById.set(node.id, node);
    runtime.intersectionIndexById.set(node.id, runtime.intersections.length - 1);
    runtime.intersectionIds.push(node.id);
    getNodeKPI(node.id);
    [0, 1, 2, 3].forEach((lane) => runtime.laneCooldown.set(`${entry.id}:${lane}`, 0));
  });
  runtime.focusNodeId = runtime.intersectionIds[0] ?? null;
}

function resolvePlanMode(nodeId) {
  const mode = runtime.plan?.modes?.[nodeId];
  return (mode && INTERSECTION_MODES[mode]) ? mode : INTERSECTION_MODES.COORDINATED;
}

function applyNodeModePolicy(node) {
  if (!node || !node.controller) return;
  if (node.controller.mode === INTERSECTION_MODES.EMERGENCY) return;
  if (node.failureStates && node.failureStates.size > 0) {
    node.controller.setMode(INTERSECTION_MODES.FIXED);
    return;
  }
  node.controller.setMode(resolvePlanMode(node.id));
}

function setCameraMode(mode) {
  runtime.cameraMode = mode;
  if (mode === 1) {
    runtime.followEnabled = false;
    runtime.followPinned = false;
    runtime.followVehicleId = null;
    controls.enabled = true;
    camera.fov = 56;
    camera.updateProjectionMatrix();
    camera.position.set(0, 74, 120);
    controls.target.set(0, 0, (runtime.maxZ + runtime.minZ) * 0.5);
    controls.minDistance = 10;
    controls.maxDistance = 1400;
  } else if (mode === 2) {
    runtime.followEnabled = false;
    runtime.followPinned = false;
    runtime.followVehicleId = null;
    controls.enabled = true;
    camera.fov = 40;
    camera.updateProjectionMatrix();
    camera.position.set(0, 240, (runtime.maxZ + runtime.minZ) * 0.5);
    controls.target.set(0, 0, (runtime.maxZ + runtime.minZ) * 0.5);
    controls.minDistance = 40;
    controls.maxDistance = 1800;
  } else if (mode === 3) {
    runtime.followEnabled = false;
    runtime.followPinned = false;
    runtime.followVehicleId = null;
    controls.enabled = true;
    camera.fov = 62;
    camera.updateProjectionMatrix();
  } else if (mode === 4) {
    runtime.followEnabled = true;
    controls.enabled = false;
    if (!runtime.followVehicleId) {
      runtime.followPinned = false;
    }
  }
  if (runtime.focusNodeId && mode !== 4) {
    focusJunction(runtime.focusNodeId, true);
  }
  updateViewButtons();
}

function updateViewButtons() {
  Object.entries(ui.camButtons || {}).forEach(([id, button]) => {
    if (!button) return;
    button.classList.toggle("is-active", Number(id) === runtime.cameraMode);
  });
  if (ui.aiToggle) {
    ui.aiToggle.classList.toggle("is-active", runtime.aiVisionEnabled);
    ui.aiToggle.textContent = runtime.aiVisionEnabled ? "AI On" : "AI Off";
  }
}

function syncJunctionViewControl() {
  if (!ui.junctionView) return;
  if (runtime.focusNodeId && ui.junctionView.value !== runtime.focusNodeId) {
    ui.junctionView.value = runtime.focusNodeId;
  }
}

function populateJunctionViewControl() {
  if (!ui.junctionView) return;
  ui.junctionView.innerHTML = "";
  runtime.intersectionIds.forEach((id) => {
    const opt = document.createElement("option");
    opt.value = id;
    opt.textContent = id;
    ui.junctionView.appendChild(opt);
  });
  syncJunctionViewControl();
}

function focusJunction(nodeId, immediate = false) {
  const node = runtime.intersectionsById.get(nodeId);
  if (!node) return;
  runtime.focusNodeId = nodeId;

  const target = new THREE.Vector3(0, 0, node.centerZ);
  if (runtime.cameraMode === 1) {
    camera.position.set(0, 74, node.centerZ + 120);
    controls.target.copy(target);
    camera.lookAt(target);
  } else if (runtime.cameraMode === 2) {
    camera.position.set(0, 240, node.centerZ);
    controls.target.copy(target);
    camera.lookAt(target);
  } else if (runtime.cameraMode === 3) {
    const dz = camera.position.z - controls.target.z;
    controls.target.copy(target);
    camera.position.z = node.centerZ + dz;
  }

  if (immediate) {
    controls.target.copy(target);
  }
  syncJunctionViewControl();
}

function stepJunction(step) {
  if (!runtime.intersectionIds.length) return;
  if (runtime.cameraMode === 4) setCameraMode(1);
  const current = runtime.focusNodeId ? runtime.intersectionIds.indexOf(runtime.focusNodeId) : 0;
  const nextIndex = (Math.max(0, current) + step + runtime.intersectionIds.length) % runtime.intersectionIds.length;
  focusJunction(runtime.intersectionIds[nextIndex]);
}

function updateFreeCamera(dt) {
  if (runtime.cameraMode !== 3) return;
  const speed = 34 * dt * (keyState.shift ? 2.0 : 1.0);
  camera.getWorldDirection(TMP_FORWARD);
  TMP_FORWARD.y = 0;
  if (TMP_FORWARD.lengthSq() < 1e-6) TMP_FORWARD.set(0, 0, -1);
  TMP_FORWARD.normalize();
  TMP_RIGHT.set(TMP_FORWARD.z, 0, -TMP_FORWARD.x).normalize();

  if (keyState.w || keyState.arrowup) camera.position.addScaledVector(TMP_FORWARD, speed);
  if (keyState.s || keyState.arrowdown) camera.position.addScaledVector(TMP_FORWARD, -speed);
  if (keyState.a || keyState.arrowleft) camera.position.addScaledVector(TMP_RIGHT, -speed);
  if (keyState.d || keyState.arrowright) camera.position.addScaledVector(TMP_RIGHT, speed);
  if (keyState.q) camera.position.y -= speed;
  if (keyState.e) camera.position.y += speed;
  camera.position.y = clamp(camera.position.y, 6, 320);
}

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function getTrafficProfile(hour) {
  if (hour >= 8 && hour < 10) {
    return {
      mult: 1.85,
      label: "Morning Peak",
      laneBias: { 0: 2.0, 1: 0.9, 2: 1.5, 3: 0.9 },
    };
  }
  if (hour >= 17 && hour < 20) {
    return {
      mult: 1.95,
      label: "Evening Peak",
      laneBias: { 0: 1.4, 1: 1.0, 2: 2.1, 3: 1.0 },
    };
  }
  if (hour >= 22 || hour < 5) {
    return {
      mult: 0.35,
      label: "Night",
      laneBias: { 0: 0.8, 1: 0.7, 2: 0.8, 3: 0.7 },
    };
  }
  if (hour >= 14 && hour < 16) {
    return {
      mult: 1.25,
      label: "School Dismissal",
      laneBias: { 0: 1.35, 1: 1.1, 2: 1.35, 3: 1.1 },
    };
  }
  return {
    mult: 1.0,
    label: "Normal Flow",
    laneBias: { 0: 1.0, 1: 1.0, 2: 1.0, 3: 1.0 },
  };
}

function ensureAuditPanel() {
  if (ui.auditPanel) return;
  const panel = document.createElement("div");
  panel.id = "sim-audit-panel";
  panel.className = "sim-audit-panel";
  panel.innerHTML = "<h4>Exit Audit</h4><div class='audit-lines'></div>";
  document.body.appendChild(panel);
  ui.auditPanel = panel;
}

function recordAudit(reason, details = "", violation = false) {
  runtime.audit.removed += 1;
  runtime.audit.byReason[reason] = (runtime.audit.byReason[reason] || 0) + 1;
  if (violation) runtime.audit.violations += 1;
  runtime.audit.recent.push({
    ts: new Date().toLocaleTimeString(),
    reason,
    details,
    violation,
  });
  if (runtime.audit.recent.length > 14) {
    runtime.audit.recent = runtime.audit.recent.slice(-10);
  }
}

function updateAuditPanel() {
  ensureAuditPanel();
  const lines = ui.auditPanel.querySelector(".audit-lines");
  const reasons = Object.entries(runtime.audit.byReason)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([k, v]) => `${k}: ${v}`)
    .join(" | ");
  const recent = runtime.audit.recent
    .slice(-4)
    .map((item) => `<div class="${item.violation ? "audit-violation" : "audit-ok"}">${item.ts} ${item.reason} ${item.details}</div>`)
    .join("");
  lines.innerHTML = `
    <div>Total exits: ${runtime.audit.removed}</div>
    <div>Violations: ${runtime.audit.violations}</div>
    <div class="audit-reasons">${reasons || "No exits yet"}</div>
    ${recent}
  `;
}

function classifyExitReason(v) {
  const p = v.mesh.position;
  if (v.lane === 0 && p.z < runtime.minZ - 60) return "corridor_exit_forward";
  if (v.lane === 2 && p.z > runtime.maxZ + 60) return "corridor_exit_reverse";
  if (v.lane === 1 && p.x < -130) return "cross_exit_west";
  if (v.lane === 3 && p.x > 130) return "cross_exit_east";
  return null;
}

function removeVehicleAtIndex(index, reason, violation = false) {
  const v = runtime.vehicles[index];
  if (!v) return;
  const nowSec = runtime.simMinutes * 60;
  const currentWait = v.waiting ? Math.max(0, nowSec - v.waitStart) : 0;
  const totalWait = Math.max(0, v.totalWait + currentWait);
  const kpi = getNodeKPI(v.nodeId);
  kpi.clearedVehiclesTotal += 1;
  kpi.totalWaitSec += totalWait;
  kpi.waitSamples.push(totalWait);
  if (kpi.waitSamples.length > 200) kpi.waitSamples = kpi.waitSamples.slice(-200);
  kpi.clearedTimestampsSec.push(nowSec);
  if (kpi.clearedTimestampsSec.length > 500) kpi.clearedTimestampsSec = kpi.clearedTimestampsSec.slice(-500);

  scene.remove(v.mesh);
  v.mesh.traverse((child) => {
    if (!child.isMesh) return;
    if (child.geometry && !child.geometry.isShared) child.geometry.dispose();
    if (child.material && !child.material.isShared) {
      if (Array.isArray(child.material)) child.material.forEach((m) => m.dispose());
      else child.material.dispose();
    }
  });
  if (runtime.followVehicleId === v.id) {
    runtime.followVehicleId = null;
    runtime.followPinned = false;
  }
  runtime.vehicles.splice(index, 1);
  recordAudit(reason, `id=${v.id}`, violation);
}

function progressFromSpawn(v) {
  const node = runtime.intersectionsById.get(v.nodeId);
  const lane = node?.lanes[v.lane];
  if (!lane) return 0;
  const subOffset = SUBLANE_OFFSETS[v.subLane] ?? 0;
  const sx = lane.spawn.x + (lane.left.x * subOffset);
  const sz = lane.spawn.z + (lane.left.z * subOffset);
  return ((v.mesh.position.x - sx) * lane.dir.x) + ((v.mesh.position.z - sz) * lane.dir.z);
}

function distToStop(v) { return (SPAWN_DIST - STOP_DIST) - progressFromSpawn(v); }
function laneSortValue(v) { const d = progressFromSpawn(v); return v.hasCrossed ? d + 1000 : d; }

function spawnVehicle(node, laneId, forceType = null, vehicleIndex = null) {
  const lane = node.lanes[laneId];
  if (!lane) return false;
  if (runtime.vehicles.length >= MAX_ACTIVE_VEHICLES) return false;
  const load = vehicleIndex
    ? getLaneLoad(vehicleIndex, node.id, laneId)
    : runtime.vehicles.filter((v) => v.nodeId === node.id && v.lane === laneId && !v.hasCrossed).length;
  if (load >= MAX_PER_LANE) return false;
  const pool = (USE_CASES[runtime.useCase] || USE_CASES.BALANCED).typePool;
  const type = forceType || pool[Math.floor(Math.random() * pool.length)];
  const { group, length, wheels, minYLocal } = cloneVehicleModelOrFallback(type, randColor());
  group.traverse((child) => {
    if (!child.isMesh) return;
    child.castShadow = false;
    child.receiveShadow = false;
  });
  const subLane = Math.floor(Math.random() * INBOUND_SUBLANES);
  group.position.copy(lane.spawn.clone().add(lane.left.clone().multiplyScalar(SUBLANE_OFFSETS[subLane] ?? 0)));
  group.position.y = ROAD_TOP_Y - minYLocal + 0.05;
  group.rotation.y = lane.rotY;
  scene.add(group);
  const vehicle = {
    id: `V${runtime.nextVehicleId++}`, nodeId: node.id, lane: laneId, subLane, type, mesh: group,
    length: length || 4, wheels, minYLocal, speed: 6.4 + Math.random() * 2.4, cruise: 7.1 + Math.random() * 3.2,
    hasCrossed: false, waiting: false, waitStart: 0, totalWait: 0, wobblePhase: Math.random() * Math.PI * 2,
    detectConf: (0.78 + (Math.random() * 0.2)),
  };
  runtime.vehicles.push(vehicle);
  if (vehicleIndex) {
    if (!vehicleIndex.nodeVehicles.has(node.id)) vehicleIndex.nodeVehicles.set(node.id, []);
    vehicleIndex.nodeVehicles.get(node.id).push(vehicle);
    vehicleIndex.nodeLaneCounts.set(laneKey(node.id, laneId), load + 1);
    const key = `${node.id}:${laneId}:${subLane}`;
    if (!vehicleIndex.laneGroups.has(key)) vehicleIndex.laneGroups.set(key, []);
    vehicleIndex.laneGroups.get(key).push(vehicle);
  }
  return true;
}

function collectCounts(node, vehicleIndex = null) {
  const counts = { 0: 0, 1: 0, 2: 0, 3: 0 };
  if (!vehicleIndex) {
    runtime.vehicles.forEach((v) => { if (v.nodeId === node.id && !v.hasCrossed) counts[v.lane] += 1; });
    return counts;
  }
  counts[0] = getLaneLoad(vehicleIndex, node.id, 0);
  counts[1] = getLaneLoad(vehicleIndex, node.id, 1);
  counts[2] = getLaneLoad(vehicleIndex, node.id, 2);
  counts[3] = getLaneLoad(vehicleIndex, node.id, 3);
  return counts;
}

function getOpenInSeconds(node, laneId) {
  const fsm = node.controller.fsm; const phases = fsm.phases;
  const currentLane = phases[fsm.phase];
  if (currentLane === laneId && fsm.phaseState === "GREEN") return 0;
  // Avoid perceived "double 3s": show a continuous countdown to green for the upcoming lane.
  if (currentLane === laneId && fsm.phaseState === "ALL_RED") {
    return Math.ceil(fsm.phaseRemaining + SIGNAL_TIMINGS.RED_AMBER);
  }
  if (currentLane === laneId && fsm.phaseState === "RED_AMBER") {
    return Math.ceil(fsm.phaseRemaining);
  }
  let eta = fsm.phaseRemaining; let simPhase = fsm.phase; let simNext = fsm.nextPhase; let simState = fsm.phaseState;
  for (let i = 0; i < 40; i += 1) {
    if (simState === "GREEN") { simNext = (simPhase + 1) % phases.length; simState = "YELLOW"; eta += SIGNAL_TIMINGS.YELLOW; }
    else if (simState === "YELLOW") { simState = "ALL_RED"; eta += SIGNAL_TIMINGS.ALL_RED; }
    else if (simState === "ALL_RED") { simPhase = simNext; simState = "RED_AMBER"; eta += SIGNAL_TIMINGS.RED_AMBER; }
    else { simState = "GREEN"; if (phases[simPhase] === laneId) return Math.ceil(eta); eta += fsm.mode === INTERSECTION_MODES.FIXED ? CONTROL_THRESHOLDS.MIN_GREEN : (fsm.cycleDurations[simPhase] || CONTROL_THRESHOLDS.MIN_GREEN); }
  }
  return Math.ceil(eta);
}

function applySignalVisuals(node) {
  const runwayActive = runtime.emergencyPathSet.has(node.id);
  if (Array.isArray(node.runwayMats)) {
    const pulse = 0.3 + (0.25 * (0.5 + (0.5 * Math.sin(runtime.simMinutes * 8.0))));
    node.runwayMats.forEach((mat) => {
      mat.color.setHex(runwayActive ? 0x00e5ff : 0x00a2c2);
      mat.opacity = runwayActive ? pulse : 0.04;
    });
  }

  const snap = node.controller.fsm.snapshot();
  const active = Number(snap.activeLane);
  const signals = { 0: "R", 1: "R", 2: "R", 3: "R" };
  if (!node.freeTraffic) {
    if (snap.phaseState === "GREEN") signals[active] = "G";
    else if (snap.phaseState === "YELLOW") signals[active] = "Y";
    else if (snap.phaseState === "RED_AMBER") signals[active] = "RY";
  }
  const lamp = (entry, key, level, color) => {
    const v = Math.max(0, Math.min(1, Number(level) || 0));
    if (v <= 0.001) {
      entry[key].lens.material.color.setHex(0x050505);
      entry[key].lens.material.emissive.setHex(0x000000);
      entry[key].glow.material.opacity = 0;
      return;
    }
    const r = ((color >> 16) & 255) / 255;
    const g = ((color >> 8) & 255) / 255;
    const b = (color & 255) / 255;
    entry[key].lens.material.color.setRGB(r * v, g * v, b * v);
    entry[key].lens.material.emissive.setRGB(r * v, g * v, b * v);
    entry[key].glow.material.opacity = 0.4 * v;
  };
  Object.keys(node.lights).forEach((key) => {
    const entry = node.lights[key]; const sig = signals[key] || "R";
    if (node.freeTraffic) {
      // Real-time 1 Hz blink: 0.5s ON, 0.5s OFF.
      const t = (typeof performance !== "undefined" ? performance.now() : Date.now()) * 0.001;
      const yellowPulse = (Math.floor(t * 2) % 2) === 0 ? 1 : 0;
      lamp(entry, "red", 0, 0xff2e2e);
      lamp(entry, "yellow", yellowPulse, 0xffd14a);
      lamp(entry, "green", 0, 0x47ff5b);
    } else {
      lamp(entry, "red", (sig === "R" || sig === "RY") ? 1 : 0, 0xff2e2e);
      lamp(entry, "yellow", (sig === "Y" || sig === "RY") ? 1 : 0, 0xffd14a);
      lamp(entry, "green", sig === "G" ? 1 : 0, 0x47ff5b);
    }
    entry.arrowParts.forEach((p) => { p.material = sig === "G" ? entry.arrowMatGreen : entry.arrowMatEmpty; });
    if (entry.timerSprite?.sprite) {
      entry.timerSprite.sprite.visible = !node.freeTraffic;
    }
    if (node.freeTraffic) return;
    const sec = (sig === "G" || sig === "Y") ? Math.ceil(snap.phaseRemaining) : getOpenInSeconds(node, Number(key));
    if (entry.timerSprite.lastSec !== sec || entry.timerSprite.lastSignal !== sig) {
      const ctx = entry.timerSprite.ctx;
      ctx.clearRect(0, 0, 256, 128);
      ctx.fillStyle = "rgba(0,10,16,0.88)";
      ctx.fillRect(0, 0, 256, 128);
      ctx.strokeStyle = sig === "G" ? "#00e676" : (sig === "Y" || sig === "RY" ? "#ffb74d" : "#ff5252");
      ctx.lineWidth = 4;
      ctx.strokeRect(4, 4, 248, 120);
      ctx.fillStyle = ctx.strokeStyle;
      ctx.font = "bold 72px monospace";
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      ctx.fillText(String(Math.max(0, sec)), 128, 64);
      entry.timerSprite.tex.needsUpdate = true;
      entry.timerSprite.lastSec = sec;
      entry.timerSprite.lastSignal = sig;
    }
  });
}

function laneGreen(node, laneId) {
  if (node?.freeTraffic) return true;
  const s = node.controller.fsm.snapshot();
  return s.phaseState === "GREEN" && Number(s.activeLane) === Number(laneId);
}

function advanceToNextNode(v) {
  const idx = runtime.intersectionIndexById.get(v.nodeId);
  if (idx == null || idx < 0 || !v.hasCrossed) return;
  if (v.lane === 0 && idx + 1 < runtime.intersections.length && v.mesh.position.z < runtime.intersections[idx].centerZ - 12) { v.nodeId = runtime.intersections[idx + 1].id; v.hasCrossed = false; }
  if (v.lane === 2 && idx - 1 >= 0 && v.mesh.position.z > runtime.intersections[idx].centerZ + 12) { v.nodeId = runtime.intersections[idx - 1].id; v.hasCrossed = false; }
}

function updateVehicles(dt, vehicleIndex) {
  const groups = vehicleIndex?.laneGroups ?? new Map();
  if (!vehicleIndex) {
    runtime.vehicles.forEach((v) => {
      const key = `${v.nodeId}:${v.lane}:${v.subLane}`;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(v);
    });
  }
  groups.forEach((arr) => {
    if (arr.length < 2) return;
    for (let i = 0; i < arr.length; i += 1) {
      const v = arr[i];
      v._laneSort = laneSortValue(v);
    }
    arr.sort((a, b) => b._laneSort - a._laneSort);
  });
  const now = runtime.simMinutes * 60;
  groups.forEach((arr) => {
    let lead = null;
    arr.forEach((v) => {
      const node = runtime.intersectionsById.get(v.nodeId);
      const lane = node?.lanes[v.lane];
      if (!node || !lane) return;
      let target = v.cruise; const d = distToStop(v); let stop = false;
      if (lead) { const gap = progressFromSpawn(lead) - progressFromSpawn(v); const safe = CONTROL_THRESHOLDS.SPAWN_MIN_GAP_M + (v.length * 0.4) + (lead.length * 0.4); if (gap < safe * 1.2) { target = Math.min(target, Math.max(0, lead.speed - 0.6)); if (gap < safe) stop = true; } }
      const green = lane.hasSignal === false || laneGreen(node, v.lane);
      if (!v.hasCrossed && d > 0 && d < 20 && !green) { const ratio = Math.max(0, Math.min(1, (d - 0.45) / 8)); target *= ratio; if (d < 0.55) { target = 0; stop = true; } }
      const delta = target - v.speed; const stepDelta = (delta >= 0 ? 3.2 : 7.2) * dt; v.speed += Math.abs(delta) <= stepDelta ? delta : Math.sign(delta) * stepDelta; if (v.speed < 0.02) v.speed = 0;
      if (stop || (v.speed < 0.3 && target < 0.4)) { if (!v.waiting) { v.waiting = true; v.waitStart = now; } } else if (v.waiting) { v.waiting = false; v.totalWait += now - v.waitStart; }
      let move = v.speed * dt; if (!v.hasCrossed && !green && d > 0) move = Math.min(move, Math.max(0, d - 0.45));
      v.mesh.position.addScaledVector(lane.dir, move); if (v.wheels?.length) v.wheels.forEach((w) => { w.rotation.x -= move / 0.24; });
      v.mesh.position.y = ROAD_TOP_Y - v.minYLocal + 0.03 + (Math.sin(runtime.simMinutes * 0.8 + v.wobblePhase) * 0.008);
      if (!v.hasCrossed && distToStop(v) <= 0) {
        v.hasCrossed = true;
        const servedNodeId = v.nodeId;
        const kpi = getNodeKPI(servedNodeId);
        kpi.servedVehiclesTotal += 1;
        kpi.servedTimestampsSec.push(now);
        if (kpi.servedTimestampsSec.length > 800) kpi.servedTimestampsSec = kpi.servedTimestampsSec.slice(-600);
        const servedWait = Math.max(0, v.totalWait + (v.waiting ? (now - v.waitStart) : 0));
        kpi.servedTotalWaitSec += servedWait;
        kpi.servedWaitSamples.push(servedWait);
        if (kpi.servedWaitSamples.length > 400) kpi.servedWaitSamples = kpi.servedWaitSamples.slice(-300);
      }
      advanceToNextNode(v); lead = v;
    });
  });
  for (let i = runtime.vehicles.length - 1; i >= 0; i -= 1) {
    const v = runtime.vehicles[i];
    const p = v.mesh.position;
    const exitReason = classifyExitReason(v);
    if (exitReason) {
      removeVehicleAtIndex(i, exitReason, false);
      continue;
    }

    // Safety clip should be exceptional; keep explicit audit if it ever occurs.
    const severelyOut = Math.abs(p.x) > 1200 || p.z < runtime.minZ - 1200 || p.z > runtime.maxZ + 1200;
    if (severelyOut) {
      removeVehicleAtIndex(i, "safety_clip_outlier", true);
    }
  }
}

function updateSpawns(dt, vehicleIndex) {
  if (runtime.vehicles.length >= MAX_ACTIVE_VEHICLES) return;
  const useCase = USE_CASES[runtime.useCase] || USE_CASES.BALANCED;
  const hour = Math.floor((runtime.simMinutes / 60) % 24);
  const profile = getTrafficProfile(hour);
  runtime.currentProfileLabel = profile.label;
  const direction = String(runtime.plan?.priority_direction || "NORTHBOUND").toUpperCase();

  runtime.intersections.forEach((node) => {
    const loadsByLane = [0, 1, 2, 3].map((lane) => getLaneLoad(vehicleIndex, node.id, lane));
    const avgLoad = loadsByLane.reduce((s, v) => s + v, 0) / 4;

    [0, 1, 2, 3].forEach((lane) => {
      const key = `${node.id}:${lane}`; let cd = Math.max(0, (runtime.laneCooldown.get(key) ?? 0) - dt);
      const laneBias = useCase.laneBias ? (useCase.laneBias[lane] ?? 1) : 1;
      const profileLaneBias = profile.laneBias[lane] ?? 1.0;
      const load = loadsByLane[lane];
      const laneBalance = clamp((avgLoad + 1.5) / (load + 1.5), 0.65, 1.65);
      const directionBias = (
        (direction.includes("NORTH") && lane === 0) ||
        (direction.includes("SOUTH") && lane === 2) ||
        (direction.includes("EAST") && lane === 3) ||
        (direction.includes("WEST") && lane === 1)
      ) ? 1.2 : 1.0;
      const throttle = Math.max(0.08, 1 - ((load / MAX_PER_LANE) * 1.15));
      const fleetPressure = clamp(1 - (runtime.vehicles.length / MAX_ACTIVE_VEHICLES), 0.05, 1.0);
      const baseChance = SPAWN_CONTROL.BASE_RATE * profile.mult * laneBias * profileLaneBias * laneBalance * directionBias * throttle * dt * 0.78;
      const starvationBoost = load === 0 ? 1.35 : 1.0;
      const chance = baseChance * starvationBoost * fleetPressure;

      if (cd <= 0 && Math.random() < chance) {
        if (spawnVehicle(node, lane, null, vehicleIndex)) {
          const demand = Math.max(0.45, profile.mult * laneBias * profileLaneBias);
          const jitter = 0.92 + (Math.random() * 0.16);
          cd = clamp((0.88 / demand) * jitter, SPAWN_CONTROL.MIN_COOLDOWN, SPAWN_CONTROL.MAX_COOLDOWN);
        }
      }

      // Secondary pass keeps lane populations balanced during dense periods.
      if (cd <= 0 && load < avgLoad * 0.55 && Math.random() < chance * 0.42) {
        if (spawnVehicle(node, lane, null, vehicleIndex)) {
          cd = clamp((0.95 / Math.max(0.5, profile.mult * profileLaneBias)), SPAWN_CONTROL.MIN_COOLDOWN, SPAWN_CONTROL.MAX_COOLDOWN);
        }
      }

      runtime.laneCooldown.set(key, cd);
    });
  });
}

async function publishMetricsAndState(nowMs) {
  const tasks = runtime.intersections.map(async (node) => {
    const nodeVehicles = runtime.lastVehicleIndex?.nodeVehicles.get(node.id) ?? [];
    const vehicles = nodeVehicles.map((v) => ({ lane: String(v.lane), type: v.type, hasCrossed: false }));
    const metrics = computeTrafficMetrics({ intersectionId: node.id, vehicles, laneIds: ["0", "1", "2", "3"], previous: runtime.metricCache.get(node.id), timestamp: nowMs });
    runtime.metricCache.set(node.id, { timestamp: nowMs, totalLoad: metrics.totalLoad });
    node.controller.updateMetrics(metrics);
    const statePromise = fetch(`/api/intersections/${encodeURIComponent(node.id)}/state`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(node.controller.getState()),
    });

    const nowSec = runtime.simMinutes * 60;
    const kpi = getNodeKPI(node.id);
    kpi.clearedTimestampsSec = kpi.clearedTimestampsSec.filter((ts) => (nowSec - ts) <= 60);
    kpi.servedTimestampsSec = kpi.servedTimestampsSec.filter((ts) => (nowSec - ts) <= 60);
    const waitSamples = [...kpi.servedWaitSamples, ...kpi.waitSamples].sort((a, b) => a - b);
    const p95 = waitSamples.length
      ? waitSamples[Math.floor(0.95 * (waitSamples.length - 1))]
      : 0;
    const totalServed = (kpi.servedVehiclesTotal + kpi.clearedVehiclesTotal);
    const totalServedWait = (kpi.servedTotalWaitSec + kpi.totalWaitSec);
    const avgWait = totalServed > 0
      ? (totalServedWait / totalServed)
      : 0;
    const throughputPerMin = Math.max(kpi.servedTimestampsSec.length, kpi.clearedTimestampsSec.length);

    const kpiPromise = fetch(`/api/intersections/${encodeURIComponent(node.id)}/kpi`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        queue_length: metrics.queue_count,
        occupancy_ratio: metrics.occupancy_ratio,
        avg_wait_sec: Number(avgWait.toFixed(3)),
        p95_wait_sec: Number((p95 || 0).toFixed(3)),
        throughput_veh_per_min: Number(throughputPerMin.toFixed(3)),
        active_waiting_vehicles: nodeVehicles.filter((v) => v.waiting).length,
        cleared_vehicles_total: totalServed,
      }),
    });
    await Promise.allSettled([publishTrafficMetrics("", metrics), statePromise, kpiPromise]);
  });
  await Promise.all(tasks.map((t) => t.catch(() => null)));
}

async function refreshPlan() {
  try {
    runtime.plan = await corridorClient.getPlan();
    runtime.intersections.forEach((node) => {
      node.controller.applyCorridorPlan(runtime.plan);
      const offset = Number(runtime.plan?.offset?.[node.id] ?? 0);
      node.offsetSec = offset;
      node.offsetTargetSec = offset;
      if (!node.offsetInitialized) {
        node.offsetCurrentSec = offset;
        if (offset > 0) {
          node.controller.fsm.applyTimeCorrection(offset);
        }
        node.offsetInitialized = true;
      }
      applyNodeModePolicy(node);
    });
  } catch (_) {}
}

function rememberCommand(k) {
  if (runtime.processedCommands.has(k)) return;
  runtime.processedCommands.add(k);
  runtime.processedCommandOrder.push(k);
  if (runtime.processedCommandOrder.length > 500) {
    const stale = runtime.processedCommandOrder.splice(0, runtime.processedCommandOrder.length - 300);
    stale.forEach((key) => runtime.processedCommands.delete(key));
  }
}

function addRunwayGuides(z) {
  const mats = [];
  const edge = (ROAD_W / 2) - 0.8;
  const makeStrip = (x, zz, w, d) => {
    const mat = new THREE.MeshBasicMaterial({
      color: 0x00a2c2,
      transparent: true,
      opacity: 0.04,
      depthWrite: false,
    });
    const mesh = new THREE.Mesh(new THREE.BoxGeometry(w, 0.06, d), mat);
    mesh.position.set(x, 0.12, zz);
    scene.add(mesh);
    mats.push(mat);
  };
  makeStrip(-edge, z, 0.24, 105);
  makeStrip(edge, z, 0.24, 105);
  makeStrip(0, z - edge, 105, 0.24);
  makeStrip(0, z + edge, 105, 0.24);
  return mats;
}

function addLaneBadge(laneNumber, position, rotY = 0) {
  const canvas = document.createElement("canvas");
  canvas.width = 256;
  canvas.height = 128;
  const ctx = canvas.getContext("2d");
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = "rgba(255,255,255,0.98)";
  ctx.strokeStyle = "rgba(0,0,0,0.85)";
  ctx.lineWidth = 10;
  ctx.font = "bold 94px sans-serif";
  ctx.textAlign = "center";
  ctx.textBaseline = "middle";
  const text = `L${laneNumber}`;
  ctx.strokeText(text, canvas.width / 2, canvas.height / 2 + 2);
  ctx.fillText(text, canvas.width / 2, canvas.height / 2 + 2);

  const tex = new THREE.CanvasTexture(canvas);
  tex.colorSpace = THREE.SRGBColorSpace;
  const mat = new THREE.SpriteMaterial({
    map: tex,
    transparent: true,
    depthWrite: false,
    depthTest: true,
  });
  const sprite = new THREE.Sprite(mat);
  sprite.position.copy(position);
  sprite.position.y = 0.95;
  sprite.scale.set(4.4, 2.2, 1);
  scene.add(sprite);
}
function hasCommand(k) { return runtime.processedCommands.has(k); }

function applyCommand(event) {
  const payload = event.payload || {}; const name = payload.event || payload.type; const intersectionId = payload.intersection_id || null;
  const key = `${event.timestamp}|${name}|${intersectionId}|${JSON.stringify(payload.payload || payload.targets || {})}`; if (hasCommand(key)) return; rememberCommand(key);
  const targets = runtime.intersections.filter((n) => !intersectionId || n.id === intersectionId);
  if (name === "force_green") {
    const lane = Number(payload.payload?.lane_id ?? 0);
    targets.forEach((n) => {
      n.controller.forceGreen(lane);
      n.controller.fsm.phaseRemaining = Math.min(n.controller.fsm.phaseRemaining, 0.05);
    });
  }
  else if (name === "activate_corridor") {
    const corridorLane = Number(payload.payload?.lane_id ?? 0);
    const spacingSec = Math.max(0.5, Math.min(6, Number(payload.payload?.spacing_sec ?? 2)));
    const ordered = [...runtime.intersections];
    if (corridorLane === 0) ordered.sort((a, b) => b.centerZ - a.centerZ);
    else if (corridorLane === 2) ordered.sort((a, b) => a.centerZ - b.centerZ);
    else ordered.sort((a, b) => String(a.id).localeCompare(String(b.id)));

    ordered.forEach((n, idx) => {
      if (n.failureStates && n.failureStates.size > 0) return;
      n.freeTraffic = false;
      n.controller.clearEmergency();
      n.controller.setMode(INTERSECTION_MODES.COORDINATED);

      const fsm = n.controller.fsm;
      const laneIdx = fsm.phases.indexOf(corridorLane);
      if (laneIdx < 0) return;

      const baseGreen = fsm.mode === INTERSECTION_MODES.FIXED
        ? CONTROL_THRESHOLDS.MIN_GREEN
        : (fsm.cycleDurations[laneIdx] || CONTROL_THRESHOLDS.MIN_GREEN);
      const remaining = Math.max(2, baseGreen - (idx * spacingSec));

      // Immediate visible green-wave bootstrap for demo.
      fsm.phase = laneIdx;
      fsm.nextPhase = (laneIdx + 1) % fsm.phases.length;
      fsm.phaseState = "GREEN";
      fsm.phaseDuration = baseGreen;
      fsm.greenDuration = baseGreen;
      fsm.phaseRemaining = remaining;
      fsm.phaseElapsed = Math.max(0, baseGreen - remaining);
    });
  }
  else if (name === "inject_emergency") {
    const lane = Number(payload.payload?.lane_id ?? 0);
    targets.forEach((n) => n.controller.setEmergencyLane(lane));
    const path = payload.result?.path || payload.path || (intersectionId ? [intersectionId] : []);
    runtime.emergencyPathSet = new Set((Array.isArray(path) ? path : []).map((id) => String(id)));
    if (targets.length) spawnVehicle(targets[0], lane, TYPE.AMBULANCE);
  }
  else if (name === "clear_emergency") {
    runtime.intersections.forEach((n) => {
      n.controller.clearEmergency();
      applyNodeModePolicy(n);
    });
    runtime.emergencyPathSet.clear();
  }
  else if (name === "free_traffic") {
    const active = Boolean(payload.payload?.active ?? true);
    const affected = targets.length ? targets : runtime.intersections;
    affected.forEach((n) => {
      n.freeTraffic = active;
      if (active) {
        n.controller.clearEmergency();
      } else {
        applyNodeModePolicy(n);
      }
    });
  }
  else if (["network_outage", "camera_failure", "low_visibility", "node_crash"].includes(name)) {
    const active = Boolean(payload.active ?? payload.payload?.active ?? true);
    const affected = payload.targets
      ? runtime.intersections.filter((n) => payload.targets.includes(n.id))
      : targets;
    affected.forEach((n) => {
      if (!n.failureStates) n.failureStates = new Set();
      if (active) n.failureStates.add(name);
      else n.failureStates.delete(name);
      applyNodeModePolicy(n);
    });
  }
}

async function pollCommands() {
  try {
    const r = await fetch("/api/control/commands?limit=120"); if (!r.ok) return;
    const data = await r.json(); (Array.isArray(data.items) ? data.items : []).forEach((e) => applyCommand(e));
  } catch (_) {}
}

function updateOverlay() {
  if (!ui.cvOverlay) return;
  if (!runtime.aiVisionEnabled) {
    ui.cvOverlay.innerHTML = "";
    ui.cvOverlay.style.display = "none";
    return;
  }
  ui.cvOverlay.style.display = "block";
  let html = "";
  let count = 0;
  for (let i = 0; i < runtime.vehicles.length; i += 1) {
    if (count >= MAX_OVERLAY_BOXES) break;
    const v = runtime.vehicles[i];
    const pos = v.mesh.position.clone().project(camera); if (pos.z > 1) continue;
    const x = (pos.x * 0.5 + 0.5) * window.innerWidth; const y = (pos.y * -0.5 + 0.5) * window.innerHeight;
    const d = Math.max(1, camera.position.distanceTo(v.mesh.position)); const w = Math.max(24, 700 / d); const h = Math.max(18, 520 / d);
    html += `<div class="ai-bbox ai-bbox--car" data-label="${String(v.type).toUpperCase()} ${Number(v.detectConf || 0.82).toFixed(2)}" data-trackid="#${v.id}" style="left:${x - w / 2}px;top:${y - h / 2}px;width:${w}px;height:${h}px;"></div>`;
    count += 1;
  }
  ui.cvOverlay.innerHTML = html;
}

function retargetFollow() {
  const moving = runtime.vehicles.filter((v) => v.speed > 1.1 && (v.lane === 0 || v.lane === 2));
  const pool = moving.length ? moving : runtime.vehicles;
  runtime.followVehicleId = pool.length ? pool[Math.floor(Math.random() * pool.length)].id : null;
  runtime.followPinned = false;
}

function updateFollowCamera(dt) {
  if (runtime.cameraMode !== 4) return;
  runtime.followRetargetTimer += dt;
  if (!runtime.followPinned && (runtime.followRetargetTimer > 4 || !runtime.followVehicleId)) {
    runtime.followRetargetTimer = 0;
    retargetFollow();
  }
  if (!runtime.followEnabled) return;
  const v = runtime.vehicles.find((item) => item.id === runtime.followVehicleId);
  if (!v) {
    runtime.followVehicleId = null;
    runtime.followPinned = false;
    return;
  }
  controls.enabled = false;
  const p = v.mesh.position; const desired = new THREE.Vector3(p.x + (v.lane === 2 ? -1.3 : 1.3), p.y + 3.8, p.z + (v.lane === 2 ? -10 : 10));
  camera.position.lerp(desired, Math.min(1, dt * 2.3));
  controls.target.lerp(new THREE.Vector3(p.x, p.y + 1.2, p.z + (v.lane === 2 ? 15 : -15)), Math.min(1, dt * 2.8));
  camera.lookAt(controls.target);
}

function updateUI() {
  if (ui.nodeCount) ui.nodeCount.textContent = `Intersections: ${runtime.intersections.length}`;
  if (ui.vehicleCount) ui.vehicleCount.textContent = `Vehicles: ${runtime.vehicles.length}`;
  if (ui.followStatus) {
    const follow = runtime.cameraMode === 4
      ? (runtime.followVehicleId ? `${runtime.followVehicleId}${runtime.followPinned ? " (PINNED)" : ""}` : "AUTO")
      : "OFF";
    const cam = `CAM-${runtime.cameraMode}`;
    const ai = runtime.aiVisionEnabled ? "AI-VISION ON" : "AI-VISION OFF";
    const focus = runtime.focusNodeId || "--";
    ui.followStatus.textContent = `${cam} | Junction: ${focus} | Follow: ${follow} | ${runtime.currentProfileLabel} | ${ai}`;
  }
  syncJunctionViewControl();
  updateViewButtons();
}

function updateIntersections(dt, vehicleIndex) {
  runtime.intersections.forEach((node) => {
    const counts = collectCounts(node, vehicleIndex);
    const nodeVehicles = vehicleIndex?.nodeVehicles.get(node.id) ?? [];
    const vehicles = nodeVehicles.map((v) => ({ lane: String(v.lane), type: v.type, hasCrossed: false }));
    const snap = node.controller.update(dt, counts, vehicles);

    const cycleBoundary = (
      snap.phase === 0 &&
      snap.phaseState === "GREEN" &&
      !(node.prevPhase === 0 && node.prevPhaseState === "GREEN")
    );

    if (cycleBoundary && node.controller.mode === INTERSECTION_MODES.COORDINATED) {
      const error = (node.offsetTargetSec ?? 0) - (node.offsetCurrentSec ?? 0);
      if (Math.abs(error) >= 0.5) {
        const correction = Math.round((clamp(error, -1, 1) / 0.5)) * 0.5;
        node.controller.fsm.applyTimeCorrection(correction);
        node.offsetCurrentSec = (node.offsetCurrentSec ?? 0) + correction;
      }
    }

    node.prevPhase = snap.phase;
    node.prevPhaseState = snap.phaseState;
    applySignalVisuals(node);
  });
}

function findVehicleFromObject(object3d) {
  if (!object3d) return null;
  let node = object3d;
  while (node) {
    const vehicle = runtime.vehicles.find((v) => v.mesh === node);
    if (vehicle) return vehicle;
    node = node.parent;
  }
  return null;
}

if (renderer?.domElement) {
  renderer.domElement.addEventListener("pointerdown", (event) => {
    if (event.button !== 0) return;
    const rect = renderer.domElement.getBoundingClientRect();
    if (rect.width <= 0 || rect.height <= 0) return;
    pointer.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
    pointer.y = -(((event.clientY - rect.top) / rect.height) * 2 - 1);
    raycaster.setFromCamera(pointer, camera);
    const intersects = raycaster.intersectObjects(scene.children, true);
    const hit = intersects.find((it) => findVehicleFromObject(it.object));
    if (!hit) return;
    const vehicle = findVehicleFromObject(hit.object);
    if (!vehicle) return;
    runtime.followVehicleId = vehicle.id;
    runtime.followPinned = true;
    runtime.followEnabled = true;
    runtime.followRetargetTimer = 0;
    if (runtime.cameraMode !== 4) setCameraMode(4);
    updateUI();
  });
}

function tick() {
  const dtRaw = Math.min(MAX_FRAME_DELTA, clock.getDelta());
  runtime.simAccumulator += dtRaw;
  let steps = 0;
  while (runtime.simAccumulator >= SIM_STEP && steps < MAX_SUBSTEPS) {
    runtime.simMinutes += SIM_STEP * 0.65;
    const preVehicleIndex = runtime.lastVehicleIndex || buildVehicleIndex();
    updateIntersections(SIM_STEP, preVehicleIndex);
    updateVehicles(SIM_STEP, preVehicleIndex);
    const nextVehicleIndex = buildVehicleIndex();
    runtime.lastVehicleIndex = nextVehicleIndex;
    updateSpawns(SIM_STEP, nextVehicleIndex);
    runtime.metricTimer += SIM_STEP; runtime.planTimer += SIM_STEP; runtime.commandTimer += SIM_STEP; runtime.uiTimer += SIM_STEP; runtime.overlayTimer += SIM_STEP;
    if (runtime.metricTimer >= 3) { runtime.metricTimer = 0; publishMetricsAndState(Date.now()); }
    if (runtime.planTimer >= 10) { runtime.planTimer = 0; refreshPlan(); }
    if (runtime.commandTimer >= 1) { runtime.commandTimer = 0; pollCommands(); }
    if (runtime.uiTimer >= 0.16) { runtime.uiTimer = 0; updateUI(); updateAuditPanel(); }
    runtime.simAccumulator -= SIM_STEP;
    steps += 1;
  }
  if (steps === MAX_SUBSTEPS && runtime.simAccumulator >= SIM_STEP) {
    // Drop overdue backlog to avoid spiral-of-death freezes on slower hardware.
    runtime.simAccumulator = 0;
  }
  updateFreeCamera(dtRaw);
  if (runtime.cameraMode === 1 || runtime.cameraMode === 2 || runtime.cameraMode === 3) controls.update();
  updateFollowCamera(dtRaw);
  renderer.render(scene, camera);
  if (runtime.overlayTimer >= OVERLAY_INTERVAL) {
    runtime.overlayTimer = 0;
    if (!document.hidden) updateOverlay();
  }
  requestAnimationFrame(tick);
}

window.addEventListener("keydown", (e) => {
  const key = e.key.toLowerCase();
  keyState[key] = true;
  if (key === "1") setCameraMode(1);
  if (key === "2") setCameraMode(2);
  if (key === "3") setCameraMode(3);
  if (key === "4") setCameraMode(4);
  if (key === "[") stepJunction(-1);
  if (key === "]") stepJunction(1);
  if (key === "f") {
    if (runtime.cameraMode === 4) {
      runtime.followEnabled = false;
      setCameraMode(1);
    } else {
      runtime.followEnabled = true;
      setCameraMode(4);
    }
  }
  if (key === "v") {
    runtime.aiVisionEnabled = !runtime.aiVisionEnabled;
    updateViewButtons();
    updateOverlay();
  }
});
window.addEventListener("keyup", (e) => {
  keyState[e.key.toLowerCase()] = false;
});

if (ui.junctionView) {
  ui.junctionView.addEventListener("change", (event) => {
    const selected = String(event.target.value || "");
    if (!selected) return;
    if (runtime.cameraMode === 4) setCameraMode(1);
    focusJunction(selected);
  });
}

Object.entries(ui.camButtons || {}).forEach(([id, button]) => {
  if (!button) return;
  button.addEventListener("click", () => setCameraMode(Number(id)));
});

if (ui.aiToggle) {
  ui.aiToggle.addEventListener("click", () => {
    runtime.aiVisionEnabled = !runtime.aiVisionEnabled;
    updateViewButtons();
    updateOverlay();
  });
}

if (ui.prevJunction) {
  ui.prevJunction.addEventListener("click", () => {
    stepJunction(-1);
  });
}

if (ui.nextJunction) {
  ui.nextJunction.addEventListener("click", () => {
    stepJunction(1);
  });
}

window.addEventListener("resize", () => { renderer.setSize(window.innerWidth, window.innerHeight); camera.aspect = window.innerWidth / window.innerHeight; camera.updateProjectionMatrix(); });

async function bootstrap() {
  await initVehicleModels();
  try { runtime.topology = await corridorClient.getTopology(); } catch (_) { runtime.topology = { intersections: [{ intersection_id: "J01" }], links: [] }; }
  buildWorld(runtime.topology);
  runtime.lastVehicleIndex = buildVehicleIndex();
  populateJunctionViewControl();
  await refreshPlan();
  if (ui.cvOverlay) ui.cvOverlay.style.display = "none";
  setCameraMode(1);
  if (runtime.focusNodeId) focusJunction(runtime.focusNodeId, true);
  updateUI();
  updateAuditPanel();
  clock.start();
  requestAnimationFrame(tick);
}

bootstrap();
