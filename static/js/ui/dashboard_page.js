const state = {
  topology: null,
  plan: null,
  health: null,
  incidents: new Map(),
  intersectionStates: new Map(),
  metrics: new Map(),
  failureToggles: {
    network_outage: false,
    camera_failure: false,
    low_visibility: false,
    node_crash: false,
  },
  freeTrafficEnabled: false,
  piProfiles: [],
  piDraftId: null,
  piDemoConnected: {},
};

const el = {
  summaryCards: document.getElementById("summary-cards"),
  healthCards: document.getElementById("health-cards"),
  mapGrid: document.getElementById("corridor-map-grid"),
  mapSort: document.getElementById("map-sort"),
  incidentCards: document.getElementById("incident-cards"),
  incidentSummary: document.getElementById("incident-summary"),
  intersectionSelect: document.getElementById("intersection-select"),
  laneSelect: document.getElementById("lane-select"),
  failureBadges: document.getElementById("failure-badges"),
  controlStatus: document.getElementById("control-status"),
  intersectionTable: document.getElementById("intersection-table"),
  statusSearch: document.getElementById("status-search"),
  statusSort: document.getElementById("status-sort"),
  eventLog: document.getElementById("event-log"),
  lastSync: document.getElementById("dashboard-last-sync"),
  piSummary: document.getElementById("pi-summary"),
  piIntersection: document.getElementById("pi-intersection"),
  piIp: document.getElementById("pi-ip"),
  piCamera: document.getElementById("pi-camera"),
  piSave: document.getElementById("btn-pi-save"),
  piClear: document.getElementById("btn-pi-clear"),
  piProfileList: document.getElementById("pi-profile-list"),
  piEnvPreview: document.getElementById("pi-env-preview"),
};

const FAILURE_TYPES = ["network_outage", "camera_failure", "low_visibility", "node_crash"];
const FAILURE_SEVERITY = {
  network_outage: "critical",
  node_crash: "critical",
  camera_failure: "high",
  low_visibility: "high",
};

const SEVERITY_RANK = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

const PI_STORAGE_KEY = "tancam.pi_profiles.v1";

function safeNum(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function setLastSync(label = "synced") {
  if (!el.lastSync) return;
  el.lastSync.textContent = `Last sync: ${new Date().toLocaleTimeString()} (${label})`;
}

function setStatus(text, isError = false) {
  if (!el.controlStatus) return;
  el.controlStatus.textContent = text;
  el.controlStatus.classList.toggle("is-error", isError);
}

async function jsonFetch(url, options = {}) {
  const res = await fetch(url, options);
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`${res.status} ${body}`);
  }
  return res.json();
}

function appendEvent(message, tone = "info") {
  if (!el.eventLog) return;
  const row = document.createElement("div");
  row.className = `event-row tone-${tone}`;
  row.textContent = `${new Date().toLocaleTimeString()} | ${message}`;
  el.eventLog.appendChild(row);
  while (el.eventLog.childNodes.length > 160) {
    el.eventLog.removeChild(el.eventLog.firstChild);
  }
  el.eventLog.scrollTop = el.eventLog.scrollHeight;
}

function onlineIntersections() {
  const list = state.health?.intersection_connectivity?.online;
  if (!Array.isArray(list)) return new Set();
  return new Set(list.map((id) => String(id)));
}

function loadPiProfiles() {
  try {
    const raw = window.localStorage.getItem(PI_STORAGE_KEY);
    if (!raw) return;
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return;
    state.piProfiles = parsed
      .map((item) => ({
        id: String(item.id || `pi-${Date.now()}`),
        intersection_id: String(item.intersection_id || "").trim(),
        host: String(item.host || "").trim(),
        camera_index: Number.isFinite(Number(item.camera_index)) ? Number(item.camera_index) : 0,
      }))
      .filter((item) => item.intersection_id && item.host);
  } catch (_) {
    state.piProfiles = [];
  }
}

function savePiProfiles() {
  window.localStorage.setItem(PI_STORAGE_KEY, JSON.stringify(state.piProfiles));
}

function resetPiForm() {
  state.piDraftId = null;
  if (el.piIp) el.piIp.value = "";
  if (el.piCamera) el.piCamera.value = "0";
  if (el.piSave) el.piSave.textContent = "Save Pi Profile";
  syncPiIntersectionOptions();
  updatePiEnvPreview();
}

function syncPiIntersectionOptions() {
  const options = (state.topology?.intersections || []).map((item) => String(item.intersection_id));
  const selects = [el.piIntersection, el.intersectionSelect].filter(Boolean);
  selects.forEach((selectEl) => {
    const current = selectEl.value;
    selectEl.innerHTML = "";
    options.forEach((id) => {
      const option = document.createElement("option");
      option.value = id;
      option.textContent = id;
      selectEl.appendChild(option);
    });
    if (options.includes(current)) {
      selectEl.value = current;
    }
  });
}

function updatePiEnvPreview(profile = null) {
  if (!el.piEnvPreview) return;
  const current = profile || {
    intersection_id: el.piIntersection?.value || "",
    host: el.piIp?.value?.trim() || "<pi-host-or-ip>",
    camera_index: safeNum(el.piCamera?.value, 0),
  };
  if (!current.intersection_id) {
    el.piEnvPreview.value = "# Select an intersection and set Pi IP to generate run command preview.";
    return;
  }
  const lines = [
    "source tancam-env/bin/activate",
    'export SERVER_URL="http://<central-server-ip>:8000"',
    `export INTERSECTION_ID="${current.intersection_id}"`,
    `export CAMERA_INDEX=${safeNum(current.camera_index, 0)}`,
    "python3 pi_edge_client.py",
  ];
  el.piEnvPreview.value = lines.join("\n");
}

function renderPiProfiles() {
  if (!el.piProfileList || !el.piSummary) return;
  if (!state.piProfiles.length) {
    el.piSummary.textContent = "No Pi profiles configured.";
    el.piProfileList.innerHTML = `<div class="incident-empty">Add at least one Pi profile for demo.</div>`;
    return;
  }

  const online = onlineIntersections();
  const connectedCount = state.piProfiles.reduce((sum, profile) => {
    const demoConnected = state.piDemoConnected[profile.id] !== false;
    return sum + (demoConnected && online.has(profile.intersection_id) ? 1 : 0);
  }, 0);
  el.piSummary.textContent = `Profiles ${state.piProfiles.length} | Connected ${connectedCount}`;

  el.piProfileList.innerHTML = state.piProfiles.map((profile) => {
    const demoConnected = state.piDemoConnected[profile.id] !== false;
    const serverOnline = online.has(profile.intersection_id);
    const status = demoConnected ? (serverOnline ? "ONLINE" : "WAITING") : "DISCONNECTED";
    const statusClass = demoConnected ? (serverOnline ? "ok" : "warn") : "danger";
    const envText = [
      'export SERVER_URL="http://<central-server-ip>:8000"',
      `export INTERSECTION_ID="${profile.intersection_id}"`,
      `export CAMERA_INDEX=${safeNum(profile.camera_index, 0)}`,
      "python3 pi_edge_client.py",
    ].join(" && ");
    return `
      <article class="pi-card" data-pi-id="${escapeHtml(profile.id)}">
        <div class="pi-card-head">
          <strong>${escapeHtml(profile.intersection_id)}</strong>
          <span class="failure-badge ${statusClass}">${status}</span>
        </div>
        <div class="pi-card-body">
          <span>Host ${escapeHtml(profile.host)}</span>
          <span>Camera ${safeNum(profile.camera_index, 0)}</span>
        </div>
        <div class="pi-card-actions">
          <button data-pi-action="toggle">${demoConnected ? "Disconnect Demo" : "Connect Demo"}</button>
          <button data-pi-action="edit">Edit</button>
          <button data-pi-action="copy" data-env="${escapeHtml(envText)}">Copy Env</button>
          <button data-pi-action="remove" class="danger">Remove</button>
        </div>
      </article>
    `;
  }).join("");
}

function upsertIncident(incident) {
  if (!incident || !incident.key) return;
  const next = {
    key: String(incident.key),
    title: String(incident.title || "Incident"),
    detail: String(incident.detail || ""),
    severity: String(incident.severity || "medium").toLowerCase(),
    source: String(incident.source || "system"),
    active: incident.active !== false,
    updatedAt: Date.now(),
  };
  if (!next.active) {
    state.incidents.delete(next.key);
    renderIncidents();
    return;
  }
  state.incidents.set(next.key, next);
  renderIncidents();
}

function renderIncidents() {
  if (!el.incidentCards || !el.incidentSummary) return;
  const items = Array.from(state.incidents.values())
    .sort((a, b) => {
      const sev = (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0);
      if (sev !== 0) return sev;
      return b.updatedAt - a.updatedAt;
    })
    .slice(0, 8);

  if (!items.length) {
    el.incidentSummary.textContent = "No active incidents.";
    el.incidentCards.innerHTML = `<div class="incident-empty">All systems normal.</div>`;
    return;
  }

  const critical = items.filter((it) => it.severity === "critical").length;
  const high = items.filter((it) => it.severity === "high").length;
  el.incidentSummary.textContent = `${items.length} active | Critical ${critical} | High ${high}`;

  el.incidentCards.innerHTML = items.map((it) => `
    <article class="incident-card sev-${escapeHtml(it.severity)}">
      <div class="incident-head">
        <strong>${escapeHtml(it.title)}</strong>
        <span class="incident-sev">${escapeHtml(it.severity)}</span>
      </div>
      <div class="incident-detail">${escapeHtml(it.detail || "-")}</div>
      <div class="incident-meta">${escapeHtml(it.source)} | ${new Date(it.updatedAt).toLocaleTimeString()}</div>
    </article>
  `).join("");
}

function activeFailureCount() {
  return FAILURE_TYPES.reduce((sum, type) => sum + (state.failureToggles[type] ? 1 : 0), 0);
}

function renderSummary() {
  if (!el.summaryCards) return;
  const rows = Array.from(state.intersectionStates.values());
  const intersections = state.topology?.intersections?.length || 0;
  const strategy = String(state.plan?.strategy || "ADAPTIVE");
  const cycle = safeNum(state.plan?.cycle_length);
  const totalQueue = rows.reduce((sum, row) => sum + safeNum(row.queue_length), 0);
  const avgOcc = rows.length
    ? rows.reduce((sum, row) => sum + safeNum(row.occupancy), 0) / rows.length
    : 0;
  const avgConf = rows.length
    ? rows.reduce((sum, row) => sum + safeNum(row.confidence), 0) / rows.length
    : 0;
  const emergencyNodes = rows.filter((row) => String(row.mode).toUpperCase() === "EMERGENCY").length;
  const cards = [
    ["Strategy", strategy, strategy === "ADAPTIVE" ? "ok" : "warn"],
    ["Cycle", cycle ? `${cycle}s` : "-", ""],
    ["Intersections", String(intersections), ""],
    ["Total Queue", String(totalQueue), ""],
    ["Avg Occupancy", `${Math.round(avgOcc * 100)}%`, ""],
    ["Avg Confidence", `${Math.round(avgConf * 100)}%`, ""],
    ["Emergency Nodes", String(emergencyNodes), emergencyNodes > 0 ? "warn" : ""],
    ["Active Failures", String(activeFailureCount()), activeFailureCount() > 0 ? "warn" : ""],
  ];
  el.summaryCards.innerHTML = cards
    .map(([label, value, tone]) => `<div class="summary-card ${tone}"><span>${label}</span><strong>${value}</strong></div>`)
    .join("");
}

function renderHealth() {
  if (!state.health || !el.healthCards) return;
  const connectivity = state.health.intersection_connectivity || {};
  const yolo = state.health.yolo || {};
  const timeSync = state.health.time_sync || {};
  const cards = [
    ["CPU", `${state.health.cpu_percent ?? "n/a"}%`],
    ["RAM", `${state.health.ram_percent ?? "n/a"}%`],
    ["Inference", `${state.health.inference_latency_ms?.avg ?? 0} ms`],
    ["Online Nodes", `${connectivity.online_count ?? 0}`],
    ["Offline Nodes", `${connectivity.offline_count ?? 0}`],
    ["Coordination", timeSync.coordination_allowed === false ? "OFF" : "ON"],
    ["Drift", `${Math.round(timeSync.max_abs_drift_ms ?? 0)} ms`],
    ["YOLO", `${yolo.backend || "mock"} @ ${yolo.max_fps ?? 5} FPS`],
  ];
  el.healthCards.innerHTML = cards
    .map(([label, value]) => `<div class="health-card"><span>${label}</span><strong>${value}</strong></div>`)
    .join("");
}

function sortedMapRows() {
  const topologyItems = Array.isArray(state.topology?.intersections) ? state.topology.intersections : [];
  const topologyIds = topologyItems.map((item) => String(item.intersection_id));
  const fallbackIds = new Set([
    ...Array.from(state.intersectionStates.keys()),
    ...Object.keys(state.plan?.offset || {}),
    ...Object.keys(state.plan?.phase_split || {}),
    ...((state.health?.intersection_connectivity?.online || []).map((id) => String(id))),
    ...((state.health?.intersection_connectivity?.offline || []).map((id) => String(id))),
  ]);
  const orderedFallback = Array.from(fallbackIds).filter((id) => !topologyIds.includes(id)).sort();
  const ids = [...topologyIds, ...orderedFallback];

  const rows = ids.map((id, idx) => {
    const nodeState = state.intersectionStates.get(id);
    return {
      idx,
      id,
      signal: nodeState?.signal_state || "UNKNOWN",
      queue: safeNum(nodeState?.queue_length),
      mode: nodeState?.mode || state.plan?.modes?.[id] || "LOCAL_ADAPTIVE",
      offset: safeNum(state.plan?.offset?.[id]),
      occupancy: safeNum(nodeState?.occupancy),
      confidence: safeNum(nodeState?.confidence),
    };
  });
  const sort = el.mapSort?.value || "corridor";
  if (sort === "queue_desc") rows.sort((a, b) => b.queue - a.queue);
  if (sort === "confidence_asc") rows.sort((a, b) => a.confidence - b.confidence);
  if (sort === "corridor") rows.sort((a, b) => a.idx - b.idx);
  return rows;
}

function renderMap() {
  if (!el.mapGrid) return;
  const rows = sortedMapRows();
  if (!rows.length) {
    el.mapGrid.innerHTML = "<p class='empty'>No intersections available.</p>";
    return;
  }
  const maxQueue = Math.max(...rows.map((row) => row.queue), 1);
  el.mapGrid.innerHTML = rows
    .map((row) => {
      const signalClassSafe = String(row.signal).toLowerCase().replaceAll("_", "-").replace(/[^a-z0-9-]/g, "");
      const signalClass = `sig-${signalClassSafe || "unknown"}`;
      const qPct = Math.min(100, Math.round((row.queue / maxQueue) * 100));
      const oPct = Math.min(100, Math.round(row.occupancy * 100));
      const cPct = Math.min(100, Math.round(row.confidence * 100));
      const idSafe = escapeHtml(row.id);
      const signalSafe = escapeHtml(String(row.signal).toUpperCase() === "UNKNOWN" ? "NO DATA" : row.signal);
      const modeSafe = escapeHtml(row.mode);
      return `
        <article class="map-node ${signalClass}" data-id="${idSafe}">
          <div class="map-node-head">
            <strong>${idSafe}</strong>
            <span class="map-signal-pill">${signalSafe}</span>
          </div>
          <div class="map-node-body">
            <span>Mode ${modeSafe}</span>
            <span>Offset ${row.offset}s</span>
            <span>Queue ${row.queue}</span>
            <span>Occ ${oPct}%</span>
            <span>Conf ${cPct}%</span>
          </div>
          <div class="map-queue-bar"><i style="width:${qPct}%"></i></div>
        </article>
      `;
    })
    .join("");
}

function normalizedRows() {
  const rows = Array.from(state.intersectionStates.values()).map((row) => {
    const metric = state.metrics.get(row.intersection_id);
    return {
      ...row,
      occupancy_ratio: metric?.occupancy_ratio,
      arrival_rate: metric?.arrival_rate,
    };
  });

  const query = String(el.statusSearch?.value || "").trim().toLowerCase();
  const filtered = query
    ? rows.filter((row) =>
        String(row.intersection_id).toLowerCase().includes(query) ||
        String(row.mode || "").toLowerCase().includes(query) ||
        String(row.signal_state || "").toLowerCase().includes(query))
    : rows;

  const sort = el.statusSort?.value || "id";
  if (sort === "id") filtered.sort((a, b) => String(a.intersection_id).localeCompare(String(b.intersection_id)));
  if (sort === "queue_desc") filtered.sort((a, b) => safeNum(b.queue_length) - safeNum(a.queue_length));
  if (sort === "confidence_asc") filtered.sort((a, b) => safeNum(a.confidence, 1) - safeNum(b.confidence, 1));
  if (sort === "updated_desc") filtered.sort((a, b) => String(b.last_update || "").localeCompare(String(a.last_update || "")));
  return filtered;
}

function renderIntersectionTable() {
  if (!el.intersectionTable) return;
  const rows = normalizedRows();
  if (!rows.length) {
    el.intersectionTable.innerHTML = '<p class="empty">No intersection states yet.</p>';
    return;
  }

  const header = `
    <div class="table-row table-head">
      <span>ID</span><span>Signal</span><span>Queue</span><span>Occ</span><span>Mode</span><span>Updated</span>
    </div>
  `;
  const body = rows
    .map((row) => {
      const queue = safeNum(row.queue_length);
      const occ = Math.round(safeNum(row.occupancy) * 100);
      const hot = queue >= 12 ? "table-row-hot" : "";
      const rowIdSafe = escapeHtml(row.intersection_id);
      const signalSafe = escapeHtml(row.signal_state);
      const modeSafe = escapeHtml(row.mode);
      const updatedSafe = escapeHtml(row.last_update || "-");
      return `
        <div class="table-row ${hot}">
          <span>${rowIdSafe}</span>
          <span>${signalSafe}</span>
          <span>${queue}</span>
          <span>${occ}%</span>
          <span>${modeSafe}</span>
          <span>${updatedSafe}</span>
        </div>
      `;
    })
    .join("");

  el.intersectionTable.innerHTML = header + body;
}

function updateIntersectionSelect() {
  if (!state.topology) return;
  syncPiIntersectionOptions();
  updatePiEnvPreview();
  renderPiProfiles();
}

function setFailureButtonState(type, active) {
  const id = `btn-${type.replace("_", "-")}`;
  const button = document.getElementById(id);
  if (!button) return;
  button.classList.toggle("is-active", Boolean(active));
}

function renderFailureBadges() {
  if (!el.failureBadges) return;
  const active = FAILURE_TYPES.filter((type) => state.failureToggles[type]);
  if (!active.length) {
    el.failureBadges.innerHTML = `<span class="failure-badge ok">No active failures</span>`;
    return;
  }
  el.failureBadges.innerHTML = active
    .map((type) => `<span class="failure-badge warn">${type.replaceAll("_", " ")}</span>`)
    .join("");
}

function applyFailureSnapshot(snapshot) {
  if (!snapshot || typeof snapshot !== "object") return;
  FAILURE_TYPES.forEach((type) => {
    const branch = snapshot[type];
    if (typeof branch === "boolean") {
      state.failureToggles[type] = branch;
      return;
    }
    if (branch && typeof branch === "object") {
      const values = Object.values(branch);
      state.failureToggles[type] = values.some((value) => Boolean(value));
    }
  });
  FAILURE_TYPES.forEach((type) => setFailureButtonState(type, state.failureToggles[type]));
  FAILURE_TYPES.forEach((type) => {
    const active = Boolean(state.failureToggles[type]);
    upsertIncident({
      key: `failure:${type}`,
      title: type.replaceAll("_", " ").toUpperCase(),
      detail: active ? "Failure mode active" : "Recovered",
      severity: FAILURE_SEVERITY[type] || "high",
      source: "failure-control",
      active,
    });
  });
  renderFailureBadges();
}

function setTrafficButtonState(id, active) {
  const button = document.getElementById(id);
  if (!button) return;
  button.classList.toggle("is-active", Boolean(active));
}

async function sendCommand(action, payload = {}, intersectionId = null) {
  const body = {
    action,
    intersection_id: intersectionId,
    payload,
  };
  const result = await jsonFetch("/api/control/command", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  appendEvent(`Command ${action} sent`, "info");
  return result;
}

function bindControls() {
  const getIntersection = () => el.intersectionSelect?.value || null;
  const getLane = () => Math.max(0, Math.min(3, Number(el.laneSelect?.value || 1) - 1));

  document.getElementById("btn-force-green")?.addEventListener("click", async () => {
    try {
      await sendCommand("force_green", { lane_id: getLane() }, getIntersection());
      setStatus(`Force green applied to ${getIntersection() || "corridor"}.`);
    } catch (err) {
      setStatus(err.message, true);
    }
  });

  document.getElementById("btn-activate-corridor")?.addEventListener("click", async () => {
    try {
      await sendCommand("activate_corridor", { active: true }, null);
      setStatus("Corridor coordination activation sent.");
    } catch (err) {
      setStatus(err.message, true);
    }
  });

  document.getElementById("btn-inject-emergency")?.addEventListener("click", async () => {
    try {
      await sendCommand("inject_emergency", { lane_id: getLane() }, getIntersection());
      setStatus(`Emergency injected at ${getIntersection()}.`);
      appendEvent(`Emergency route requested at ${getIntersection()}`, "warn");
    } catch (err) {
      setStatus(err.message, true);
    }
  });

  FAILURE_TYPES.forEach((type) => {
    const id = `btn-${type.replace("_", "-")}`;
    document.getElementById(id)?.addEventListener("click", async () => {
      try {
        state.failureToggles[type] = !state.failureToggles[type];
        const active = state.failureToggles[type];
        await sendCommand(type, { active }, getIntersection());
        setFailureButtonState(type, active);
        renderFailureBadges();
        upsertIncident({
          key: `failure:${type}`,
          title: type.replaceAll("_", " ").toUpperCase(),
          detail: active
            ? `Active on ${getIntersection() || "all nodes"}`
            : "Recovered",
          severity: FAILURE_SEVERITY[type] || "high",
          source: "operator",
          active,
        });
        setStatus(`${type} ${active ? "enabled" : "disabled"}.`);
        appendEvent(`${type} ${active ? "enabled" : "disabled"} for ${getIntersection() || "all nodes"}`, active ? "warn" : "info");
      } catch (err) {
        state.failureToggles[type] = !state.failureToggles[type];
        setFailureButtonState(type, state.failureToggles[type]);
        renderFailureBadges();
        setStatus(err.message, true);
      }
    });
  });

  document.getElementById("btn-ntp-sync")?.addEventListener("click", async () => {
    try {
      await sendCommand("ntp_sync", {}, null);
      setStatus("NTP sync command sent.");
      appendEvent("NTP sync requested", "info");
    } catch (err) {
      setStatus(err.message, true);
    }
  });

  document.getElementById("btn-free-traffic")?.addEventListener("click", async () => {
    try {
      state.freeTrafficEnabled = !state.freeTrafficEnabled;
      const active = state.freeTrafficEnabled;
      await sendCommand("free_traffic", { active }, getIntersection());
      setTrafficButtonState("btn-free-traffic", active);
      setStatus(`Free traffic ${active ? "enabled" : "disabled"} for ${getIntersection() || "corridor"}.`);
      appendEvent(`free_traffic ${active ? "enabled" : "disabled"} for ${getIntersection() || "corridor"}`, active ? "warn" : "info");
    } catch (err) {
      state.freeTrafficEnabled = !state.freeTrafficEnabled;
      setTrafficButtonState("btn-free-traffic", state.freeTrafficEnabled);
      setStatus(err.message, true);
    }
  });

  el.statusSearch?.addEventListener("input", () => renderIntersectionTable());
  el.statusSort?.addEventListener("change", () => renderIntersectionTable());
  el.mapSort?.addEventListener("change", () => renderMap());

  el.mapGrid?.addEventListener("click", (event) => {
    const node = event.target.closest(".map-node");
    if (!node) return;
    const nodeId = node.getAttribute("data-id");
    if (!nodeId || !el.intersectionSelect) return;
    el.intersectionSelect.value = nodeId;
    if (el.piIntersection) el.piIntersection.value = nodeId;
    updatePiEnvPreview();
    setStatus(`Selected intersection ${nodeId}.`);
  });

  el.piIntersection?.addEventListener("change", () => updatePiEnvPreview());
  el.piIp?.addEventListener("input", () => updatePiEnvPreview());
  el.piCamera?.addEventListener("input", () => updatePiEnvPreview());

  el.piSave?.addEventListener("click", () => {
    const intersection_id = String(el.piIntersection?.value || "").trim();
    const host = String(el.piIp?.value || "").trim();
    const camera_index = safeNum(el.piCamera?.value, 0);
    if (!intersection_id || !host) {
      setStatus("Pi profile needs intersection and IP/hostname.", true);
      return;
    }
    if (state.piDraftId) {
      const idx = state.piProfiles.findIndex((profile) => profile.id === state.piDraftId);
      if (idx >= 0) {
        state.piProfiles[idx] = { ...state.piProfiles[idx], intersection_id, host, camera_index };
      }
      appendEvent(`Pi profile updated for ${intersection_id} (${host})`, "info");
    } else {
      const id = `pi-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
      state.piProfiles.push({ id, intersection_id, host, camera_index });
      state.piDemoConnected[id] = true;
      appendEvent(`Pi profile added for ${intersection_id} (${host})`, "ok");
    }
    savePiProfiles();
    resetPiForm();
    renderPiProfiles();
    setStatus(`Pi profile saved for ${intersection_id}.`);
  });

  el.piClear?.addEventListener("click", () => {
    resetPiForm();
    setStatus("Pi form reset.");
  });

  el.piProfileList?.addEventListener("click", async (event) => {
    const card = event.target.closest(".pi-card");
    const button = event.target.closest("button[data-pi-action]");
    if (!card || !button) return;
    const profileId = card.getAttribute("data-pi-id");
    const action = button.getAttribute("data-pi-action");
    const profile = state.piProfiles.find((item) => item.id === profileId);
    if (!profile || !action) return;

    if (action === "toggle") {
      const connected = state.piDemoConnected[profile.id] !== false;
      state.piDemoConnected[profile.id] = !connected;
      renderPiProfiles();
      setStatus(`Pi ${profile.host} ${connected ? "disconnected" : "connected"} for demo.`);
      appendEvent(`Demo ${connected ? "disconnect" : "connect"} ${profile.intersection_id} @ ${profile.host}`, connected ? "warn" : "ok");
      return;
    }

    if (action === "edit") {
      state.piDraftId = profile.id;
      if (el.piIntersection) el.piIntersection.value = profile.intersection_id;
      if (el.piIp) el.piIp.value = profile.host;
      if (el.piCamera) el.piCamera.value = String(safeNum(profile.camera_index, 0));
      if (el.piSave) el.piSave.textContent = "Update Pi Profile";
      updatePiEnvPreview(profile);
      setStatus(`Editing Pi profile ${profile.intersection_id}.`);
      return;
    }

    if (action === "copy") {
      const env = [
        'source tancam-env/bin/activate',
        'export SERVER_URL="http://<central-server-ip>:8000"',
        `export INTERSECTION_ID="${profile.intersection_id}"`,
        `export CAMERA_INDEX=${safeNum(profile.camera_index, 0)}`,
        "python3 pi_edge_client.py",
      ].join("\n");
      try {
        await navigator.clipboard.writeText(env);
        setStatus(`Pi env copied for ${profile.intersection_id}.`);
      } catch (_) {
        setStatus("Clipboard unavailable in this browser context.", true);
      }
      return;
    }

    if (action === "remove") {
      state.piProfiles = state.piProfiles.filter((item) => item.id !== profile.id);
      delete state.piDemoConnected[profile.id];
      if (state.piDraftId === profile.id) resetPiForm();
      savePiProfiles();
      renderPiProfiles();
      setStatus(`Pi profile removed for ${profile.intersection_id}.`);
      appendEvent(`Removed Pi profile ${profile.intersection_id} @ ${profile.host}`, "warn");
    }
  });
}

function connectMonitorSocket() {
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${window.location.host}/ws/monitor`);

  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      if (data.topic === "traffic_metrics") {
        const payload = data.payload || {};
        if (payload.intersection_id) state.metrics.set(payload.intersection_id, payload);
        renderIntersectionTable();
      }
      if (data.topic === "signal_plans") {
        state.plan = data.payload;
        renderMap();
      }
      if (data.topic === "system_events") {
        const payload = data.payload || {};
        if (payload.event === "intersection_state" && payload.state?.intersection_id) {
          state.intersectionStates.set(payload.state.intersection_id, payload.state);
          renderIntersectionTable();
          renderMap();
          renderSummary();
        }
        if (FAILURE_TYPES.includes(payload.event) && typeof payload.active === "boolean") {
          state.failureToggles[payload.event] = payload.active;
          setFailureButtonState(payload.event, payload.active);
          renderFailureBadges();
          upsertIncident({
            key: `failure:${payload.event}`,
            title: payload.event.replaceAll("_", " ").toUpperCase(),
            detail: payload.active
              ? `Active on ${(payload.targets || []).join(", ") || "selected nodes"}`
              : "Recovered",
            severity: FAILURE_SEVERITY[payload.event] || "high",
            source: "system_events",
            active: payload.active,
          });
        }
        if (payload.event === "free_traffic") {
          state.freeTrafficEnabled = Boolean(payload.payload?.active ?? true);
          setTrafficButtonState("btn-free-traffic", state.freeTrafficEnabled);
        }
        if (payload.event === "inject_emergency") {
          const laneRaw = Number(payload.payload?.lane_id ?? 0);
          upsertIncident({
            key: `emergency:${payload.intersection_id || "corridor"}`,
            title: "EMERGENCY ROUTE",
            detail: `Intersection ${payload.intersection_id || "corridor"}, lane ${Number.isFinite(laneRaw) ? laneRaw + 1 : "-"}`,
            severity: "critical",
            source: "system_events",
            active: true,
          });
        }
        if (payload.event === "clear_emergency") {
          const eventId = payload.payload?.event_id || payload.result?.event_id;
          if (eventId) {
            upsertIncident({
              key: `emergency:${eventId}`,
              title: "EMERGENCY ROUTE",
              detail: "Cleared",
              severity: "critical",
              source: "system_events",
              active: false,
            });
          } else {
            Array.from(state.incidents.keys())
              .filter((key) => key.startsWith("emergency:"))
              .forEach((key) => {
                upsertIncident({
                  key,
                  title: "EMERGENCY ROUTE",
                  detail: "Cleared",
                  severity: "critical",
                  source: "system_events",
                  active: false,
                });
              });
          }
        }
      }
      if (data.topic === "alerts") {
        appendEvent(`ALERT ${JSON.stringify(data.payload)}`, "warn");
        const alert = data.payload || {};
        const type = String(alert.type || "alert");
        const active = alert.active !== false;
        upsertIncident({
          key: `alert:${type}`,
          title: type.replaceAll("_", " ").toUpperCase(),
          detail: active
            ? `Targets: ${(alert.targets || []).join(", ") || "n/a"}`
            : "Cleared",
          severity: FAILURE_SEVERITY[type] || "high",
          source: "alerts",
          active,
        });
      }
      if (data.topic === "bootstrap") {
        if (data.payload?.plan) state.plan = data.payload.plan;
        if (data.payload?.topology) state.topology = data.payload.topology;
        if (data.payload?.health) state.health = data.payload.health;
        if (data.payload?.failures) applyFailureSnapshot(data.payload.failures);
        if (Array.isArray(data.payload?.states)) {
          state.intersectionStates.clear();
          data.payload.states.forEach((item) => state.intersectionStates.set(item.intersection_id, item));
        }
        updateIntersectionSelect();
        renderSummary();
        renderHealth();
        renderPiProfiles();
        renderMap();
        renderIntersectionTable();
        renderIncidents();
      }
      setLastSync("ws");
    } catch (err) {
      appendEvent(`WS parse error: ${err.message}`, "error");
    }
  };

  ws.onopen = () => appendEvent("Monitor socket connected.", "ok");
  ws.onclose = () => {
    appendEvent("Monitor socket closed. Reconnecting...", "warn");
    setTimeout(connectMonitorSocket, 2000);
  };
}

async function refreshSnapshots() {
  try {
    const [topology, plan, health, states] = await Promise.all([
      jsonFetch("/api/topology"),
      jsonFetch("/api/corridor/plan"),
      jsonFetch("/api/system/health"),
      jsonFetch("/api/intersections/state"),
    ]);
    state.topology = topology;
    state.plan = plan;
    state.health = health;
    state.intersectionStates.clear();
    (states.items || []).forEach((item) => state.intersectionStates.set(item.intersection_id, item));
    updateIntersectionSelect();
    renderSummary();
    renderHealth();
    renderPiProfiles();
    renderMap();
    renderIntersectionTable();
    setLastSync("snapshot");
  } catch (err) {
    setStatus(`Snapshot refresh failed: ${err.message}`, true);
  }
}

async function bootstrap() {
  loadPiProfiles();
  bindControls();
  renderFailureBadges();
  renderIncidents();
  resetPiForm();
  renderPiProfiles();
  await refreshSnapshots();
  connectMonitorSocket();

  setInterval(async () => {
    try {
      state.health = await jsonFetch("/api/system/health");
      renderHealth();
      renderPiProfiles();
      setLastSync("health");
    } catch (_) {
      // keep previous health snapshot on transient failures
    }
  }, 5000);

  setInterval(async () => {
    try {
      state.plan = await jsonFetch("/api/corridor/plan");
      renderMap();
      setLastSync("plan");
    } catch (_) {
      // keep previous plan on transient failures
    }
  }, 3000);

  setInterval(async () => {
    try {
      const states = await jsonFetch("/api/intersections/state");
      (states.items || []).forEach((item) => state.intersectionStates.set(item.intersection_id, item));
      renderSummary();
      renderIntersectionTable();
      renderMap();
      setLastSync("states");
    } catch (_) {
      // keep previous states on transient failures
    }
  }, 3000);
}

bootstrap();
