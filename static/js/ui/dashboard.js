import { CorridorMap } from "./corridor_map.js";

function ensureDashboardShell() {
  let panel = document.getElementById("corridor-dashboard");
  if (panel) return panel;

  panel = document.createElement("section");
  panel.id = "corridor-dashboard";
  panel.className = "panel panel-corridor";
  panel.innerHTML = `
    <h2>Corridor Monitor</h2>
    <div id="corridor-status" class="corridor-status">Waiting for corridor data...</div>
    <div id="corridor-health" class="corridor-health"></div>
    <div id="corridor-map" class="corridor-map"></div>
    <div class="corridor-controls">
      <button id="cmd-force-green">Force Green</button>
      <button id="cmd-activate-corridor">Activate Corridor</button>
      <button id="cmd-inject-emergency">Inject Emergency</button>
      <button id="cmd-network-outage">Toggle Network Outage</button>
      <button id="cmd-camera-failure">Toggle Camera Failure</button>
      <button id="cmd-low-visibility">Toggle Low Visibility</button>
      <button id="cmd-node-crash">Toggle Node Crash</button>
    </div>
    <label class="ctl-label" for="topology-editor">Topology JSON</label>
    <textarea id="topology-editor" rows="8" class="topology-editor"></textarea>
    <button id="save-topology">Save Topology</button>
  `;

  const hud = document.querySelector(".hud");
  const controlPanel = document.querySelector(".panel-control");
  if (controlPanel) {
    controlPanel.appendChild(panel);
  } else if (hud) {
    hud.appendChild(panel);
  } else {
    document.body.appendChild(panel);
  }
  return panel;
}

export class DashboardController {
  constructor({ corridorClient, baseUrl = "" } = {}) {
    this.corridorClient = corridorClient;
    this.baseUrl = baseUrl;
    this.panel = ensureDashboardShell();
    this.map = new CorridorMap(document.getElementById("corridor-map"));
    this.statusEl = document.getElementById("corridor-status");
    this.healthEl = document.getElementById("corridor-health");
    this.topologyEditor = document.getElementById("topology-editor");
    this.commandHandlers = {};
    this.toggleState = {
      network_outage: false,
      camera_failure: false,
      low_visibility: false,
      node_crash: false,
    };
  }

  bindCommands({
    onForceGreen,
    onActivateCorridor,
    onInjectEmergency,
    onToggleFailure,
    onSaveTopology,
  }) {
    this.commandHandlers = {
      onForceGreen,
      onActivateCorridor,
      onInjectEmergency,
      onToggleFailure,
      onSaveTopology,
    };

    const bind = (id, fn) => {
      const el = document.getElementById(id);
      if (el) el.addEventListener("click", fn);
    };

    bind("cmd-force-green", () => onForceGreen && onForceGreen());
    bind("cmd-activate-corridor", () => onActivateCorridor && onActivateCorridor());
    bind("cmd-inject-emergency", () => onInjectEmergency && onInjectEmergency());

    bind("cmd-network-outage", () => this.toggleFailure("network_outage"));
    bind("cmd-camera-failure", () => this.toggleFailure("camera_failure"));
    bind("cmd-low-visibility", () => this.toggleFailure("low_visibility"));
    bind("cmd-node-crash", () => this.toggleFailure("node_crash"));

    bind("save-topology", () => {
      if (!onSaveTopology) return;
      try {
        const parsed = JSON.parse(this.topologyEditor.value || "{}");
        onSaveTopology(parsed);
      } catch (err) {
        this.setStatus(`Topology JSON parse error: ${err.message}`);
      }
    });
  }

  toggleFailure(type) {
    this.toggleState[type] = !this.toggleState[type];
    const active = this.toggleState[type];
    if (this.commandHandlers.onToggleFailure) {
      this.commandHandlers.onToggleFailure(type, active);
    }
    this.setStatus(`${type} ${active ? "enabled" : "disabled"}`);
  }

  setTopology(topology) {
    if (this.topologyEditor) {
      this.topologyEditor.value = JSON.stringify(topology, null, 2);
    }
  }

  setStatus(text) {
    if (this.statusEl) this.statusEl.textContent = text;
  }

  render(intersectionStates, plan, healthSnapshot = null) {
    this.map.render(intersectionStates, plan);
    if (plan) {
      this.setStatus(
        `Corridor ${plan.corridor_id || "C1"} | ${Object.keys(plan.offset || {}).length} nodes | cycle ${plan.cycle_length || "?"}s`
      );
    }

    if (healthSnapshot && this.healthEl) {
      const cpu = healthSnapshot.cpu_percent;
      const ram = healthSnapshot.ram_percent;
      const latency = healthSnapshot.inference_latency_ms?.avg ?? 0;
      const sync = healthSnapshot.time_sync?.coordination_allowed;
      this.healthEl.innerHTML = `
        <span>CPU: ${cpu ?? "n/a"}%</span>
        <span>RAM: ${ram ?? "n/a"}%</span>
        <span>Inference: ${Number(latency).toFixed(2)}ms</span>
        <span>Coordination: ${sync === false ? "OFF" : "ON"}</span>
      `;
    }
  }
}
