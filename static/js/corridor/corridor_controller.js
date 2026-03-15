export class CorridorClient {
  constructor({ baseUrl = "" } = {}) {
    this.baseUrl = baseUrl;
    this.plan = null;
    this.topology = null;
  }

  async getTopology() {
    const res = await fetch(`${this.baseUrl}/api/topology`);
    if (!res.ok) throw new Error(`Failed to load topology: ${res.status}`);
    this.topology = await res.json();
    return this.topology;
  }

  async saveTopology(topology) {
    const res = await fetch(`${this.baseUrl}/api/topology`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(topology),
    });
    if (!res.ok) {
      const err = await res.text();
      throw new Error(`Topology save failed: ${err}`);
    }
    this.topology = await res.json();
    return this.topology;
  }

  async getPlan() {
    const res = await fetch(`${this.baseUrl}/api/corridor/plan`);
    if (!res.ok) throw new Error(`Failed to load plan: ${res.status}`);
    this.plan = await res.json();
    return this.plan;
  }

  async sendCommand(action, payload = {}, intersectionId = null) {
    const res = await fetch(`${this.baseUrl}/api/control/command`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        action,
        intersection_id: intersectionId,
        payload,
      }),
    });
    if (!res.ok) {
      const err = await res.text();
      throw new Error(`Control command failed: ${err}`);
    }
    return res.json();
  }

  async getSystemHealth() {
    const res = await fetch(`${this.baseUrl}/api/system/health`);
    if (!res.ok) throw new Error(`Failed to load system health: ${res.status}`);
    return res.json();
  }
}
