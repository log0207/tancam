export class CorridorMap {
  constructor(container) {
    this.container = container;
  }

  render(intersectionStates = [], plan = null) {
    if (!this.container) return;

    const visibleStates = intersectionStates.filter((state) => {
      const signal = state?.signal_state;
      return signal && signal !== "UNKNOWN";
    });

    if (!visibleStates.length) {
      this.container.innerHTML = "<p class=\"corridor-empty\">No corridor intersections yet.</p>";
      return;
    }

    const offset = plan?.offset || {};
    const cards = visibleStates
      .map((state) => {
        const phase = state.phase ?? 0;
        const signal = state.signal_state || "UNKNOWN";
        const queue = state.queue_length ?? 0;
        const occ = state.occupancy ?? 0;
        const conf = state.confidence ?? 0;
        const mode = state.mode || "LOCAL_ADAPTIVE";
        const nodeOffset = offset[state.intersection_id] ?? 0;

        return `
          <div class="corridor-node" data-signal="${signal}">
            <div class="corridor-node-head">
              <strong>${state.intersection_id}</strong>
              <span class="phase">P${phase} ${signal}</span>
            </div>
            <div class="corridor-node-body">
              <span>Queue ${queue}</span>
              <span>Occ ${(Number(occ) * 100).toFixed(0)}%</span>
              <span>Conf ${(Number(conf) * 100).toFixed(0)}%</span>
              <span>Mode ${mode}</span>
              <span>Offset ${nodeOffset}s</span>
            </div>
          </div>
        `;
      })
      .join("");

    this.container.innerHTML = cards;
  }
}
