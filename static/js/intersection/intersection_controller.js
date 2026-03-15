import { CONTROL_THRESHOLDS, TYPE } from "../constants.js";
import { SignalFSM, INTERSECTION_MODES } from "./signal_fsm.js";

const TYPE_WEIGHT = {
  [TYPE.BIKE]: 0.5,
  [TYPE.CAR]: 1.0,
  [TYPE.AUTO]: 1.2,
  [TYPE.BUS]: 2.5,
  [TYPE.AMBULANCE]: 3.0,
  [TYPE.VIP]: 1.4,
};

export class IntersectionController {
  constructor({ intersectionId, phases = [0, 1, 2, 3], mode = INTERSECTION_MODES.LOCAL_ADAPTIVE } = {}) {
    this.intersectionId = intersectionId || "J01";
    this.mode = mode;
    this.phases = phases;
    this.fsm = new SignalFSM({ phases, mode });
    this.baseCycleDurations = phases.map(() => CONTROL_THRESHOLDS.MIN_GREEN);
    this.coordinatedAdaptiveBlend = 0.32;
    this.metrics = {
      queue_count: 0,
      lane_density: 0,
      vehicle_type_weight: 0,
      occupancy_ratio: 0,
      arrival_rate: 0,
    };
    this.confidence = 0.9;
    this.emergencyLane = null;
    this.lastUpdate = new Date().toISOString();
  }

  setMode(mode) {
    this.mode = mode;
    this.fsm.setMode(mode);
  }

  applyCorridorPlan(plan) {
    if (!plan) return;
    const split = plan.phase_split?.[this.intersectionId];
    if (split) {
      this.baseCycleDurations = this.phases.map((laneId) => split[String(laneId)] ?? CONTROL_THRESHOLDS.MIN_GREEN);
      this.fsm.setCycleDurations(this.baseCycleDurations);
    }
    const mode = plan.modes?.[this.intersectionId];
    if (mode && INTERSECTION_MODES[mode]) {
      this.setMode(mode);
    }
  }

  setEmergencyLane(laneId) {
    this.emergencyLane = laneId;
    this.setMode(INTERSECTION_MODES.EMERGENCY);
    this.fsm.forcePhaseByLane(laneId);
  }

  clearEmergency() {
    this.emergencyLane = null;
    if (this.mode === INTERSECTION_MODES.EMERGENCY) {
      this.setMode(INTERSECTION_MODES.COORDINATED);
    }
  }

  forceGreen(laneId) {
    this.fsm.forcePhaseByLane(laneId);
  }

  update(dt, laneCounts = {}, vehicles = []) {
    const demandByPhase = this.phases.map((laneId) => this.calcLaneDemand(laneId, vehicles, laneCounts));
    this.fsm.setPhaseDemand(demandByPhase);

    // Only update durations right before the start of a cycle to avoid jumping timers
    if (this.fsm.phaseState === "RED_AMBER" && this.fsm.phaseRemaining < 0.2) {
      if (this.mode === INTERSECTION_MODES.LOCAL_ADAPTIVE) {
        const durations = this.phases.map((laneId, idx) => this.calcGreenDuration(laneId, vehicles, laneCounts, demandByPhase[idx]));
        this.fsm.setCycleDurations(durations);
      } else if (this.mode === INTERSECTION_MODES.COORDINATED) {
        const local = this.phases.map((laneId, idx) => this.calcGreenDuration(laneId, vehicles, laneCounts, demandByPhase[idx]));
        const blended = this.baseCycleDurations.map((base, idx) => {
          const target = (base * (1 - this.coordinatedAdaptiveBlend)) + (local[idx] * this.coordinatedAdaptiveBlend);
          return Math.max(CONTROL_THRESHOLDS.MIN_GREEN, Math.min(CONTROL_THRESHOLDS.MAX_GREEN, target));
        });
        this.fsm.setCycleDurations(blended);
      }
    }

    this.lastUpdate = new Date().toISOString();
    return this.fsm.update(dt, { emergencyLane: this.emergencyLane });
  }

  calcLaneDemand(laneId, vehicles, laneCounts = {}) {
    let weightedCount = laneCounts[laneId] || 0;
    if (Array.isArray(vehicles) && vehicles.length > 0) {
      weightedCount = 0;
      vehicles.forEach((vehicle) => {
        if (String(vehicle.lane) !== String(laneId) || vehicle.hasCrossed) return;
        weightedCount += TYPE_WEIGHT[vehicle.type] ?? 1.0;
      });
    }
    return weightedCount;
  }

  calcGreenDuration(laneId, vehicles, laneCounts = {}, precomputedDemand = null) {
    const weightedCount = precomputedDemand ?? this.calcLaneDemand(laneId, vehicles, laneCounts);
    const scaled = CONTROL_THRESHOLDS.MIN_GREEN + (weightedCount * 2.2);
    const green = Math.max(CONTROL_THRESHOLDS.MIN_GREEN, Math.min(CONTROL_THRESHOLDS.MAX_GREEN, scaled));
    if (this.emergencyLane !== null && String(this.emergencyLane) === String(laneId)) {
      return Math.max(green, 30);
    }
    return green;
  }

  updateMetrics(metrics) {
    this.metrics = {
      ...this.metrics,
      ...metrics,
    };
    if (typeof metrics.confidence === "number") {
      this.confidence = metrics.confidence;
    }
    this.lastUpdate = new Date().toISOString();
  }

  getState() {
    const fsmState = this.fsm.snapshot();
    return {
      intersection_id: this.intersectionId,
      signal_state: fsmState.phaseState,
      phase: fsmState.phase,
      queue_length: this.metrics.queue_count,
      occupancy: this.metrics.occupancy_ratio,
      confidence: this.confidence,
      mode: this.mode,
      last_update: this.lastUpdate,
      active_lane: fsmState.activeLane,
      phase_remaining: fsmState.phaseRemaining,
    };
  }
}

export { INTERSECTION_MODES };
