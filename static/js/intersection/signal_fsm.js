import { CONTROL_THRESHOLDS, SIGNAL_TIMINGS } from "../constants.js";

export const INTERSECTION_MODES = {
  COORDINATED: "COORDINATED",
  LOCAL_ADAPTIVE: "LOCAL_ADAPTIVE",
  FIXED: "FIXED",
  EMERGENCY: "EMERGENCY",
};

export class SignalFSM {
  constructor({ phases = [0, 1, 2, 3], mode = INTERSECTION_MODES.LOCAL_ADAPTIVE } = {}) {
    this.phases = phases;
    this.mode = mode;
    this.phase = 0;
    this.nextPhase = phases.length > 1 ? 1 : 0;
    this.phaseState = "GREEN";
    this.phaseElapsed = 0;
    this.phaseDuration = CONTROL_THRESHOLDS.MIN_GREEN;
    this.phaseRemaining = CONTROL_THRESHOLDS.MIN_GREEN;
    this.greenDuration = CONTROL_THRESHOLDS.MIN_GREEN;
    this.cycleDurations = phases.map(() => CONTROL_THRESHOLDS.MIN_GREEN);
    this.phaseDemand = phases.map(() => 0);
    this.skipCounts = phases.map(() => 0);
    this.forcedNextPhase = null;
    this.interruptedPhase = null;
    this.nonGreenElapsed = 0;
  }

  setMode(mode) {
    this.mode = mode;
  }

  setCycleDurations(durations = []) {
    for (let i = 0; i < this.cycleDurations.length; i += 1) {
      const next = Number(durations[i]);
      if (Number.isFinite(next)) {
        this.cycleDurations[i] = Math.max(CONTROL_THRESHOLDS.MIN_GREEN, Math.min(CONTROL_THRESHOLDS.MAX_GREEN, next));
      }
    }
  }

  setPhaseDemand(demand = []) {
    for (let i = 0; i < this.phaseDemand.length; i += 1) {
      const value = Number(demand[i]);
      this.phaseDemand[i] = Number.isFinite(value) ? Math.max(0, value) : 0;
    }
  }

  chooseNextPhase() {
    const count = this.phases.length;
    if (count <= 1) return 0;
    const current = Number(this.phase);
    const baseNext = (current + 1) % count;
    // Keep deterministic progression for demo/coordinated control.
    // Adaptive reordering is only enabled in LOCAL_ADAPTIVE mode.
    if (this.mode !== INTERSECTION_MODES.LOCAL_ADAPTIVE) {
      for (let i = 0; i < count; i += 1) {
        if (i === baseNext) this.skipCounts[i] = 0;
        else this.skipCounts[i] = (this.skipCounts[i] || 0) + 1;
      }
      return baseNext;
    }
    const maxDemand = this.phaseDemand.reduce((m, v) => Math.max(m, Number(v) || 0), 0);
    if (maxDemand <= 0) return baseNext;

    const lowDemandCutoff = Math.max(0.15, maxDemand * 0.25);
    const starvationLimit = Math.max(1, Number(CONTROL_THRESHOLDS.STARVATION_CYCLES) || 3);
    let chosen = baseNext;
    let chosenDemand = -1;
    for (let offset = 1; offset <= count; offset += 1) {
      const idx = (current + offset) % count;
      const demand = this.phaseDemand[idx] || 0;
      const forcedBySkip = (this.skipCounts[idx] || 0) >= starvationLimit;
      if (forcedBySkip) {
        chosen = idx;
        chosenDemand = demand;
        break;
      }
      if (demand >= lowDemandCutoff && demand > chosenDemand) {
        chosen = idx;
        chosenDemand = demand;
      }
    }

    for (let i = 0; i < count; i += 1) {
      if (i === chosen) this.skipCounts[i] = 0;
      else this.skipCounts[i] = (this.skipCounts[i] || 0) + 1;
    }
    return chosen;
  }
  forcePhaseByLane(laneId) {
    const idx = this.phases.indexOf(Number(laneId));
    if (idx >= 0) {
      this.forcedNextPhase = idx;
    }
  }

  applyTimeCorrection(seconds = 0) {
    const delta = Number(seconds);
    if (!Number.isFinite(delta) || delta === 0) return;
    this.phaseRemaining = Math.max(0, this.phaseRemaining - delta);
    this.phaseElapsed = Math.max(0, this.phaseElapsed + delta);
  }

  update(dt, options = {}) {
    const emergencyLane = options.emergencyLane === undefined ? null : String(options.emergencyLane);

    this.phaseElapsed += dt;
    this.phaseRemaining -= dt;

    // Defensive normalization: avoid invalid indices causing undefined active lanes
    // and visually "stuck red" intersections.
    if (!Number.isFinite(this.phase) || this.phase < 0 || this.phase >= this.phases.length) {
      this.phase = 0;
    }
    if (!Number.isFinite(this.nextPhase) || this.nextPhase < 0 || this.nextPhase >= this.phases.length) {
      this.nextPhase = (this.phase + 1) % this.phases.length;
    }

    let transition = false;
    let nextStateDef = null;

    const FSM = {
      GREEN: {
        update: () => {
          const currentLane = this.phases[this.phase];
          if (emergencyLane !== null && emergencyLane === String(currentLane)) {
            return null;
          }
          if (this.forcedNextPhase !== null) {
            if (this.interruptedPhase === null) {
              this.interruptedPhase = (this.phase + 1) % this.phases.length;
            }
            this.nextPhase = this.forcedNextPhase;
            this.forcedNextPhase = null;
            return "YELLOW";
          }
          if (this.phaseRemaining <= 0) {
            if (this.interruptedPhase !== null) {
              this.nextPhase = this.interruptedPhase;
              this.interruptedPhase = null;
            } else {
              this.nextPhase = this.chooseNextPhase();
            }
            return "YELLOW";
          }
          return null;
        },
        setup: () => {
          // BUG FIX: Removed dynamic reassignment in the setup hook to prevent sudden
          // timer jumping seconds before proper counting finishes during dynamic corridor plan arrivals.
          // Duration is only latched at the *start* of the GREEN phase.
        },
      },
      YELLOW: {
        update: () => (this.phaseRemaining <= 0 ? "ALL_RED" : null),
        setup: () => {
          this.phaseDuration = SIGNAL_TIMINGS.YELLOW;
          this.phaseRemaining = this.phaseDuration;
        },
      },
      ALL_RED: {
        update: () => (this.phaseRemaining <= 0 ? "RED_AMBER" : null),
        setup: () => {
          this.phase = this.nextPhase;
          this.phaseDuration = SIGNAL_TIMINGS.ALL_RED;
          this.phaseRemaining = this.phaseDuration;
        },
      },
      RED_AMBER: {
        update: () => (this.phaseRemaining <= 0 ? "GREEN" : null),
        setup: () => {
          this.phaseDuration = SIGNAL_TIMINGS.RED_AMBER;
          this.phaseRemaining = this.phaseDuration;
        },
      },
    };

    // Override GREEN setup properly outside the dynamic block, so when transitioning
    // from RED_AMBER to GREEN, we grab the NEWEST duration, but once we are *in* GREEN,
    // it doesn't arbitrarily expand.
    FSM.GREEN.setup = () => {
        const greenTime = this.mode === INTERSECTION_MODES.FIXED
            ? CONTROL_THRESHOLDS.MIN_GREEN
            : (this.cycleDurations[this.phase] || CONTROL_THRESHOLDS.MIN_GREEN);
        this.phaseDuration = greenTime;
        this.greenDuration = greenTime;
        this.phaseRemaining = greenTime;
    };

    const currentFSM = FSM[this.phaseState];
    if (currentFSM) {
      const nextStateName = currentFSM.update();
      if (nextStateName) {
        this.phaseState = nextStateName;
        this.phaseElapsed = 0;
        transition = true;
        nextStateDef = FSM[nextStateName];
      }
    }

    if (transition && nextStateDef) {
      const carry = this.phaseRemaining < 0 ? -this.phaseRemaining : 0;
      nextStateDef.setup();
      this.phaseRemaining = Math.max(0, this.phaseRemaining - carry);
    }

    // Watchdog recovery: if a controller remains in non-green states for too long,
    // force return to GREEN on a valid phase to prevent all-red lockups.
    if (this.phaseState === "GREEN") {
      this.nonGreenElapsed = 0;
    } else {
      this.nonGreenElapsed += Math.max(0, Number(dt) || 0);
      if (this.nonGreenElapsed >= 12) {
        this.phaseState = "GREEN";
        this.phaseElapsed = 0;
        this.nonGreenElapsed = 0;
        const greenTime = this.mode === INTERSECTION_MODES.FIXED
          ? CONTROL_THRESHOLDS.MIN_GREEN
          : (this.cycleDurations[this.phase] || CONTROL_THRESHOLDS.MIN_GREEN);
        this.phaseDuration = greenTime;
        this.greenDuration = greenTime;
        this.phaseRemaining = greenTime;
      }
    }

    return this.snapshot();
  }

  snapshot() {
    return {
      phase: this.phase,
      nextPhase: this.nextPhase,
      phaseState: this.phaseState,
      phaseElapsed: this.phaseElapsed,
      phaseDuration: this.phaseDuration,
      phaseRemaining: this.phaseRemaining,
      greenDuration: this.greenDuration,
      activeLane: this.phases[this.phase],
      mode: this.mode,
    };
  }
}

