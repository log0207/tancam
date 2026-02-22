"""
TNI26165 — Industry-Grade Adaptive Traffic Signal Controller
=============================================================
Indian signal sequence:
  GREEN → YELLOW_CLOSE(3s) → CLEARANCE(2s, next lane shows Yellow) → GREEN

During CLEARANCE the closing lane is Red and the next lane shows Yellow
("get ready to go") — matching real Indian signal behavior where the
opening Yellow overlaps with the clearance interval.
"""
from collections import deque

# ── Signal Phase Durations ────────────────────────────────────────────
YELLOW_CLOSE      = 3.0   # Current lane: Green → Yellow (slow down)
CLEARANCE         = 2.0   # Clearance: closing=Red, next=Yellow ("get ready")

# ── Adaptive Green Parameters ─────────────────────────────────────────
BASE_GREEN       = 15.0    # Absolute minimum green (pedestrian crossing safety)
BASE_GREEN       = 15.0    # Absolute minimum green (pedestrian crossing safety)
DEFAULT_MAX      = 60.0    # Default maximum green
PEAK_MAX         = 60.0    # Extended max during peak hours (Limited by sim screen size)
NIGHT_GREEN      = 20.0    # Short green in night mode
DENSITY_FACTOR   = 2.0     # Seconds of green per weighted vehicle in queue

# ── Vehicle Detection Weights (PCU - Passenger Car Units, Indian std) ─
#    Indian traffic: ~60% two-wheelers, hence lower weight
#    Buses carry 40+ people: higher priority
WEIGHT_BIKE       = 0.5   # Motorcycle / Bicycle
WEIGHT_AUTO       = 0.8   # Auto-rickshaw
WEIGHT_CAR        = 1.0   # Car / sedan / SUV
WEIGHT_BUS        = 3.0   # Bus (public transport priority)
WEIGHT_TRUCK      = 2.5   # Truck / goods vehicle
WEIGHT_AMBULANCE  = 1.0   # Counted normally; priority handled via preemption
WEIGHT_VIP        = 1.0   # Same as car; priority handled via preemption

DETECTION_WEIGHTS = {
    1:  WEIGHT_BIKE,
    2:  WEIGHT_CAR,
    3:  WEIGHT_AUTO,
    5:  WEIGHT_BUS,
    7:  WEIGHT_TRUCK,
    99: WEIGHT_AMBULANCE,
    88: WEIGHT_VIP,
}

LANE_NAMES = ["North", "East", "South", "West"]

# ── Time-of-Day Profiles (South Indian Traffic) ──────────────────────
# Each profile: (spawn_rate_multiplier, max_green_override, dominant_types, label)
#   spawn_rate_multiplier: 1.0 = normal, 2.0 = double, 0.3 = very light
#   dominant_types:  bias vehicle type probabilities

PROFILES = {
    # hour_range: (rate_mult, max_green, label)
    (5, 6):   (0.3,  40, "Early Morning — Light trucks/autos"),
    (6, 7):   (0.6,  50, "Dawn — Early commuters begin"),
    (7, 8):   (1.4,  80, "School Rush — Buses + 2-wheelers heavy"),
    (8, 9):   (1.8, 100, "Morning Peak — Office + School overflow"),
    (9, 10):  (2.0, 120, "Peak Hour — IT/corporate commute flood"),
    (10, 11): (1.0,  70, "Mid-Morning — Market traffic"),
    (11, 12): (0.8,  60, "Late Morning — Moderate mixed"),
    (12, 13): (0.7,  50, "Lunch — Light movement"),
    (13, 14): (0.8,  60, "Post-Lunch — Gradual pickup"),
    (14, 15): (1.2,  80, "School Dismissal — Buses + autos"),
    (15, 16): (1.0,  70, "Afternoon — Moderate"),
    (16, 17): (1.3,  80, "Pre-Evening — Traffic building"),
    (17, 18): (1.8, 100, "Evening Rush Start — Return commute"),
    (18, 19): (2.0, 120, "Peak Evening — Maximum congestion"),
    (19, 20): (1.6,  90, "Evening — Heavy shopping/dining"),
    (20, 21): (1.0,  70, "Night Social — Cinema/restaurants"),
    (21, 22): (0.6,  50, "Late Evening — Tapering"),
    (22, 23): (0.2,  30, "Night — Flashing Yellow eligible"),
    (23, 24): (0.1,  20, "Late Night — Minimal"),
    (0, 5):   (0.1,  20, "Deep Night — Flashing Yellow active"),
}

NIGHT_HOURS = set(range(0, 5)) | {22, 23}  # Hours with flashing yellow
STARVATION_LIMIT = 2  # If a lane misses this many cycles, force-serve it


def get_profile(hour):
    """Get traffic profile for a given hour (0-23)"""
    for (h_start, h_end), val in PROFILES.items():
        if h_start <= hour < h_end:
            return val
    return (0.1, 20, "Unknown")


class TrafficController:
    """
    Base class. Indian signal state machine:
      GREEN → YELLOW_CLOSE (3s) → CLEARANCE (2s, next=Yellow) → GREEN
    """

    STATES = ['GREEN', 'YELLOW_CLOSE', 'CLEARANCE']

    def __init__(self, sim):
        self.sim = sim
        self.phase = 0              # Current/active green lane
        self.next_phase = None      # Lane that WILL get green
        self.state = 'GREEN'
        self.state_start = 0.0
        self.green_duration = 30.0  # How long current GREEN was given
        self.sim_hour = 8           # Simulated hour of day

        # Round-robin: track which lanes have been served this cycle
        # All 4 must be served before any lane repeats
        self.served_this_cycle = {0}  # Lane 0 starts green
        self.cycle_order = [0]        # Order of service in current cycle

        # Per-lane starvation counter (how many cycles since last served)
        self.starvation = {i: 0 for i in range(4)}
        self.starvation[0] = 0  # Lane 0 starts green

        # Decision log
        self.log = deque(maxlen=16)

        # Init lights
        for i in range(4):
            self.sim.lights[i] = 'R'
        self.sim.lights[0] = 'G'
        self._log("INIT", f"{LANE_NAMES[0]} GREEN ({self.green_duration:.0f}s) | Cycle: [N]")

    def _log(self, tag, msg):
        h = int(self.sim_hour) % 24
        m = int((self.sim_hour % 1) * 60)
        self.log.append(f"[{h:02d}:{m:02d}] {tag:12s}| {msg}")

    def elapsed(self):
        return self.sim.sim_time - self.state_start

    def time_remaining(self):
        if self.state == 'GREEN':
            return max(0, self.green_duration - self.elapsed())
        elif self.state == 'YELLOW_CLOSE':
            return max(0, YELLOW_CLOSE - self.elapsed())
        elif self.state == 'CLEARANCE':
            return max(0, CLEARANCE - self.elapsed())
        return 0

    def get_lane_eta(self):
        """Return estimated seconds until each lane gets green.
        Returns dict {lane: seconds}. 0 = currently green, -1 = unknown."""
        eta = {}
        # Current green lane
        for i in range(4):
            if i == self.phase and self.state == 'GREEN':
                eta[i] = 0  # Currently green
            else:
                eta[i] = -1  # Will be calculated below

        # Figure out remaining time in current phase + transition
        remain = self.time_remaining()  # Time left in current state
        transition = YELLOW_CLOSE + CLEARANCE  # 3+2 = 5s per switch

        # Which lanes still need serving this cycle?
        unserved = [l for l in range(4) if l not in self.served_this_cycle]

        # If we're mid-transition, the next_phase is known
        if self.state in ('YELLOW_CLOSE', 'CLEARANCE') and self.next_phase is not None:
            # Next phase will get green after remaining transition
            eta[self.next_phase] = remain
            # Others come after that
            after_next = [l for l in unserved if l != self.next_phase]
            cumulative = remain + BASE_GREEN  # at minimum
            for l in after_next:
                cumulative += transition
                eta[l] = cumulative
                cumulative += BASE_GREEN
        else:
            # We're in GREEN — current phase finishes, then transitions
            cumulative = remain + transition  # time until next lane gets green
            if self.next_phase is not None:
                pos = 0
            else:
                for l in unserved:
                    eta[l] = cumulative
                    cumulative += BASE_GREEN + transition

        return eta

    # ── Phase Transitions ─────────────────────────────────────────────

    def _enter_yellow_close(self, next_lane, reason):
        """Current green lane → Yellow (closing)"""
        self.next_phase = next_lane
        self.sim.lights[self.phase] = 'Y'
        self.state = 'YELLOW_CLOSE'
        self.state_start = self.sim.sim_time
        self._log("⬛ YELLOW_CL", f"{LANE_NAMES[self.phase]} closing | {reason}")

    def _enter_clearance(self):
        """Clearance: closing lane → Red, next lane → Yellow (get ready)"""
        self.sim.lights[self.phase] = 'R'          # Close current
        self.sim.lights[self.next_phase] = 'Y'      # Next lane: "get ready"
        self.state = 'CLEARANCE'
        self.state_start = self.sim.sim_time
        self._log("🟡 CLEARANCE", f"{LANE_NAMES[self.phase]}→Red, {LANE_NAMES[self.next_phase]}→Yellow (get ready, 2s)")

    def _enter_green(self, duration, reason):
        """Next lane → Green"""
        old = self.phase
        # Update starvation counters
        for i in range(4):
            if i == self.next_phase:
                self.starvation[i] = 0
            elif i != old:
                self.starvation[i] += 1

        self.phase = self.next_phase
        self.green_duration = duration
        self.sim.lights[self.phase] = 'G'
        self.state = 'GREEN'
        self.state_start = self.sim.sim_time
        self.next_phase = None

        # Round-robin tracking
        self.served_this_cycle.add(self.phase)
        self.cycle_order.append(self.phase)
        if len(self.served_this_cycle) == 4:
            # All 4 served → reset cycle
            self._log("🔄 CYCLE", f"Complete: {[LANE_NAMES[l] for l in self.cycle_order]}")
            self.served_this_cycle = {self.phase}
            self.cycle_order = [self.phase]

        remain = [LANE_NAMES[l] for l in range(4) if l not in self.served_this_cycle]
        self._log("🟢 GREEN", f"{LANE_NAMES[self.phase]} for {duration:.0f}s | {reason} | Unserved: {remain}")

    def update(self):
        raise NotImplementedError


# ══════════════════════════════════════════════════════════════════════
# FIXED TIMER CONTROLLER (Baseline for comparison)
# ══════════════════════════════════════════════════════════════════════
class FixedController(TrafficController):
    """30s fixed green, cyclic rotation. No camera intelligence."""

    def __init__(self, sim, fixed_green=30.0):
        self.fixed_green = fixed_green
        super().__init__(sim)
        self.green_duration = fixed_green

    def update(self):
        e = self.elapsed()
        if self.state == 'GREEN':
            if e >= self.fixed_green:
                nxt = (self.phase + 1) % 4
                self._enter_yellow_close(nxt, f"fixed {self.fixed_green:.0f}s expired")
        elif self.state == 'YELLOW_CLOSE':
            if e >= YELLOW_CLOSE:
                self._enter_clearance()
        elif self.state == 'CLEARANCE':
            if e >= CLEARANCE:
                self._enter_green(self.fixed_green, "cyclic rotation")


# ══════════════════════════════════════════════════════════════════════
# ADAPTIVE CONTROLLER (Density-Based — TNI26165)
# ══════════════════════════════════════════════════════════════════════
class AdaptiveController(TrafficController):
    """
    Industry-grade adaptive controller using simulated camera detections.

    Decision Rules:
      1. Density-based green: green = BASE + queue_pcu × FACTOR (clamped)
      2. Emergency preemption (ambulance/VIP) — shortens current green
      3. Early drain — lane empties → switch before max
      4. Starvation guard — no lane waits > 2 cycles
      5. Night mode — flashing yellow when traffic < threshold
      6. Peak hour boost — extend max green during peaks
      7. Queue spillback warning — log when queue > 15
      8. Density comparison — heavily congested other lane gets priority
    """

    def __init__(self, sim):
        super().__init__(sim)
        self._last_hold_log = 0.0
        self.night_flash = False
        self.night_flash_timer = 0.0

    # ── Detection Processing (Simulated YOLO Feed) ────────────────────

    def _get_lane_data(self):
        """Process camera detections into lane scores and emergency info"""
        dets = self.sim.get_detections()
        scores = {i: 0.0 for i in range(4)}   # Weighted PCU score
        counts = {i: 0 for i in range(4)}      # Raw vehicle count
        emergency = None
        emg_type = ""

        for d in dets:
            lane = int(d['lane'])
            cls = d['class']
            w = DETECTION_WEIGHTS.get(cls, 1.0)
            scores[lane] += w
            counts[lane] += 1

            # Emergency detection (only matters if that lane is NOT already green)
            if cls in (99, 88) and self.sim.lights[lane] != 'G':
                if emergency is None or cls == 99:  # Ambulance > VIP
                    emergency = lane
                    emg_type = "AMBULANCE" if cls == 99 else "VIP"

        return scores, counts, emergency, emg_type

    def _calc_green(self, lane, scores):
        """Calculate density-based green time for a lane"""
        _, max_green, _ = get_profile(self.sim_hour)
        g = BASE_GREEN + scores.get(lane, 0) * DENSITY_FACTOR
        return max(BASE_GREEN, min(max_green, g))

    def _pick_next(self, scores):
        """
        Pick next lane using priority (round-robin enforced):
          1. Only consider lanes NOT yet served this cycle
          2. Among those: starved lane first
          3. Then highest density (PCU weighted)
          4. Cyclic fallback
        If all lanes served this cycle, reset and pick densest.
        """
        # Only consider unserved lanes (round-robin enforcement)
        unserved = [l for l in range(4) if l != self.phase and l not in self.served_this_cycle]
        if not unserved:
            # All served → allow any (cycle will reset in _enter_green)
            unserved = [l for l in range(4) if l != self.phase]

        # Check starvation first (among unserved)
        starved = [(l, self.starvation[l]) for l in unserved
                    if self.starvation[l] >= STARVATION_LIMIT]
        if starved:
            worst = max(starved, key=lambda x: x[1])
            self._log("⚠ STARVE", f"{LANE_NAMES[worst[0]]} waited {worst[1]} cycles — forcing")
            return worst[0]

        # Highest density among unserved
        candidates = {l: scores.get(l, 0) for l in unserved}
        if candidates:
            best = max(candidates, key=candidates.get)
            if candidates[best] > 0:
                return best

        # Cyclic fallback among unserved
        for offset in range(1, 4):
            nxt = (self.phase + offset) % 4
            if nxt in unserved:
                return nxt

        return (self.phase + 1) % 4

    # ── Night Mode ────────────────────────────────────────────────────

    def _check_night_mode(self, total_vehicles):
        """Enter/Exit flashing yellow for very low traffic"""
        hour = int(self.sim_hour) % 24
        if hour in NIGHT_HOURS and total_vehicles <= 3:
            if not self.night_flash:
                self.night_flash = True
                self._log("🌙 NIGHT", "Entering flashing Yellow mode (very low traffic)")
        else:
            if self.night_flash:
                self.night_flash = False
                self._log("☀ RESUME", "Exiting night mode — traffic detected")
                for i in range(4):
                    self.sim.lights[i] = 'R'
                self.sim.lights[self.phase] = 'G'
                self.state = 'GREEN'
                self.state_start = self.sim.sim_time
                self.green_duration = NIGHT_GREEN

    def _flash_yellow_tick(self):
        """In night mode: all signals flash yellow (1s on, 1s off)"""
        cycle = self.sim.sim_time % 2.0
        for i in range(4):
            self.sim.lights[i] = 'Y' if cycle < 1.0 else 'R'

    # ── Main Update ───────────────────────────────────────────────────

    def update(self):
        scores, counts, emg_lane, emg_type = self._get_lane_data()
        total_v = sum(counts.values())

        # Night mode check
        self._check_night_mode(total_v)
        if self.night_flash:
            self._flash_yellow_tick()
            return

        e = self.elapsed()
        _, max_green_profile, profile_label = get_profile(self.sim_hour)

        # ─── YELLOW_CLOSE (3s) ────────────────────────────────────────
        if self.state == 'YELLOW_CLOSE':
            if e >= YELLOW_CLOSE:
                self._enter_clearance()
            return

        # ─── CLEARANCE (2s) — closing=Red, next=Yellow (get ready) ───
        if self.state == 'CLEARANCE':
            if e >= CLEARANCE:
                nxt = self.next_phase
                g = self._calc_green(nxt, scores)
                self._enter_green(g, f"density={scores[nxt]:.1f} PCU → {g:.0f}s")
            return

        # ─── GREEN (adaptive) ────────────────────────────────────────
        cur_score = scores[self.phase]

        # Rule 1: Emergency Preemption (after 8s min to avoid signal flip-flop)
        if emg_lane is not None and e >= 8.0:
            self._enter_yellow_close(emg_lane,
                f"🚨 {emg_type} in {LANE_NAMES[emg_lane]} — PREEMPT after {e:.0f}s")
            return

        # Rule 2: Green time not yet at minimum → hold
        if e < BASE_GREEN:
            return

        # Rule 3: Current lane drained → early switch
        if cur_score < 0.5:
            nxt = self._pick_next(scores)
            self._enter_yellow_close(nxt,
                f"{LANE_NAMES[self.phase]} empty (score={cur_score:.1f}) after {e:.0f}s")
            return

        # Rule 4: Green duration expired
        if e >= self.green_duration:
            nxt = self._pick_next(scores)
            self._enter_yellow_close(nxt,
                f"green expired ({self.green_duration:.0f}s) → {LANE_NAMES[nxt]} (score={scores[nxt]:.1f})")
            return

        # Rule 5: Starvation — another lane has been waiting too long
        starved = [l for l in range(4) if l != self.phase and self.starvation[l] >= STARVATION_LIMIT]
        if starved and e >= BASE_GREEN + 5:
            worst = max(starved, key=lambda l: self.starvation[l])
            self._enter_yellow_close(worst,
                f"⚠ {LANE_NAMES[worst]} starved ({self.starvation[worst]} cycles)")
            return

        # Rule 6: Queue spillback on other lane (>15 vehicles)
        for l in range(4):
            if l != self.phase and counts[l] > 15 and e >= BASE_GREEN + 5:
                self._enter_yellow_close(l,
                    f"⚠ Spillback: {LANE_NAMES[l]} has {counts[l]} vehicles queued")
                return

        # Rule 7: Density imbalance — other lane has much more traffic
        other_best = max((l for l in range(4) if l != self.phase), key=lambda l: scores[l])
        if scores[other_best] > cur_score * 4 and e >= BASE_GREEN + 8:
            self._enter_yellow_close(other_best,
                f"Imbalance: {LANE_NAMES[other_best]}={scores[other_best]:.0f} vs current={cur_score:.0f}")
            return

        # Rule 8: Dynamic hold — keep green, log periodically
        if self.sim.sim_time - self._last_hold_log >= 8.0:
            self._last_hold_log = self.sim.sim_time
            remain = self.green_duration - e
            self._log("⏳ HOLDING", f"{LANE_NAMES[self.phase]} score={cur_score:.1f}, {remain:.0f}s left")
# ══════════════════════════════════════════════════════════════════════
# PREDICTIVE ADAPTIVE CONTROLLER (PDWP - TNI26165)
# ══════════════════════════════════════════════════════════════════════
class PredictiveAdaptiveController(AdaptiveController):
    """
    Predictive Density-Weighted Pressure (PDWP) Controller - Throughput Optimized.
    
    Strategy:
      - Maximize Throughput: Keeps green as long as flow is high to avoid 5s switching penalty.
      - Rapid Response: Switches within 1s of lane becoming empty.
      - Waiting Timer: Uses real waiting time to prevent any lane from being overlooked.
    """

    def __init__(self, sim):
        super().__init__(sim)
        self.min_green = BASE_GREEN
        self.extension_step = 5.0 
        self._empty_since = None

    def _get_lane_pressure(self, lane, scores):
        q_score = scores.get(lane, 0)
        actual_wait = 0
        max_wait = 0
        for v in self.sim.vehicles[lane]:
            if v.waiting:
                 w = (self.sim.sim_time - v.wait_start_time)
                 actual_wait += w
                 max_wait = max(max_wait, w)
        
        # Pressure = Density + (Avg Wait * 0.1) + (Max Wait penalty if > 60s)
        wait_bonus = (max_wait * 0.5) if max_wait > 60 else 0
        return q_score + (actual_wait * 0.05) + wait_bonus + (self.starvation[lane] * 5.0)

    def _pick_next_by_pressure(self, scores):
        unserved = [l for l in range(4) if l != self.phase and l not in self.served_this_cycle]
        if not unserved:
            unserved = [l for l in range(4) if l != self.phase]

        pressures = {l: self._get_lane_pressure(l, scores) for l in unserved}
        if pressures:
             return max(pressures, key=pressures.get)
        return (self.phase + 1) % 4

    def update(self):
        scores, counts, emg_lane, emg_type = self._get_lane_data()
        total_v = sum(counts.values())

        self._check_night_mode(total_v)
        if self.night_flash:
            self._flash_yellow_tick()
            return

        e = self.elapsed()
        _, max_green_profile, _ = get_profile(self.sim_hour)

        if self.state == 'YELLOW_CLOSE':
            if e >= YELLOW_CLOSE: self._enter_clearance()
            return

        if self.state == 'CLEARANCE':
            if e >= CLEARANCE:
                nxt = self.next_phase
                # Set initial green based on current pressure
                g = BASE_GREEN + (scores[nxt] * 2.0)
                g = max(BASE_GREEN, min(max_green_profile, g))
                self._enter_green(g, f"set {g:.0f}s (flow detection active)")
            return

        # ─── GREEN Phase ───
        cur_score = scores[self.phase]

        # 1. Emergency
        if emg_lane is not None and e >= 8.0:
            self._enter_yellow_close(emg_lane, f"🚨 {emg_type} EMERGENCY")
            return

        # 2. Min Green
        if e < self.min_green:
            return

        # 3. Dynamic Switching based on FLOW
        # If current lane is busy (> 2.0 vehicles), keep it green (throughput)
        # UNLESS another lane has reached a "Critical Wait" (> 80s max wait)
        max_other_wait = 0
        critical_lane = None
        for l in range(4):
            if l != self.phase:
                for v in self.sim.vehicles[l]:
                    if v.waiting:
                        w = (self.sim.sim_time - v.wait_start_time)
                        if w > max_other_wait:
                            max_other_wait = w
                            critical_lane = l

        if critical_lane is not None and max_other_wait > 90.0:
            self._enter_yellow_close(critical_lane, f"CRITICAL WAIT ({max_other_wait:.0f}s)")
            return

        # 4. Saturation Check
        if cur_score < 0.3: # Lane is empty or finishing
            if self._empty_since is None:
                self._empty_since = self.sim.sim_time
            elif self.sim.sim_time - self._empty_since >= 1.0: # Very fast switch
                nxt = self._pick_next_by_pressure(scores)
                if scores[nxt] > 0.5:
                    self._enter_yellow_close(nxt, "flow saturated")
                    self._empty_since = None
                    return
        else:
            self._empty_since = None

        # 5. Extension Logic
        # Continually extend by 5s if flow is healthy
        if (self.green_duration - e) < 2.0:
            if cur_score > 3.0 and self.green_duration + self.extension_step <= max_green_profile:
                self.green_duration += self.extension_step
                self._log("➕ EXTEND", f"Flow={cur_score:.1f} → +{self.extension_step}s")

        # 6. Time limit
        if e >= self.green_duration:
            nxt = self._pick_next_by_pressure(scores)
            self._enter_yellow_close(nxt, "duration limit")
            return
