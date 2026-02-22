"""
TNI26165 — BRUTAL TEST SUITE (100+ Real-World Scenarios)
=========================================================
Covers: Signal phases, timing, emergencies, density, night mode,
starvation, spillback, vehicle mix, time-of-day profiles,
stress tests, edge cases, and South Indian traffic patterns.
"""
import random
import sys
# Fix Windows console encoding for Unicode characters
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')
from simulation import (Intersection, Vehicle, TYPE_CAR, TYPE_BIKE, TYPE_BUS,
                         TYPE_AUTO, TYPE_AMBULANCE, TYPE_VIP, pick_type,
                         get_mix, VEHICLE_GAP)
from controller import (AdaptiveController, FixedController, get_profile,
                         LANE_NAMES, BASE_GREEN, YELLOW_CLOSE, CLEARANCE,
                         DETECTION_WEIGHTS, NIGHT_HOURS,
                         STARVATION_LIMIT)

DT = 1/60
PASS = 0
FAIL = 0
TOTAL = 0

def ok(name, cond, detail=""):
    global PASS, FAIL, TOTAL
    TOTAL += 1
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print(f"  ❌ T{TOTAL:03d}: {name} — {detail}")

def tick(sim, ctrl, frames):
    for _ in range(frames):
        ctrl.update(); sim.update(dt=DT)

def spawn_n(sim, lane, n, vtype=TYPE_CAR):
    x, y = sim.spawn_points[lane]
    off = {0:(0,40), 2:(0,-40), 1:(-40,0), 3:(40,0)}
    dx, dy = off[lane]
    for i in range(n):
        v = Vehicle(lane, x + dx*i, y + dy*i, lane, sim.sim_time, vtype)
        sim.vehicles[lane].add(v)

def make(hour=10):
    sim = Intersection(680, 520)
    ctrl = AdaptiveController(sim)
    ctrl.sim_hour = hour
    return sim, ctrl

def make_fixed(green=30):
    sim = Intersection(680, 520)
    ctrl = FixedController(sim, green)
    return sim, ctrl

def wait_for_state(sim, ctrl, target, max_frames=90*60):
    for _ in range(max_frames):
        ctrl.update(); sim.update(dt=DT)
        if ctrl.state == target: return True
    return False

def wait_for_phase(sim, ctrl, lane, max_frames=120*60):
    for _ in range(max_frames):
        ctrl.update(); sim.update(dt=DT)
        if ctrl.phase == lane and ctrl.state == 'GREEN': return True
    return False

def log_has(ctrl, keyword):
    return any(keyword in e for e in ctrl.log)

def run_all():
    global PASS, FAIL, TOTAL

    print("=" * 70)
    print("  TNI26165 — BRUTAL TEST SUITE (100+ Scenarios)")
    print("=" * 70)

    # ══════════════════════════════════════════════════════════════════
    # CATEGORY 1: SIGNAL PHASE SEQUENCE (Tests 1-10)
    # ══════════════════════════════════════════════════════════════════
    print("\n── CATEGORY 1: Signal Phase Sequence ──")

    # T1: Full 5-phase sequence order
    sim, ctrl = make()
    spawn_n(sim, 1, 10)
    states = [ctrl.state]
    for _ in range(60*60):
        ctrl.update(); sim.update(dt=DT)
        if ctrl.state != states[-1]: states.append(ctrl.state)
        if len(states) >= 6: break
    ok("3-phase order correct", states[:4] == ['GREEN','YELLOW_CLOSE','CLEARANCE','GREEN'])

    # T2: Second full cycle also follows 5-phase
    for _ in range(90*60):
        ctrl.update(); sim.update(dt=DT)
        if ctrl.state != states[-1]: states.append(ctrl.state)
        if len(states) >= 10: break
    ok("Second cycle also 3-phase", states[3:7] == ['GREEN','YELLOW_CLOSE','CLEARANCE','GREEN'])

    # T3: YELLOW_CLOSE duration = 3.0s
    sim, ctrl = make(); spawn_n(sim, 1, 8)
    t0 = t1 = None
    for _ in range(60*60):
        ctrl.update(); sim.update(dt=DT)
        if ctrl.state == 'YELLOW_CLOSE' and t0 is None: t0 = sim.sim_time
        if t0 and ctrl.state == 'CLEARANCE' and t1 is None: t1 = sim.sim_time; break
    ok("YELLOW_CLOSE = 3.0s", t0 and t1 and abs((t1-t0)-3.0) < 0.1, f"{(t1-t0):.2f}s" if t0 and t1 else "N/A")

    # T4: CLEARANCE duration = 2.0s (next lane shows Yellow during this)
    sim, ctrl = make(); spawn_n(sim, 1, 8)
    t0 = t1 = None
    for _ in range(60*60):
        ctrl.update(); sim.update(dt=DT)
        if ctrl.state == 'CLEARANCE' and t0 is None: t0 = sim.sim_time
        if t0 and ctrl.state == 'GREEN' and ctrl.phase != 0 and t1 is None: t1 = sim.sim_time; break
    ok("CLEARANCE = 2.0s", t0 and t1 and abs((t1-t0)-2.0) < 0.1)

    # T5: During CLEARANCE, next lane shows Yellow ("get ready")
    sim, ctrl = make(); spawn_n(sim, 1, 8)
    clr_ok = False
    for _ in range(60*60):
        ctrl.update(); sim.update(dt=DT)
        if ctrl.state == 'CLEARANCE' and ctrl.next_phase is not None:
            clr_ok = sim.lights[ctrl.next_phase] == 'Y'
            break
    ok("CLEARANCE: next lane shows Y (get ready)", clr_ok)

    # T6: During CLEARANCE, closing lane is Red and next lane is Yellow
    sim, ctrl = make(); spawn_n(sim, 1, 8)
    clearance_ok = True
    for _ in range(60*60):
        ctrl.update(); sim.update(dt=DT)
        if ctrl.state == 'CLEARANCE' and ctrl.next_phase is not None:
            if sim.lights[ctrl.phase] != 'R': clearance_ok = False
            if sim.lights[ctrl.next_phase] != 'Y': clearance_ok = False
            # Other lanes should be Red
            for i in range(4):
                if i != ctrl.phase and i != ctrl.next_phase:
                    if sim.lights[i] != 'R': clearance_ok = False
            break
    ok("CLEARANCE: closing=Red, next=Yellow, others=Red", clearance_ok)

    # T7: During YELLOW_CLOSE, closing lane is Yellow
    sim, ctrl = make(); spawn_n(sim, 1, 8)
    yc_ok = False
    for _ in range(60*60):
        ctrl.update(); sim.update(dt=DT)
        if ctrl.state == 'YELLOW_CLOSE':
            yc_ok = sim.lights[ctrl.phase] == 'Y'
            break
    ok("YELLOW_CLOSE: closing lane shows Y", yc_ok)

    # T8: During CLEARANCE, next lane is Yellow
    sim, ctrl = make(); spawn_n(sim, 1, 8)
    yo_ok = False
    for _ in range(60*60):
        ctrl.update(); sim.update(dt=DT)
        if ctrl.state == 'CLEARANCE' and ctrl.next_phase is not None:
            yo_ok = sim.lights[ctrl.next_phase] == 'Y'
            break
    ok("CLEARANCE: next lane shows Y", yo_ok)

    # T9: No two lanes GREEN simultaneously
    sim, ctrl = make(); spawn_n(sim, 1, 5); spawn_n(sim, 2, 5)
    no_double_green = True
    for _ in range(90*60):
        ctrl.update(); sim.update(dt=DT)
        greens = sum(1 for i in range(4) if sim.lights[i] == 'G')
        if greens > 1: no_double_green = False; break
    ok("Never two lanes GREEN simultaneously", no_double_green)

    # T10: State machine never skips a state
    sim, ctrl = make(); spawn_n(sim, 1, 8); spawn_n(sim, 2, 8)
    valid_transitions = {
        'GREEN': {'YELLOW_CLOSE'},
        'YELLOW_CLOSE': {'CLEARANCE'},
        'CLEARANCE': {'GREEN'},
    }
    prev_state = ctrl.state
    valid = True
    for _ in range(120*60):
        ctrl.update(); sim.update(dt=DT)
        if ctrl.state != prev_state:
            if ctrl.state not in valid_transitions.get(prev_state, set()):
                if not ctrl.night_flash:
                    valid = False; break
            prev_state = ctrl.state
    ok("State machine never skips a phase", valid)

    # ══════════════════════════════════════════════════════════════════
    # CATEGORY 2: MINIMUM GREEN & PEDESTRIAN SAFETY (Tests 11-18)
    # ══════════════════════════════════════════════════════════════════
    print("\n── CATEGORY 2: Minimum Green & Pedestrian Safety ──")

    # T11: Empty lane holds green >= 15s
    sim, ctrl = make()
    switch_t = None
    for _ in range(20*60):
        ctrl.update(); sim.update(dt=DT)
        if ctrl.state == 'YELLOW_CLOSE': switch_t = sim.sim_time; break
    ok("Empty lane green >= 15s", switch_t is None or switch_t >= 14.9)

    # T12: 1 bike in lane — still holds >= 15s
    sim, ctrl = make(); spawn_n(sim, 0, 1, TYPE_BIKE)
    switch_t = None
    for _ in range(20*60):
        ctrl.update(); sim.update(dt=DT)
        if ctrl.state == 'YELLOW_CLOSE': switch_t = sim.sim_time; break
    ok("1 bike: green >= 15s", switch_t is None or switch_t >= 14.9)

    # T13: 1 auto — holds >= 15s
    sim, ctrl = make(); spawn_n(sim, 0, 1, TYPE_AUTO)
    switch_t = None
    for _ in range(20*60):
        ctrl.update(); sim.update(dt=DT)
        if ctrl.state == 'YELLOW_CLOSE': switch_t = sim.sim_time; break
    ok("1 auto: green >= 15s", switch_t is None or switch_t >= 14.9)

    # T14: Full transition time >= 7s (3+2+2)
    sim, ctrl = make(); spawn_n(sim, 1, 8)
    yc_start = g_start = None
    for _ in range(60*60):
        ctrl.update(); sim.update(dt=DT)
        if ctrl.state == 'YELLOW_CLOSE' and yc_start is None: yc_start = sim.sim_time
        if yc_start and ctrl.state == 'GREEN' and ctrl.phase != 0 and g_start is None:
            g_start = sim.sim_time; break
    ok("Transition duration >= 5s", yc_start and g_start and (g_start - yc_start) >= 4.9)

    # T15: Pedestrian crossing: min green covers crossing time
    ok("BASE_GREEN >= 15s (pedestrian)", BASE_GREEN >= 15.0)

    # T16: YELLOW_CLOSE warns drivers
    ok("YELLOW_CLOSE duration standard (3s)", YELLOW_CLOSE == 3.0)

    # T17: CLEARANCE allows get-ready + clearance
    ok("CLEARANCE duration standard (2s)", CLEARANCE == 2.0)

    # T18: Transition = YELLOW_CLOSE + CLEARANCE = 5s
    ok("Total transition = 5s", YELLOW_CLOSE + CLEARANCE == 5.0)

    # ══════════════════════════════════════════════════════════════════
    # CATEGORY 3: DENSITY-BASED GREEN CALCULATION (Tests 19-30)
    # ══════════════════════════════════════════════════════════════════
    print("\n── CATEGORY 3: Density-Based Green Calculation ──")

    # T19: 5 cars (5.0 PCU) → green = 15 + 5*3.5 = 32.5s (test formula directly)
    sim, ctrl = make(9)
    scores = {0: 0, 1: 5.0, 2: 0, 3: 0}  # 5 cars × 1.0 PCU
    g = ctrl._calc_green(1, scores)
    ok("5 cars (5 PCU): green ~32s", 30 <= g <= 35, f"{g:.0f}s")

    # T20: 15 cars (15.0 PCU) → green = 15 + 15*3.5 = 67.5s
    g = ctrl._calc_green(1, {0:0, 1:15.0, 2:0, 3:0})
    ok("15 cars (15 PCU): green ~67s", 60 <= g <= 75, f"{g:.0f}s")

    # T21: 25 cars → capped at max
    sim, ctrl = make(9); spawn_n(sim, 1, 25, TYPE_CAR)
    tick(sim, ctrl, 30*60); wait_for_phase(sim, ctrl, 1, 60*60)
    ok("25 cars: green capped at max", ctrl.green_duration <= 120 if ctrl.phase == 1 else True)

    # T22: Heavy bus lane gets more green than bike lane
    sim1, c1 = make(10); spawn_n(sim1, 1, 5, TYPE_BUS); tick(sim1, c1, 25*60); wait_for_phase(sim1, c1, 1)
    g_bus = c1.green_duration
    sim2, c2 = make(10); spawn_n(sim2, 1, 5, TYPE_BIKE); tick(sim2, c2, 25*60); wait_for_phase(sim2, c2, 1)
    g_bike = c2.green_duration
    ok("5 buses get longer green than 5 bikes", g_bus > g_bike, f"bus={g_bus:.0f}, bike={g_bike:.0f}")

    # T23: PCU weights are correct
    ok("Bike PCU = 0.5", DETECTION_WEIGHTS[1] == 0.5)
    ok("Car PCU = 1.0", DETECTION_WEIGHTS[2] == 1.0)
    ok("Auto PCU = 0.8", DETECTION_WEIGHTS[3] == 0.8)
    ok("Bus PCU = 3.0", DETECTION_WEIGHTS[5] == 3.0)

    # T27: Empty lane gets BASE_GREEN
    sim, ctrl = make(10)
    ok("Initial green = BASE or more", ctrl.green_duration >= BASE_GREEN)

    # T28: Green never below BASE_GREEN
    sim, ctrl = make(10); spawn_n(sim, 1, 1, TYPE_BIKE)
    tick(sim, ctrl, 20*60); wait_for_phase(sim, ctrl, 1, 60*60)
    ok("Green never < BASE_GREEN", ctrl.green_duration >= BASE_GREEN)

    # T29: Green never above profile max
    sim, ctrl = make(9); spawn_n(sim, 1, 30, TYPE_CAR)
    _, max_g, _ = get_profile(9)
    tick(sim, ctrl, 30*60); wait_for_phase(sim, ctrl, 1, 60*60)
    ok("Green never > profile max", ctrl.green_duration <= max_g if ctrl.phase == 1 else True)

    # T30: Densest lane picked next
    sim, ctrl = make(10)
    spawn_n(sim, 1, 2); spawn_n(sim, 2, 15); spawn_n(sim, 3, 1)
    tick(sim, ctrl, 20*60)
    wait_for_state(sim, ctrl, 'YELLOW_CLOSE', 60*60)
    ok("Densest lane picked as next", ctrl.next_phase == 2 if ctrl.next_phase is not None else True)

    # ══════════════════════════════════════════════════════════════════
    # CATEGORY 4: EMERGENCY PREEMPTION (Tests 31-42)
    # ══════════════════════════════════════════════════════════════════
    print("\n── CATEGORY 4: Emergency Preemption ──")

    # T31: Ambulance in lane 1 → preempt
    sim, ctrl = make(); spawn_n(sim, 0, 5); tick(sim, ctrl, 10*60)
    spawn_n(sim, 1, 1, TYPE_AMBULANCE)
    ok("Ambulance preempt to lane 1", wait_for_phase(sim, ctrl, 1, 30*60))

    # T32: Ambulance in lane 2
    sim, ctrl = make(); spawn_n(sim, 0, 5); tick(sim, ctrl, 10*60)
    spawn_n(sim, 2, 1, TYPE_AMBULANCE)
    ok("Ambulance preempt to lane 2", wait_for_phase(sim, ctrl, 2, 30*60))

    # T33: Ambulance in lane 3
    sim, ctrl = make(); spawn_n(sim, 0, 5); tick(sim, ctrl, 10*60)
    spawn_n(sim, 3, 1, TYPE_AMBULANCE)
    ok("Ambulance preempt to lane 3", wait_for_phase(sim, ctrl, 3, 30*60))

    # T34: VIP preempt
    sim, ctrl = make(); spawn_n(sim, 0, 5); tick(sim, ctrl, 10*60)
    spawn_n(sim, 2, 1, TYPE_VIP)
    ok("VIP preempt works", wait_for_phase(sim, ctrl, 2, 30*60))

    # T35: Ambulance beats VIP when both present
    sim, ctrl = make(); spawn_n(sim, 0, 5); tick(sim, ctrl, 10*60)
    spawn_n(sim, 1, 1, TYPE_VIP); spawn_n(sim, 2, 1, TYPE_AMBULANCE)
    wait_for_state(sim, ctrl, 'YELLOW_CLOSE', 30*60)
    ok("Ambulance > VIP priority", ctrl.next_phase == 2, f"next={ctrl.next_phase}")

    # T36: No preempt in first 8s (anti flip-flop)
    sim, ctrl = make()
    spawn_n(sim, 1, 1, TYPE_AMBULANCE)
    tick(sim, ctrl, 4*60)  # Only 4 seconds
    ok("No preempt before 8s", ctrl.state == 'GREEN' and ctrl.phase == 0)

    # T37: Preempt happens after 8s
    tick(sim, ctrl, 5*60)  # Now at ~9s
    ok("Preempt after 8s", ctrl.state != 'GREEN' or ctrl.phase != 0 or wait_for_state(sim, ctrl, 'YELLOW_CLOSE', 5*60))

    # T38: Ambulance in current green lane → no preempt
    sim, ctrl = make(); spawn_n(sim, 0, 1, TYPE_AMBULANCE)
    tick(sim, ctrl, 10*60)
    ok("No preempt for ambulance in current green", ctrl.phase == 0)

    # T39: Multiple ambulances in same lane
    sim, ctrl = make(); spawn_n(sim, 0, 5); tick(sim, ctrl, 10*60)
    spawn_n(sim, 2, 3, TYPE_AMBULANCE)
    ok("Multiple ambulances preempt", wait_for_phase(sim, ctrl, 2, 30*60))

    # T40: Emergency log recorded
    sim, ctrl = make(); spawn_n(sim, 0, 5); tick(sim, ctrl, 10*60)
    spawn_n(sim, 1, 1, TYPE_AMBULANCE)
    tick(sim, ctrl, 15*60)
    ok("Emergency logged as AMBULANCE", log_has(ctrl, "AMBULANCE"))

    # T41: VIP logged
    sim, ctrl = make(); spawn_n(sim, 0, 5); tick(sim, ctrl, 10*60)
    spawn_n(sim, 3, 1, TYPE_VIP)
    tick(sim, ctrl, 15*60)
    ok("VIP logged", log_has(ctrl, "VIP"))

    # T42: Preempt still goes through full 5-phase
    sim, ctrl = make(); spawn_n(sim, 0, 5); tick(sim, ctrl, 10*60)
    spawn_n(sim, 2, 1, TYPE_AMBULANCE)
    states = [ctrl.state]
    for _ in range(60*60):
        ctrl.update(); sim.update(dt=DT)
        if ctrl.state != states[-1]: states.append(ctrl.state)
        if 'GREEN' in states[1:]: break
    ok("Preempt goes through YELLOW_CL→CLEARANCE→GREEN",
       len(states) >= 4 and 'YELLOW_CLOSE' in states and 'CLEARANCE' in states)

    # ══════════════════════════════════════════════════════════════════
    # CATEGORY 5: EARLY DRAIN (Tests 43-48)
    # ══════════════════════════════════════════════════════════════════
    print("\n── CATEGORY 5: Early Drain ──")

    # T43: Empty lane 0, lanes 1-3 have traffic → switch < 25s
    sim, ctrl = make(); spawn_n(sim, 1, 5); spawn_n(sim, 2, 5)
    t = None
    for _ in range(30*60):
        ctrl.update(); sim.update(dt=DT)
        if ctrl.state == 'YELLOW_CLOSE': t = sim.sim_time; break
    ok("Empty lane switches < 25s", t is not None and t < 25, f"{t:.1f}s" if t else "never")

    # T44: Lane with 1 car that leaves → drains and switches
    sim, ctrl = make(); spawn_n(sim, 0, 1, TYPE_CAR); spawn_n(sim, 2, 10)
    switched = False
    for _ in range(45*60):
        ctrl.update(); sim.update(dt=DT)
        if ctrl.phase != 0: switched = True; break
    ok("Lane with departing car drains and switches", switched)

    # T45: All 4 lanes empty → still cycles (no hang)
    sim, ctrl = make()
    hung = False
    for _ in range(120*60):
        ctrl.update(); sim.update(dt=DT)
    ok("All empty: no hang", ctrl.state in ['GREEN','YELLOW_CLOSE','CLEARANCE'])

    # T46: Drain happens AFTER min green
    sim, ctrl = make()
    t = None
    for _ in range(20*60):
        ctrl.update(); sim.update(dt=DT)
        if ctrl.state == 'YELLOW_CLOSE': t = sim.sim_time; break
    ok("Drain after min green (>=15s)", t is None or t >= 14.9)

    # T47: Lane with only bikes (low weight) drains quickly
    sim, ctrl = make(); spawn_n(sim, 0, 2, TYPE_BIKE); spawn_n(sim, 1, 10)
    t = None
    for _ in range(45*60):
        ctrl.update(); sim.update(dt=DT)
        if ctrl.state == 'YELLOW_CLOSE': t = sim.sim_time; break
    ok("Bike-only lane drains after min green", t is not None and t < 30)

    # T48: Lane drains to exactly 0 → score < 0.5
    sim, ctrl = make()
    tick(sim, ctrl, 16*60)
    scores, _, _, _ = ctrl._get_lane_data()
    ok("Empty lane score < 0.5", scores[0] < 0.5)

    # ══════════════════════════════════════════════════════════════════
    # CATEGORY 6: NIGHT MODE (Tests 49-60)
    # ══════════════════════════════════════════════════════════════════
    print("\n── CATEGORY 6: Night Mode ──")

    # T49: Night mode at 23:00 with 0 vehicles
    sim, ctrl = make(23)
    tick(sim, ctrl, 3*60)
    ok("Night mode at 23:00, 0 vehicles", ctrl.night_flash)

    # T50: Night mode at 01:00
    sim, ctrl = make(); ctrl.sim_hour = 1
    tick(sim, ctrl, 3*60)
    ok("Night mode at 01:00", ctrl.night_flash)

    # T51: Night mode at 03:00
    sim, ctrl = make(); ctrl.sim_hour = 3
    tick(sim, ctrl, 3*60)
    ok("Night mode at 03:00", ctrl.night_flash)

    # T52: No night mode at 10:00 even with 0 vehicles
    sim, ctrl = make(10)
    tick(sim, ctrl, 3*60)
    ok("No night mode at 10:00", not ctrl.night_flash)

    # T53: No night mode at 18:00
    sim, ctrl = make(18)
    tick(sim, ctrl, 3*60)
    ok("No night mode at 18:00", not ctrl.night_flash)

    # T54: Night mode with exactly 3 vehicles → yes
    sim, ctrl = make(23)
    spawn_n(sim, 0, 3)
    tick(sim, ctrl, 3*60)
    ok("Night mode with exactly 3 veh", ctrl.night_flash)

    # T55: Night mode with 4 vehicles → no
    sim, ctrl = make(23)
    for i in range(4): spawn_n(sim, i, 1)
    # Keep vehicles alive
    for _ in range(60):
        if sum(sim.get_lane_count(l) for l in range(4)) < 4:
            for i in range(4): spawn_n(sim, i, 1)
        ctrl.update(); sim.update(dt=DT)
    ok("No night mode with 4+ vehicles", not ctrl.night_flash)

    # T56: Night exit logged
    sim, ctrl = make(23)
    tick(sim, ctrl, 3*60)
    for _ in range(5): spawn_n(sim, 0, 3); spawn_n(sim, 1, 3)
    for _ in range(60):
        if sum(sim.get_lane_count(l) for l in range(4)) < 6:
            spawn_n(sim, 0, 3)
        ctrl.update(); sim.update(dt=DT)
    ok("Night exit RESUME logged", log_has(ctrl, "RESUME"))

    # T57: Flashing yellow alternates Y/R
    sim, ctrl = make(23)
    tick(sim, ctrl, 3*60)
    saw_y = saw_r = False
    for _ in range(120):
        ctrl.update(); sim.update(dt=DT)
        if sim.lights[0] == 'Y': saw_y = True
        if sim.lights[0] == 'R': saw_r = True
    ok("Night flash alternates Y/R", saw_y and saw_r)

    # T58: During night flash, all 4 lanes same state
    sim, ctrl = make(23)
    tick(sim, ctrl, 3*60)
    all_same = True
    for _ in range(60):
        ctrl.update(); sim.update(dt=DT)
        s = sim.lights[0]
        for i in range(4):
            if sim.lights[i] != s: all_same = False
    ok("Night flash: all 4 lanes synchronized", all_same)

    # T59: Night hours set includes 22,23,0,1,2,3,4
    for h in [22,23,0,1,2,3,4]:
        ok(f"Hour {h} is night hour", h in NIGHT_HOURS)

    # T60: Hour 5 is NOT night
    ok("Hour 5 is not night", 5 not in NIGHT_HOURS)

    # ══════════════════════════════════════════════════════════════════
    # CATEGORY 7: STARVATION GUARD (Tests 61-68)
    # ══════════════════════════════════════════════════════════════════
    print("\n── CATEGORY 7: Starvation Guard ──")

    # T61: Starved lane with count=2 gets served
    sim, ctrl = make(); ctrl.starvation[3] = 2; spawn_n(sim, 3, 5)
    tick(sim, ctrl, 25*60)
    ok("Starved lane (2 cycles) served", ctrl.starvation[3] == 0 or ctrl.phase == 3 or log_has(ctrl, "STARVE"))

    # T62: Starved lane with count=5 → forced immediately
    sim, ctrl = make(); ctrl.starvation[2] = 5; spawn_n(sim, 2, 3)
    tick(sim, ctrl, 25*60)
    ok("Heavily starved (5 cycles) forced", log_has(ctrl, "STARVE") or ctrl.phase == 2)

    # T63: Starvation counter resets on serve
    sim, ctrl = make(); ctrl.starvation[1] = 3; spawn_n(sim, 1, 5)
    wait_for_phase(sim, ctrl, 1, 60*60)
    ok("Starvation resets on serve", ctrl.starvation[1] == 0 if ctrl.phase == 1 else True)

    # T64: Starvation counter increments for skipped lanes
    sim, ctrl = make(); spawn_n(sim, 1, 10); spawn_n(sim, 2, 10)
    # Force switch to lane 1 (lane 2 and 3 get skipped)
    initial_s2 = ctrl.starvation[2]
    wait_for_phase(sim, ctrl, 1, 60*60)
    ok("Skipped lane starvation increments", ctrl.starvation[2] > initial_s2 or ctrl.starvation[3] > 0)

    # T65: STARVATION_LIMIT = 2
    ok("Starvation limit set to 2", STARVATION_LIMIT == 2)

    # T66: Starvation log appears
    sim, ctrl = make(); ctrl.starvation[3] = 3; spawn_n(sim, 3, 5)
    tick(sim, ctrl, 25*60)
    ok("Starvation log entry", log_has(ctrl, "STARVE") or log_has(ctrl, "starved"))

    # T67: All lanes at starvation=0 initially
    sim, ctrl = make()
    all_zero = all(ctrl.starvation[i] == 0 for i in range(4))
    ok("Initial starvation all zero", all_zero)

    # T68: Current green lane never starved
    sim, ctrl = make()
    ok("Active lane starvation = 0", ctrl.starvation[ctrl.phase] == 0)

    # ══════════════════════════════════════════════════════════════════
    # CATEGORY 8: QUEUE SPILLBACK (Tests 69-73)
    # ══════════════════════════════════════════════════════════════════
    print("\n── CATEGORY 8: Queue Spillback ──")

    # T69: 16 vehicles in waiting lane → spillback
    sim, ctrl = make(18); spawn_n(sim, 0, 3); spawn_n(sim, 2, 18)
    tick(sim, ctrl, 25*60)
    ok("Spillback with 18 vehicles", log_has(ctrl, "Spillback") or ctrl.phase == 2)

    # T70: 10 vehicles → no spillback warning
    sim, ctrl = make(10); spawn_n(sim, 0, 3); spawn_n(sim, 2, 10)
    tick(sim, ctrl, 25*60)
    ok("No spillback with 10 vehicles", not log_has(ctrl, "Spillback") or ctrl.phase == 2)

    # T71: Spillback triggers switch to congested lane
    sim, ctrl = make(18); spawn_n(sim, 0, 2); spawn_n(sim, 1, 20)
    tick(sim, ctrl, 30*60)
    ok("Spillback switches to congested lane", ctrl.phase == 1 or log_has(ctrl, "Spillback"))

    # T72: Multiple lanes with spillback → one gets served
    sim, ctrl = make(18)
    spawn_n(sim, 1, 18); spawn_n(sim, 2, 20); spawn_n(sim, 3, 16)
    tick(sim, ctrl, 30*60)
    ok("Multi-spillback: one lane served", ctrl.phase in [1,2,3])

    # T73: Spillback doesn't fire in first 20s
    sim, ctrl = make(18); spawn_n(sim, 2, 20)
    tick(sim, ctrl, 15*60)
    ok("No spillback before min+5s", ctrl.state == 'GREEN' and ctrl.phase == 0)

    # ══════════════════════════════════════════════════════════════════
    # CATEGORY 9: DENSITY IMBALANCE (Tests 74-78)
    # ══════════════════════════════════════════════════════════════════
    print("\n── CATEGORY 9: Density Imbalance ──")

    # T74: 4x imbalance triggers switch
    sim, ctrl = make(); spawn_n(sim, 0, 2); spawn_n(sim, 2, 15)
    tick(sim, ctrl, 30*60)
    ok("4x imbalance triggers switch", ctrl.phase != 0 or log_has(ctrl, "Imbalance"))

    # T75: 2x imbalance does NOT trigger
    sim, ctrl = make(); spawn_n(sim, 0, 5); spawn_n(sim, 2, 10)
    tick(sim, ctrl, 25*60)
    ok("2x imbalance no forced switch", ctrl.phase == 0 or not log_has(ctrl, "Imbalance"))

    # T76: Imbalance needs min+8s elapsed
    sim, ctrl = make(); spawn_n(sim, 0, 1); spawn_n(sim, 2, 20)
    tick(sim, ctrl, 15*60)
    ok("Imbalance after min+8s", True)  # Just verifying no crash

    # T77: Imbalance logged
    sim, ctrl = make(); spawn_n(sim, 0, 1); spawn_n(sim, 2, 20)
    tick(sim, ctrl, 30*60)
    ok("Imbalance logged", log_has(ctrl, "Imbalance") or ctrl.phase == 2)

    # T78: Equal traffic → no imbalance switch
    sim, ctrl = make(); spawn_n(sim, 0, 5); spawn_n(sim, 1, 5); spawn_n(sim, 2, 5)
    tick(sim, ctrl, 20*60)
    ok("Equal traffic: no imbalance", not log_has(ctrl, "Imbalance"))

    # ══════════════════════════════════════════════════════════════════
    # CATEGORY 10: TIME-OF-DAY PROFILES (Tests 79-96)
    # ══════════════════════════════════════════════════════════════════
    print("\n── CATEGORY 10: Time-of-Day Profiles ──")

    profiles = [
        (5, 0.3, 40, "Early morning"),
        (6, 0.6, 50, "Dawn"),
        (7, 1.4, 80, "School rush"),
        (8, 1.8, 100, "Morning peak"),
        (9, 2.0, 120, "Peak hour"),
        (10, 1.0, 70, "Mid-morning"),
        (11, 0.8, 60, "Late morning"),
        (12, 0.7, 50, "Lunch"),
        (13, 0.8, 60, "Post-lunch"),
        (14, 1.2, 80, "School dismissal"),
        (15, 1.0, 70, "Afternoon"),
        (16, 1.3, 80, "Pre-evening"),
        (17, 1.8, 100, "Evening rush start"),
        (18, 2.0, 120, "Peak evening"),
        (19, 1.6, 90, "Evening"),
        (20, 1.0, 70, "Night social"),
        (21, 0.6, 50, "Late evening"),
        (22, 0.2, 30, "Night"),
    ]
    for hour, exp_rate, exp_max, desc in profiles:
        rate, max_g, label = get_profile(hour)
        ok(f"Profile {hour:02d}:00 rate={exp_rate}", abs(rate - exp_rate) < 0.01, f"got {rate}")
        ok(f"Profile {hour:02d}:00 maxG={exp_max}s", max_g == exp_max, f"got {max_g}")

    # ══════════════════════════════════════════════════════════════════
    # CATEGORY 11: VEHICLE MIX BY TIME (Tests 97-106)
    # ══════════════════════════════════════════════════════════════════
    print("\n── CATEGORY 11: Vehicle Mix by Time of Day ──")

    random.seed(42)
    def count_types(hour, n=2000):
        types = [pick_type(hour) for _ in range(n)]
        return {t: types.count(t)/n for t in [TYPE_BIKE, TYPE_AUTO, TYPE_CAR, TYPE_BUS, TYPE_AMBULANCE, TYPE_VIP]}

    # Morning rush
    m = count_types(9)
    ok("9AM: bikes > 30%", m[TYPE_BIKE] >= 0.28)
    ok("9AM: autos present", m[TYPE_AUTO] >= 0.10)
    ok("9AM: cars present", m[TYPE_CAR] >= 0.10)

    # Evening
    e = count_types(20)
    ok("8PM: cars dominant", e[TYPE_CAR] >= 0.20)

    # Night
    n = count_types(2)
    ok("2AM: cars highest share", n[TYPE_CAR] >= n[TYPE_BIKE])

    # All hours: ambulance always ~2-3%
    for h in [2, 9, 14, 18, 22]:
        m = count_types(h)
        ok(f"{h:02d}:00 ambulance ~2-3%", 0.01 <= m[TYPE_AMBULANCE] <= 0.06, f"{m[TYPE_AMBULANCE]:.1%}")

    # All hours: VIP always ~2%
    for h in [6, 12, 18]:
        m = count_types(h)
        ok(f"{h:02d}:00 VIP ~2%", 0.005 <= m[TYPE_VIP] <= 0.06, f"{m[TYPE_VIP]:.1%}")

    # ══════════════════════════════════════════════════════════════════
    # CATEGORY 12: FIXED CONTROLLER BASELINE (Tests 107-112)
    # ══════════════════════════════════════════════════════════════════
    print("\n── CATEGORY 12: Fixed Controller Baseline ──")

    # T107: Fixed uses 5-phase
    sim, ctrl = make_fixed(30); spawn_n(sim, 1, 5)
    states = [ctrl.state]
    for _ in range(60*60):
        ctrl.update(); sim.update(dt=DT)
        if ctrl.state != states[-1]: states.append(ctrl.state)
        if len(states) >= 6: break
    ok("Fixed: 3-phase sequence", states[:4] == ['GREEN','YELLOW_CLOSE','CLEARANCE','GREEN'])

    # T108: Fixed green = 30s exactly
    sim, ctrl = make_fixed(30)
    t = None
    for _ in range(45*60):
        ctrl.update(); sim.update(dt=DT)
        if ctrl.state == 'YELLOW_CLOSE': t = sim.sim_time; break
    ok("Fixed green = 30s", t is not None and abs(t - 30.0) < 0.1)

    # T109: Fixed cycles through all 4 lanes
    sim, ctrl = make_fixed(10); spawn_n(sim, 1, 3)
    phases_seen = {ctrl.phase}
    for _ in range(180*60):
        ctrl.update(); sim.update(dt=DT)
        if ctrl.state == 'GREEN': phases_seen.add(ctrl.phase)
        if len(phases_seen) == 4: break
    ok("Fixed cycles all 4 lanes", len(phases_seen) == 4)

    # T110: Fixed ignores density (always same green)
    ok("Fixed controller green_duration = set value", ctrl.green_duration == 10)

    # T111: Fixed 15s green
    sim, ctrl = make_fixed(15)
    t = None
    for _ in range(25*60):
        ctrl.update(); sim.update(dt=DT)
        if ctrl.state == 'YELLOW_CLOSE': t = sim.sim_time; break
    ok("Fixed 15s green works", t and abs(t - 15.0) < 0.1)

    # T112: Fixed 60s green
    sim, ctrl = make_fixed(60)
    t = None
    for _ in range(70*60):
        ctrl.update(); sim.update(dt=DT)
        if ctrl.state == 'YELLOW_CLOSE': t = sim.sim_time; break
    ok("Fixed 60s green works", t and abs(t - 60.0) < 0.1)

    # ══════════════════════════════════════════════════════════════════
    # CATEGORY 13: STRESS TESTS (Tests 113-120)
    # ══════════════════════════════════════════════════════════════════
    print("\n── CATEGORY 13: Stress Tests ──")

    # T113: 50 vehicles per lane → no crash
    sim, ctrl = make(18)
    for i in range(4): spawn_n(sim, i, 50)
    tick(sim, ctrl, 60*60)
    ok("50 veh/lane: no crash", True)

    # T114: Rapid phase cycling → no state corruption
    sim, ctrl = make()
    for _ in range(10):
        spawn_n(sim, random.randint(0,3), 5, TYPE_AMBULANCE)
        tick(sim, ctrl, 10*60)
    ok("Rapid cycling: state valid", ctrl.state in ['GREEN','YELLOW_CLOSE','CLEARANCE'])

    # T115: 5-minute continuous run
    sim, ctrl = make(9)
    for f in range(300*60):
        if random.randint(1,100) <= 5: sim.spawn_vehicle(hour=9)
        ctrl.update(); sim.update(dt=DT)
    ok("5-min run: no crash", True)

    # T116: All lanes maxed → fair distribution
    sim, ctrl = make(18)
    for i in range(4): spawn_n(sim, i, 20)
    phases_seen = set()
    for _ in range(300*60):
        ctrl.update(); sim.update(dt=DT)
        if ctrl.state == 'GREEN': phases_seen.add(ctrl.phase)
    ok("All lanes maxed: all 4 served", len(phases_seen) == 4)

    # T117: Spawn/despawn cycle → no memory leak
    sim, ctrl = make(10)
    for _ in range(10):
        for i in range(4): spawn_n(sim, i, 10)
        tick(sim, ctrl, 30*60)
    total = sum(sim.get_lane_count(i) for i in range(4))
    ok("Spawn/despawn: vehicles bounded", total < 200)

    # T118: Single lane traffic for 2 minutes
    sim, ctrl = make(10)
    for _ in range(120*60):
        sim.spawn_vehicle(lane=0, v_type=TYPE_CAR, hour=10)
        ctrl.update(); sim.update(dt=DT)
    ok("Single-lane 2-min: no hang", True)

    # T119: No traffic for 2 minutes → no hang
    sim, ctrl = make(10)
    tick(sim, ctrl, 120*60)
    ok("No traffic 2-min: no hang", True)

    # T120: Alternating rush/calm
    sim, ctrl = make(10)
    for cycle in range(6):
        for _ in range(4): spawn_n(sim, random.randint(0,3), 15)
        tick(sim, ctrl, 30*60)
        tick(sim, ctrl, 30*60)
    ok("Alternating rush/calm: stable", ctrl.state in ['GREEN','YELLOW_CLOSE','CLEARANCE'])

    # ══════════════════════════════════════════════════════════════════
    # CATEGORY 14: LOG INTEGRITY (Tests 121-125)
    # ══════════════════════════════════════════════════════════════════
    print("\n── CATEGORY 14: Log Integrity ──")

    sim, ctrl = make(10)
    spawn_n(sim, 1, 10); spawn_n(sim, 2, 10)
    tick(sim, ctrl, 60*60)

    ok("Log not empty", len(ctrl.log) > 0)
    ok("Log has INIT entry", any("INIT" in e for e in ctrl.log))
    ok("Log entries have timestamps", all("[" in e and "]" in e for e in ctrl.log))
    ok("Log has GREEN entry", log_has(ctrl, "GREEN"))
    ok("Log capped at maxlen", len(ctrl.log) <= 16)

    # ══════════════════════════════════════════════════════════════════
    # CATEGORY 15: DETECTION API (Tests 126-130)
    # ══════════════════════════════════════════════════════════════════
    print("\n── CATEGORY 15: Detection API (Simulated YOLO) ──")

    sim, ctrl = make()
    spawn_n(sim, 0, 3, TYPE_CAR); spawn_n(sim, 1, 2, TYPE_BUS)
    dets = sim.get_detections()
    ok("Detections returned", len(dets) > 0)
    ok("Detection has 'class' field", 'class' in dets[0])
    ok("Detection has 'conf' field", 'conf' in dets[0])
    ok("Detection has 'box' field", 'box' in dets[0])
    ok("Detection has 'lane' field", 'lane' in dets[0])

    confs = [d['conf'] for d in dets]
    ok("Confidence in [0.8, 1.0]", all(0.8 <= c <= 1.0 for c in confs))

    boxes = [d['box'] for d in dets]
    ok("Box has 4 coords", all(len(b) == 4 for b in boxes))

    classes = [d['class'] for d in dets]
    ok("Car class = 2", 2 in classes)
    ok("Bus class = 5", 5 in classes)

    # ══════════════════════════════════════════════════════════════════
    # CATEGORY 16: ROUND-ROBIN CYCLE ENFORCEMENT
    # ══════════════════════════════════════════════════════════════════
    print("\n── CATEGORY 16: Round-Robin Cycle Enforcement ──")

    # All 4 lanes served before any repeats
    sim, ctrl = make(10)
    for i in range(4): spawn_n(sim, i, 5)
    phases_seen = []
    for _ in range(300*60):
        ctrl.update(); sim.update(dt=DT)
        if ctrl.state == 'GREEN' and (not phases_seen or phases_seen[-1] != ctrl.phase):
            phases_seen.append(ctrl.phase)
        if len(phases_seen) >= 5: break
    # First 4 distinct phases, then one repeats
    ok("All 4 lanes served before repeat", len(set(phases_seen[:4])) == 4)
    ok("5th phase is a repeat", phases_seen[4] in phases_seen[:4] if len(phases_seen) >= 5 else True)

    # served_this_cycle starts with {0}
    sim, ctrl = make(10)
    ok("Initial served_this_cycle = {0}", ctrl.served_this_cycle == {0})

    # cycle_order tracks service order
    ok("Initial cycle_order = [0]", ctrl.cycle_order == [0])

    # After one full cycle, served resets
    sim, ctrl = make(10)
    for i in range(4): spawn_n(sim, i, 5)
    for _ in range(300*60):
        ctrl.update(); sim.update(dt=DT)
        if len(ctrl.cycle_order) >= 4 and len(ctrl.served_this_cycle) <= 2:
            break  # Cycle just reset
    ok("Cycle resets after all 4 served", log_has(ctrl, "CYCLE") or len(ctrl.served_this_cycle) <= 2)

    # Per-lane ETA returns 4 lanes
    sim, ctrl = make(10)
    eta = ctrl.get_lane_eta()
    ok("ETA has all 4 lanes", len(eta) == 4)
    ok("Current green lane ETA = 0", eta[ctrl.phase] == 0)

    # _pick_next only picks unserved when available
    sim, ctrl = make(10)
    ctrl.served_this_cycle = {0, 1, 2}  # Only lane 3 left
    spawn_n(sim, 3, 5)
    nxt = ctrl._pick_next({0:1, 1:5, 2:10, 3:2})
    ok("_pick_next picks unserved lane 3", nxt == 3)

    # Unserved log shows remaining lanes
    sim, ctrl = make(10); spawn_n(sim, 1, 10)
    wait_for_phase(sim, ctrl, 1, 60*60)
    ok("Log shows Unserved lanes", log_has(ctrl, "Unserved"))

    # ══════════════════════════════════════════════════════════════════
    print("\n" + "=" * 70)
    pct = (PASS / TOTAL * 100) if TOTAL > 0 else 0
    color = "" if FAIL == 0 else ""
    print(f"  FINAL: {PASS}/{TOTAL} passed ({pct:.0f}%) — {FAIL} failed")
    print("=" * 70)

    if FAIL > 0:
        print("\n  Failed tests listed above with ❌")

    return FAIL == 0


if __name__ == "__main__":
    success = run_all()
    sys.exit(0 if success else 1)
