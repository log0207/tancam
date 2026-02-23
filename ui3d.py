from ursina import *


class SimulationUI:
    def __init__(self, ctrl, sim_inter):
        self.ctrl = ctrl
        self.sim = sim_inter
        self.mode = "PDWP"
        self.on_mode_change_callback = None

        self.root = Entity(parent=camera.ui)

        c_panel = color.rgb(12, 18, 28)
        c_panel2 = color.rgb(16, 24, 36)
        c_text = color.rgb(230, 235, 240)
        c_dim = color.rgb(160, 170, 180)

        Entity(parent=self.root, model="quad", scale=(0.7, 0.1), x=0, y=0.45, color=c_panel)
        Entity(parent=self.root, model="quad", scale=(0.46, 0.56), x=-0.27, y=-0.2, color=c_panel)
        Entity(parent=self.root, model="quad", scale=(0.42, 0.36), x=0.27, y=-0.3, color=c_panel2)

        self.title = Text(parent=self.root, text="TNI26165 ADAPTIVE TRAFFIC 3D", x=0, y=0.475, origin=(0, 0), scale=1.25, color=color.cyan)
        self.subtitle = Text(parent=self.root, text="Predictive Density Weighted Pressure", x=0, y=0.44, origin=(0, 0), scale=0.78, color=c_dim)

        Text(parent=self.root, text="SYSTEM STATUS", x=-0.48, y=0.02, origin=(-0.5, 0), scale=0.95, color=c_dim)
        self.time_text = Text(parent=self.root, text="Time: 08:00", x=-0.48, y=-0.04, origin=(-0.5, 0), scale=1.05, color=c_text)
        self.profile_text = Text(parent=self.root, text="Profile: Moderate", x=-0.48, y=-0.09, origin=(-0.5, 0), scale=0.9, color=color.cyan)

        self.stats_texts = []
        for i in range(4):
            t = Text(parent=self.root, text=f"[STOP] L{i} | Count: 0 | PCU: 0.0", x=-0.48, y=-0.15 - i * 0.06, origin=(-0.5, 0), scale=0.86, color=c_text)
            self.stats_texts.append(t)

        self.total_wait_text = Text(parent=self.root, text="Throughput: 0 | Avg Wait: 0.0s", x=-0.48, y=-0.41, origin=(-0.5, 0), scale=0.88, color=color.orange)

        Text(parent=self.root, text="CONTROLS", x=0.08, y=-0.18, origin=(-0.5, 0), scale=0.95, color=c_dim)
        Text(parent=self.root, text="[1] ISO  [2] TOP  [3] FREE  [4] FOLLOW", x=0.08, y=-0.23, origin=(-0.5, 0), scale=0.78, color=c_text)

        self.mode_btn = Button(parent=self.root, text="MODE: PDWP ADAPTIVE", x=0.28, y=-0.31, scale=(0.34, 0.07), color=color.rgb(25, 35, 50), text_color=color.cyan)
        self.mode_btn.on_click = self.toggle_mode

        self.amb_btn = Button(parent=self.root, text="DISPATCH AMBULANCE L0", x=0.28, y=-0.40, scale=(0.34, 0.07), color=color.rgb(60, 18, 18), text_color=color.red)
        self.amb_btn.on_click = lambda: self.sim.spawn_vehicle(0, 99)

        self.pole_timers = {}

    def add_pole_timer(self, lane, pole_root):
        timer = Text(parent=pole_root, text="00", font="VeraMono.ttf", position=(0, 7.8, 7.2), origin=(0, 0.5), scale=(10, 10, 10), color=color.white)
        self.pole_timers[lane] = timer

    def toggle_mode(self):
        if self.mode == "PDWP":
            self.mode = "FIXED"
            self.mode_btn.text = "MODE: FIXED TIMER"
            self.mode_btn.text_color = color.orange
            self.title.text = "TNI26165 FIXED TIMER"
            self.title.color = color.orange
        else:
            self.mode = "PDWP"
            self.mode_btn.text = "MODE: PDWP ADAPTIVE"
            self.mode_btn.text_color = color.cyan
            self.title.text = "TNI26165 ADAPTIVE TRAFFIC 3D"
            self.title.color = color.cyan

        if self.on_mode_change_callback is not None:
            self.on_mode_change_callback(self.mode)

    def _get_lane_timer(self, lane):
        if lane == self.ctrl.phase and self.ctrl.state == "GREEN":
            return self.ctrl.time_remaining()
        if self.ctrl.state == "YELLOW_CLOSE" and lane == self.ctrl.phase:
            from controller import YELLOW_CLOSE

            return max(0, YELLOW_CLOSE - self.ctrl.elapsed())
        if self.ctrl.state == "CLEARANCE" and self.ctrl.next_phase == lane:
            from controller import CLEARANCE

            return max(0, CLEARANCE - self.ctrl.elapsed())

        eta = self.ctrl.get_lane_eta()
        e = eta.get(lane, -1)
        return e if e > 0 else -1

    def update_ui(self, hour, profile_label, lane_scores):
        h = int(hour) % 24
        m = int((hour % 1.0) * 60)
        self.time_text.text = f"Time: {h:02d}:{m:02d}"
        self.profile_text.text = f"Profile: {profile_label}"

        for i in range(4):
            state = self.sim.lights[i]
            count = self.sim.get_lane_count(i)
            pcu = lane_scores.get(i, 0.0)

            if state == "G":
                s = "GO"
                c = color.green
            elif state == "Y":
                s = "WAIT"
                c = color.yellow
            else:
                s = "STOP"
                c = color.red

            self.stats_texts[i].text = f"[{s}] L{i} | Count: {count:<2} | PCU: {pcu:>4.1f}"
            self.stats_texts[i].color = c

        done = self.sim.total_completed_vehicles
        avg_wait = self.sim.total_wait_time_sum / done if done > 0 else 0.0
        self.total_wait_text.text = f"Throughput: {done} | Avg Wait: {avg_wait:.1f}s"

        for lane, t in self.pole_timers.items():
            val = self._get_lane_timer(lane)
            val = int(val) if val >= 0 else 0
            t.text = f"{val:02d}"

            state = self.sim.lights[lane]
            if state == "G":
                t.color = color.green
            elif state == "Y":
                t.color = color.yellow
            else:
                t.color = color.red
