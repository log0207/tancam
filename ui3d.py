from ursina import *

class SimulationUI:
    def __init__(self, ctrl, sim_inter):
        self.ctrl = ctrl
        self.sim = sim_inter
        
        self.container = Entity(parent=camera.ui)
        
        # System Stats Container (Bottom Left)
        self.stats_panel = Entity(parent=self.container, model='quad', scale=(0.6, 0.35), origin=(-0.5, -0.5), color=color.black66, position=window.bottom_left + Vec2(0.02, 0.02))
        
        s_base_x = window.bottom_left.x + 0.04
        s_base_y = window.bottom_left.y + 0.32
        
        self.title_text = Text(parent=self.container, text="PDWP CONTROLLER", scale=1.5, position=(s_base_x, s_base_y), color=color.cyan)
        self.time_text = Text(parent=self.container, text="Time: 08:00", scale=1.2, position=(s_base_x + 0.35, s_base_y))
        self.profile_text = Text(parent=self.container, text="Profile: Normal", scale=1.1, position=(s_base_x, s_base_y - 0.06))
        
        self.stats_texts = []
        for i in range(4):
            x_offset = (i % 2) * 0.28
            y_offset = (i // 2) * 0.06
            t = Text(parent=self.container, text=f"L{i}: ", scale=1.1, position=(s_base_x + x_offset, s_base_y - 0.14 - y_offset))
            self.stats_texts.append(t)
            
        self.total_wait_text = Text(parent=self.container, text="Throughput: 0   Wait: 0.0s", scale=1.1, position=(s_base_x, s_base_y - 0.28), color=color.orange)
        
        # Controls Container (Bottom Right)
        self.action_panel = Entity(parent=self.container, model='quad', scale=(0.45, 0.25), origin=(0.5, -0.5), color=color.black66, position=window.bottom_right + Vec2(-0.02, 0.02))
        
        c_base_x = window.bottom_right.x - 0.44
        c_base_y = window.bottom_right.y + 0.22
        
        Text(parent=self.container, text="VIEWS:", scale=1.2, position=(c_base_x, c_base_y), color=color.white)
        Text(parent=self.container, text="1:Iso | 2:Top | 3:Free | 4:Drive", scale=1.1, position=(c_base_x, c_base_y - 0.05), color=color.light_gray)
        
        self.mode = "PDWP"
        self.mode_btn = Button(parent=self.container, text="Mode: PDWP", scale=(0.2, 0.05), origin=(-0.5, 0.5), position=(c_base_x, c_base_y - 0.12), color=color.black66)
        self.mode_btn.on_click = self.toggle_mode
        self.on_mode_change_callback = None
        
        self.amb_btn = Button(parent=self.container, text="Emergency (Lane 0)", scale=(0.2, 0.05), origin=(-0.5, 0.5), position=(c_base_x + 0.21, c_base_y - 0.12), color=color.red)
        self.amb_btn.on_click = lambda: self.sim.spawn_vehicle(0, 99)
        
        # Timers on poles
        self.pole_timers = {}
        
    def add_pole_timer(self, lane, pole_root):
        # Attach 3D text safely to the scaled-1 root entity.
        t = Text(parent=pole_root, text="00", font='VeraMono.ttf', 
                 scale=(12, 12, 12), position=(0, 7.0, 6.8), color=color.white, origin=(0, 0.5))
        self.pole_timers[lane] = t
        
    def toggle_mode(self):
        if self.mode == "PDWP":
            self.mode = "FIXED"
            self.mode_btn.text = "Mode: FIXED"
            self.mode_btn.color = color.orange
            self.title_text.text = "FIXED TIMER"
            self.title_text.color = color.orange
        else:
            self.mode = "PDWP"
            self.mode_btn.text = "Mode: PDWP"
            self.mode_btn.color = color.black66
            self.title_text.text = "PDWP ADAPTIVE"
            self.title_text.color = color.cyan
            
        if self.on_mode_change_callback:
            self.on_mode_change_callback(self.mode)
            
    def update_ui(self, hour, profile_label, lane_densities):
        h = int(hour) % 24
        m = int((hour % 1) * 60)
        self.time_text.text = f"Time: {h:02d}:{m:02d}"
        self.profile_text.text = f"Profile: {profile_label}"
        
        for i in range(4):
            state = "[GREEN] " if self.sim.lights[i] == 'G' else ("[YELLOW]" if self.sim.lights[i] in ['Y', 'YELLOW_CLOSE'] else "[RED]   ")
            count = self.sim.get_lane_count(i)
            density = lane_densities.get(i, 0.0)
            self.stats_texts[i].text = f"Lane {i} {state} | C: {count} | PCU: {density:.1f}"
            
        total_count = self.sim.total_completed_vehicles
        avg_w = self.sim.total_wait_time_sum / total_count if total_count > 0 else 0
        self.total_wait_text.text = f"Throughput: {total_count} | Avg Wait: {avg_w:.1f}s"
        
        # Update pole timers
        for lane, t in self.pole_timers.items():
            val = self._get_lane_timer(lane)
            val = int(val) if val >= 0 else 0
            t.text = f"{val:02d}"
            state = self.sim.lights[lane]
            t.color = color.green if state == 'G' else (color.yellow if state == 'Y' else color.red)
            
    def _get_lane_timer(self, lane):
        # Helper to get the time from controller visually
        # Copied from original Pygame logically
        if lane == self.ctrl.phase and self.ctrl.state == 'GREEN':
            return self.ctrl.time_remaining()
        elif self.ctrl.state == 'YELLOW_CLOSE' and lane == self.ctrl.phase:
            from controller import YELLOW_CLOSE
            return max(0, YELLOW_CLOSE - self.ctrl.elapsed())
        elif self.ctrl.state == 'CLEARANCE' and self.ctrl.next_phase == lane:
            from controller import CLEARANCE
            return max(0, CLEARANCE - self.ctrl.elapsed())
        else:
            eta = self.ctrl.get_lane_eta()
            e = eta.get(lane, -1)
            return e if e > 0 else -1
