from ursina import *
import random

from controller import FixedController, PredictiveAdaptiveController, get_profile
from ui3d import SimulationUI
from vehicles3d import TYPE_AUTO, TYPE_BIKE, TYPE_BUS, TYPE_CAR, TYPE_VIP, Vehicle3D

ROAD_WIDTH = 24
ROAD_LENGTH = 220
STOP_DIST = 16
SPAWN_DIST = 92
WORLD_LIMIT = 110

app = Ursina(title="TNI26165 Adaptive Traffic 3D", borderless=False, exit_button=False)
window.color = color.rgb(22, 28, 36)
scene.fog_density = 0.0
scene.fog_color = window.color


class Intersection3D:
    def __init__(self):
        self.vehicles = {i: [] for i in range(4)}
        self.lights = {i: "R" for i in range(4)}
        self.sim_time = 0.0

        self.spawn_rates_per_lane = {i: 6 for i in range(4)}
        self.total_completed_vehicles = 0
        self.total_wait_time_sum = 0.0

    def spawn_vehicle(self, lane=None, vtype=TYPE_CAR):
        lane = random.randint(0, 3) if lane is None else lane
        sub_lane = random.randint(0, 1)
        self.vehicles[lane].append(
            Vehicle3D(lane, vtype, sub_lane, road_width=ROAD_WIDTH, stop_dist=STOP_DIST, spawn_dist=SPAWN_DIST)
        )

    def get_lane_count(self, lane):
        return sum(1 for v in self.vehicles[lane] if not v.has_crossed)

    def get_detections(self):
        class_map = {TYPE_BIKE: 1, TYPE_CAR: 2, TYPE_AUTO: 3, TYPE_BUS: 5, 99: 99, TYPE_VIP: 88}
        dets = []
        for lane in range(4):
            for v in self.vehicles[lane]:
                if v.has_crossed:
                    continue
                dets.append({"class": class_map.get(v.vtype, 2), "conf": 0.95, "box": [0, 0, 10, 10], "lane": lane})
        return dets

    def _sort_key(self, lane):
        if lane == 0:
            return lambda v: v.z
        if lane == 1:
            return lambda v: v.x
        if lane == 2:
            return lambda v: -v.z
        return lambda v: -v.x

    def _is_out(self, v):
        return abs(v.x) > WORLD_LIMIT or abs(v.z) > WORLD_LIMIT

    def update_sim(self, dt):
        self.sim_time += dt

        for lane in range(4):
            self.vehicles[lane].sort(key=self._sort_key(lane))

            for i, v in enumerate(self.vehicles[lane]):
                lead = None
                for j in range(i - 1, -1, -1):
                    if self.vehicles[lane][j].sub_lane == v.sub_lane:
                        lead = self.vehicles[lane][j]
                        break
                v.update_vehicle(self.lights[lane], lead, dt, self.sim_time)

            done = [v for v in self.vehicles[lane] if self._is_out(v)]
            for v in done:
                self.total_completed_vehicles += 1
                self.total_wait_time_sum += v.total_wait_time
                self.vehicles[lane].remove(v)
                destroy(v)


inter = Intersection3D()
ctrl = PredictiveAdaptiveController(inter)
day_clock = 8.0 * 60.0

signal_lights = {i: None for i in range(4)}
camera_mode = "ISO"


def create_signal_pole(x, z, rot_y, lane):
    root = Entity(position=(x, 0, z), rotation_y=rot_y)
    Entity(parent=root, model="cube", scale=(0.8, 13, 0.8), y=6.5, color=color.rgb(30, 30, 30))
    Entity(parent=root, model="cube", scale=(0.6, 0.6, 8), y=12.3, z=3.8, color=color.rgb(30, 30, 30))
    head = Entity(parent=root, model="cube", scale=(2.0, 5.7, 1.9), y=10.5, z=7.2, color=color.rgb(12, 12, 12))

    r = Entity(parent=head, model="sphere", scale=(0.66, 0.23, 0.66), y=0.36, z=-0.55, color=color.black)
    y = Entity(parent=head, model="sphere", scale=(0.66, 0.23, 0.66), y=0.0, z=-0.55, color=color.black)
    g = Entity(parent=head, model="sphere", scale=(0.66, 0.23, 0.66), y=-0.36, z=-0.55, color=color.black)

    signal_lights[lane] = {"R": r, "Y": y, "G": g, "pole": root}


def create_environment():
    Sky(color=color.rgb(22, 28, 36))

    Entity(model="plane", scale=(320, 1, 320), color=color.rgb(30, 92, 42))
    Entity(model="cube", scale=(ROAD_WIDTH, 0.12, ROAD_LENGTH), y=0.06, color=color.rgb(50, 54, 62))
    Entity(model="cube", scale=(ROAD_LENGTH, 0.12, ROAD_WIDTH), y=0.07, color=color.rgb(50, 54, 62))

    curb = color.rgb(145, 145, 145)
    for edge in (-ROAD_WIDTH * 0.5, ROAD_WIDTH * 0.5):
        Entity(model="cube", scale=(0.36, 0.25, ROAD_LENGTH), position=(edge, 0.13, 0), color=curb)
        Entity(model="cube", scale=(ROAD_LENGTH, 0.25, 0.36), position=(0, 0.13, edge), color=curb)

    dash = color.rgba(250, 250, 250, 190)
    for z in range(20, 104, 7):
        for x in (-6, 6):
            Entity(model="cube", scale=(0.22, 0.05, 3.5), position=(x, 0.1, z), color=dash)
            Entity(model="cube", scale=(0.22, 0.05, 3.5), position=(x, 0.1, -z), color=dash)
    for x in range(20, 104, 7):
        for z in (-6, 6):
            Entity(model="cube", scale=(3.5, 0.05, 0.22), position=(x, 0.1, z), color=dash)
            Entity(model="cube", scale=(3.5, 0.05, 0.22), position=(-x, 0.1, z), color=dash)

    zebra_w = 5
    zebra_off = ROAD_WIDTH * 0.5 + zebra_w * 0.5 + 1
    for i in range(-10, 11, 2):
        Entity(model="cube", scale=(1.2, 0.05, zebra_w), position=(i, 0.11, zebra_off), color=color.white)
        Entity(model="cube", scale=(1.2, 0.05, zebra_w), position=(i, 0.11, -zebra_off), color=color.white)
        Entity(model="cube", scale=(zebra_w, 0.05, 1.2), position=(zebra_off, 0.11, i), color=color.white)
        Entity(model="cube", scale=(zebra_w, 0.05, 1.2), position=(-zebra_off, 0.11, i), color=color.white)

    Entity(model="cube", scale=(ROAD_WIDTH * 0.5, 0.05, 0.5), position=(-ROAD_WIDTH * 0.25, 0.12, STOP_DIST), color=color.white)
    Entity(model="cube", scale=(ROAD_WIDTH * 0.5, 0.05, 0.5), position=(ROAD_WIDTH * 0.25, 0.12, -STOP_DIST), color=color.white)
    Entity(model="cube", scale=(0.5, 0.05, ROAD_WIDTH * 0.5), position=(STOP_DIST, 0.12, -ROAD_WIDTH * 0.25), color=color.white)
    Entity(model="cube", scale=(0.5, 0.05, ROAD_WIDTH * 0.5), position=(-STOP_DIST, 0.12, ROAD_WIDTH * 0.25), color=color.white)

    pole_off = ROAD_WIDTH * 0.5 + 5
    create_signal_pole(-pole_off, STOP_DIST + 1.5, 180, 0)
    create_signal_pole(STOP_DIST + 1.5, pole_off, 90, 3)
    create_signal_pole(pole_off, -STOP_DIST - 1.5, 0, 2)
    create_signal_pole(-STOP_DIST - 1.5, -pole_off, -90, 1)


def update_signal_visuals():
    for lane in range(4):
        state = inter.lights[lane]
        lamps = signal_lights[lane]
        lamps["R"].color = color.rgb(255, 45, 45) if state == "R" else color.rgb(20, 20, 20)
        lamps["Y"].color = color.rgb(255, 200, 0) if state == "Y" else color.rgb(20, 20, 20)
        lamps["G"].color = color.rgb(45, 255, 45) if state == "G" else color.rgb(20, 20, 20)


def set_camera_mode(mode):
    global camera_mode
    camera_mode = mode

    if mode == "ISO":
        camera.orthographic = False
        camera.position = Vec3(0, 68, -94)
        camera.look_at(Vec3(0, 0, 0))
    elif mode == "TOP":
        camera.orthographic = True
        camera.position = Vec3(0, 140, 0)
        camera.rotation = Vec3(90, 0, 0)
        camera.fov = 80
    elif mode == "FREE":
        camera.orthographic = False
    elif mode == "FOLLOW":
        camera.orthographic = False


def update_free_camera(dt):
    move = 52 * dt
    if held_keys["w"]:
        camera.position += camera.forward * move
    if held_keys["s"]:
        camera.position -= camera.forward * move
    if held_keys["a"]:
        camera.position -= camera.right * move
    if held_keys["d"]:
        camera.position += camera.right * move
    if held_keys["e"]:
        camera.position += camera.up * move
    if held_keys["q"]:
        camera.position -= camera.up * move

    if held_keys["left mouse"]:
        camera.rotation_y += mouse.velocity[0] * 125
        camera.rotation_x -= mouse.velocity[1] * 125

    camera.x = max(-160, min(160, camera.x))
    camera.y = max(3, min(200, camera.y))
    camera.z = max(-160, min(160, camera.z))


def update_follow_camera(dt):
    target = None
    for lane in range(4):
        if inter.vehicles[lane]:
            target = inter.vehicles[lane][0]
            break

    if target is None:
        camera.position = lerp(camera.position, Vec3(0, 28, -46), dt * 2)
        camera.look_at(Vec3(0, 0, 0))
        return

    cam_pos = target.position - target.forward * 11 + Vec3(0, 4, 0)
    camera.position = lerp(camera.position, cam_pos, dt * 6)
    camera.rotation_y = lerp(camera.rotation_y, target.rotation_y, dt * 6)
    camera.rotation_x = lerp(camera.rotation_x, 10, dt * 6)


create_environment()
AmbientLight(color=color.rgba(115, 118, 124, 255))
DirectionalLight(rotation=(55, -28, 0), shadows=False, color=color.rgba(255, 242, 220, 255))

sim_ui = SimulationUI(ctrl, inter)


def on_mode_change(mode):
    global ctrl
    if mode == "FIXED":
        ctrl = FixedController(inter)
    else:
        ctrl = PredictiveAdaptiveController(inter)

    ctrl.sim_hour = day_clock / 60.0
    sim_ui.ctrl = ctrl


sim_ui.on_mode_change_callback = on_mode_change
for lane in range(4):
    sim_ui.add_pole_timer(lane, signal_lights[lane]["pole"])

window.fps_counter.enabled = True
window.fps_counter.color = color.cyan
set_camera_mode("ISO")


def update():
    global day_clock

    if held_keys["1"] and camera_mode != "ISO":
        set_camera_mode("ISO")
    if held_keys["2"] and camera_mode != "TOP":
        set_camera_mode("TOP")
    if held_keys["3"] and camera_mode != "FREE":
        set_camera_mode("FREE")
    if held_keys["4"] and camera_mode != "FOLLOW":
        set_camera_mode("FOLLOW")

    if camera_mode == "FREE":
        update_free_camera(time.dt)
    elif camera_mode == "FOLLOW":
        update_follow_camera(time.dt)

    day_clock += time.dt
    if day_clock >= 1440:
        day_clock -= 1440

    hour = day_clock / 60.0
    ctrl.sim_hour = hour

    rate_mult, _, profile_label = get_profile(int(hour))
    for lane in range(4):
        spawn_rate = inter.spawn_rates_per_lane[lane] * rate_mult
        if random.random() < (spawn_rate * time.dt * 0.045):
            pool = [TYPE_CAR, TYPE_CAR, TYPE_CAR, TYPE_BIKE, TYPE_BIKE, TYPE_AUTO, TYPE_BUS, TYPE_VIP]
            inter.spawn_vehicle(lane=lane, vtype=random.choice(pool))

    ctrl.update()
    inter.update_sim(time.dt)

    lane_scores = {}
    if hasattr(ctrl, "_get_lane_data"):
        lane_scores, _, _, _ = ctrl._get_lane_data()

    sim_ui.update_ui(hour, profile_label, lane_scores)
    update_signal_visuals()


if __name__ == "__main__":
    app.run()
