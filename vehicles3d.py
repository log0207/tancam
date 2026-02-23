from ursina import *
import random

TYPE_BIKE = 1
TYPE_CAR = 2
TYPE_AUTO = 3
TYPE_BUS = 5
TYPE_AMBULANCE = 99
TYPE_VIP = 88

LANE_DIRS = {
    0: Vec3(0, 0, -1),
    1: Vec3(-1, 0, 0),
    2: Vec3(0, 0, 1),
    3: Vec3(1, 0, 0),
}

LANE_ROTS = {0: 180, 1: -90, 2: 0, 3: 90}


class Vehicle3D(Entity):
    def __init__(self, lane_id, vtype, sub_lane, road_width=24, stop_dist=16, spawn_dist=88, **kwargs):
        super().__init__(**kwargs)
        self.lane_id = lane_id
        self.vtype = vtype
        self.sub_lane = sub_lane
        self.road_width = road_width
        self.stop_dist = stop_dist

        self.has_crossed = False
        self.waiting = False
        self.wait_start_time = 0.0
        self.total_wait_time = 0.0

        cfg = {
            TYPE_BIKE: {"size": Vec3(1.0, 0.7, 2.0), "speed": 17.0, "length": 2.0, "color": color.gray},
            TYPE_AUTO: {"size": Vec3(1.3, 1.0, 2.8), "speed": 14.0, "length": 2.8, "color": color.yellow},
            TYPE_CAR: {"size": Vec3(1.6, 1.0, 4.0), "speed": 15.0, "length": 4.0, "color": color.rgb(70, 140, 220)},
            TYPE_BUS: {"size": Vec3(2.2, 1.6, 8.4), "speed": 10.5, "length": 8.4, "color": color.orange},
            TYPE_AMBULANCE: {"size": Vec3(1.7, 1.1, 4.5), "speed": 18.0, "length": 4.5, "color": color.white},
            TYPE_VIP: {"size": Vec3(1.6, 1.0, 4.1), "speed": 16.0, "length": 4.1, "color": color.rgb(20, 20, 20)},
        }[vtype]

        self.speed = cfg["speed"] * random.uniform(0.92, 1.08)
        self.length = cfg["length"]

        self.model = "cube"
        self.scale = cfg["size"]
        self.color = cfg["color"]
        self.collider = "box"

        roof_color = color.rgb(45, 55, 70)
        if vtype == TYPE_AMBULANCE:
            roof_color = color.rgb(210, 210, 230)

        Entity(
            parent=self,
            model="cube",
            scale=(0.7 / self.scale.x, 0.28 / self.scale.y, 0.48 / self.scale.z),
            y=(0.33 / self.scale.y),
            color=roof_color,
        )

        if vtype == TYPE_AMBULANCE:
            Entity(
                parent=self,
                model="cube",
                scale=(0.34 / self.scale.x, 0.18 / self.scale.y, 0.95 / self.scale.z),
                y=(0.56 / self.scale.y),
                color=color.red,
            )

        self._place_at_spawn(spawn_dist)
        self.rotation_y = LANE_ROTS[self.lane_id]

    def _place_at_spawn(self, spawn_dist):
        forward = LANE_DIRS[self.lane_id]
        right = Vec3(forward.z, 0, -forward.x)

        half_side = self.road_width * 0.5
        lane_width = half_side * 0.5
        lateral = -(lane_width * 0.6) if self.sub_lane == 0 else -(lane_width * 1.4)

        spawn = (-forward * spawn_dist) + (right * lateral)
        spawn.y = self.scale.y * 0.5
        self.position = spawn

    def _dist_to_stop(self):
        if self.lane_id == 0:
            return self.z - self.stop_dist
        if self.lane_id == 1:
            return self.x - self.stop_dist
        if self.lane_id == 2:
            return -self.stop_dist - self.z
        return -self.stop_dist - self.x

    def _gap_to_lead(self, lead):
        if self.lane_id == 0:
            return self.z - lead.z
        if self.lane_id == 1:
            return self.x - lead.x
        if self.lane_id == 2:
            return lead.z - self.z
        return lead.x - self.x

    def update_vehicle(self, current_light, lead_vehicle, dt, sim_time):
        should_stop = False
        dist_to_stop = self._dist_to_stop()

        if not self.has_crossed and 0 < dist_to_stop < 18 and current_light != "G":
            should_stop = True

        if lead_vehicle is not None:
            gap = self._gap_to_lead(lead_vehicle)
            safe_gap = (self.length * 0.5) + (lead_vehicle.length * 0.5) + 2.2
            if gap < safe_gap:
                should_stop = True

        if should_stop:
            if not self.waiting:
                self.waiting = True
                self.wait_start_time = sim_time
            return

        if self.waiting:
            self.waiting = False
            self.total_wait_time += (sim_time - self.wait_start_time)

        self.position += LANE_DIRS[self.lane_id] * self.speed * dt
        if not self.has_crossed and dist_to_stop < 0:
            self.has_crossed = True
