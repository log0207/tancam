from ursina import *
from ursina.shaders import lit_with_shadows_shader
import random
import math

TYPE_BIKE = 1
TYPE_CAR = 2
TYPE_AUTO = 3
TYPE_BUS = 5
TYPE_AMBULANCE = 99
TYPE_VIP = 88

# Maps to 0: North setup (moving -Z), 1: East setup (moving -X), 2: South setup (moving +Z), 3: West setup (moving +X)
LANE_DIRS = {
    0: (0, 0, -1),
    1: (-1, 0, 0),
    2: (0, 0, 1),
    3: (1, 0, 0)
}
# Rotations based on movement direction
LANE_ROTS = {
    0: 180,
    1: -90,
    2: 0,
    3: 90
}

class Vehicle3D(Entity):
    def __init__(self, lane_id, vtype, sub_lane, road_width=16, stop_dist=12, spawn_dist=50, **kwargs):
        super().__init__(**kwargs)
        self.lane_id = lane_id
        self.vtype = vtype
        self.sub_lane = sub_lane
        self.road_width = road_width
        self.stop_dist = stop_dist
        self.has_crossed = False
        self.waiting = False
        self.wait_start_time = 0
        self.total_wait_time = 0

        # Base speeds and lengths
        configs = {
            TYPE_BIKE:      {'scale': (0.8, 1.2, 2.0), 'base_col': color.gray, 'speed': 18, 'len': 2.0},
            TYPE_AUTO:      {'scale': (1.4, 1.6, 2.8), 'base_col': color.yellow, 'speed': 15, 'len': 2.8},
            TYPE_CAR:       {'scale': (1.8, 1.2, 4.0), 'base_col': color.random_color(), 'speed': 18, 'len': 4.0},
            TYPE_BUS:       {'scale': (2.4, 2.5, 9.0), 'base_col': color.azure, 'speed': 12, 'len': 9.0},
            TYPE_AMBULANCE: {'scale': (1.8, 1.8, 5.0), 'base_col': color.white, 'speed': 22, 'len': 5.0},
            TYPE_VIP:       {'scale': (1.8, 1.2, 4.5), 'base_col': color.black, 'speed': 20, 'len': 4.5}
        }
        
        cfg = configs.get(self.vtype, configs[TYPE_CAR])
        self.speed = cfg['speed'] * random.uniform(0.9, 1.1)
        self.length = cfg['len']

        # Vehicle Appearance Setup
        self.collider = 'box'
        self.shader = lit_with_shadows_shader
        
        if self.vtype in [TYPE_CAR, TYPE_VIP, TYPE_AUTO]:
            self.model = 'model/car.obj'
            self.scale = 4.0 / 5.9 # Target length 4.0, real 5.9
            self.color = color.yellow if self.vtype == TYPE_AUTO else cfg['base_col']
            
        elif self.vtype == TYPE_BUS or self.vtype == TYPE_AMBULANCE:
            self.model = 'model/bus.obj'
            self.scale = 9.0 / 8.9 # Target length 9.0, real 8.9
            self.color = color.white if self.vtype == TYPE_AMBULANCE else cfg['base_col']
            
            if self.vtype == TYPE_AMBULANCE:
                # Add a red light bar on top of the bus model
                # Scaled relative to parent
                Entity(parent=self, model='cube', scale=(0.4/self.scale.x, 0.4/self.scale.y, 0.4/self.scale.z), 
                       y=1.5/self.scale.y, z=0.2, color=color.red, shader=lit_with_shadows_shader)
        
        elif self.vtype == TYPE_BIKE:
            self.model = 'model/bike.obj'
            self.scale = 2.0 / 1796.0 # Giantic native scale
            self.color = cfg['base_col']
            
        else:
            self.model = 'cube'
            self.scale = cfg['scale']
            self.color = cfg['base_col']
            
        self.shader = lit_with_shadows_shader
        
        # Position logic
        # For left-hand traffic, driving on the left side of the road.
        
        dir_vec = Vec3(*LANE_DIRS[self.lane_id])
        right_vec = Vec3(dir_vec.z, 0, -dir_vec.x) # Right perpendicular to forward direction
        
        sub_width = (road_width / 2) / 2
        offset_from_center = -(sub_width / 2) if sub_lane == 0 else -(sub_width * 1.5)

        # Apply start position based on direction
        spawn_pos = (dir_vec * -spawn_dist) + (right_vec * offset_from_center)
        spawn_pos.y = self.scale.y / 2
        
        self.position = spawn_pos
        self.rotation_y = LANE_ROTS[self.lane_id]
        
    def update_vehicle(self, current_light, lead_vehicle, dt, sim_time):
        should_stop = False
        
        # Distance to stop line
        dir_vec = Vec3(*LANE_DIRS[self.lane_id])
        # stop_dist is the global coordinate boundary for this lane
        # e.g., if lane 0 (moving -Z), stop line is at Z = stop_dist (since it approaches from +Z)
        
        dist_to_stop = 0
        if self.lane_id == 0: dist_to_stop = self.z - self.stop_dist
        elif self.lane_id == 1: dist_to_stop = self.x - self.stop_dist
        elif self.lane_id == 2: dist_to_stop = -self.stop_dist - self.z
        elif self.lane_id == 3: dist_to_stop = -self.stop_dist - self.x

        if not self.has_crossed:
            # Check light if close to stop line
            # Distance 0 means exactly on the line
            if 0 < dist_to_stop < 15:
                if current_light != 'G':
                    should_stop = True

        # Check lead vehicle gap
        if lead_vehicle:
            # Simple distance check based on position along the primary movement axis
            gap = 999
            if self.lane_id == 0: gap = self.z - lead_vehicle.z
            elif self.lane_id == 1: gap = self.x - lead_vehicle.x
            elif self.lane_id == 2: gap = lead_vehicle.z - self.z
            elif self.lane_id == 3: gap = lead_vehicle.x - self.x
            
            # Gap considers vehicle lengths (approximate center-to-center distance needed)
            safe_gap = (self.length/2) + (lead_vehicle.length/2) + 2.0 
            if gap < safe_gap:
                should_stop = True

        if should_stop:
            if not self.waiting:
                self.waiting = True
                self.wait_start_time = sim_time
        else:
            if self.waiting:
                self.waiting = False
                self.total_wait_time += (sim_time - self.wait_start_time)
            # Move forward
            self.position += dir_vec * self.speed * dt

            # Check if crossed
            if not self.has_crossed and dist_to_stop < 0:
                self.has_crossed = True
