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
        # Updated for compressed models
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
        
        # Models paths
        MODEL_CAR = 'models_compressed/uploads_files_2787791_Mercedes+Benz+GLS+580_clean.bam'
        MODEL_BUS = 'models_compressed/uploads_files_2263056_bus_byjoao3DModels_clean.bam'
        MODEL_BIKE = 'models_compressed/Kawasaki Ninja ZX-6R Sport Bike_clean.bam'

        if self.vtype in [TYPE_CAR, TYPE_VIP, TYPE_AUTO]:
            self.model = MODEL_CAR
            # Bounds analysis: Size ~5.9m long. Target ~4m. Scale ~0.68
            # The model might need rotation correction if it faces wrong way.
            # Assuming standard Z-forward or Y-forward. Ursina is Z-forward.
            # Most external models are Y-forward or -Y.
            # We will apply a base rotation fix if needed in future steps, but for now assuming direct mapping.
            # Scaling: 4.0 target / 5.92 real = 0.675
            scale_factor = 0.68
            self.scale = scale_factor
            
            if self.vtype == TYPE_AUTO:
                self.color = color.yellow
                self.scale = scale_factor * 0.7 # Autos are smaller
            else:
                self.color = color.white if self.vtype == TYPE_VIP else cfg['base_col']
                if self.vtype == TYPE_VIP: self.color = color.black
            
        elif self.vtype == TYPE_BUS or self.vtype == TYPE_AMBULANCE:
            if self.vtype == TYPE_AMBULANCE:
                self.model = MODEL_CAR # Use Car model for ambulance for better look than Bus
                self.scale = 0.8 # Slightly larger than car
                self.color = color.white
                # Add red cross or lights
                Entity(parent=self, model='cube', scale=(0.6, 0.2, 0.2), y=2.5, color=color.red, shader=lit_with_shadows_shader)
            else:
                self.model = MODEL_BUS
                # Bounds analysis: Size ~9m. Target ~9m. Scale ~1.0
                self.scale = 1.0
                self.color = cfg['base_col']
        
        elif self.vtype == TYPE_BIKE:
            self.model = MODEL_BIKE
            # Bounds analysis: Size ~1796m. Target ~2m. Scale ~0.0011
            self.scale = 0.0011
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
        spawn_pos.y = 0.5 # Lift slightly above ground
        if self.model == MODEL_BIKE: spawn_pos.y = 0 # Bike pivot might be at bottom
        
        self.position = spawn_pos
        self.rotation_y = LANE_ROTS[self.lane_id]
        
        # Adjust specific model rotations if they are imported sideways
        # Common fix for BAM models if they face +Y or -Y instead of +Z
        if self.model in [MODEL_CAR, MODEL_BUS, MODEL_BIKE]:
             # Often external models need 180 or 90 fix.
             # Let's assume they are standard and see.
             # If they drive sideways, we add rotation here.
             pass

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
