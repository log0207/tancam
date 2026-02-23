from ursina import *
from ursina.shaders import lit_with_shadows_shader
from vehicles3d import Vehicle3D, TYPE_CAR, TYPE_BIKE, TYPE_AUTO, TYPE_BUS, TYPE_AMBULANCE, TYPE_VIP
from controller import PredictiveAdaptiveController, FixedController, get_profile
from ui3d import SimulationUI
import random

app = Ursina(title='TNI26165 - Adaptive Traffic 3D', borderless=False, exit_button=False)

# Camera setup
window.color = color.rgb(135, 206, 235)  # Sky blue
camera.position = (0, 45, -55)
camera.rotation_x = 45

class Intersection3D:
    def __init__(self):
        self.vehicles = {i: [] for i in range(4)}
        self.lights = {i: 'R' for i in range(4)}
        self.total_completed_vehicles = 0
        self.total_wait_time_sum = 0.0
        self.sim_time = 0.0
        self.spawn_rates_per_lane = {i: 6 for i in range(4)}
        
    def spawn_vehicle(self, lane=None, vtype=TYPE_CAR):
        if lane is None: lane = random.randint(0, 3)
        sub_lane = random.choice([0, 1])
        nv = Vehicle3D(lane, vtype, sub_lane, road_width=16, stop_dist=12, spawn_dist=50)
        self.vehicles[lane].append(nv)
        
    def get_detections(self):
        d = []
        for lane in range(4):
            for v in self.vehicles[lane]:
                if not v.has_crossed:
                    d.append({'class': self.vtype_to_detector_class(v.vtype), 
                              'conf': 0.95, 'box': [0,0,10,10], 'lane': lane})
        return d
        
    def vtype_to_detector_class(self, vtype):
        cmap = {TYPE_BIKE: 1, TYPE_AUTO: 3, TYPE_CAR: 2, TYPE_BUS: 5, TYPE_AMBULANCE: 99, TYPE_VIP: 88}
        return cmap.get(vtype, 2)
        
    def get_lane_count(self, lane):
        return len([v for v in self.vehicles[lane] if not v.has_crossed])

    def update_sim(self, dt):
        self.sim_time += dt
        
        for lane in range(4):
            self.vehicles[lane].sort(key=self.get_sort_key(lane))
            
            for i, v in enumerate(self.vehicles[lane]):
                lead = None
                for j in range(i-1, -1, -1):
                    if self.vehicles[lane][j].sub_lane == v.sub_lane:
                        lead = self.vehicles[lane][j]
                        break
                
                v.update_vehicle(self.lights[lane], lead, dt, self.sim_time)
                
            to_remove = []
            for v in self.vehicles[lane]:
                if self.is_out_of_bounds(v):
                    to_remove.append(v)
            for v in to_remove:
                self.total_completed_vehicles += 1
                self.total_wait_time_sum += v.total_wait_time
                self.vehicles[lane].remove(v)
                destroy(v)
                
    def get_sort_key(self, lane):
        if lane == 0: return lambda v: v.z
        if lane == 1: return lambda v: v.x
        if lane == 2: return lambda v: -v.z
        if lane == 3: return lambda v: -v.x
        return lambda v: 0
        
    def is_out_of_bounds(self, v):
        limit = 60
        return v.x > limit or v.x < -limit or v.z > limit or v.z < -limit

inter = Intersection3D()
ctrl = PredictiveAdaptiveController(inter)
day_clock = 8.0 * 60

signal_lights = {0:None, 1:None, 2:None, 3:None}

def create_static_environment():
    ground = Entity(model='plane', scale=(200, 1, 200), color=color.hex('#304D30'), collider='box', shader=lit_with_shadows_shader)
    road_width = 16
    lane_width = road_width / 2

    Entity(model='cube', scale=(road_width, 0.1, 200), color=color.hex('#2E2E33'), y=0.01, shader=lit_with_shadows_shader)
    Entity(model='cube', scale=(200, 0.1, road_width), color=color.hex('#2E2E33'), y=0.02, shader=lit_with_shadows_shader)
    center = Entity(model='cube', scale=(road_width, 0.1, road_width), color=color.hex('#2E2E33'), y=0.03, shader=lit_with_shadows_shader)

    marking_color = color.white
    Entity(model='cube', scale=(0.2, 0.1, 100 - road_width/2), color=marking_color, position=(-0.3, 0.04, road_width/2 + (100 - road_width/2)/2), shader=lit_with_shadows_shader)
    Entity(model='cube', scale=(0.2, 0.1, 100 - road_width/2), color=marking_color, position=(0.3, 0.04, road_width/2 + (100 - road_width/2)/2), shader=lit_with_shadows_shader)
    Entity(model='cube', scale=(0.2, 0.1, 100 - road_width/2), color=marking_color, position=(-0.3, 0.04, -road_width/2 - (100 - road_width/2)/2), shader=lit_with_shadows_shader)
    Entity(model='cube', scale=(0.2, 0.1, 100 - road_width/2), color=marking_color, position=(0.3, 0.04, -road_width/2 - (100 - road_width/2)/2), shader=lit_with_shadows_shader)
    
    Entity(model='cube', scale=(100 - road_width/2, 0.1, 0.2), color=marking_color, position=(road_width/2 + (100 - road_width/2)/2, 0.04, -0.3))
    Entity(model='cube', scale=(100 - road_width/2, 0.1, 0.2), color=marking_color, position=(road_width/2 + (100 - road_width/2)/2, 0.04, 0.3))
    Entity(model='cube', scale=(100 - road_width/2, 0.1, 0.2), color=marking_color, position=(-road_width/2 - (100 - road_width/2)/2, 0.04, -0.3))
    Entity(model='cube', scale=(100 - road_width/2, 0.1, 0.2), color=marking_color, position=(-road_width/2 - (100 - road_width/2)/2, 0.04, 0.3))

    for z in range(int(road_width/2) + 2, 100, 4):
        Entity(model='cube', scale=(0.1, 0.1, 2), color=color.gray, position=(-road_width/4, 0.04, z))
        Entity(model='cube', scale=(0.1, 0.1, 2), color=color.gray, position=(road_width/4, 0.04, z))
        Entity(model='cube', scale=(0.1, 0.1, 2), color=color.gray, position=(-road_width/4, 0.04, -z))
        Entity(model='cube', scale=(0.1, 0.1, 2), color=color.gray, position=(road_width/4, 0.04, -z))

    for x in range(int(road_width/2) + 2, 100, 4):
        Entity(model='cube', scale=(2, 0.1, 0.1), color=color.gray, position=(x, 0.04, -road_width/4))
        Entity(model='cube', scale=(2, 0.1, 0.1), color=color.gray, position=(x, 0.04, road_width/4))
        Entity(model='cube', scale=(2, 0.1, 0.1), color=color.gray, position=(-x, 0.04, -road_width/4))
        Entity(model='cube', scale=(2, 0.1, 0.1), color=color.gray, position=(-x, 0.04, road_width/4))

    zebra_width = 4
    zebra_offset = road_width/2 + zebra_width/2 + 1
    
    for i in range(-7, 8, 2):
        Entity(model='cube', scale=(1, 0.1, zebra_width), color=color.white, position=(i, 0.05, zebra_offset))
        Entity(model='cube', scale=(1, 0.1, zebra_width), color=color.white, position=(i, 0.05, -zebra_offset))
        Entity(model='cube', scale=(zebra_width, 0.1, 1), color=color.white, position=(zebra_offset, 0.05, i))
        Entity(model='cube', scale=(zebra_width, 0.1, 1), color=color.white, position=(-zebra_offset, 0.05, i))

    stop_dist = zebra_offset + zebra_width/2 + 0.5
    Entity(model='cube', scale=(road_width/2, 0.1, 0.5), color=color.white, position=(-road_width/4, 0.05, stop_dist))
    Entity(model='cube', scale=(road_width/2, 0.1, 0.5), color=color.white, position=(road_width/4, 0.05, -stop_dist))
    Entity(model='cube', scale=(0.5, 0.1, road_width/2), color=color.white, position=(stop_dist, 0.05, -road_width/4))
    Entity(model='cube', scale=(0.5, 0.1, road_width/2), color=color.white, position=(-stop_dist, 0.05, road_width/4))

    pole_offset = road_width/2 + 3
    create_signal_pole((-pole_offset, stop_dist+1), rotation_y=180, lane=0)
    create_signal_pole((stop_dist+1, pole_offset), rotation_y=90, lane=3)
    create_signal_pole((pole_offset, -stop_dist-1), rotation_y=0, lane=2)
    create_signal_pole((-stop_dist-1, -pole_offset), rotation_y=-90, lane=1)


def create_signal_pole(pos, rotation_y=0, lane=0):
    pole = Entity(position=(pos[0], 0, pos[1]), rotation_y=rotation_y)
    
    # Vertical Pole
    Entity(parent=pole, model='cube', scale=(0.5, 12, 0.5), color=color.hex('#303030'), y=6.0, shader=lit_with_shadows_shader)
    # Horizontal boom extending forward (+z in local space)
    Entity(parent=pole, model='cube', scale=(0.4, 0.4, 8), color=color.hex('#303030'), position=(0, 11.5, 4), shader=lit_with_shadows_shader)
    
    # Signal Head Box hanging from boom
    box = Entity(parent=pole, model='cube', scale=(1.2, 4, 1.2), color=color.hex('#1A1A1A'), position=(0, 9.5, 7.5), shader=lit_with_shadows_shader)
    
    # Detailed lights structure (Red, Yellow, Green) inside the box
    c_red = Entity(parent=box, model='sphere', scale=(0.6, 0.6*1.2/4, 0.6), y=0.3, z=-0.5, color=color.black)
    c_yel = Entity(parent=box, model='sphere', scale=(0.6, 0.6*1.2/4, 0.6), y=0.0, z=-0.5, color=color.black)
    c_grn = Entity(parent=box, model='sphere', scale=(0.6, 0.6*1.2/4, 0.6), y=-0.3, z=-0.5, color=color.black)
    
    # Blinders/Sun hoods out of cubes
    Entity(parent=box, model='cube', scale=(0.8, 0.1, 0.8), y=0.45, z=-0.6, color=color.black)
    Entity(parent=box, model='cube', scale=(0.8, 0.1, 0.8), y=0.15, z=-0.6, color=color.black)
    Entity(parent=box, model='cube', scale=(0.8, 0.1, 0.8), y=-0.15, z=-0.6, color=color.black)

    # Store references
    signal_lights[lane] = {'R': c_red, 'Y': c_yel, 'G': c_grn, 'box': box, 'pole': pole}


create_static_environment()

sim_ui = SimulationUI(ctrl, inter)

def on_mode_change(new_mode):
    global ctrl, day_clock
    if new_mode == "FIXED":
        ctrl = FixedController(inter)
    else:
        ctrl = PredictiveAdaptiveController(inter)
    ctrl.sim_hour = day_clock / 60.0
    sim_ui.ctrl = ctrl

sim_ui.on_mode_change_callback = on_mode_change

for l in range(4):
    sim_ui.add_pole_timer(l, signal_lights[l]['pole'])

AmbientLight(color=color.rgb(150, 150, 150))
DirectionalLight(y=10, z=5, shadows=True, rotation=(45, -45, 45))

window.fps_counter.enabled = True

camera_modes = ['FREE', 'ORTHO', 'ISO', 'DRIVER']
current_camera = 'ISO'

def update_camera_mode():
    if current_camera == 'ORTHO':
        camera.position = (0, 100, 0)
        camera.rotation = (90, 0, 0)
        camera.orthographic = True
        camera.fov = 80
    elif current_camera == 'ISO':
        camera.position = (0, 45, -55)
        camera.rotation = (45, 0, 0)
        camera.orthographic = False
    elif current_camera == 'DRIVER':
        # Front driver view looking into intersection from Lane 0
        camera.position = (-4, 2, -40) 
        camera.rotation = (0, 0, 0)
        camera.orthographic = False
    elif current_camera == 'FREE':
        camera.orthographic = False
        
update_camera_mode()

def update():
    global day_clock, ctrl, current_camera
    
    # Handle camera toggle
    if held_keys['1']: 
        current_camera = 'ISO'
        update_camera_mode()
    if held_keys['2']: 
        current_camera = 'ORTHO'
        update_camera_mode()
    if held_keys['3']: 
        current_camera = 'FREE'
        update_camera_mode()
    if held_keys['4']: 
        current_camera = 'DRIVER'
        update_camera_mode()
        
    if current_camera == 'FREE':
        move_speed = 50 * time.dt
        if held_keys['w'] or held_keys['up arrow']: camera.position += camera.forward * move_speed
        if held_keys['s'] or held_keys['down arrow']: camera.position -= camera.forward * move_speed
        if held_keys['a'] or held_keys['left arrow']: camera.position -= camera.right * move_speed
        if held_keys['d'] or held_keys['right arrow']: camera.position += camera.right * move_speed
        if held_keys['e']: camera.position += camera.up * move_speed
        if held_keys['q']: camera.position -= camera.up * move_speed
        
        # Simple intuitive mouse look when clicking
        if held_keys['left mouse'] or held_keys['right mouse']:
            camera.rotation_y += mouse.velocity[0] * 150
            camera.rotation_x -= mouse.velocity[1] * 150
            
        # Constrain Camera Bounds
        camera.x = max(-90, min(camera.x, 90))
        camera.y = max(2, min(camera.y, 90)) # Prevent clipping through ground
        camera.z = max(-90, min(camera.z, 90))
        
    day_clock += 1.0 * time.dt
    if day_clock >= 1440: day_clock -= 1440
    hour = day_clock / 60.0
    ctrl.sim_hour = hour
    
    rate_mult, _, profile_label = get_profile(int(hour))
    for lid in range(4):
        base_rate = inter.spawn_rates_per_lane[lid]
        effective_rate = base_rate * rate_mult
        if effective_rate > 0 and random.random() * 100 < (effective_rate * time.dt * 10):
            choices = [TYPE_CAR, TYPE_CAR, TYPE_CAR, TYPE_BIKE, TYPE_BIKE, TYPE_AUTO, TYPE_BUS]
            inter.spawn_vehicle(lane=lid, vtype=random.choice(choices))
            
    # Traffic Logic
    ctrl.update()
    inter.update_sim(time.dt)
    
    # Fetch densities
    scores = {}
    if hasattr(ctrl, '_get_lane_data'):
        lane_scores, _, _, _ = ctrl._get_lane_data()
        scores = lane_scores
        
    sim_ui.update_ui(hour, profile_label, scores)
    
    # Update visuals
    for lane in range(4):
        state = inter.lights[lane]
        sg = signal_lights[lane]
        sg['R'].color = color.red if state == 'R' else color.rgba(30,30,30,255)
        # Yellow includes 'Y' and 'YELLOW_CLOSE' logically but the dict from controller is 'Y'
        sg['Y'].color = color.yellow if state == 'Y' else color.rgba(30,30,30,255)
        sg['G'].color = color.green if state == 'G' else color.rgba(30,30,30,255)

if __name__ == '__main__':
    app.run()
