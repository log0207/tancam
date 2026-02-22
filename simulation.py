"""
TNI26165 — Smart Traffic Simulation (Pygame)
=============================================
Indian-style 4-way junction:
  - Left-hand traffic (vehicles drive on left side)
  - Multi-direction: straight, left turn, right turn
  - Countdown timer on each traffic signal
  - 24-hour day clock (1 real sec = 1 sim minute)
"""
import pygame
import random
import math
import sys

# ── Layout ────────────────────────────────────────────────────────────
TARGET_SIM_W = 680
TARGET_SIM_H = 520
SIDE_PANEL_W = 280
LOG_PANEL_H  = 175
ROAD_WIDTH   = 110
LANE_WIDTH   = ROAD_WIDTH // 2
FPS = 60

# Signal Dimensions
SIGNAL_W, SIGNAL_H = 62, 24
SIGNAL_R = 8

# ── Colors (Modern Palette) ───────────────────────────────────────────
BLACK        = (10, 10, 15)
WHITE        = (240, 245, 250)
DARK_BG      = (18, 20, 28)
ROAD_COLOR   = (45, 48, 55)
SIDEWALK     = (100, 105, 115)
GRASS_DAY    = (45, 70, 45)
GRASS_NIGHT  = (15, 25, 20)

# Traffic Lights
GREEN        = (0, 220, 100)
BRIGHT_GREEN = (50, 255, 140)
RED          = (230, 40, 60)
BRIGHT_RED   = (255, 80, 100)
YELLOW       = (255, 200, 40)
BRIGHT_YELLOW= (255, 230, 80)
ORANGE       = (255, 140, 0)
CYAN         = (0, 200, 200)
PURPLE       = (160, 50, 200)
DIM_COLOR    = (50, 50, 50)

# UI Elements
LOG_BG       = (16, 16, 26)
PANEL_BG     = (25, 30, 45)
PANEL_BORDER = (60, 70, 90)
TEXT_COLOR   = (220, 230, 240)
ACCENT_CYAN  = (0, 200, 220)
DIVIDER_WHITE = (200, 200, 210)
ZEBRA_WHITE  = (230, 230, 235)
LIGHT_GRAY   = (130, 130, 130)  # For minor labels
GRAY         = (80, 80, 80)

# ── Vehicle Types ─────────────────────────────────────────────────────
TYPE_BIKE      = 1;  TYPE_CAR = 2;  TYPE_AUTO = 3
TYPE_BUS       = 5;  TYPE_AMBULANCE = 99;  TYPE_VIP = 88

VEHICLE_SPEED = 1.8
VEHICLE_GAP   = 32
LANE_NAMES    = ["North", "East", "South", "West"]
TYPE_LABELS   = {TYPE_CAR:"Car", TYPE_BIKE:"Bike", TYPE_AUTO:"Auto",
                 TYPE_BUS:"Bus", TYPE_AMBULANCE:"Amb", TYPE_VIP:"VIP"}

# Turn directions
TURN_STRAIGHT = 0
TURN_LEFT     = 1
TURN_RIGHT    = 2

# ── Time-of-Day Vehicle Mix (South Indian) ────────────────────────────
VEHICLE_MIX = {
    (5,7):   (0.20, 0.30, 0.15, 0.30, 0.03, 0.02),
    (7,10):  (0.40, 0.25, 0.20, 0.10, 0.03, 0.02),
    (10,13): (0.30, 0.30, 0.25, 0.10, 0.03, 0.02),
    (13,16): (0.35, 0.25, 0.20, 0.15, 0.03, 0.02),
    (16,20): (0.40, 0.20, 0.25, 0.10, 0.03, 0.02),
    (20,22): (0.25, 0.30, 0.35, 0.05, 0.03, 0.02),
    (22,5):  (0.15, 0.25, 0.50, 0.05, 0.03, 0.02),
}

def get_mix(hour):
    for (a, b), mix in VEHICLE_MIX.items():
        if a <= b:
            if a <= hour < b: return mix
        else:
            if hour >= a or hour < b: return mix
    return (0.30, 0.25, 0.25, 0.15, 0.03, 0.02)

def pick_type(hour):
    mix = get_mix(hour)
    r = random.random()
    cum = 0
    types = [TYPE_BIKE, TYPE_AUTO, TYPE_CAR, TYPE_BUS, TYPE_AMBULANCE, TYPE_VIP]
    for i, p in enumerate(mix):
        cum += p
        if r < cum: return types[i]
    return TYPE_CAR


# ── Vehicle Drawing (Improved Indian Vehicles) ───────────────────────
def _car(s, c, w, h):
    """Sedan with windshield, headlights, taillights"""
    s.fill((0,0,0,0))
    # Main body
    pygame.draw.rect(s, c, (2, 3, w-4, h-6), border_radius=5)
    # Roof (darker)
    darker = (max(0,c[0]-40), max(0,c[1]-40), max(0,c[2]-40))
    pygame.draw.rect(s, darker, (4, int(h*0.25), w-8, int(h*0.3)), border_radius=3)
    # Windshields
    pygame.draw.rect(s, (160,200,240), (5, int(h*0.22), w-10, int(h*0.12)), border_radius=2)
    pygame.draw.rect(s, (140,180,220), (5, int(h*0.48), w-10, int(h*0.1)), border_radius=2)
    # Headlights
    pygame.draw.rect(s, (255,255,200), (3, 3, 4, 3))
    pygame.draw.rect(s, (255,255,200), (w-7, 3, 4, 3))
    # Taillights
    pygame.draw.rect(s, (255,30,30), (3, h-6, 4, 3))
    pygame.draw.rect(s, (255,30,30), (w-7, h-6, 4, 3))
    # Side mirrors
    for y in [int(h*0.25), int(h*0.25)]:
        pygame.draw.rect(s, c, (0, y, 2, 4))
        pygame.draw.rect(s, c, (w-2, y, 2, 4))

def _auto(s, c, w, h):
    """Auto-rickshaw — three-wheeler with canopy"""
    s.fill((0,0,0,0))
    pygame.draw.rect(s, c, (2, 4, w-4, h-8), border_radius=5)
    # Yellow top usually
    pygame.draw.rect(s, (255,220,100), (3, 2, w-6, int(h*0.4)), border_radius=4)
    pygame.draw.rect(s, (50,50,50), (4, int(h*0.2), w-8, int(h*0.15)), border_radius=2)
    # Wheels
    pygame.draw.circle(s, (20,20,20), (w//2, 4), 3)
    pygame.draw.circle(s, (20,20,20), (3, h-5), 3)
    pygame.draw.circle(s, (20,20,20), (w-3, h-5), 3)
    # Headlight
    pygame.draw.rect(s, (255,255,200), (w//2-2, 1, 4, 3))

def _bus(s, c, w, h):
    """Long bus with windows and route band"""
    s.fill((0,0,0,0))
    pygame.draw.rect(s, c, (2, 2, w-4, h-4), border_radius=4)
    # Roof
    pygame.draw.rect(s, (240,240,240), (4, 4, w-8, h-8), border_radius=2)
    # Stripe
    pygame.draw.rect(s, c, (2, int(h*0.4), w-4, int(h*0.2)))
    # Windows
    for i in range(5):
        wy = int(h*0.1) + i*int(h*0.16)
        pygame.draw.rect(s, (50,50,50), (3, wy, 2, int(h*0.1))) # Left windows
        pygame.draw.rect(s, (50,50,50), (w-5, wy, 2, int(h*0.1))) # Right windows
    # Lights
    pygame.draw.rect(s, (255,200,50), (3, 1, 4, 3))
    pygame.draw.rect(s, (255,200,50), (w-7, 1, 4, 3))

def _bike(s, c, w, h):
    """Two-wheeler with rider"""
    s.fill((0,0,0,0))
    cx = w // 2
    # Bike body
    pygame.draw.rect(s, c, (cx-2, 4, 4, h-8))
    # Handlebar
    pygame.draw.line(s, (200,200,200), (cx-5, 8), (cx+5, 8), 2)
    # Rider helmet
    pygame.draw.circle(s, (255,255,0), (cx, 12), 4)
    # Wheels
    pygame.draw.circle(s, (30,30,30), (cx, 4), 3)
    pygame.draw.circle(s, (30,30,30), (cx, h-4), 3)

def _amb(s, w, h):
    """Ambulance with siren"""
    s.fill((0,0,0,0))
    pygame.draw.rect(s, WHITE, (2, 2, w-4, h-4), border_radius=4)
    cx, cy = w//2, h//2
    # Cross
    pygame.draw.rect(s, RED, (cx-3, cy-8, 6, 16))
    pygame.draw.rect(s, RED, (cx-8, cy-3, 16, 6))
    # Lights bar
    pygame.draw.rect(s, (200,200,200), (4, 4, w-8, 4))
    pygame.draw.rect(s, (255,0,0), (6, 4, 4, 4))
    pygame.draw.rect(s, (0,0,255), (w-10, 4, 4, 4))

def _vip(s, w, h):
    """VIP black sedan"""
    s.fill((0,0,0,0))
    pygame.draw.rect(s, (10,10,10), (2, 2, w-4, h-4), border_radius=5)
    # Windows tint
    pygame.draw.rect(s, (20,20,30), (4, int(h*0.2), w-8, int(h*0.25)), border_radius=2)
    pygame.draw.rect(s, (20,20,30), (4, int(h*0.5), w-8, int(h*0.15)), border_radius=2)
    # Beacon
    pygame.draw.circle(s, (255,0,0), (w//2, 6), 3)
    # Flags?
    pygame.draw.rect(s, (255,150,0), (2, 2, 2, 4))


# ── Turn exit mapping ────────────────────────────────────────────────
# For each approach lane, where does each turn go?
# lane 0 (North approach, entering from bottom): straight=up, left=right, right=left
# lane 1 (East approach, entering from left):    straight=right, left=down, right=up
# lane 2 (South approach, entering from top):    straight=down, left=left, right=right
# lane 3 (West approach, entering from right):   straight=left, left=up, right=down
# In Indian LEFT-HAND traffic:
#   Left turn = easy/free turn, Right turn = cross traffic

# ── Turn exit mapping AND SUB-LANE Logic ─────────────────────────────
NUM_SUB_LANES = 2
SUB_LANE_WIDTH = LANE_WIDTH // NUM_SUB_LANES

def _pick_turn(sub_lane):
    """
    Lane logic:
    - Inner lane (sub_lane 0): Mostly Straight, some Right
    - Outer lane (sub_lane 1): Mostly Straight, some Left
    """
    r = random.random()
    if sub_lane == 0: # Inner
        if r < 0.85: return TURN_STRAIGHT
        return TURN_RIGHT # Inner lane turns RIGHT (cross traffic)
    else: # Outer
        if r < 0.85: return TURN_STRAIGHT
        return TURN_LEFT # Outer lane turns LEFT (easy turn)


class Vehicle(pygame.sprite.Sprite):
    def __init__(self, lane, x, y, direction, sim_time, vtype=TYPE_CAR, sub_lane=0):
        super().__init__()
        self.type = vtype
        self.lane_id = lane
        self.sub_lane = sub_lane
        self.direction = direction
        self.turn = _pick_turn(sub_lane)
        self.speed = VEHICLE_SPEED
        self.width = 18
        self.length = 30
        self.has_crossed = False  # Past stop line
        self.turn_progress = 0.0
        self.turning = False

        # Configs
        cfg = {
            TYPE_AMBULANCE: (1.3, 32, 20, 100, 99),
            TYPE_VIP:       (1.0, 34, 20,  50, 88),
            TYPE_BUS:       (0.8, 55, 24,   3,  5),
            TYPE_AUTO:      (1.1, 24, 16, 0.8,  3),
            TYPE_BIKE:      (1.3, 20, 10, 0.5,  1),
        }
        if vtype in cfg:
            sm, l, w, wt, dc = cfg[vtype]
            self.speed = VEHICLE_SPEED * sm
            self.length = l
            self.width = w
            self.weight = wt
            self.detected_class = dc
        else:
            self.weight = 1
            self.detected_class = 2

        # Buses don't turn (too big)
        if vtype == TYPE_BUS:
            self.turn = TURN_STRAIGHT

        self.base_surface = pygame.Surface((self.width, self.length), pygame.SRCALPHA)
        self._icon()
        self.angle = {0: 0, 2: 180, 1: 90, 3: -90}[direction]
        self.image = pygame.transform.rotate(self.base_surface, self.angle)
        self.rect = self.image.get_rect(center=(x, y))
        self.fx, self.fy = float(x), float(y)
        self.waiting = False
        self.wait_start_time = 0
        self.total_wait_time = 0

    def _icon(self):
        w, h = self.width, self.length
        if self.type == TYPE_AMBULANCE:   _amb(self.base_surface, w, h)
        elif self.type == TYPE_VIP:       _vip(self.base_surface, w, h)
        elif self.type == TYPE_BUS:
            _bus(self.base_surface, random.choice([(180,40,40),(0,120,180),(200,160,0),(40,140,40)]), w, h)
        elif self.type == TYPE_AUTO:
            _auto(self.base_surface, random.choice([(200,180,0),(220,200,0),(50,170,50)]), w, h)
        elif self.type == TYPE_BIKE:
            _bike(self.base_surface, random.choice([(50,50,50),(200,50,50),(50,50,200),(100,100,100)]), w, h)
        else:
            _car(self.base_surface,
                 (random.randint(100,240), random.randint(80,200), random.randint(80,200)), w, h)

    def update(self, lead, light, stop, sim_time, cx=0, cy=0):
        """Move vehicle."""
        sf = False  # Should stop?

        # Distance to stop line
        d = {0: self.rect.bottom - stop, 2: stop - self.rect.top,
             1: stop - self.rect.right, 3: self.rect.left - stop}
        dist_to_stop = d[self.direction]

        # STOP Logic:
        # 1. Traffic Light: Stop if Red/Yellow AND close to line AND not crossed
        # Relaxed distance check: stop between 0 and 60
        if not self.has_crossed:
            if 0 < dist_to_stop < 60:
                if light != 'G':
                    sf = True

        # 2. Lead Vehicle Gap
        # Only care about lead if they are in front and CLOSE
        if lead and not self.turning:
            g = {0: self.rect.top - lead.rect.bottom, 2: lead.rect.top - self.rect.bottom,
                 1: lead.rect.left - self.rect.right, 3: self.rect.left - lead.rect.right}
            gap = g[self.direction]
            if gap < VEHICLE_GAP:
                sf = True

        if sf:
            if not self.waiting:
                self.waiting = True
                self.wait_start_time = sim_time
        else:
            if self.waiting:
                self.waiting = False
                self.total_wait_time += (sim_time - self.wait_start_time)

            # Move logic
            if not self.has_crossed:
                # Check crossing
                # If light is Green, we proceed. Once passed stop line, we mark crossed.
                past = {0: self.rect.bottom < stop, 2: self.rect.top > stop,
                        1: self.rect.right > stop, 3: self.rect.left < stop}
                if past.get(self.direction, False):
                    self.has_crossed = True
                    if self.turn != TURN_STRAIGHT:
                        self.turning = True
                        self.turn_cx = cx
                        self.turn_cy = cy

            if self.turning and self.turn != TURN_STRAIGHT:
                self._do_turn()
            else:
                # Straight movement
                mv = {0: (0, -self.speed), 2: (0, self.speed),
                      1: (self.speed, 0), 3: (-self.speed, 0)}
                dx, dy = mv[self.direction]
                self.fx += dx
                self.fy += dy
                self.rect.center = (int(self.fx), int(self.fy))

    def _do_turn(self):
        # 1. Initialize Turn State (Run once)
        if self.turn_progress == 0.0:
            self.p0 = (self.fx, self.fy)
            lw = LANE_WIDTH // 2
            
            # Target offset needs to be dynamic based on sub-lane? 
            # If sub-lane 0 (inner), target inner lane?
            # Existing logic targets 'off = ROAD_WIDTH // 2 + 30' which is roughly centered in exit lane.
            off = ROAD_WIDTH // 2 + 15 + (self.sub_lane * SUB_LANE_WIDTH) # Preserve lane order

            cx, cy = self.turn_cx, self.turn_cy
            
            if self.turn == TURN_LEFT:
                # Short turn
                if self.lane_id == 0:   # N -> W
                    self.p1 = (cx - lw, cy + lw)
                    self.p2 = (cx - off, cy + lw - (self.sub_lane*10)) # Slight adjustment
                    self.target_angle = 90
                elif self.lane_id == 1: # E -> N
                    self.p1 = (cx - lw, cy - lw)
                    self.p2 = (cx - lw + (self.sub_lane*10), cy - off)
                    self.target_angle = 0
                elif self.lane_id == 2: # S -> E
                    self.p1 = (cx + lw, cy - lw)
                    self.p2 = (cx + off, cy - lw + (self.sub_lane*10))
                    self.target_angle = -90
                elif self.lane_id == 3: # W -> S
                    self.p1 = (cx + lw, cy + lw)
                    self.p2 = (cx + lw - (self.sub_lane*10), cy + off)
                    self.target_angle = 180
            else:
                # Right turn (Wide)
                if self.lane_id == 0:   # N -> E
                    self.p1 = (cx - lw, cy - lw)
                    self.p2 = (cx + off, cy - lw + (self.sub_lane*10))
                    self.target_angle = -90
                elif self.lane_id == 1: # E -> S
                    self.p1 = (cx + lw, cy - lw)
                    self.p2 = (cx + lw - (self.sub_lane*10), cy + off)
                    self.target_angle = 180
                elif self.lane_id == 2: # S -> W
                    self.p1 = (cx + lw, cy + lw)
                    self.p2 = (cx - off, cy + lw - (self.sub_lane*10))
                    self.target_angle = 90
                elif self.lane_id == 3: # W -> N
                    self.p1 = (cx - lw, cy + lw)
                    self.p2 = (cx - lw + (self.sub_lane*10), cy - off)
                    self.target_angle = 0

        # 2. Update Progress
        self.turn_progress += 0.020 # Slightly faster turns
        t = self.turn_progress
        
        if t >= 1.0:
            self.turning = False
            self.turn_progress = 0.0
            
            new_dir_map_L = {0: 3, 1: 0, 2: 1, 3: 2}
            new_dir_map_R = {0: 1, 1: 2, 2: 3, 3: 0}
            self.direction = new_dir_map_L[self.lane_id] if self.turn == TURN_LEFT else new_dir_map_R[self.lane_id]
            
            self.angle = {0: 0, 2: 180, 1: -90, 3: 90}[self.direction]
            self.image = pygame.transform.rotate(self.base_surface, self.angle)
            self.fx, self.fy = self.p2
            self.rect = self.image.get_rect(center=(int(self.fx), int(self.fy)))
            return

        # 3. Bezier
        u = 1 - t
        tt = t * t
        uu = u * u
        px = uu * self.p0[0] + 2 * u * t * self.p1[0] + tt * self.p2[0]
        py = uu * self.p0[1] + 2 * u * t * self.p1[1] + tt * self.p2[1]
        self.fx, self.fy = px, py
        
        # 4. Angle
        dx = 2 * u * (self.p1[0] - self.p0[0]) + 2 * t * (self.p2[0] - self.p1[0])
        dy = 2 * u * (self.p1[1] - self.p0[1]) + 2 * t * (self.p2[1] - self.p1[1])
        rad = math.atan2(dy, dx)
        deg = math.degrees(rad)
        self.angle = -deg - 90
        
        self.image = pygame.transform.rotate(self.base_surface, self.angle)
        self.rect = self.image.get_rect(center=(int(self.fx), int(self.fy)))


    # ... [Intersection Init and Update remain same] ...





class Intersection:
    def __init__(self, sw, sh):
        self.sw = sw
        self.sh = sh
        self.vehicles = {i: pygame.sprite.Group() for i in range(4)}
        cx, cy = sw // 2, sh // 2
        self.cx, self.cy = cx, cy
        
        # Road layout
        self.road_w = ROAD_WIDTH
        self.lane_w = LANE_WIDTH
        self.sub_lane_w = SUB_LANE_WIDTH

        off = self.road_w // 2 + 12

        # Stop lines (Y for vertical, X for horizontal)
        self.stop_lines = {0: cy + off, 1: cx - off, 2: cy - off, 3: cx + off}

        # Base Spawn points (Left-Edge of the Lane Group)
        lw = self.lane_w // 2
        self.spawn_anchors = {
            0: (cx - lw, sh + 40),    # Lane 0 (Northbound, Left side)
            1: (-40, cy - lw),        # Lane 1 (Eastbound, Top side)
            2: (cx + lw, -40),        # Lane 2 (Southbound, Right side)
            3: (sw + 40, cy + lw),    # Lane 3 (Westbound, Bottom side)
        }

        self.lights = {i: 'R' for i in range(4)}
        self.sim_time = 0.0
        self.latest_detections = []
        self.spawn_rates_per_lane = {i: 6 for i in range(4)} # Higher spawn rate for more traffic
        self.completed_stats = [] 

    def spawn_vehicle(self, lane=None, v_type=None, hour=8):
        if lane is None: lane = random.randint(0, 3)
        if v_type is None: v_type = pick_type(hour)
        
        # Pick sub-lane (0=Inner, 1=Outer)
        sub_lane = random.randint(0, NUM_SUB_LANES-1)
        
        bx, by = self.spawn_anchors[lane]
        # Offset logic: 
        # Inner lane (0) is closest to center median.
        # Outer lane (1) is closer to curb.
        
        # Lane 0 (Up, Left side): Inner is Right (larger X). Outer is Left (smaller X).
        # Lane 1 (Right, Top side): Inner is Bottom (larger Y). Outer is Top (smaller Y).
        # Lane 2 (Down, Right side): Inner is Left (smaller X). Outer is Right (larger X).
        # Lane 3 (Left, Bottom side): Inner is Top (smaller Y). Outer is Bottom (larger Y).
        
        offset = (sub_lane * self.sub_lane_w) + (self.sub_lane_w // 2)
        center_off = self.sub_lane_w // 2
        
        if lane == 0: # Up (North)
            # Inner (0) is higher X (closer to cx).
            # Lane 0 spans [cx-ROAD_WIDTH/2, cx] approx.
            # Actually spawn anchor is cx-lw.
            # Let's anchor from median outwards for consistency.
            # Median X = cx. Lane 0 is Left side (x < cx).
            # Inner lane center x = cx - (sub_lane_w/2) - (sub_lane * sub_lane_w) - 2 (divider)
            x = self.cx - 2 - center_off - (sub_lane * self.sub_lane_w)
            y = by
        elif lane == 1: # Right (East)
            # Median Y = cy. Lane 1 is Top side (y < cy).
            # Inner lane center y = cy - (sub_lane_w/2) - ...
            x = bx
            y = self.cy - 2 - center_off - (sub_lane * self.sub_lane_w)
        elif lane == 2: # Down (South)
            # Median X = cx. Lane 2 is Right side (x > cx).
            # Inner lane center x = cx + ...
            x = self.cx + 2 + center_off + (sub_lane * self.sub_lane_w)
            y = by
        elif lane == 3: # Left (West)
            # Median Y = cy. Lane 3 is Bottom side (y > cy).
            x = bx
            y = self.cy + 2 + center_off + (sub_lane * self.sub_lane_w)

        # Check collision
        nv = Vehicle(lane, x, y, lane, self.sim_time, v_type, sub_lane)
        
        # Explicit collision check
        for v in self.vehicles[lane]:
            dist = math.hypot(v.rect.centerx - x, v.rect.centery - y)
            if dist < VEHICLE_GAP * 1.2:
                return False
                
        self.vehicles[lane].add(nv)
        return True

    def spawn_specific(self, lane, vtype):
        self.spawn_vehicle(lane, vtype, 12)

    def get_detections(self):
        d = []
        for lane in range(4):
            for v in self.vehicles[lane]:
                if not v.has_crossed:
                    d.append({'class': v.detected_class, 'conf': random.uniform(.82, .99),
                              'box': [v.rect.x, v.rect.y, v.rect.right, v.rect.bottom],
                              'lane': lane})
        self.latest_detections = d
        return d

    def get_lane_count(self, lane):
        return len(self.vehicles[lane])

    def update(self, dt=1/60):
        self.sim_time += dt
        for lane in range(4):
            vehs = list(self.vehicles[lane])
            
            # Sort order
            sk = {
                0: lambda v: v.rect.y,     # Ascending y (Up moves -y, lead has smallest y)
                1: lambda v: -v.rect.x,    # Descending x (Right moves +x, lead has largest x)
                2: lambda v: -v.rect.y,    # Descending y (Down moves +y, lead has largest y)
                3: lambda v: v.rect.x      # Ascending x (Left moves -x, lead has smallest x)
            }
            vehs.sort(key=sk[lane])
            
            for i, veh in enumerate(vehs):
                # Find lead in SAME sub-lane
                lead = None
                # Look backwards in the sorted list (since sorted by position, previous ones are ahead)
                # vehs[i] is current. vehs[i-1] is potentially ahead.
                # If moving Up (lane 0), sorted by Y ascending.
                # y=100 (Lead), y=150 (Follower).
                # list: [Lead, Follower]. i=1. lead candidate is at i=0. Correct.
                for j in range(i-1, -1, -1):
                    if vehs[j].sub_lane == veh.sub_lane:
                        lead = vehs[j]
                        break
                        
                veh.update(lead, self.lights[lane], self.stop_lines[lane],
                           self.sim_time, self.cx, self.cy)
                
                # Despawn
                margin = 120
                if (veh.rect.y < -margin or veh.rect.y > self.sh + margin or
                    veh.rect.x < -margin or veh.rect.x > self.sw + margin):
                    self.completed_stats.append({
                        'type': veh.type,
                        'wait': veh.total_wait_time,
                        'lane': lane
                    })
                    veh.kill()

    def draw(self, surface, is_night=False, ctrl=None):
        cx, cy = self.cx, self.cy
        hw = ROAD_WIDTH // 2

        # 1. Background
        surface.fill(GRASS_NIGHT if is_night else GRASS_DAY)

        # 2. Roads
        rc = (30, 30, 35) if is_night else (50, 52, 55)
        pygame.draw.rect(surface, rc, (cx-hw, 0, ROAD_WIDTH, self.sh))
        pygame.draw.rect(surface, rc, (0, cy-hw, self.sw, ROAD_WIDTH))
        
        # Sidewalks
        sw_col = (90, 95, 100)
        pygame.draw.line(surface, sw_col, (cx-hw, 0), (cx-hw, self.sh), 6)
        pygame.draw.line(surface, sw_col, (cx+hw, 0), (cx+hw, self.sh), 6)
        pygame.draw.line(surface, sw_col, (0, cy-hw), (self.sw, cy-hw), 6)
        pygame.draw.line(surface, sw_col, (0, cy+hw), (self.sw, cy+hw), 6)

        # 3. Markings
        DIVIDER_COLOR = (255, 255, 255)
        LANE_LINE_COLOR = (150, 150, 150)

        # Solid Double Center Lines
        pygame.draw.line(surface, DIVIDER_COLOR, (cx-2, 0), (cx-2, cy-hw), 2)
        pygame.draw.line(surface, DIVIDER_COLOR, (cx+2, 0), (cx+2, cy-hw), 2)
        pygame.draw.line(surface, DIVIDER_COLOR, (cx-2, cy+hw), (cx-2, self.sh), 2)
        pygame.draw.line(surface, DIVIDER_COLOR, (cx+2, cy+hw), (cx+2, self.sh), 2)
        pygame.draw.line(surface, DIVIDER_COLOR, (0, cy-2), (cx-hw, cy-2), 2)
        pygame.draw.line(surface, DIVIDER_COLOR, (0, cy+2), (cx-hw, cy+2), 2)
        pygame.draw.line(surface, DIVIDER_COLOR, (cx+hw, cy-2), (self.sw, cy-2), 2)
        pygame.draw.line(surface, DIVIDER_COLOR, (cx+hw, cy+2), (self.sw, cy+2), 2)

        # Dashed Lane Separators
        off_q = ROAD_WIDTH // 4 
        # Vertical Roads
        for y in range(0, self.sh, 25):
             if not (cy-hw < y < cy+hw):
                 pygame.draw.line(surface, LANE_LINE_COLOR, (cx-off_q, y), (cx-off_q, y+10), 1)
                 pygame.draw.line(surface, LANE_LINE_COLOR, (cx+off_q, y), (cx+off_q, y+10), 1)
        # Horizontal Roads
        for x in range(0, self.sw, 25):
             if not (cx-hw < x < cx+hw):
                 pygame.draw.line(surface, LANE_LINE_COLOR, (x, cy-off_q), (x+10, cy-off_q), 1)
                 pygame.draw.line(surface, LANE_LINE_COLOR, (x, cy+off_q), (x+10, cy+off_q), 1)

        # Stop Lines
        sl_col = (240, 240, 240)
        pygame.draw.line(surface, sl_col, (cx-hw, self.stop_lines[0]), (cx, self.stop_lines[0]), 4)
        pygame.draw.line(surface, sl_col, (self.stop_lines[1], cy-hw), (self.stop_lines[1], cy), 4)
        pygame.draw.line(surface, sl_col, (cx, self.stop_lines[2]), (cx+hw, self.stop_lines[2]), 4)
        pygame.draw.line(surface, sl_col, (self.stop_lines[3], cy), (self.stop_lines[3], cy+hw), 4)

        # 4. Draw Vehicles
        for lane in range(4):
            self.vehicles[lane].draw(surface)

        # 5. Signals (Vertical for Horiz roads, Horizontal for Vert roads)
        # Lane 0 (Up) -> Horizontal
        self._light_horizontal(surface, cx - hw - 35, self.stop_lines[0], self.lights[0], ctrl, 0)
        # Lane 1 (Right) -> Vertical
        self._light_vertical(surface, self.stop_lines[1], cy - hw - 35, self.lights[1], ctrl, 1)
        # Lane 2 (Down) -> Horizontal
        self._light_horizontal(surface, cx + hw + 35, self.stop_lines[2], self.lights[2], ctrl, 2)
        # Lane 3 (Left) -> Vertical
        self._light_vertical(surface, self.stop_lines[3], cy + hw + 35, self.lights[3], ctrl, 3)

    def _light_horizontal(self, surface, x, y, state, ctrl, lane):
        """Draw horizontal signal [R][Y][G]"""
        bw, bh = 60, 22
        r = 7
        pygame.draw.rect(surface, (20,20,20), (x-bw//2, y-bh//2, bw, bh), border_radius=5)
        pygame.draw.rect(surface, (80,80,80), (x-bw//2, y-bh//2, bw, bh), 1, border_radius=5)
        offsets = [-18, 0, 18] # R, Y, G
        cols = [BRIGHT_RED, BRIGHT_YELLOW, BRIGHT_GREEN]
        chars = ['R', 'Y', 'G']
        for i, off in enumerate(offsets):
            on = (state == chars[i])
            c = cols[i] if on else (30,30,30)
            pygame.draw.circle(surface, c, (x+off, y), r)
            if on: pygame.draw.circle(surface, WHITE, (x+off, y), r, 1)
        if ctrl:
            val = self._get_lane_timer(ctrl, lane)
            if val >= 0: self._draw_timer(surface, x, y+20, val, state)

    def _light_vertical(self, surface, x, y, state, ctrl, lane):
        """Draw vertical signal [R] [Y] [G]"""
        bw, bh = 22, 60
        r = 7
        pygame.draw.rect(surface, (20,20,20), (x-bw//2, y-bh//2, bw, bh), border_radius=5)
        pygame.draw.rect(surface, (80,80,80), (x-bw//2, y-bh//2, bw, bh), 1, border_radius=5)
        offsets = [-18, 0, 18] # R, Y, G (Top to Bottom)
        cols = [BRIGHT_RED, BRIGHT_YELLOW, BRIGHT_GREEN]
        chars = ['R', 'Y', 'G']
        for i, off in enumerate(offsets):
            on = (state == chars[i])
            c = cols[i] if on else (30,30,30)
            pygame.draw.circle(surface, c, (x, y+off), r)
            if on: pygame.draw.circle(surface, WHITE, (x, y+off), r, 1)
        if ctrl:
            val = self._get_lane_timer(ctrl, lane)
            if val >= 0: self._draw_timer(surface, x, y+40, val, state)

    def _draw_timer(self, surface, x, y, val, state):
        font = pygame.font.SysFont("consolas", 12, bold=True)
        c = BRIGHT_GREEN if state=='G' else (BRIGHT_RED if state=='R' else BRIGHT_YELLOW)
        txt = font.render(f"{int(val)}", True, c)
        surface.blit(txt, (x - txt.get_width()//2, y))

    def _get_lane_timer(self, ctrl, lane):
        if lane == ctrl.phase and ctrl.state == 'GREEN':
            return ctrl.time_remaining()
        elif ctrl.state == 'YELLOW_CLOSE' and lane == ctrl.phase:
            from controller import YELLOW_CLOSE
            return YELLOW_CLOSE - ctrl.elapsed()
        elif ctrl.state == 'CLEARANCE' and ctrl.next_phase == lane:
            from controller import CLEARANCE
            return CLEARANCE - ctrl.elapsed()
        else:
            eta = ctrl.get_lane_eta()
            e = eta.get(lane, -1)
            return e if e > 0 else -1


# ══════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    pygame.init()
    info = pygame.display.Info()
    sim_w = min(TARGET_SIM_W, int(info.current_w * 0.55))
    sim_h = min(TARGET_SIM_H, int(info.current_h * 0.55))
    total_w = sim_w + SIDE_PANEL_W
    total_h = sim_h + LOG_PANEL_H
    screen = pygame.display.set_mode((total_w, total_h))
    pygame.display.set_caption("TNI26165 — Adaptive Traffic (Modern UI)")
    clock = pygame.time.Clock()
    
    # Modern Fonts
    try:
        f11 = pygame.font.SysFont("segoeui", 12)
        f12 = pygame.font.SysFont("segoeui", 13)
        f14 = pygame.font.SysFont("segoeui", 15)
        f16 = pygame.font.SysFont("segoeui", 17, bold=True)
        f18 = pygame.font.SysFont("segoeui", 20, bold=True)
    except:
        f11 = pygame.font.SysFont("arial", 12)
        f12 = pygame.font.SysFont("arial", 13)
        f14 = pygame.font.SysFont("arial", 15)
        f16 = pygame.font.SysFont("arial", 17, bold=True)
        f18 = pygame.font.SysFont("arial", 20, bold=True)

    sim_surface = pygame.Surface((sim_w, sim_h))
    sim = Intersection(sim_w, sim_h)

    from controller import AdaptiveController, get_profile, LANE_NAMES as LN
    ctrl = AdaptiveController(sim)

    paused = False
    sel = TYPE_CAR
    running = True
    day_clock = 8.0 * 60  # Start at 8 AM
    SIM_SPEED = 1.0

    while running:
        for ev in pygame.event.get():
            if ev.type == pygame.QUIT: running = False
            elif ev.type == pygame.KEYDOWN:
                k = ev.key
                if k == pygame.K_SPACE: paused = not paused
                elif k == pygame.K_ESCAPE: running = False
                elif k == pygame.K_1: sim.spawn_specific(0, sel)
                elif k == pygame.K_2: sim.spawn_specific(1, sel)
                elif k == pygame.K_3: sim.spawn_specific(2, sel)
                elif k == pygame.K_4: sim.spawn_specific(3, sel)
                elif k == pygame.K_c: sel = TYPE_CAR
                elif k == pygame.K_b: sel = TYPE_BUS
                elif k == pygame.K_m: sel = TYPE_BIKE
                elif k == pygame.K_a: sel = TYPE_AMBULANCE
                elif k == pygame.K_v: sel = TYPE_VIP
                elif k == pygame.K_r: sel = TYPE_AUTO
                elif k == pygame.K_F1: sim.spawn_rates_per_lane[0] = min(20,sim.spawn_rates_per_lane[0]+2)
                elif k == pygame.K_F2: sim.spawn_rates_per_lane[1] = min(20,sim.spawn_rates_per_lane[1]+2)
                elif k == pygame.K_F3: sim.spawn_rates_per_lane[2] = min(20,sim.spawn_rates_per_lane[2]+2)
                elif k == pygame.K_F4: sim.spawn_rates_per_lane[3] = min(20,sim.spawn_rates_per_lane[3]+2)
                elif k == pygame.K_F5: sim.spawn_rates_per_lane[0] = max(0,sim.spawn_rates_per_lane[0]-2)
                elif k == pygame.K_F6: sim.spawn_rates_per_lane[1] = max(0,sim.spawn_rates_per_lane[1]-2)
                elif k == pygame.K_F7: sim.spawn_rates_per_lane[2] = max(0,sim.spawn_rates_per_lane[2]-2)
                elif k == pygame.K_F8: sim.spawn_rates_per_lane[3] = max(0,sim.spawn_rates_per_lane[3]-2)

        if not paused:
            day_clock += SIM_SPEED / FPS
            if day_clock >= 1440: day_clock -= 1440
            hour = day_clock / 60.0
            ctrl.sim_hour = hour

            rate_mult, _, profile_label = get_profile(int(hour))

            for lid in range(4):
                base_rate = sim.spawn_rates_per_lane[lid]
                effective = base_rate * rate_mult
                if effective > 0 and random.random() * 100 < effective:
                    sim.spawn_vehicle(lane=lid, hour=int(hour))

            ctrl.update()
            sim.update(dt=1/60)

        # ── Derived state ──
        hour = day_clock / 60.0
        h_int = int(hour) % 24
        m_int = int((hour % 1) * 60)
        is_night = h_int >= 22 or h_int < 5
        rate_mult, max_g, profile_label = get_profile(h_int)

        # ── Draw Sim ──
        sim.draw(sim_surface, is_night, ctrl)
        if paused:
            pt = f16.render("PAUSED", True, YELLOW)
            sim_surface.blit(pt, (sim_w//2-30, 10))
        screen.blit(sim_surface, (0, 0))

        # ══ SIDE PANEL (Modern) ══
        panel = pygame.Rect(sim_w, 0, SIDE_PANEL_W, sim_h)
        pygame.draw.rect(screen, PANEL_BG, panel)
        pygame.draw.line(screen, PANEL_BORDER, (sim_w,0), (sim_w,sim_h), 2)

        py = [15]; px = sim_w + 15
        def txt(t, c=TEXT_COLOR, fnt=f14):
            s = fnt.render(t, True, c); screen.blit(s, (px, py[0])); py[0] += fnt.get_height() + 4
        def gap(n=8): py[0] += n
        def divider():
            pygame.draw.line(screen, PANEL_BORDER, (px, py[0]+4), (total_w-15, py[0]+4), 1)
            gap(12)

        txt("TNI26165 — ADAPTIVE", ACCENT_CYAN, f18)
        txt("Smart Traffic Controller", SIDEWALK, f12)
        divider()

        # Clock
        am_pm = "AM" if h_int < 12 else "PM"
        disp_h = h_int % 12 or 12
        clock_color = WHITE if not is_night else BRIGHT_YELLOW
        txt(f"{disp_h:02d}:{m_int:02d} {am_pm}", clock_color, f18)
        txt(f"{profile_label}", SIDEWALK, f11)
        txt(f"Traffic Volume: {rate_mult:.1f}x", SIDEWALK, f11)
        gap(5)

        # Controller State
        state_map = {
            'GREEN':        ("GREEN SIGNAL", BRIGHT_GREEN),
            'YELLOW_CLOSE': ("CAUTION (CLOSE)", BRIGHT_YELLOW),
            'CLEARANCE':    ("ALL RED (CLEAR)", RED),
        }
        sl, sc = state_map.get(ctrl.state, ("UNKNOWN", WHITE))
        
        # Status Box
        box_h = 70
        pygame.draw.rect(screen, DARK_BG, (px, py[0], SIDE_PANEL_W-30, box_h), border_radius=6)
        pygame.draw.rect(screen, sc, (px, py[0], 4, box_h), border_radius=6) # Accent stripe
        
        orig_py = py[0]
        py[0] += 8; px += 12
        txt(sl, sc, f16)
        if ctrl.state == 'GREEN':
            txt(f"Active: {LANE_NAMES[ctrl.phase]}", WHITE, f12)
            # Use raw scores from controller cache if possible, else 0
            txt(f"Max Green: {ctrl.green_duration:.0f}s", SIDEWALK, f11)
        elif ctrl.state == 'YELLOW_CLOSE':
            txt(f"Closing: {LANE_NAMES[ctrl.phase]}", WHITE, f12)
        elif ctrl.state == 'CLEARANCE' and ctrl.next_phase is not None:
            txt(f"Next: {LANE_NAMES[ctrl.next_phase]}", WHITE, f12)
        
        px -= 12; py[0] = orig_py + box_h + 10

        # Progress Bar
        remain = ctrl.time_remaining()
        total_dur = {'GREEN': ctrl.green_duration, 'YELLOW_CLOSE': 3, 'CLEARANCE': 2}.get(ctrl.state, 1)
        fill = max(0, min(1, remain / total_dur)) if total_dur > 0 else 0
        
        bar_w = SIDE_PANEL_W - 30
        pygame.draw.rect(screen, DARK_BG, (px, py[0], bar_w, 6), border_radius=3)
        pygame.draw.rect(screen, sc, (px, py[0], int(bar_w * fill), 6), border_radius=3)
        py[0] += 15
        
        # Lane Dashboard
        txt("LANE STATUS", ACCENT_CYAN, f12)
        eta = ctrl.get_lane_eta()
        for i in range(4):
            st = sim.lights[i]
            # Row Bg
            is_active = (i == ctrl.phase and ctrl.state != 'CLEARANCE') or (ctrl.state=='CLEARANCE' and i==ctrl.next_phase)
            row_bg = (35, 40, 55) if is_active else DARK_BG
            pygame.draw.rect(screen, row_bg, (px, py[0]-2, bar_w, 20), border_radius=4)
            
            # Indicator
            clr = BRIGHT_GREEN if st=='G' else (BRIGHT_YELLOW if st=='Y' else RED)
            pygame.draw.circle(screen, clr, (px+10, py[0]+8), 4)
            
            # Text
            cnt = sim.get_lane_count(i)
            e = eta.get(i, -1)
            eta_txt = "GLOW" if st=='G' else (f"{e:.0f}s" if e>0 else "--")
            
            name_c = WHITE if is_active else SIDEWALK
            s = f12.render(f"{LANE_NAMES[i]:<6}", True, name_c)
            screen.blit(s, (px+25, py[0]))
            
            s2 = f12.render(f"{cnt} veh", True, SIDEWALK)
            screen.blit(s2, (px+90, py[0]))
            
            s3 = f12.render(eta_txt, True, clr)
            screen.blit(s3, (px+160, py[0]))
            
            py[0] += 24

        gap(5)
        divider()
        txt("CONTROLS", SIDEWALK, f11)
        txt(f"Spawn: {TYPE_LABELS.get(sel,'?').upper()}", WHITE, f12)
        txt("Keys: 1-4 (Lane), Space (Pause)", SIDEWALK, f11)

        # ══ LOG PANEL ══
        log_rect = pygame.Rect(0, sim_h, total_w, LOG_PANEL_H)
        pygame.draw.rect(screen, LOG_BG, log_rect)
        pygame.draw.line(screen, (50,50,90), (0,sim_h), (total_w,sim_h), 2)

        title = f14.render("DECISION LOG - Signal Switch Reasoning", True, (130,130,220))
        screen.blit(title, (10, sim_h + 3))

        ly = sim_h + 20
        for entry in list(ctrl.log):
            if "YELLOW_CL" in entry:     c = BRIGHT_YELLOW
            elif "CLEARANCE" in entry:   c = ORANGE
            elif "GREEN" in entry:       c = BRIGHT_GREEN
            elif "CYCLE" in entry:       c = (130,130,255)
            elif "HOLDING" in entry:     c = (80,160,80)
            elif "NIGHT" in entry:       c = (200,200,100)
            elif "STARVE" in entry:      c = (255,150,50)
            elif "INIT" in entry:        c = CYAN
            else:                        c = LIGHT_GRAY
            t = f11.render(entry, True, c); screen.blit(t, (10, ly)); ly += 13
            if ly > sim_h + LOG_PANEL_H - 5: break

        pygame.display.flip()
        clock.tick(FPS)

    pygame.quit()
    sys.exit()
