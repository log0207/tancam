
import sys
import os
import random
import statistics
import time

# Headless setup
os.environ["SDL_VIDEODRIVER"] = "dummy"
import pygame
pygame.init()
pygame.display.set_mode((1,1))

from simulation import Intersection, Vehicle, TYPE_AMBULANCE
from controller import FixedController, AdaptiveController, PredictiveAdaptiveController, PROFILES

def run_simulation(controller_cls, duration_sec=300, seed=42, hour=8):
    """
    Run simulation for specified duration and return metrics.
    """
    random.seed(seed)
    sim = Intersection(800, 800) # Headless dimensions
    
    # Initialize Controller
    ctrl = controller_cls(sim)
    ctrl.sim_hour = hour 
    
    # Run loop
    frames = int(duration_sec * 60)
    
    # Get spawn rate from profile
    rate_mult = 1.0
    for (s, e), val in PROFILES.items():
        if s <= hour < e:
            rate_mult = val[0]
            break
            
    base_prob = 0.008 
    
    for _ in range(frames):
        for lane in range(4):
            if random.random() < base_prob * rate_mult:
                sim.spawn_vehicle(lane=lane, hour=hour)
                
        sim.update(1/60)
        ctrl.update()
        
    # Collect Metrics
    waits = [s['wait'] for s in sim.completed_stats]
    throughput = len(sim.completed_stats)
    
    active_wait = 0
    active_count = 0
    max_q = 0
    for lane in range(4):
        q = sim.get_lane_count(lane)
        max_q = max(max_q, q)
        for v in sim.vehicles[lane]:
            # Add wait time up to now for vehicles still in queue
            active_wait += (v.total_wait_time + (sim.sim_time - v.wait_start_time if v.waiting else 0))
            active_count += 1
            
    total_vehicles = throughput + active_count
    total_wait = sum(waits) + active_wait
    avg_wait = total_wait / total_vehicles if total_vehicles > 0 else 0
    
    return {
        'throughput': throughput,
        'avg_wait': avg_wait,
        'max_queue': max_q,
        'total_traffic': total_vehicles
    }

def benchmark():
    print("🚦 Traffic Simulation Benchmark (TNI26165) 🚦")
    print("=================================================")
    print(f"Scenarios: Peak (9AM), Off-Peak (2PM), Night (11PM)")
    print(f"Duration: 180s simulation per run")
    print("-" * 75)
    
    scenarios = [
        (9, "Peak Hour (High Density)"),
        (14, "Afternoon (Moderate)"),
        (23, "Night (Low Density)")
    ]
    
    for hour, label in scenarios:
        print(f"\nScenario: {label} (Hour {hour})")
        header = f"{'Controller':<20} | {'Avg Wait':<12} | {'Thruput':<10} | {'Max Q':<5}"
        print(header)
        print("-" * len(header))
        
        # Test Fixed
        f_m = run_simulation(FixedController, duration_sec=180, seed=101, hour=hour)
        print(f"{'Fixed (30s)':<20} | {f_m['avg_wait']:8.2f}s    | {f_m['throughput']:<10} | {f_m['max_queue']:<5}")
        
        # Test Adaptive (Standard)
        a_m = run_simulation(AdaptiveController, duration_sec=180, seed=101, hour=hour)
        print(f"{'Adaptive':<20} | {a_m['avg_wait']:8.2f}s    | {a_m['throughput']:<10} | {a_m['max_queue']:<5}")
        
        # Test Predictive (New)
        p_m = run_simulation(PredictiveAdaptiveController, duration_sec=180, seed=101, hour=hour)
        print(f"{'PDWP (Predictive)':<20} | {p_m['avg_wait']:8.2f}s    | {p_m['throughput']:<10} | {p_m['max_queue']:<5}")
        
        # Comparison
        imp = f_m['avg_wait'] - p_m['avg_wait']
        pct = (imp / f_m['avg_wait'] * 100) if f_m['avg_wait'] > 0 else 0
        print(f"\n✨ PDWP vs Fixed: {pct:+.1f}% improvement ({imp:+.1f}s reduction)")
        
if __name__ == "__main__":
    benchmark()
        
if __name__ == "__main__":
    benchmark()
