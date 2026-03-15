import { MAX_PER_LANE, TYPE } from "../constants.js";

const TYPE_WEIGHT = {
  [TYPE.BIKE]: 0.5,
  [TYPE.CAR]: 1.0,
  [TYPE.AUTO]: 1.2,
  [TYPE.BUS]: 2.5,
  [TYPE.AMBULANCE]: 3.0,
  [TYPE.VIP]: 1.4,
};

export function computeTrafficMetrics({ intersectionId, vehicles = [], laneIds = [], previous = null, timestamp = Date.now() }) {
  const queue_count = vehicles.filter((v) => !v.hasCrossed).length;

  let weighted = 0;
  const laneLoad = {};
  laneIds.forEach((id) => {
    laneLoad[id] = 0;
  });

  vehicles.forEach((v) => {
    if (laneLoad[v.lane] === undefined) laneLoad[v.lane] = 0;
    laneLoad[v.lane] += 1;
    if (!v.hasCrossed) {
      weighted += TYPE_WEIGHT[v.type] ?? 1.0;
    }
  });

  const activeLaneCount = Math.max(1, laneIds.length || Object.keys(laneLoad).length);
  const lane_density = Math.min(1, weighted / (MAX_PER_LANE * activeLaneCount));
  const vehicle_type_weight = queue_count > 0 ? (weighted / queue_count) : 0;

  const totalLoad = Object.values(laneLoad).reduce((sum, value) => sum + value, 0);
  const occupancy_ratio = Math.min(1, totalLoad / (MAX_PER_LANE * activeLaneCount));

  let arrival_rate = 0;
  if (previous && previous.timestamp) {
    const dtSec = Math.max(0.001, (timestamp - previous.timestamp) / 1000);
    arrival_rate = Math.max(0, (totalLoad - (previous.totalLoad ?? 0)) / dtSec);
  }

  return {
    intersection_id: intersectionId,
    queue_count,
    lane_density: Number(lane_density.toFixed(4)),
    vehicle_type_weight: Number(vehicle_type_weight.toFixed(4)),
    occupancy_ratio: Number(occupancy_ratio.toFixed(4)),
    arrival_rate: Number(arrival_rate.toFixed(4)),
    timestamp: new Date(timestamp).toISOString(),
    totalLoad,
  };
}

export async function publishTrafficMetrics(baseUrl, metrics) {
  const endpoint = `${baseUrl}/api/intersections/${encodeURIComponent(metrics.intersection_id)}/metrics`;
  await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(metrics),
  });
}
