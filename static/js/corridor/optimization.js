export function computeGreenWaveOffset(distanceMeters, avgSpeedMps) {
  const speed = Math.max(1, Number(avgSpeedMps) || 1);
  return Number((Number(distanceMeters || 0) / speed).toFixed(2));
}

export function normalizePhaseSplit(rawSplit, cycleLength = 90) {
  const split = {
    "0": Number(rawSplit?.["0"] ?? 25),
    "1": Number(rawSplit?.["1"] ?? 20),
    "2": Number(rawSplit?.["2"] ?? 25),
    "3": Number(rawSplit?.["3"] ?? 20),
  };

  const total = Object.values(split).reduce((sum, value) => sum + value, 0);
  if (total <= 0) return { "0": 25, "1": 20, "2": 25, "3": 20 };

  if (total !== cycleLength) {
    const scale = cycleLength / total;
    Object.keys(split).forEach((key) => {
      split[key] = Math.max(10, Math.round(split[key] * scale));
    });
  }
  return split;
}
