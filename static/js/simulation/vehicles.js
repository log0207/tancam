import { TYPE } from "../constants.js";

export const VEHICLE_TYPE_WEIGHT = {
  [TYPE.BIKE]: 0.5,
  [TYPE.CAR]: 1.0,
  [TYPE.AUTO]: 1.2,
  [TYPE.BUS]: 2.5,
  [TYPE.AMBULANCE]: 2.8,
  [TYPE.VIP]: 1.4,
};

export function getVehicleWeight(type) {
  return VEHICLE_TYPE_WEIGHT[type] ?? 1.0;
}
