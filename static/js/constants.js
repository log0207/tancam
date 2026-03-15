export const ROAD_W = 14;
export const STOP_DIST = 12;
export const SPAWN_DIST = 58;
export const WORLD_LIMIT = 72;
export const FPS_STEP = 1 / 60;
export const ROAD_TOP_Y = 0.13;
export const INBOUND_SUBLANES = 3;
export const MAX_PER_SUBLANE = 8;
export const MAX_PER_LANE = MAX_PER_SUBLANE * INBOUND_SUBLANES;
export const SUBLANE_SPACING = 1.55;
export const SUBLANE_BASE_OFFSET = -ROAD_W * 0.44;
export const SUBLANE_OFFSETS = Array.from({ length: INBOUND_SUBLANES }, (_, i) => (
    SUBLANE_BASE_OFFSET + (i * SUBLANE_SPACING)
));

export const SIGNAL_TIMINGS = {
    YELLOW: 3,
    ALL_RED: 2,
    RED_AMBER: 1,
};

export const CONTROL_THRESHOLDS = {
    MIN_GREEN: 3,
    MAX_GREEN: 30,
    EMPTY_CUT_GREEN: 30,
    CRITICAL_WAIT_SEC: 75,
    STARVATION_CYCLES: 3,
    SPAWN_MIN_GAP_M: 6.5,
    DEADLOCK_SECONDS: 45,
};

export const VEHICLE_DYNAMICS = {
    MAX_ACCEL: 3.2,
    MAX_BRAKE: 7.2,
    LEAD_BRAKE_LOOKAHEAD: 6.0,
    STOP_LINE_BUFFER: 0.45,
};

export const SPAWN_CONTROL = {
    BASE_RATE: 0.42,
    MIN_COOLDOWN: 0.32,
    MAX_COOLDOWN: 1.15,
};

export const TYPE = {
    BIKE: "bike",
    CAR: "car",
    AUTO: "auto",
    BUS: "bus",
    AMBULANCE: "ambulance",
    VIP: "vip",
};

export const TYPE_DIMENSIONS = {
    [TYPE.CAR]: { width: 1.9, length: 4.4, height: 1.5 },
    [TYPE.BUS]: { width: 2.6, length: 9.6, height: 3.0 },
    [TYPE.BIKE]: { width: 0.8, length: 2.1, height: 1.4 },
    [TYPE.AUTO]: { width: 1.4, length: 3.0, height: 1.8 },
    [TYPE.AMBULANCE]: { width: 2.1, length: 5.4, height: 2.6 },
    [TYPE.VIP]: { width: 1.9, length: 4.6, height: 1.5 },
};

export const USE_CASES = {
    BALANCED: {
        label: "Use Case: Balanced City Flow",
        laneBias: { 0: 1.0, 1: 1.0, 2: 1.0, 3: 1.0 },
        profileBoost: 1.0,
        typePool: [TYPE.CAR, TYPE.CAR, TYPE.BIKE, TYPE.BIKE, TYPE.AUTO, TYPE.AUTO, TYPE.BUS],
    },
    NS_PEAK: {
        label: "Use Case: North-South Peak",
        laneBias: { 0: 1.9, 1: 0.7, 2: 1.8, 3: 0.7 },
        profileBoost: 1.1,
        typePool: [TYPE.CAR, TYPE.CAR, TYPE.CAR, TYPE.BIKE, TYPE.AUTO, TYPE.BUS],
    },
    EW_PEAK: {
        label: "Use Case: East-West Peak",
        laneBias: { 0: 0.7, 1: 1.9, 2: 0.7, 3: 1.8 },
        profileBoost: 1.1,
        typePool: [TYPE.CAR, TYPE.CAR, TYPE.BIKE, TYPE.BIKE, TYPE.AUTO, TYPE.BUS],
    },
    FREIGHT: {
        label: "Use Case: Freight Hour",
        laneBias: { 0: 1.2, 1: 1.0, 2: 1.2, 3: 1.0 },
        profileBoost: 1.05,
        typePool: [TYPE.CAR, TYPE.BUS, TYPE.BUS, TYPE.AUTO, TYPE.BIKE],
    },
    EVENT_SWELL: {
        label: "Use Case: Event Exit Surge",
        laneBias: { 0: 1.6, 1: 1.4, 2: 0.9, 3: 0.8 },
        profileBoost: 1.25,
        typePool: [TYPE.CAR, TYPE.CAR, TYPE.CAR, TYPE.BIKE, TYPE.AUTO, TYPE.BUS],
    },
};
