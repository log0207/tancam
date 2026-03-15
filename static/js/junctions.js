import * as THREE from "three";
import { ROAD_W, STOP_DIST, SPAWN_DIST } from "./constants.js";

// Helper for white stripes
const addStripes = (scene, x, z, w, h) => {
    const white = new THREE.MeshBasicMaterial({ color: 0xf2f2f2 });
    const mesh = new THREE.Mesh(new THREE.BoxGeometry(w, 0.1, h), white);
    mesh.position.set(x, 0.13, z);
    scene.add(mesh);
    return mesh;
};

// Generic Pole Builder
const buildStandardGantry = (scene, signalLights, laneConfig, mkHeadCb) => {
    const poleMat = new THREE.MeshStandardMaterial({ color: 0x111111, roughness: 0.5, metalness: 0.8 });
    const headMat = new THREE.MeshStandardMaterial({ color: 0x0a0a0a, roughness: 0.35, metalness: 0.55 });
    const lensOffMat = new THREE.MeshStandardMaterial({ color: 0x050505, emissive: 0x000000, roughness: 0.2, metalness: 0.1 });
    const arrowMatEmpty = new THREE.MeshStandardMaterial({ color: 0x112211, emissive: 0x000000 });
    const arrowMatGreen = new THREE.MeshStandardMaterial({ color: 0x47ff5b, emissive: 0x22ff33, emissiveIntensity: 2.0 });

    Object.keys(laneConfig).forEach((laneId) => {
        const lane = laneConfig[laneId];
        if (!lane.hasSignal) return;

        const dir = lane.dir.clone().normalize();
        const center = lane.center ? lane.center.clone() : new THREE.Vector3(0, 0, 0);
        const fromCenter = lane.spawn.clone().sub(center).normalize();
        const stop = center.clone().addScaledVector(fromCenter, STOP_DIST);

        const poleBackOffset = 1.0;
        const poleSideOffset = (ROAD_W * 0.5) + 1.2;
        const rootPos = stop.clone()
            .addScaledVector(dir, -poleBackOffset)
            .addScaledVector(lane.left, -poleSideOffset);

        const rot = Math.atan2(dir.x, dir.z);
        const root = new THREE.Group();
        root.position.copy(rootPos);
        root.rotation.y = rot;

        const pillar = new THREE.Mesh(new THREE.CylinderGeometry(0.35, 0.45, 9.0, 12), poleMat);
        pillar.position.set(0, 4.5, 0);
        pillar.castShadow = true;
        root.add(pillar);

        const armLen = (ROAD_W * 0.5) + 1.5;
        const arm = new THREE.Mesh(new THREE.CylinderGeometry(0.2, 0.3, armLen, 12), poleMat);
        arm.rotation.z = Math.PI / 2;
        arm.position.set(-armLen / 2, 8.5, 0);
        arm.castShadow = true;
        root.add(arm);

        mkHeadCb(scene, headMat, lensOffMat, arrowMatEmpty, arrowMatGreen, laneId, root, -armLen * 0.6, signalLights);
        scene.add(root);
    });
};

function defaultHeadBuilder(scene, headMat, lensOffMat, arrowMatEmpty, arrowMatGreen, laneId, root, localX, signalLights) {
    const getGeo = (type, w, h, d) => (type === 'box') ? new THREE.BoxGeometry(w, h, d) : new THREE.CylinderGeometry(w, h, d, 10);

    const head = new THREE.Mesh(getGeo('box', 1.0, 3.2, 1.0), headMat);
    head.position.set(localX, 5.8, 0);
    head.rotation.y = Math.PI;
    head.castShadow = true;
    root.add(head);

    const mkLens = (y) => {
        const lens = new THREE.Mesh(new THREE.SphereGeometry(0.24, 16, 16), lensOffMat.clone());
        lens.position.set(0, y, 0.5);
        head.add(lens);
        const glow = new THREE.Mesh(
            new THREE.SphereGeometry(0.5, 10, 10),
            new THREE.MeshBasicMaterial({ color: 0xffffff, transparent: true, opacity: 0, depthWrite: false })
        );
        glow.position.copy(lens.position);
        head.add(glow);
        return { lens, glow };
    };

    const red = mkLens(0.9);
    const yellow = mkLens(0.0);
    const green = mkLens(-0.9);

    const arrowBox = new THREE.Mesh(getGeo('box', 0.8, 0.8, 0.8), headMat);
    arrowBox.position.set(0, -2.2, 0);
    head.add(arrowBox);

    const arrowRoot = new THREE.Group();
    arrowRoot.position.set(0, 0, 0.41);
    const s1 = new THREE.Mesh(getGeo('box', 0.1, 0.5, 0.05), arrowMatEmpty.clone());
    s1.position.set(0, -0.05, 0);
    const h1 = new THREE.Mesh(getGeo('box', 0.1, 0.35, 0.05), arrowMatEmpty.clone());
    h1.rotation.z = Math.PI / 4; h1.position.set(-0.1, 0.15, 0);
    const h2 = new THREE.Mesh(getGeo('box', 0.1, 0.35, 0.05), arrowMatEmpty.clone());
    h2.rotation.z = -Math.PI / 4; h2.position.set(0.1, 0.15, 0);
    arrowRoot.add(s1, h1, h2);
    arrowBox.add(arrowRoot);

    const canvas = document.createElement("canvas");
    canvas.width = 256;
    canvas.height = 128;
    const ctx = canvas.getContext("2d");
    const tex = new THREE.CanvasTexture(canvas);
    tex.colorSpace = THREE.SRGBColorSpace;
    const mat = new THREE.SpriteMaterial({ map: tex, transparent: true, depthTest: false, depthWrite: false });
    const sprite = new THREE.Sprite(mat);
    sprite.renderOrder = 999;
    sprite.position.set(0, 3.4, 0.0);
    sprite.scale.set(8.0, 3.8, 1);
    head.add(sprite);

    signalLights[laneId] = { red, yellow, green, arrowParts: [s1, h1, h2], timerSprite: { sprite, canvas, ctx, tex }, arrowMatEmpty, arrowMatGreen };
}

// Geometry Definitions
export const JUNCTIONS = {
    "FOUR_WAY": {
        name: "Standard 4-Way Intersection",
        phases: [0, 1, 2, 3], // Lanes that map to Phase indices
        getLanes: () => {
            const b = {
                0: { dir: new THREE.Vector3(0, 0, -1), rotY: Math.PI, spawn: new THREE.Vector3(0, 0, SPAWN_DIST), hasSignal: true },
                1: { dir: new THREE.Vector3(-1, 0, 0), rotY: -Math.PI / 2, spawn: new THREE.Vector3(SPAWN_DIST, 0, 0), hasSignal: true },
                2: { dir: new THREE.Vector3(0, 0, 1), rotY: 0, spawn: new THREE.Vector3(0, 0, -SPAWN_DIST), hasSignal: true },
                3: { dir: new THREE.Vector3(1, 0, 0), rotY: Math.PI / 2, spawn: new THREE.Vector3(-SPAWN_DIST, 0, 0), hasSignal: true },
            };
            Object.values(b).forEach(l => l.left = new THREE.Vector3(-l.dir.z, 0, l.dir.x).normalize());
            return b;
        },
        buildEnv: (scene) => {
            const gMat = new THREE.MeshPhongMaterial({ color: 0x8ca88b });
            const ground = new THREE.Mesh(new THREE.PlaneGeometry(240, 240), gMat);
            ground.rotation.x = -Math.PI / 2;
            ground.receiveShadow = true;
            scene.add(ground);

            const roadMat = new THREE.MeshPhongMaterial({ color: 0x777a81 });
            const roadA = new THREE.Mesh(new THREE.BoxGeometry(ROAD_W, 0.1, 240), roadMat);
            roadA.position.y = 0.05;
            roadA.receiveShadow = true;
            scene.add(roadA);
            const roadB = new THREE.Mesh(new THREE.BoxGeometry(240, 0.1, ROAD_W), roadMat);
            roadB.position.y = 0.06;
            roadB.receiveShadow = true;
            scene.add(roadB);

            const zebraOffset = ROAD_W / 2 + 3;
            for (let i = -7; i <= 7; i += 2) {
                addStripes(scene, i, zebraOffset, 1, 4);
                addStripes(scene, i, -zebraOffset, 1, 4);
                addStripes(scene, zebraOffset, i, 4, 1);
                addStripes(scene, -zebraOffset, i, 4, 1);
            }
        },
        buildSignals: (scene, lightsObj, lanes) => {
            buildStandardGantry(scene, lightsObj, lanes, defaultHeadBuilder);
        }
    },

    "THREE_WAY": {
        name: "T-Junction",
        phases: [0, 1, 3], // Exclude lane 2 (South)
        getLanes: () => {
            const b = {
                0: { dir: new THREE.Vector3(0, 0, -1), rotY: Math.PI, spawn: new THREE.Vector3(0, 0, SPAWN_DIST), hasSignal: true },
                1: { dir: new THREE.Vector3(-1, 0, 0), rotY: -Math.PI / 2, spawn: new THREE.Vector3(SPAWN_DIST, 0, 0), hasSignal: true },
                3: { dir: new THREE.Vector3(1, 0, 0), rotY: Math.PI / 2, spawn: new THREE.Vector3(-SPAWN_DIST, 0, 0), hasSignal: true },
            };
            Object.values(b).forEach(l => l.left = new THREE.Vector3(-l.dir.z, 0, l.dir.x).normalize());
            return b;
        },
        buildEnv: (scene) => {
            const gMat = new THREE.MeshPhongMaterial({ color: 0x8ca88b });
            const ground = new THREE.Mesh(new THREE.PlaneGeometry(240, 240), gMat);
            ground.rotation.x = -Math.PI / 2; ground.receiveShadow = true;
            scene.add(ground);

            const roadMat = new THREE.MeshPhongMaterial({ color: 0x777a81 });
            const roadB = new THREE.Mesh(new THREE.BoxGeometry(240, 0.1, ROAD_W), roadMat); // Full East-West
            roadB.position.y = 0.05; roadB.receiveShadow = true; scene.add(roadB);
            // Half North-South
            const roadA = new THREE.Mesh(new THREE.BoxGeometry(ROAD_W, 0.1, 120), roadMat);
            roadA.position.set(0, 0.06, 60); roadA.receiveShadow = true; scene.add(roadA);

            const zebraOffset = ROAD_W / 2 + 3;
            for (let i = -7; i <= 7; i += 2) {
                addStripes(scene, i, zebraOffset, 1, 4); // North crossing
                if (i < 0) {
                    addStripes(scene, zebraOffset, i, 4, 1); // Only East side
                    addStripes(scene, -zebraOffset, i, 4, 1); // West side
                }
            }
        },
        buildSignals: (scene, lightsObj, lanes) => {
            buildStandardGantry(scene, lightsObj, lanes, defaultHeadBuilder);
        }
    },

    "ROUNDABOUT": {
        name: "Roundabout AI Circle",
        phases: [0, 1, 2, 3], // Virtual signals dictating roundabout yield pressure
        getLanes: () => {
            const b = {
                0: { dir: new THREE.Vector3(0, 0, -1), rotY: Math.PI, spawn: new THREE.Vector3(0, 0, SPAWN_DIST), hasSignal: true },
                1: { dir: new THREE.Vector3(-1, 0, 0), rotY: -Math.PI / 2, spawn: new THREE.Vector3(SPAWN_DIST, 0, 0), hasSignal: true },
                2: { dir: new THREE.Vector3(0, 0, 1), rotY: 0, spawn: new THREE.Vector3(0, 0, -SPAWN_DIST), hasSignal: true },
                3: { dir: new THREE.Vector3(1, 0, 0), rotY: Math.PI / 2, spawn: new THREE.Vector3(-SPAWN_DIST, 0, 0), hasSignal: true },
            };
            Object.values(b).forEach(l => l.left = new THREE.Vector3(-l.dir.z, 0, l.dir.x).normalize());
            return b;
        },
        buildEnv: (scene) => {
            const gMat = new THREE.MeshPhongMaterial({ color: 0x8ca88b });
            const ground = new THREE.Mesh(new THREE.PlaneGeometry(240, 240), gMat);
            ground.rotation.x = -Math.PI / 2; ground.receiveShadow = true; scene.add(ground);

            const roadMat = new THREE.MeshPhongMaterial({ color: 0x777a81 });
            // Circle
            const circleGeo = new THREE.CylinderGeometry(18, 18, 0.15, 64);
            const circle = new THREE.Mesh(circleGeo, roadMat);
            circle.receiveShadow = true;
            scene.add(circle);

            // Inner Island
            const islandGeo = new THREE.CylinderGeometry(8, 8, 0.3, 32);
            const islandMat = new THREE.MeshPhongMaterial({ color: 0x4a6b49 });
            const island = new THREE.Mesh(islandGeo, islandMat);
            island.castShadow = true; island.receiveShadow = true;
            scene.add(island);

            const cross1 = new THREE.Mesh(new THREE.BoxGeometry(ROAD_W, 0.1, 240), roadMat);
            cross1.position.y = 0.05; cross1.receiveShadow = true; scene.add(cross1);
            const cross2 = new THREE.Mesh(new THREE.BoxGeometry(240, 0.1, ROAD_W), roadMat);
            cross2.position.y = 0.06; cross2.receiveShadow = true; scene.add(cross2);
        },
        buildSignals: (scene, lightsObj, lanes) => {
            // In a roundabout, signals are placed further back giving yielding signals
            buildStandardGantry(scene, lightsObj, lanes, defaultHeadBuilder);
        }
    },

    "FIVE_WAY": {
        name: "5-Way Star Junction",
        phases: [0, 1, 2, 3, 4], // 5 active lanes
        getLanes: () => {
            // Create 5 symmetrical lanes evenly spread over 360 deg
            const b = {};
            for (let i = 0; i < 5; i++) {
                const offsetAng = (i * Math.PI * 2) / 5;
                const dir = new THREE.Vector3(Math.sin(offsetAng), 0, Math.cos(offsetAng)).normalize(); // heading towards center (0,0,0)
                // However, our spawn points traditionally aim towards the center, so direction of movement:
                const moveDir = new THREE.Vector3(-Math.sin(offsetAng), 0, -Math.cos(offsetAng));
                const spawnPos = new THREE.Vector3(
                    Math.sin(offsetAng) * SPAWN_DIST,
                    0,
                    Math.cos(offsetAng) * SPAWN_DIST
                );

                b[i] = {
                    dir: moveDir,
                    rotY: Math.atan2(moveDir.x, moveDir.z),
                    spawn: spawnPos,
                    hasSignal: true
                };
            }
            Object.values(b).forEach(l => l.left = new THREE.Vector3(-l.dir.z, 0, l.dir.x).normalize());
            return b;
        },
        buildEnv: (scene) => {
            const gMat = new THREE.MeshPhongMaterial({ color: 0x8ca88b });
            const ground = new THREE.Mesh(new THREE.PlaneGeometry(240, 240), gMat);
            ground.rotation.x = -Math.PI / 2; ground.receiveShadow = true; scene.add(ground);

            const roadMat = new THREE.MeshPhongMaterial({ color: 0x777a81 });

            // Creating roads from center outward using Box/Cylinder
            const centerCircle = new THREE.Mesh(new THREE.CylinderGeometry(ROAD_W * 0.6, ROAD_W * 0.6, 0.12, 32), roadMat);
            centerCircle.receiveShadow = true; scene.add(centerCircle);

            for (let i = 0; i < 5; i++) {
                const offsetAng = (i * Math.PI * 2) / 5;
                const arm = new THREE.Mesh(new THREE.BoxGeometry(ROAD_W, 0.11, 120), roadMat);
                const spawnPos = new THREE.Vector3(Math.sin(offsetAng) * 60, 0, Math.cos(offsetAng) * 60);
                arm.position.copy(spawnPos);
                arm.rotation.y = offsetAng; // Align radially
                arm.receiveShadow = true; scene.add(arm);

                // Add crossing lines
                const cross = new THREE.Mesh(new THREE.BoxGeometry(ROAD_W, 0.14, 1.2), new THREE.MeshBasicMaterial({ color: 0xf2f2f2 }));
                const crossPos = new THREE.Vector3(Math.sin(offsetAng) * STOP_DIST, 0, Math.cos(offsetAng) * STOP_DIST);
                cross.position.copy(crossPos);
                cross.rotation.y = offsetAng;
                scene.add(cross);
            }
        },
        buildSignals: (scene, lightsObj, lanes) => {
            buildStandardGantry(scene, lightsObj, lanes, defaultHeadBuilder);
        }
    }
};
