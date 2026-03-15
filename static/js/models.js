import * as THREE from "three";
import { GLTFLoader } from "three/addons/loaders/GLTFLoader.js";
import { TYPE, TYPE_DIMENSIONS } from "./constants.js";

const vehicleModelStore = {
    ready: false,
    templates: {},
};

const localModelUrls = {
    car: [
        "/static/models/2016_mercedes-benz_gle63_amg_coupe.glb",
        "/static/models/spy-hypersport.glb",
    ],
    bus: [
        "/static/models/bus.glb",
        "/static/models/japanese_bus_nagoya_city_bus_aichi.glb",
    ],
    bike: [
        "/static/models/honda_shadow_rs_2010.glb",
        "/static/models/honda_cb_750_f_super_sport_1970.glb",
    ],
    ambulance: [
        "/static/models/shvan_92_ambulance_-_low_poly_model.glb",
    ],
};

const MAT_CACHE = {
    glass: new THREE.MeshPhongMaterial({ color: 0x8ec8ff, transparent: true, opacity: 0.86 }),
    tire: new THREE.MeshPhongMaterial({ color: 0x1a1a1a }),
    headlight: new THREE.MeshBasicMaterial({ color: 0xfafafa }),
    taillight: new THREE.MeshBasicMaterial({ color: 0xff2b2b }),
    ambBar: new THREE.MeshBasicMaterial({ color: 0xd3001b })
};
Object.values(MAT_CACHE).forEach(m => m.isShared = true);

const GEO_CACHE = {};
function getGeo(type, w, h, d) {
    const key = `${type}_${w}_${h}_${d}`;
    if (!GEO_CACHE[key]) {
        if (type === 'box') GEO_CACHE[key] = new THREE.BoxGeometry(w, h, d);
        else GEO_CACHE[key] = new THREE.CylinderGeometry(w, h, d, 10);
        GEO_CACHE[key].isShared = true;
    }
    return GEO_CACHE[key];
}

export function brighten(hex, amount) {
    const c = new THREE.Color(hex);
    const r = Math.min(1, c.r + amount / 255);
    const g = Math.min(1, c.g + amount / 255);
    const b = Math.min(1, c.b + amount / 255);
    return new THREE.Color(r, g, b).getHex();
}

export function randColor() {
    const palette = [0x2aa2ff, 0x1fc96d, 0xffb347, 0xd275ff, 0x32d2d5, 0xe65d5d, 0x3f6fff];
    return palette[Math.floor(Math.random() * palette.length)];
}

function buildProceduralVehicle(type, bodyColor) {
    const group = new THREE.Group();
    let width = 1.8;
    let length = 4.0;
    let height = 1.2;
    let roofScale = 0.68;

    if (type === TYPE.BIKE) {
        width = 0.8;
        length = 2.0;
        height = 0.7;
        roofScale = 0.52;
    } else if (type === TYPE.AUTO) {
        width = 1.4;
        length = 2.8;
        height = 1.25;
        roofScale = 0.72;
    } else if (type === TYPE.BUS) {
        width = 2.5;
        length = 9.0;
        height = 2.2;
        roofScale = 0.84;
    } else if (type === TYPE.AMBULANCE) {
        width = 2.0;
        length = 5.2;
        height = 1.7;
        roofScale = 0.75;
    } else if (type === TYPE.VIP) {
        width = 1.9;
        length = 4.4;
        height = 1.2;
        roofScale = 0.68;
    }

    const darkBody = brighten(bodyColor, -30);
    const bodyMat = new THREE.MeshPhongMaterial({ color: bodyColor });
    const trimMat = new THREE.MeshPhongMaterial({ color: darkBody });
    const glassMat = MAT_CACHE.glass;
    const tireMat = MAT_CACHE.tire;

    const body = new THREE.Mesh(
        getGeo('box', width, Math.max(0.35, height * 0.45), length),
        bodyMat
    );
    body.position.y = Math.max(0.2, height * 0.225);
    body.castShadow = true;
    body.receiveShadow = true;
    group.add(body);

    if (type !== TYPE.BIKE) {
        const roof = new THREE.Mesh(
            getGeo('box', width * 0.72, Math.max(0.22, height * 0.35), length * roofScale),
            trimMat
        );
        roof.position.y = body.position.y + Math.max(0.24, height * 0.34);
        roof.position.z = length * 0.03;
        roof.castShadow = true;
        roof.receiveShadow = true;
        group.add(roof);
    }

    const glass = new THREE.Mesh(
        getGeo('box', width * (type === TYPE.BIKE ? 0.35 : 0.56), Math.max(0.12, height * 0.12), length * 0.2),
        glassMat
    );
    glass.position.set(0, body.position.y + Math.max(0.18, height * 0.24), length * 0.08);
    group.add(glass);

    const wheelRadius = type === TYPE.BIKE ? 0.2 : Math.max(0.2, width * 0.16);
    const wheelDepth = type === TYPE.BIKE ? 0.16 : 0.22;
    const wheelY = wheelRadius;
    const wheelX = Math.max(0.28, width * 0.44);
    const wheelZ = Math.max(0.45, length * 0.34);
    const wheelGeo = getGeo('cyl', wheelRadius, wheelRadius, wheelDepth);
    const wheels = [];
    const addWheel = (x, z) => {
        const w = new THREE.Mesh(wheelGeo, tireMat);
        w.rotation.z = Math.PI / 2;
        w.position.set(x, wheelY, z);
        w.castShadow = true;
        wheels.push(w);
        group.add(w);
    };
    addWheel(-wheelX, wheelZ);
    addWheel(wheelX, wheelZ);
    if (type !== TYPE.BIKE) {
        addWheel(-wheelX, -wheelZ);
        addWheel(wheelX, -wheelZ);
    } else {
        addWheel(0, -wheelZ);
    }

    const headLight = new THREE.Mesh(
        getGeo('box', Math.max(0.2, width * 0.22), 0.08, 0.08),
        MAT_CACHE.headlight
    );
    headLight.position.set(0, body.position.y * 0.9, length * 0.5 + 0.01);
    group.add(headLight);

    const tailLight = new THREE.Mesh(
        getGeo('box', Math.max(0.2, width * 0.22), 0.08, 0.08),
        MAT_CACHE.taillight
    );
    tailLight.position.set(0, body.position.y * 0.9, -length * 0.5 - 0.01);
    group.add(tailLight);

    if (type === TYPE.AMBULANCE) {
        const bar = new THREE.Mesh(
            getGeo('box', width * 0.46, 0.12, 0.24),
            MAT_CACHE.ambBar
        );
        bar.position.y = body.position.y + Math.max(0.36, height * 0.48);
        bar.castShadow = true;
        group.add(bar);
    }

    return { group, width, length, wheels, bodyY: body.position.y, minYLocal: 0.0 };
}

function loadGltfModel(url) {
    const loader = new GLTFLoader();
    return new Promise((resolve, reject) => {
        loader.load(url, (gltf) => resolve(gltf.scene), undefined, reject);
    });
}

function normalizeObjectToRoad(obj, target) {
    obj.updateMatrixWorld(true);
    let box = new THREE.Box3().setFromObject(obj);
    let size = box.getSize(new THREE.Vector3());
    if (size.z <= 0 || size.x <= 0 || size.y <= 0) return obj;

    if (size.x > size.z) {
        obj.rotation.y += Math.PI / 2;
        obj.updateMatrixWorld(true);
        box = new THREE.Box3().setFromObject(obj);
        size = box.getSize(new THREE.Vector3());
    }

    let s = target.length / Math.max(size.z, 0.001);
    if (size.x * s > target.width * 1.25) s *= (target.width * 1.25) / (size.x * s);
    if (size.y * s > target.height * 1.4) s *= (target.height * 1.4) / (size.y * s);
    obj.scale.multiplyScalar(s);

    obj.updateMatrixWorld(true);
    const box2 = new THREE.Box3().setFromObject(obj);
    const center = box2.getCenter(new THREE.Vector3());
    obj.position.x -= center.x;
    obj.position.z -= center.z;
    obj.position.y -= box2.min.y;
    obj.updateMatrixWorld(true);
    return obj;
}

function enforceTypeDimensions(obj, target) {
    obj.updateMatrixWorld(true);
    let box = new THREE.Box3().setFromObject(obj);
    let size = box.getSize(new THREE.Vector3());
    if (size.z <= 0 || size.x <= 0 || size.y <= 0) return;

    if (size.x > size.z) {
        obj.rotation.y += Math.PI / 2;
        obj.updateMatrixWorld(true);
        box = new THREE.Box3().setFromObject(obj);
        size = box.getSize(new THREE.Vector3());
    }

    let s = target.length / Math.max(size.z, 0.001);
    if (size.x * s > target.width * 1.15) s *= (target.width * 1.15) / (size.x * s);
    if (size.y * s > target.height * 1.2) s *= (target.height * 1.2) / (size.y * s);
    obj.scale.multiplyScalar(s);

    obj.updateMatrixWorld(true);
    const box2 = new THREE.Box3().setFromObject(obj);
    const center = box2.getCenter(new THREE.Vector3());
    obj.position.x -= center.x;
    obj.position.z -= center.z;
    obj.position.y -= box2.min.y;
    obj.updateMatrixWorld(true);
}

function computeLocalMinY(group) {
    const box = new THREE.Box3().setFromObject(group);
    if (!Number.isFinite(box.min.y)) return 0;
    return box.min.y;
}

function applyModelMaterial(root, colorHex) {
    root.traverse((n) => {
        if (!n.isMesh) return;
        if (!n.geometry.attributes.normal) {
            n.geometry.computeVertexNormals();
        }

        const applyToMaterial = (mat) => {
            if (!mat) return mat;
            const localMat = mat.clone();
            const hasTexture = !!mat.map;

            if (!hasTexture) {
                localMat.color = new THREE.Color(colorHex);
            }

            if (localMat.map) localMat.map.colorSpace = THREE.SRGBColorSpace;
            if (localMat.emissiveMap) localMat.emissiveMap.colorSpace = THREE.SRGBColorSpace;
            localMat.side = THREE.FrontSide;
            localMat.needsUpdate = true;
            return localMat;
        };

        if (Array.isArray(n.material)) {
            n.material = n.material.map((m) => applyToMaterial(m));
        } else {
            n.material = applyToMaterial(n.material);
        }

        n.castShadow = true;
        n.receiveShadow = true;
    });
}

export async function initVehicleModels() {
    const specs = {
        [TYPE.CAR]: { urls: localModelUrls.car, dims: { width: 1.9, length: 4.4, height: 1.45 } },
        [TYPE.BUS]: { urls: localModelUrls.bus, dims: { width: 2.6, length: 9.6, height: 3.0 } },
        [TYPE.BIKE]: { urls: localModelUrls.bike, dims: { width: 0.8, length: 2.1, height: 1.35 } },
        [TYPE.AMBULANCE]: { urls: localModelUrls.ambulance, dims: { width: 2.1, length: 5.4, height: 2.6 } },
    };

    vehicleModelStore.templates = {
        [TYPE.CAR]: [],
        [TYPE.BUS]: [],
        [TYPE.BIKE]: [],
        [TYPE.AMBULANCE]: [],
    };

    const entries = Object.entries(specs);
    const loaded = await Promise.all(entries.map(async ([k, v]) => {
        let ok = false;
        for (const url of v.urls) {
            try {
                const scene = await loadGltfModel(url);
                scene.traverse((n) => {
                    if (n.isMesh && n.geometry) n.geometry.isShared = true;
                });
                normalizeObjectToRoad(scene, v.dims);
                vehicleModelStore.templates[k].push(scene);
                ok = true;
            } catch (err) {
                console.warn("Model load failed:", url, err);
            }
        }
        return ok;
    }));

    vehicleModelStore.ready = loaded.some(Boolean);
}

export function cloneVehicleModelOrFallback(type, bodyColor) {
    let baseType = type;
    if (type === TYPE.AUTO || type === TYPE.VIP) baseType = TYPE.CAR;
    const pool = vehicleModelStore.templates[baseType] || [];

    // Only allow cars to fallback to cars. Let bikes naturally fail down to procedural bikes if glb is missing.
    const template = pool.length > 0 ? pool[Math.floor(Math.random() * pool.length)] : null;
    if (!template) {
        return buildProceduralVehicle(type, bodyColor);
    }

    const group = new THREE.Group();
    const model = template.clone(true);
    applyModelMaterial(model, bodyColor);
    group.add(model);

    const fitDims = TYPE_DIMENSIONS[type] || TYPE_DIMENSIONS[TYPE.CAR];
    enforceTypeDimensions(model, fitDims);

    let length = 4.2;
    if (type === TYPE.BUS) length = 9.4;
    if (type === TYPE.BIKE) length = 2.1;
    if (type === TYPE.AUTO) length = 3.0;
    if (type === TYPE.AMBULANCE) length = 5.1;

    if (type === TYPE.AMBULANCE) {
        const bar = new THREE.Mesh(
            new THREE.BoxGeometry(0.8, 0.15, 0.24),
            new THREE.MeshBasicMaterial({ color: 0xd8001d })
        );
        bar.position.y = 1.8;
        group.add(bar);
    }
    if (type === TYPE.AUTO) {
        const top = new THREE.Mesh(
            new THREE.BoxGeometry(1.2, 0.55, 1.4),
            new THREE.MeshStandardMaterial({ color: 0x101010, roughness: 0.7 })
        );
        top.position.y = 1.3;
        group.add(top);
    }

    return { group, width: 1.8, length, wheels: [], bodyY: 0.8, minYLocal: computeLocalMinY(group) };
}
