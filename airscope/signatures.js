// Airscope classification engine: what a Bluetooth LE advertisement (or a
// Wi-Fi network name) most likely belongs to. Pure and dependency-light so it
// is unit-tested. Every result says how it was matched and how confident it is.
//
// Sources for byte-level signatures:
//  - Drone Remote ID: ASTM F3411-22a "Open Drone ID" over Bluetooth, service
//    data UUID 0xFFFA, application code 0x0D, 25-byte messages (layout as in
//    the opendroneid-core-c reference implementation).
//  - Eddystone beacons: Google's Eddystone spec, service data UUID 0xFEAA.
//  - Apple / Tile / Samsung / Google trackers: see ../scanner/trackers.js.
//  - Tesla vehicles: Tesla's vehicle-command BLE name "S" + 16 hex + "C".
// Name-keyword rules are labeled "possible": names can be set to anything.

import { classify as classifyTracker, normalizeAdvert, CONCERN } from "../scanner/trackers.js";

export const CATEGORIES = {
  drone: { label: "Drone", color: "#ff6b5a" },
  vehicle: { label: "Vehicle", color: "#f3b54a" },
  fleet: { label: "Fleet & telematics", color: "#e0a84f" },
  camera: { label: "Camera", color: "#ff8fd8" },
  publicsafety: { label: "Public-safety equipment", color: "#ff9d5c" },
  tracker: { label: "Tracker", color: "#ff7a6b" },
  infrastructure: { label: "Infrastructure & beacons", color: "#62c6ff" },
  wearable: { label: "Wearable", color: "#a78bfa" },
  audio: { label: "Audio", color: "#8fb8ff" },
  phone: { label: "Phone & computer", color: "#7fd6b4" },
  other: { label: "Other", color: "#8fa19b" },
  unknown: { label: "Unknown", color: "#5f706b" },
};

// ------------------------------------------------------------ Remote ID

const UA_TYPES = ["None", "Aeroplane", "Multirotor or helicopter", "Gyroplane", "Hybrid lift (VTOL)", "Ornithopter", "Glider", "Kite", "Free balloon", "Captive balloon", "Airship", "Parachute", "Rocket", "Tethered powered aircraft", "Ground obstacle", "Other"];
const ID_TYPES = ["None", "Serial number", "Registration ID", "UTM-assigned ID", "Session ID"];
const STATUS = ["Undeclared", "On ground", "Airborne", "Emergency", "Remote ID failure"];

const ascii = (b, from, len) => {
  let s = "";
  for (let i = from; i < from + len && i < b.length; i++) {
    if (b[i] === 0) break;
    if (b[i] >= 0x20 && b[i] < 0x7f) s += String.fromCharCode(b[i]);
  }
  return s.trim();
};
const i32 = (b, o) => b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24);
const u16 = (b, o) => b[o] | (b[o + 1] << 8);
const alt = (b, o) => {
  const v = u16(b, o);
  return v === 0 ? null : Math.round((v * 0.5 - 1000) * 10) / 10; // 0 = unknown
};
const coord = (b, o) => {
  const v = i32(b, o);
  return v === 0 ? null : v / 1e7;
};

/** Decode one 25-byte Open Drone ID message into `into`. */
function decodeMessage(m, into) {
  const type = m[0] >> 4;
  if (type === 0x0) {
    into.idType = ID_TYPES[m[1] >> 4] ?? `Type ${m[1] >> 4}`;
    into.uaType = UA_TYPES[m[1] & 0x0f];
    into.uasId = ascii(m, 2, 20) || null;
  } else if (type === 0x1) {
    const flags = m[1];
    into.status = STATUS[flags >> 4] ?? `Status ${flags >> 4}`;
    const ew = (flags >> 1) & 1;
    const mult = flags & 1;
    const dir = m[2] + (ew ? 180 : 0);
    into.heading = m[2] > 180 ? null : dir;
    into.speed = m[3] === 255 ? null : mult ? m[3] * 0.75 + 255 * 0.25 : m[3] * 0.25; // m/s
    const vs = (m[4] << 24) >> 24;
    into.verticalSpeed = vs === 63 ? null : vs * 0.5;
    const lat = coord(m, 5);
    const lon = coord(m, 9);
    if (lat != null && lon != null && Math.abs(lat) <= 90 && Math.abs(lon) <= 180) {
      into.latitude = lat;
      into.longitude = lon;
    }
    into.altitudeBaro = alt(m, 13);
    into.altitudeGeo = alt(m, 15);
    into.height = alt(m, 17);
    into.heightRef = (flags >> 2) & 1 ? "above ground" : "above takeoff";
  } else if (type === 0x3) {
    into.description = ascii(m, 2, 23) || null;
  } else if (type === 0x4) {
    const lat = coord(m, 2);
    const lon = coord(m, 6);
    if (lat != null && lon != null && Math.abs(lat) <= 90 && Math.abs(lon) <= 180) {
      into.operatorLatitude = lat;
      into.operatorLongitude = lon;
    }
  } else if (type === 0x5) {
    into.operatorId = ascii(m, 2, 20) || null;
  }
  return type;
}

/**
 * Decode Remote ID service data (UUID 0xFFFA): [0x0D app code, counter, message].
 * Returns null when the data isn't Remote ID.
 */
export function decodeRemoteId(bytes) {
  if (!bytes || bytes.length < 3 || bytes[0] !== 0x0d) return null;
  const msg = bytes.subarray(2);
  const out = { counter: bytes[1], messages: [] };
  if (msg[0] >> 4 === 0xf) {
    // Message pack: [header, size, count, messages...]
    const size = msg[1] || 25;
    const count = msg[2];
    for (let i = 0; i < count; i++) {
      const m = msg.subarray(3 + i * size, 3 + (i + 1) * size);
      if (m.length < size) break;
      out.messages.push(decodeMessage(m, out));
    }
  } else if (msg.length >= 25) {
    out.messages.push(decodeMessage(msg, out));
  } else {
    return null;
  }
  return out;
}

// ------------------------------------------------------------ Eddystone

const EDDY_SCHEMES = ["http://www.", "https://www.", "http://", "https://"];
const EDDY_EXP = [".com/", ".org/", ".edu/", ".net/", ".info/", ".biz/", ".gov/", ".com", ".org", ".edu", ".net", ".info", ".biz", ".gov"];

export function decodeEddystone(b) {
  if (!b || !b.length) return null;
  const frame = b[0];
  if (frame === 0x10 && b.length >= 3) {
    let url = EDDY_SCHEMES[b[2]] ?? "";
    for (let i = 3; i < b.length; i++) url += b[i] < EDDY_EXP.length ? EDDY_EXP[b[i]] : String.fromCharCode(b[i]);
    return { frame: "URL", url, txPower: (b[1] << 24) >> 24 };
  }
  if (frame === 0x00 && b.length >= 18) {
    const hex = (from, to) => [...b.subarray(from, to)].map((x) => x.toString(16).padStart(2, "0")).join("");
    return { frame: "UID", namespace: hex(2, 12), instance: hex(12, 18) };
  }
  if (frame === 0x20) return { frame: "TLM" };
  if (frame === 0x30) return { frame: "EID" };
  return null;
}

// ------------------------------------------------------------ rules

const COMPANY = {
  0x004c: ["Apple", "phone"], 0x0006: ["Microsoft", "phone"], 0x0075: ["Samsung", "phone"], 0x00e0: ["Google", "phone"],
  0x0087: ["Garmin", "wearable"], 0x0157: ["Huami / Amazfit", "wearable"], 0x038f: ["Xiaomi", "wearable"], 0x006b: ["Polar", "wearable"],
  0x009e: ["Bose", "audio"], 0x012d: ["Sony", "audio"], 0x0057: ["Harman (JBL)", "audio"], 0x00c7: ["Tile", "tracker"],
  0x0059: ["Nordic Semiconductor (module)", "other"], 0x02e5: ["Espressif (ESP32 module)", "other"],
};

const NAME_RULES = [
  { re: /^S[0-9a-f]{16}[CDPR]$/i, category: "vehicle", label: "Tesla vehicle", confidence: "likely", reason: "Tesla vehicle Bluetooth name format (S + 16 hex + letter)." },
  { re: /\b(dji|mavic|phantom|tello|autel|skydio|parrot|anafi|fimi)\b/i, category: "drone", label: "Drone or controller (by name)", confidence: "possible" },
  { re: /\b(geotab|samsara|calamp|verizon ?connect|motive|keeptruckin|lytx|omnitracs|teletrac|zonar|gps ?trackit|fleet|eld)\b/i, category: "fleet", label: "Fleet telematics (by name)", confidence: "possible" },
  { re: /\b(axon|body ?cam|bodyworn|watchguard|signal sidearm)\b/i, category: "publicsafety", label: "Body camera or public-safety device (by name)", confidence: "possible" },
  { re: /\b(dash ?cam|gopro|insta360|blackvue|nextbase|vantrue|viofo|ipc|ipcam|camera)\b/i, category: "camera", label: "Camera (by name)", confidence: "possible" },
  { re: /\b(carplay|uconnect|sync|mbux|my car|onstar|bmw|audi|vw|volkswagen|toyota|lexus|honda|acura|hyundai|kia|nissan|subaru|mazda|ford|chevrolet|chevy|gmc|cadillac|jeep|dodge|volvo|porsche|rivian|lucid|mercedes|jaguar|land rover|buick|polestar)\b/i, category: "vehicle", label: "Vehicle (by name)", confidence: "possible" },
  { re: /\b(chargepoint|evgo|electrify|wallbox|juicebox|charger|parking|meter|kiosk|transit|bus stop|scooter|lime|bird)\b/i, category: "infrastructure", label: "Infrastructure (by name)", confidence: "possible" },
  { re: /\b(watch|band|fitbit|whoop|oura|garmin|amazfit|mi band)\b/i, category: "wearable", label: "Wearable (by name)", confidence: "possible" },
  { re: /\b(airpods|beats|buds|headphones|earbuds|speaker|soundbar|jbl|bose|sony)\b/i, category: "audio", label: "Audio device (by name)", confidence: "possible" },
];

const TRACKER_TO_CATEGORY = { tracker: "tracker", camera: "camera", audio: "audio", phone: "phone", beacon: "infrastructure", media: "other", other: "other", unknown: "unknown" };

/**
 * Classify an advertisement. Returns
 * { category, label, vendor, confidence, reason, concern, details }.
 */
export function classifyAdvert(raw) {
  const a = raw.manufacturer instanceof Map ? raw : normalizeAdvert(raw);

  // Drone Remote ID (public by regulation in the US, EU and elsewhere).
  const rid = decodeRemoteId(a.service.get("fffa"));
  if (rid) {
    const kind = rid.uaType && rid.uaType !== "None" ? rid.uaType : "Drone";
    return {
      category: "drone",
      label: rid.uasId ? `${kind} · ${rid.uasId}` : `${kind} (Remote ID)`,
      vendor: null,
      confidence: "certain",
      reason: "Broadcast Remote ID (ASTM F3411) over Bluetooth.",
      concern: "medium",
      details: { remoteId: rid },
    };
  }

  // Eddystone beacons (FMDN trackers share UUID 0xFEAA; trackers.js handles those).
  const feaa = a.service.get("feaa");
  const eddy = feaa && feaa[0] !== 0x40 && feaa[0] !== 0x41 ? decodeEddystone(feaa) : null;
  if (eddy) {
    return { category: "infrastructure", label: `Eddystone beacon (${eddy.frame})`, vendor: null, confidence: "certain", reason: "Eddystone beacon frame.", concern: "none", details: { eddystone: eddy } };
  }
  // AltBeacon: manufacturer data beginning 0xBE 0xAC.
  for (const [company, d] of a.manufacturer) {
    if (d[0] === 0xbe && d[1] === 0xac) return { category: "infrastructure", label: "AltBeacon", vendor: COMPANY[company]?.[0] ?? null, confidence: "certain", reason: "AltBeacon advertisement.", concern: "none", details: {} };
  }
  if (a.service.has("fd6f")) return { category: "phone", label: "Exposure Notification (phone)", vendor: null, confidence: "certain", reason: "Exposure Notification service (0xFD6F).", concern: "none", details: {} };

  // Trackers and Apple device types (shared with Signal Sweep).
  const t = classifyTracker(a);
  if (t.category === "tracker" || (t.vendor === "Apple" && t.category !== "other")) {
    return { category: TRACKER_TO_CATEGORY[t.category] ?? "other", label: t.label, vendor: t.vendor, confidence: t.confidence, reason: t.reason, concern: t.concern, details: {} };
  }

  if (a.name) {
    for (const r of NAME_RULES) {
      if (r.re.test(a.name)) {
        return { category: r.category, label: r.label, vendor: null, confidence: r.confidence, reason: r.reason ?? `Name "${a.name}" matches ${CATEGORIES[r.category].label.toLowerCase()} keywords.`, concern: r.category === "publicsafety" || r.category === "drone" ? "medium" : "none", details: {} };
      }
    }
  }

  for (const company of a.manufacturer.keys()) {
    const c = COMPANY[company];
    if (c) return { category: c[1], label: `${c[0]} device`, vendor: c[0], confidence: "likely", reason: `Manufacturer data from ${c[0]} (company ID 0x${company.toString(16).padStart(4, "0")}).`, concern: "none", details: {} };
  }
  const company = [...a.manufacturer.keys()][0];
  return {
    category: "unknown",
    label: a.name ? a.name : "Unnamed device",
    vendor: company != null ? `Company 0x${company.toString(16).padStart(4, "0")}` : null,
    confidence: "unknown",
    reason: "No matching signature.",
    concern: "none",
    details: {},
  };
}

/** Classify a Wi-Fi network name (typed or pasted on iPhone; scanned elsewhere). */
const SSID_RULES = [
  { re: /^(dji|mavic|phantom|tello|anafi|skydio|autel)[-_ ]/i, category: "drone", label: "Drone Wi-Fi" },
  { re: /^(ibr\d|cradlepoint|cp[-_ ]?\w+|sierra[-_ ]?wireless|airlink|mg90|digi[-_ ]?\w+|inseego|mifi)/i, category: "fleet", label: "Vehicle or mobile router" },
  { re: /(geotab|samsara|fleet|eld|truck)/i, category: "fleet", label: "Fleet telematics" },
  { re: /(tesla|fordpass|onstar|my ?car|uconnect|bmw|audi|vw[-_ ]|toyota|hyundai|kia|carplay)/i, category: "vehicle", label: "Vehicle hotspot" },
  { re: /(axon|watchguard|body ?cam)/i, category: "publicsafety", label: "Public-safety equipment" },
  { re: /^(ipc|ipcam|hd[-_ ]?cam|wifi[-_ ]?cam|v380|yoosee|icsee|xmeye|lookcam|dashcam|gopro|blackvue|insta360)/i, category: "camera", label: "Camera hotspot" },
  { re: /(chargepoint|evgo|electrify|parking|transit|kiosk|xfinitywifi|attwifi|guest)/i, category: "infrastructure", label: "Public or infrastructure network" },
];

export function classifySsid(ssid) {
  const s = String(ssid ?? "").trim();
  if (!s) return null;
  for (const r of SSID_RULES) if (r.re.test(s)) return { ssid: s, category: r.category, label: r.label, confidence: "possible" };
  return { ssid: s, category: "unknown", label: "No match", confidence: "unknown" };
}

export { CONCERN };
