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
  alpr: { label: "License-plate camera", color: "#ff4fa3" },
  network: { label: "Wi-Fi network", color: "#4f8fbf" },
  unknown: { label: "Unknown", color: "#5f706b" },
};

// ------------------------------------------------------------ addresses

/**
 * Manufacturer address prefixes (IEEE OUIs) with a known meaning. Only
 * prefixes with a clear association are listed, as "likely" matches; add
 * more as custom signatures in the app.
 */
export const OUI = {
  "00:25:DF": ["publicsafety", "Axon device (body camera, TASER or Signal)", "Axon Enterprise"],
  "00:30:44": ["fleet", "Cradlepoint vehicle router", "Cradlepoint"],
  "00:A0:D5": ["fleet", "Sierra Wireless AirLink router", "Sierra Wireless"],
  "60:60:1F": ["drone", "DJI drone or controller", "DJI"],
  "4C:FC:AA": ["vehicle", "Tesla vehicle", "Tesla"],
};
const VEHICLE_ROUTER_NOTE = " Rugged routers like this are standard in police, fire, EMS, transit and utility fleet vehicles.";

export function ouiOf(mac) {
  const m = /^([0-9a-f]{2})[:-]?([0-9a-f]{2})[:-]?([0-9a-f]{2})/i.exec(mac ?? "");
  return m ? `${m[1]}:${m[2]}:${m[3]}`.toUpperCase() : null;
}

/** Locally administered addresses are randomized and say nothing about the maker. */
export function isRandomizedMac(mac) {
  const first = parseInt(String(mac ?? "").slice(0, 2), 16);
  return Number.isFinite(first) && (first & 0x02) === 0x02;
}

function ouiMatch(mac) {
  if (!mac || isRandomizedMac(mac)) return null;
  const hit = OUI[ouiOf(mac)];
  if (!hit) return null;
  const [category, label, maker] = hit;
  return { category, label, vendor: maker, confidence: "likely", reason: `Hardware address prefix ${ouiOf(mac)} belongs to ${maker}.${category === "fleet" ? VEHICLE_ROUTER_NOTE : ""}`, concern: category === "publicsafety" || category === "drone" ? "medium" : "none", details: {} };
}

// ------------------------------------------------------------ custom signatures

/** User-defined signatures: { kind: "mac" | "name", value, category, label }. */
let custom = [];
export function setCustomSignatures(list) {
  custom = (list ?? []).filter((r) => r && r.value && CATEGORIES[r.category]).map((r) => {
    let test;
    if (r.kind === "mac") {
      const prefix = String(r.value).toLowerCase().replace(/[^0-9a-f]/g, "");
      test = ({ mac }) => !!mac && mac.toLowerCase().replace(/[^0-9a-f]/g, "").startsWith(prefix);
    } else {
      const m = /^\/(.+)\/([a-z]*)$/.exec(r.value);
      let re = null;
      if (m) { try { re = new RegExp(m[1], m[2].includes("i") ? m[2] : `${m[2]}i`); } catch { re = null; } }
      const needle = String(r.value).toLowerCase();
      test = ({ name }) => !!name && (re ? re.test(name) : name.toLowerCase().includes(needle));
    }
    return { ...r, test };
  });
}
function customMatch(fields) {
  const r = custom.find((x) => x.test(fields));
  return r ? { category: r.category, label: r.label || CATEGORIES[r.category].label, vendor: null, confidence: "custom", reason: `Matches your custom signature "${r.value}".`, concern: "medium", details: {} } : null;
}

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
  { re: /flock/i, category: "alpr", label: "Possible Flock Safety camera (by name)", confidence: "possible" },
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
  const mine = customMatch({ mac: a.mac, name: a.name });
  if (mine) return mine;

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

  const byAddress = ouiMatch(a.mac);
  if (byAddress) return byAddress;

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
  { re: /^(ibr\d{3,4}|r1900|r920|e300|e3000|cba850|aer\d{4}|cradlepoint)/i, category: "fleet", label: "Cradlepoint vehicle router", note: VEHICLE_ROUTER_NOTE },
  { re: /\b(mp70|rv50x?|rv55|lx40|lx60|xr80|xr90|airlink|sierra[-_ ]?wireless)\b/i, category: "fleet", label: "Sierra Wireless AirLink vehicle router", note: VEHICLE_ROUTER_NOTE },
  { re: /flock/i, category: "alpr", label: "Possible Flock Safety camera" },
  { re: /^(mg90|digi[-_ ]?\w+|inseego|mifi)/i, category: "fleet", label: "Vehicle or mobile router" },
  { re: /(geotab|samsara|fleet|eld|truck)/i, category: "fleet", label: "Fleet telematics" },
  { re: /(tesla|fordpass|onstar|my ?car|uconnect|bmw|audi|vw[-_ ]|toyota|hyundai|kia|carplay)/i, category: "vehicle", label: "Vehicle hotspot" },
  { re: /(axon|watchguard|body ?cam)/i, category: "publicsafety", label: "Public-safety equipment" },
  { re: /^(ipc|ipcam|hd[-_ ]?cam|wifi[-_ ]?cam|v380|yoosee|icsee|xmeye|lookcam|dashcam|gopro|blackvue|insta360)/i, category: "camera", label: "Camera hotspot" },
  { re: /^(iphone|galaxy|pixel|androidap|oneplus|redmi|moto)/i, category: "phone", label: "Phone hotspot" },
  { re: /(chargepoint|evgo|electrify|parking|transit|kiosk|xfinitywifi|attwifi|guest)/i, category: "infrastructure", label: "Public or infrastructure network" },
];

export function classifySsid(ssid) {
  const s = String(ssid ?? "").trim();
  if (!s) return null;
  for (const r of SSID_RULES) if (r.re.test(s)) return { ssid: s, category: r.category, label: r.label, confidence: "possible", note: r.note ?? "" };
  return { ssid: s, category: "unknown", label: "No match", confidence: "unknown" };
}

/** Wi-Fi security summary from Android's capability string, e.g. "[WPA2-PSK-CCMP][ESS]". */
export function wifiSecurity(capabilities = "") {
  const c = String(capabilities);
  if (/WPA3|SAE/.test(c)) return "WPA3";
  if (/WPA2|RSN/.test(c)) return "WPA2";
  if (/WPA/.test(c)) return "WPA";
  if (/WEP/.test(c)) return "WEP";
  return /OWE/.test(c) ? "Enhanced Open" : "Open";
}

export function wifiBand(mhz) {
  if (!mhz) return null;
  if (mhz >= 5925) return "6 GHz";
  if (mhz >= 4900) return "5 GHz";
  return "2.4 GHz";
}

const hexBytes = (h) => Uint8Array.from((String(h).match(/[0-9a-f]{2}/gi) ?? []).map((b) => parseInt(b, 16)));

/**
 * Classify a Wi-Fi access point { bssid, ssid, rssi, frequency, capabilities,
 * vendorIes: [hex] }. Vendor information elements may carry drone Remote ID
 * (OUI FA:0B:BC, type 0x0D).
 */
export function classifyWifi(n) {
  const ssid = String(n.ssid ?? "").trim();
  const details = { ssid: ssid || null, band: wifiBand(n.frequency), security: wifiSecurity(n.capabilities), randomized: isRandomizedMac(n.bssid) };
  for (const ie of n.vendorIes ?? []) {
    const b = hexBytes(ie);
    if (b[0] === 0xfa && b[1] === 0x0b && b[2] === 0xbc && b[3] === 0x0d) {
      const rid = decodeRemoteId(b.subarray(3));
      if (rid) return { category: "drone", label: rid.uasId ? `Drone · ${rid.uasId}` : "Drone (Wi-Fi Remote ID)", vendor: null, confidence: "certain", reason: "Broadcast Remote ID (ASTM F3411) in Wi-Fi beacons.", concern: "medium", details: { ...details, remoteId: rid } };
    }
  }
  const mine = customMatch({ mac: n.bssid, name: ssid });
  if (mine) return { ...mine, details };
  const byAddress = ouiMatch(n.bssid);
  if (byAddress) return { ...byAddress, details };
  const s = classifySsid(ssid);
  if (s && s.category !== "unknown") {
    return { category: s.category, label: s.label, vendor: null, confidence: "possible", reason: `Network name "${ssid}" matches ${CATEGORIES[s.category].label.toLowerCase()} patterns.${s.note ?? ""}`, concern: s.category === "publicsafety" || s.category === "alpr" || s.category === "drone" ? "medium" : "none", details };
  }
  return { category: "network", label: ssid || "Hidden network", vendor: null, confidence: "certain", reason: `${details.security} Wi-Fi network on ${details.band ?? "an unknown band"}.`, concern: "none", details };
}

export { CONCERN };
