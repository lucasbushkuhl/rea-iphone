// Identify Bluetooth LE devices from their advertisements. Pure and
// dependency-free so it can be unit-tested.
//
// The formats used here are documented in public research and vendor specs:
//  - Apple Find My "offline finding" advertisements (manufacturer 0x004C,
//    type 0x12): Heinrich et al., "Who Can Find My Devices?" (PETS 2021), and
//    the AirGuard project (TU Darmstadt). A 25-byte payload means the device
//    is separated from its owner; 2 bytes means its owner is nearby.
//  - Google Find My Device network: service data UUID 0xFEAA, frame types
//    0x40 / 0x41 (0x41 = unwanted-tracking protection mode).
//  - Samsung SmartTag: service data UUID 0xFD5A. Tile: 0xFEED / 0xFEEC.
//    Chipolo: 0xFE33. Bluetooth SIG assigned numbers.
// Classifications are best effort and say how confident they are.

export const CONCERN = { high: 3, medium: 2, low: 1, none: 0 };

const COMPANY = {
  0x004c: "Apple",
  0x0006: "Microsoft",
  0x0075: "Samsung",
  0x00e0: "Google",
  0x0157: "Huami (Amazfit)",
  0x038f: "Xiaomi",
  0x0087: "Garmin",
  0x0059: "Nordic Semiconductor",
  0x02e5: "Espressif",
};

/** "0000feed-0000-1000-8000-00805f9b34fb" -> "feed"; leaves other UUIDs whole. */
export function shortUuid(uuid) {
  const u = String(uuid).toLowerCase();
  const m = /^0000([0-9a-f]{4})-0000-1000-8000-00805f9b34fb$/.exec(u);
  if (m) return m[1];
  if (/^[0-9a-f]{4}$/.test(u)) return u;
  if (/^0x[0-9a-f]{4}$/.test(u)) return u.slice(2);
  return u;
}

const toBytes = (v) => {
  if (!v) return new Uint8Array(0);
  if (v instanceof Uint8Array) return v;
  if (v instanceof DataView) return new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
  if (ArrayBuffer.isView(v)) return new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
  if (v instanceof ArrayBuffer) return new Uint8Array(v);
  if (Array.isArray(v)) return Uint8Array.from(v);
  return new Uint8Array(0);
};

/**
 * Normalize an advertisement from Web Bluetooth (Maps of DataView) or a plain
 * object into { id, name, rssi, txPower, manufacturer: Map<number, Uint8Array>,
 * service: Map<string, Uint8Array>, uuids: string[] } with 16-bit UUIDs short.
 */
export function normalizeAdvert(a) {
  const manufacturer = new Map();
  const md = a.manufacturerData;
  if (md instanceof Map) for (const [k, v] of md) manufacturer.set(Number(k), toBytes(v));
  else if (md) for (const [k, v] of Object.entries(md)) manufacturer.set(Number(k), toBytes(v));
  const service = new Map();
  const sd = a.serviceData;
  if (sd instanceof Map) for (const [k, v] of sd) service.set(shortUuid(k), toBytes(v));
  else if (sd) for (const [k, v] of Object.entries(sd)) service.set(shortUuid(k), toBytes(v));
  const uuids = (a.uuids ?? []).map(shortUuid);
  return {
    id: a.id ?? a.device?.id ?? null,
    name: a.name ?? a.device?.name ?? null,
    rssi: typeof a.rssi === "number" ? a.rssi : null,
    txPower: typeof a.txPower === "number" ? a.txPower : null,
    manufacturer,
    service,
    uuids,
    mac: a.mac ?? null,
  };
}

const APPLE_FINDMY_TYPES = {
  0: "Apple device (iPhone, iPad, Mac or Watch)",
  1: "AirTag",
  2: "Find My accessory (third-party tracker)",
  3: "AirPods",
};

function apple(bytes) {
  const type = bytes[0];
  if (type === 0x12) {
    const len = bytes[1];
    const separated = len === 0x19 || bytes.length >= 25;
    const status = bytes[2] ?? 0;
    const kind = separated ? (status >> 4) & 0x3 : null;
    const what = kind == null ? "Find My device" : APPLE_FINDMY_TYPES[kind];
    if (separated) {
      const isTracker = kind === 1 || kind === 2;
      return {
        category: isTracker ? "tracker" : kind === 3 ? "audio" : "phone",
        label: `${what}, away from its owner`,
        vendor: "Apple",
        concern: isTracker ? "high" : kind === 3 ? "medium" : "low",
        confidence: "likely",
        reason: "Apple Find My advertisement in separated mode: its owner's devices are not nearby.",
      };
    }
    return {
      category: "tracker",
      label: "Find My device, near its owner",
      vendor: "Apple",
      concern: "low",
      confidence: "likely",
      reason: "Apple Find My advertisement in near-owner mode: its owner's iPhone is close by.",
    };
  }
  const simple = {
    0x07: ["audio", "AirPods or Beats", "Proximity-pairing advertisement from Apple headphones."],
    0x10: ["phone", "Apple device nearby", "Nearby Info advertisement from an iPhone, iPad, Mac or Watch."],
    0x0c: ["phone", "Apple device (Handoff)", "Handoff advertisement from an Apple device."],
    0x0f: ["phone", "Apple device (Nearby Action)", "Nearby Action advertisement from an Apple device."],
    0x09: ["media", "AirPlay receiver", "AirPlay target advertisement."],
    0x02: ["beacon", "iBeacon", "iBeacon advertisement. Used by stores and venues for location."],
  }[type];
  if (simple) return { category: simple[0], label: simple[1], vendor: "Apple", concern: type === 0x02 ? "low" : "none", confidence: "likely", reason: simple[2] };
  return { category: "other", label: "Apple device", vendor: "Apple", concern: "none", confidence: "possible", reason: `Apple manufacturer data, type 0x${type?.toString(16) ?? "??"}.` };
}

const NAME_HINTS = [
  { re: /\b(air ?tag|tile|chipolo|smart ?tag|itag|nut ?find|pebblebee|tracker|key ?finder|find ?my)\b/i, category: "tracker", label: "Possible tracker (by name)", concern: "medium" },
  { re: /\b(cam|camera|ipc|dvr|spy|recorder|hd-?cam|minicam|p2p)\b/i, category: "camera", label: "Possible camera (by name)", concern: "medium" },
  { re: /\b(gps|locator|obd)\b/i, category: "tracker", label: "Possible GPS tracker (by name)", concern: "medium" },
];

/** Classify a normalized advertisement. Always returns a result. */
export function classify(input) {
  const a = input.manufacturer instanceof Map ? input : normalizeAdvert(input);

  // Google Find My Device network (Fast Pair FMDN).
  const feaa = a.service.get("feaa");
  if (feaa && (feaa[0] === 0x40 || feaa[0] === 0x41)) {
    const protect = feaa[0] === 0x41;
    return {
      category: "tracker",
      label: protect ? "Find My Device tracker, away from its owner" : "Find My Device tracker",
      vendor: "Google network",
      concern: protect ? "high" : "medium",
      confidence: "likely",
      reason: protect
        ? "Google Find My Device advertisement in unwanted-tracking protection mode: it has been away from its owner."
        : "Google Find My Device network advertisement (an Android-compatible tracker tag).",
    };
  }
  if (a.service.has("fd5a")) {
    return { category: "tracker", label: "Samsung SmartTag", vendor: "Samsung", concern: "medium", confidence: "likely", reason: "Samsung SmartTag service data (0xFD5A)." };
  }
  if (a.uuids.includes("feed") || a.uuids.includes("feec") || a.service.has("feed") || a.service.has("feec")) {
    return { category: "tracker", label: "Tile tracker", vendor: "Tile", concern: "medium", confidence: "likely", reason: "Tile service UUID (0xFEED / 0xFEEC)." };
  }
  if (a.uuids.includes("fe33") || a.service.has("fe33")) {
    return { category: "tracker", label: "Chipolo tracker", vendor: "Chipolo", concern: "medium", confidence: "likely", reason: "Chipolo service UUID (0xFE33)." };
  }
  const appleData = a.manufacturer.get(0x004c);
  if (appleData && appleData.length) return apple(appleData);

  for (const h of NAME_HINTS) {
    if (a.name && h.re.test(a.name)) {
      return { category: h.category, label: h.label, vendor: null, concern: h.concern, confidence: "possible", reason: `The device's name, "${a.name}", suggests it.` };
    }
  }

  const companies = [...a.manufacturer.keys()];
  const vendor = companies.map((c) => COMPANY[c]).find(Boolean) ?? null;
  if (vendor) {
    return { category: "other", label: `${vendor} device`, vendor, concern: "none", confidence: "possible", reason: `Manufacturer data from ${vendor}.` };
  }
  return {
    category: "unknown",
    label: a.name ? "Named device" : "Unnamed device",
    vendor: companies.length ? `Company 0x${companies[0].toString(16).padStart(4, "0")}` : null,
    concern: "none",
    confidence: "unknown",
    reason: "No known tracker or camera signature.",
  };
}

/**
 * Rough distance from signal strength (log-distance path loss). Indoor RSSI
 * swings by ±10 dB, so this returns a band, not meters to trust.
 */
export function proximity(rssi, txPower = null) {
  if (rssi == null) return { band: "unknown", meters: null };
  const measured = txPower != null && txPower < 0 && txPower > -100 ? txPower : -59; // RSSI at 1 m
  const meters = 10 ** ((measured - rssi) / (10 * 2.2));
  const band = rssi >= -55 ? "very close" : rssi >= -67 ? "near" : rssi >= -80 ? "in the room" : "far";
  return { band, meters: Math.round(meters * 10) / 10 };
}

/** Wi-Fi network names commonly broadcast by cheap hidden cameras' own hotspots. */
const SSID_RULES = [
  { re: /^(ipc|ipcam|ip-cam|ipcamera)[-_ ]?/i, why: "IP camera default hotspot name" },
  { re: /(hd[-_ ]?cam|wifi[-_ ]?cam|mini[-_ ]?cam|spy|hidden[-_ ]?cam|nanny[-_ ]?cam)/i, why: "Camera-like name" },
  { re: /^(mv|lookcam|v380|yoosee|carecam|icsee|xmeye|tuya[-_ ]?cam|smartlife[-_ ]?cam|accq|hdwificam|p2pcam)/i, why: "Prefix used by budget camera apps (V380, Yoosee, iCSee, LookCam and similar)" },
  { re: /^(cam|camera)[-_ ]?[0-9a-f]{3,}/i, why: "\"CAM\" followed by a serial number" },
  { re: /^(dvr|nvr|ezviz|wyze|blink|ring[-_ ]?setup|arlo)/i, why: "Camera or recorder brand / setup network" },
  { re: /^[A-Z0-9]{2,4}[-_][0-9A-F]{6,12}$/i, why: "Model code plus a hardware serial, typical of devices in setup mode", weak: true },
];

export function checkNetworkName(ssid) {
  const s = String(ssid ?? "").trim();
  if (!s) return null;
  for (const r of SSID_RULES) {
    if (r.re.test(s)) return { ssid: s, suspicious: true, strength: r.weak ? "weak" : "strong", why: r.why };
  }
  return { ssid: s, suspicious: false, strength: null, why: null };
}
