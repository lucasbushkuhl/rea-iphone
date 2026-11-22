// Bluetooth LE scanning through Web Bluetooth, plus a device registry that
// smooths signal strength and tracks how long each device has been around.

import { normalizeAdvert, classify, proximity, CONCERN } from "./trackers.js";

const EMA = 0.3; // weight of each new RSSI reading

export class DeviceRegistry {
  constructor() {
    this.devices = new Map();
  }

  /** Record one advertisement. `now` in ms. Returns the device record. */
  ingest(raw, now = Date.now()) {
    const a = normalizeAdvert(raw);
    const id = a.id ?? `${a.name ?? "?"}|${[...a.manufacturer.keys()].join(",")}`;
    let d = this.devices.get(id);
    const c = classify(a);
    if (!d) {
      d = { id, name: a.name, firstSeen: now, lastSeen: now, count: 0, rssi: a.rssi, rssiRaw: a.rssi, rssiMin: a.rssi, rssiMax: a.rssi, txPower: a.txPower, trend: 0, history: [], ...c };
      this.devices.set(id, d);
    } else {
      // Keep the most concerning classification seen for this device.
      if ((CONCERN[c.concern] ?? 0) > (CONCERN[d.concern] ?? 0) || d.category === "unknown") Object.assign(d, c);
      if (a.name) d.name = a.name;
      if (a.txPower != null) d.txPower = a.txPower;
    }
    d.count++;
    d.lastSeen = now;
    if (a.rssi != null) {
      const prev = d.rssi;
      d.rssiRaw = a.rssi;
      d.rssi = prev == null ? a.rssi : Math.round((prev * (1 - EMA) + a.rssi * EMA) * 10) / 10;
      d.rssiMin = d.rssiMin == null ? a.rssi : Math.min(d.rssiMin, a.rssi);
      d.rssiMax = d.rssiMax == null ? a.rssi : Math.max(d.rssiMax, a.rssi);
      d.history.push([now, d.rssi]);
      if (d.history.length > 120) d.history.shift();
      // Trend: smoothed signal now versus ~3 seconds ago.
      const old = d.history.find(([t]) => t >= now - 3000);
      d.trend = old ? Math.round((d.rssi - old[1]) * 10) / 10 : 0;
    }
    d.proximity = proximity(d.rssi, d.txPower);
    return d;
  }

  /** Devices sorted by concern, then signal strength. Stale ones excluded. */
  list(now = Date.now(), staleMs = 30000) {
    return [...this.devices.values()]
      .filter((d) => now - d.lastSeen <= staleMs)
      .map((d) => ({ ...d, minutesAround: Math.floor((d.lastSeen - d.firstSeen) / 60000) }))
      .sort((x, y) => (CONCERN[y.concern] ?? 0) - (CONCERN[x.concern] ?? 0) || (y.rssi ?? -999) - (x.rssi ?? -999));
  }

  clear() {
    this.devices.clear();
  }
}

/** What this browser can do with Bluetooth. */
export function bluetoothSupport(nav = globalThis.navigator) {
  const bt = nav?.bluetooth;
  if (!bt) return { level: "none" };
  if (typeof bt.requestLEScan === "function") return { level: "scan" };
  if (typeof bt.requestDevice === "function") return { level: "pick" };
  return { level: "none" };
}

/**
 * Start scanning. onAdvert(event) is called for every advertisement.
 * Returns { stop() }. Must be called from a user gesture.
 */
export async function startScan(onAdvert, nav = globalThis.navigator) {
  const bt = nav.bluetooth;
  const handler = (e) => onAdvert({
    id: e.device?.id,
    name: e.name ?? e.device?.name,
    rssi: e.rssi,
    txPower: e.txPower,
    manufacturerData: e.manufacturerData,
    serviceData: e.serviceData,
    uuids: e.uuids,
  });
  bt.addEventListener("advertisementreceived", handler);
  let scan;
  try {
    scan = await bt.requestLEScan({ acceptAllAdvertisements: true, keepRepeatedDevices: true });
  } catch (err) {
    bt.removeEventListener("advertisementreceived", handler);
    throw err;
  }
  return {
    stop() {
      try { scan?.stop(); } catch { /* already stopped */ }
      bt.removeEventListener("advertisementreceived", handler);
    },
  };
}

/**
 * Fallback for browsers that can only pick one device: the browser shows its
 * own list of nearby devices; then we follow the chosen one's signal.
 */
export async function pickAndWatch(onAdvert, nav = globalThis.navigator) {
  const device = await nav.bluetooth.requestDevice({ acceptAllDevices: true });
  const handler = (e) => onAdvert({ id: device.id, name: device.name, rssi: e.rssi, txPower: e.txPower, manufacturerData: e.manufacturerData, serviceData: e.serviceData, uuids: e.uuids });
  onAdvert({ id: device.id, name: device.name });
  let live = false;
  if (typeof device.watchAdvertisements === "function") {
    device.addEventListener("advertisementreceived", handler);
    try {
      await device.watchAdvertisements();
      live = true;
    } catch { /* this browser can't stream the device's signal */ }
  }
  return {
    device,
    live,
    stop() {
      try { device.unwatchAdvertisements?.(); } catch { /* ignore */ }
      device.removeEventListener?.("advertisementreceived", handler);
    },
  };
}

/** Explain a scan error in plain words. */
export function explainBluetoothError(err) {
  const name = err?.name ?? "";
  const msg = err?.message ?? String(err);
  if (name === "NotFoundError" || /cancel/i.test(msg)) return "No device was chosen.";
  if (name === "NotAllowedError" || /permission|denied/i.test(msg)) return "Bluetooth permission was denied. Allow Bluetooth for this browser in Settings, then try again.";
  if (name === "InvalidStateError" || /powered off|bluetooth.*off|adapter/i.test(msg)) return "Bluetooth is turned off. Turn it on and try again.";
  if (name === "SecurityError") return "Bluetooth needs a secure (https) page opened directly, not inside another page.";
  return `Bluetooth scanning failed: ${msg}`;
}
