// Airscope session: observed devices over time, watchlist and mute rules,
// alerts, and exports (CSV, JSON, AI debrief). Pure; unit-tested.

import { classifyAdvert, classifyWifi, CATEGORIES, CONCERN } from "./signatures.js";
import { normalizeAdvert, proximity } from "../scanner/trackers.js";

const EMA = 0.3;
const SAMPLE_EVERY_MS = 5000;
const MAX_SAMPLES_PER_DEVICE = 600;

/**
 * Watch / mute rule: { id, kind, value, label?, sound? }
 *   kind "keyword"  - case-insensitive text, or /regex/flags, matched against
 *                     name, label, vendor, drone serial and operator ID
 *   kind "device"   - exact device identifier
 *   kind "company"  - Bluetooth company ID, e.g. 004C or 0x004C
 *   kind "service"  - 16-bit service UUID, e.g. FFFA
 *   kind "category" - an Airscope category key, e.g. drone
 *   kind "mac"      - hardware address or prefix, e.g. 00:25:DF
 */
export function makeMatcher(rule) {
  const v = String(rule.value ?? "").trim();
  if (!v) return () => false;
  switch (rule.kind) {
    case "device": return (d) => d.id === v;
    case "company": {
      const n = parseInt(v.replace(/^0x/i, ""), 16);
      return (d) => d.companies.includes(n);
    }
    case "service": {
      const s = v.toLowerCase().replace(/^0x/, "");
      return (d) => d.services.includes(s);
    }
    case "category": return (d) => d.category === v;
    case "mac": {
      const prefix = v.toLowerCase().replace(/[^0-9a-f]/g, "");
      return (d) => !!d.mac && d.mac.toLowerCase().replace(/[^0-9a-f]/g, "").startsWith(prefix);
    }
    default: {
      let re = null;
      const m = /^\/(.+)\/([a-z]*)$/.exec(v);
      if (m) {
        try { re = new RegExp(m[1], m[2].includes("i") ? m[2] : `${m[2]}i`); } catch { re = null; }
      }
      const needle = v.toLowerCase();
      return (d) => {
        const hay = [d.name, d.label, d.vendor, d.drone?.uasId, d.drone?.operatorId, d.id, d.mac, d.ssid];
        return hay.some((h) => h != null && (re ? re.test(String(h)) : String(h).toLowerCase().includes(needle)));
      };
    }
  }
}

export class Session {
  constructor({ watch = [], mute = [], reappearMs = 5 * 60000, startedAt = Date.now() } = {}) {
    this.devices = new Map();
    this.startedAt = startedAt;
    this.reappearMs = reappearMs;
    this.alerts = [];
    this.setRules(watch, mute);
  }

  setRules(watch, mute) {
    this.watch = watch.map((r) => ({ ...r, match: makeMatcher(r) }));
    this.mute = mute.map((r) => ({ ...r, match: makeMatcher(r) }));
    for (const d of this.devices.values()) this.#applyRules(d);
  }

  #applyRules(d) {
    d.muted = this.mute.some((r) => r.match(d));
    d.watched = this.watch.filter((r) => r.match(d)).map((r) => r.id);
  }

  /**
   * Record one advertisement. geo = { latitude, longitude } or null.
   * Returns { device, alerts } where alerts are new watchlist alerts.
   */
  ingest(raw, now = Date.now(), geo = null) {
    const a = normalizeAdvert(raw);
    const id = a.id ?? `${a.name ?? "?"}|${[...a.manufacturer.keys()].join(",")}|${[...a.service.keys()].join(",")}`;
    const c = classifyAdvert(a);
    let d = this.devices.get(id);
    let isNew = false;
    let reappeared = false;
    if (!d) {
      isNew = true;
      d = { id, radio: "ble", mac: a.mac, ssid: null, frequency: null, security: null, name: a.name, firstSeen: now, lastSeen: now, count: 0, rssi: null, rssiMax: null, txPower: a.txPower, companies: [], services: [], samples: [], places: new Set(), lastSample: 0, alertedAt: null, ...c, details: undefined, drone: null, eddystone: null };
      this.devices.set(id, d);
    } else {
      reappeared = now - d.lastSeen >= this.reappearMs;
      // Prefer the most specific / concerning classification seen.
      const better = d.category === "unknown" || (CONCERN[c.concern] ?? 0) > (CONCERN[d.concern] ?? 0) || (c.confidence === "certain" && d.confidence !== "certain");
      if (better) Object.assign(d, { category: c.category, label: c.label, vendor: c.vendor, confidence: c.confidence, reason: c.reason, concern: c.concern });
      if (a.name) d.name = a.name;
      if (a.mac) d.mac = a.mac;
      if (a.txPower != null) d.txPower = a.txPower;
    }
    for (const k of a.manufacturer.keys()) if (!d.companies.includes(k)) d.companies.push(k);
    for (const k of [...a.service.keys(), ...a.uuids]) if (!d.services.includes(k)) d.services.push(k);

    // Remote ID arrives as separate messages (ID, location, operator...): merge.
    if (c.details?.remoteId) {
      const { messages, counter, ...fields } = c.details.remoteId;
      d.drone = { ...(d.drone ?? {}), ...Object.fromEntries(Object.entries(fields).filter(([, v]) => v != null)) };
      if (d.drone.uasId) d.label = `${d.drone.uaType && d.drone.uaType !== "None" ? d.drone.uaType : "Drone"} · ${d.drone.uasId}`;
    }
    if (c.details?.eddystone) d.eddystone = c.details.eddystone;

    d.count++;
    d.lastSeen = now;
    if (a.rssi != null) {
      d.rssi = d.rssi == null ? a.rssi : Math.round((d.rssi * (1 - EMA) + a.rssi * EMA) * 10) / 10;
      d.rssiMax = d.rssiMax == null ? a.rssi : Math.max(d.rssiMax, a.rssi);
    }
    d.proximity = proximity(d.rssi, d.txPower);
    if (geo && Number.isFinite(geo.latitude) && Number.isFinite(geo.longitude)) {
      d.places.add(`${geo.latitude.toFixed(3)},${geo.longitude.toFixed(3)}`); // ~100 m cells
    }
    if (now - d.lastSample >= SAMPLE_EVERY_MS || isNew) {
      d.lastSample = now;
      d.samples.push({ t: now, rssi: a.rssi, lat: geo?.latitude ?? null, lon: geo?.longitude ?? null, droneLat: d.drone?.latitude ?? null, droneLon: d.drone?.longitude ?? null, droneAlt: d.drone?.altitudeGeo ?? d.drone?.altitudeBaro ?? null });
      if (d.samples.length > MAX_SAMPLES_PER_DEVICE) d.samples.splice(0, d.samples.length - MAX_SAMPLES_PER_DEVICE);
    }

    this.#applyRules(d);
    const alerts = [];
    if (!d.muted && d.watched.length && (isNew || reappeared || d.alertedAt == null)) {
      for (const ruleId of d.watched) {
        const rule = this.watch.find((r) => r.id === ruleId);
        const alert = { t: now, deviceId: d.id, ruleId, rule: rule.label || rule.value, sound: rule.sound !== false, kind: reappeared ? "reappeared" : "appeared", label: d.label, name: d.name, category: d.category };
        alerts.push(alert);
        this.alerts.push(alert);
      }
      d.alertedAt = now;
    }
    return { device: d, alerts };
  }

  /**
   * Record one Wi-Fi access point { bssid, ssid, rssi, frequency,
   * capabilities, vendorIes }. Returns { device, alerts }.
   */
  ingestWifi(n, now = Date.now(), geo = null) {
    const c = classifyWifi(n);
    const id = `wifi:${String(n.bssid).toLowerCase()}`;
    let d = this.devices.get(id);
    let isNew = false;
    let reappeared = false;
    if (!d) {
      isNew = true;
      d = { id, radio: "wifi", mac: n.bssid, name: c.details.ssid, ssid: c.details.ssid, frequency: n.frequency ?? null, security: c.details.security, band: c.details.band, randomized: c.details.randomized, firstSeen: now, lastSeen: now, count: 0, rssi: null, rssiMax: null, txPower: null, companies: [], services: [], samples: [], places: new Set(), lastSample: 0, alertedAt: null, drone: null, eddystone: null, category: c.category, label: c.label, vendor: c.vendor, confidence: c.confidence, reason: c.reason, concern: c.concern };
      this.devices.set(id, d);
    } else {
      reappeared = now - d.lastSeen >= this.reappearMs;
      Object.assign(d, { category: c.category, label: c.label, vendor: c.vendor, confidence: c.confidence, reason: c.reason, concern: c.concern, name: c.details.ssid, ssid: c.details.ssid, frequency: n.frequency ?? d.frequency, security: n.capabilities != null ? c.details.security : d.security, band: c.details.band ?? d.band });
    }
    if (c.details.remoteId) {
      const { messages, counter, ...fields } = c.details.remoteId;
      d.drone = { ...(d.drone ?? {}), ...Object.fromEntries(Object.entries(fields).filter(([, v]) => v != null)) };
    }
    return this.#observe(d, n.rssi, now, geo, isNew, reappeared);
  }

  #observe(d, rssi, now, geo, isNew, reappeared) {
    d.count++;
    d.lastSeen = now;
    if (rssi != null) {
      d.rssi = d.rssi == null ? rssi : Math.round((d.rssi * (1 - EMA) + rssi * EMA) * 10) / 10;
      d.rssiMax = d.rssiMax == null ? rssi : Math.max(d.rssiMax, rssi);
    }
    d.proximity = proximity(d.rssi, d.txPower);
    if (geo && Number.isFinite(geo.latitude) && Number.isFinite(geo.longitude)) d.places.add(`${geo.latitude.toFixed(3)},${geo.longitude.toFixed(3)}`);
    if (now - d.lastSample >= SAMPLE_EVERY_MS || isNew) {
      d.lastSample = now;
      d.samples.push({ t: now, rssi, lat: geo?.latitude ?? null, lon: geo?.longitude ?? null, droneLat: d.drone?.latitude ?? null, droneLon: d.drone?.longitude ?? null, droneAlt: d.drone?.altitudeGeo ?? d.drone?.altitudeBaro ?? null });
      if (d.samples.length > MAX_SAMPLES_PER_DEVICE) d.samples.splice(0, d.samples.length - MAX_SAMPLES_PER_DEVICE);
    }
    this.#applyRules(d);
    const alerts = [];
    if (!d.muted && d.watched.length && (isNew || reappeared || d.alertedAt == null)) {
      for (const ruleId of d.watched) {
        const rule = this.watch.find((r) => r.id === ruleId);
        const alert = { t: now, deviceId: d.id, ruleId, rule: rule.label || rule.value, sound: rule.sound !== false, kind: reappeared ? "reappeared" : "appeared", label: d.label, name: d.name, category: d.category };
        alerts.push(alert);
        this.alerts.push(alert);
      }
      d.alertedAt = now;
    }
    return { device: d, alerts };
  }

  /** Devices seen within `windowMs` (all when null), most notable first. */
  list(now = Date.now(), windowMs = 60000, { includeMuted = false } = {}) {
    return [...this.devices.values()]
      .filter((d) => (windowMs == null || now - d.lastSeen <= windowMs) && (includeMuted || !d.muted))
      .sort((x, y) => (y.watched.length > 0) - (x.watched.length > 0) || (CONCERN[y.concern] ?? 0) - (CONCERN[x.concern] ?? 0) || (y.rssi ?? -999) - (x.rssi ?? -999));
  }

  counts(now = Date.now(), windowMs = 60000) {
    const out = {};
    for (const d of this.list(now, windowMs)) out[d.category] = (out[d.category] ?? 0) + 1;
    return out;
  }

  // -------------------------------------------------------------- export

  toJSON() {
    return {
      app: "Airscope",
      exportedAt: new Date().toISOString(),
      session: { startedAt: new Date(this.startedAt).toISOString() },
      devices: [...this.devices.values()].map((d) => ({
        id: d.id, radio: d.radio, mac: d.mac ?? null, ssid: d.ssid ?? null, frequencyMHz: d.frequency ?? null, security: d.security ?? null, name: d.name, category: d.category, label: d.label, vendor: d.vendor, confidence: d.confidence, reason: d.reason,
        firstSeen: new Date(d.firstSeen).toISOString(), lastSeen: new Date(d.lastSeen).toISOString(), advertisements: d.count,
        rssiLast: d.rssi, rssiMax: d.rssiMax, places: d.places.size, companies: d.companies.map((c) => `0x${c.toString(16).padStart(4, "0")}`), services: d.services,
        watched: d.watched.length > 0, muted: d.muted, drone: d.drone, eddystone: d.eddystone,
        samples: d.samples.map((s) => ({ ...s, t: new Date(s.t).toISOString() })),
      })),
      alerts: this.alerts.map((a) => ({ ...a, t: new Date(a.t).toISOString() })),
    };
  }

  toCSV() {
    const cols = ["time", "radio", "device_id", "mac", "frequency_mhz", "name", "category", "label", "vendor", "confidence", "rssi", "latitude", "longitude", "drone_id", "drone_latitude", "drone_longitude", "drone_altitude_m", "watched", "muted"];
    const rows = [cols.join(",")];
    for (const d of this.devices.values()) {
      for (const s of d.samples) {
        rows.push([new Date(s.t).toISOString(), d.radio === "wifi" ? "Wi-Fi" : "Bluetooth", d.id, d.mac, d.frequency, d.name, CATEGORIES[d.category]?.label ?? d.category, d.label, d.vendor, d.confidence, s.rssi, s.lat, s.lon, d.drone?.uasId, s.droneLat, s.droneLon, s.droneAlt, d.watched.length > 0, d.muted].map(csvCell).join(","));
      }
    }
    return `${rows.join("\r\n")}\r\n`;
  }

  /** A structured summary to paste into any AI assistant. No API involved. */
  debrief(now = Date.now()) {
    const all = [...this.devices.values()];
    const mins = Math.max(1, Math.round((now - this.startedAt) / 60000));
    const byCat = {};
    for (const d of all) byCat[d.category] = (byCat[d.category] ?? 0) + 1;
    const fmt = (d) => {
      const bits = [d.label, d.radio === "wifi" ? "Wi-Fi" : "Bluetooth", d.name && d.name !== d.label ? `name "${d.name}"` : null, d.mac && !d.randomized ? `address ${d.mac}` : null, d.vendor, `${d.confidence} match`, `strongest ${d.rssiMax ?? "?"} dBm`, `seen ${Math.max(1, Math.round((d.lastSeen - d.firstSeen) / 60000))} min`, d.places.size > 1 ? `at ${d.places.size} places` : null];
      if (d.drone) bits.push(`drone ${[d.drone.uasId, d.drone.status, d.drone.latitude != null ? `at ${d.drone.latitude.toFixed(5)}, ${d.drone.longitude.toFixed(5)}` : null, d.drone.altitudeGeo != null ? `${d.drone.altitudeGeo} m` : null].filter(Boolean).join(", ")}`);
      return `- ${bits.filter(Boolean).join("; ")}`;
    };
    const notable = all.filter((d) => !["unknown", "phone", "audio", "network"].includes(d.category) && !d.muted).sort((a, b) => (b.rssiMax ?? -999) - (a.rssiMax ?? -999)).slice(0, 40);
    const watched = all.filter((d) => d.watched.length);
    const persistent = all.filter((d) => d.places.size > 1 || d.lastSeen - d.firstSeen > 20 * 60000).slice(0, 20);
    const lines = [
      "You are helping me review a passive wireless survey recorded with Airscope on my phone. It lists Bluetooth Low Energy devices and Wi-Fi networks that broadcast near me. Classifications are pattern matches (\"certain\", \"likely\", \"possible\"), not proof of who owns a device or what it is used for. Signal strength (dBm) is a rough indicator of distance, not a location.",
      "",
      "Please: (1) summarize what kinds of equipment and infrastructure were around, (2) point out anything unusual or worth a closer look and why, (3) note which classifications are weak, and (4) suggest what I could check next. Don't speculate about individuals' identities.",
      "",
      `## Session`,
      `- Duration: about ${mins} min, from ${new Date(this.startedAt).toISOString()}`,
      `- Devices observed: ${all.length} (Bluetooth ${all.filter((d) => d.radio !== "wifi").length}, Wi-Fi networks ${all.filter((d) => d.radio === "wifi").length})`,
      `- By category: ${Object.entries(byCat).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${CATEGORIES[k]?.label ?? k} ${v}`).join(", ") || "none"}`,
      `- Watchlist alerts: ${this.alerts.length}`,
      "",
      "## Notable devices",
      ...(notable.length ? notable.map(fmt) : ["- None"]),
      "",
      "## Watchlist matches",
      ...(watched.length ? watched.map(fmt) : ["- None"]),
      "",
      "## Seen for a long time or at several places",
      ...(persistent.length ? persistent.map(fmt) : ["- None"]),
    ];
    return `${lines.join("\n")}\n`;
  }
}

/** CSV cell: quoted when needed, with spreadsheet-formula injection neutralized. */
export function csvCell(v) {
  if (v == null) return "";
  let s = String(v);
  if (/^[=+\-@\t\r]/.test(s) && !/^-?\d+(\.\d+)?$/.test(s)) s = `'${s}`;
  if (/[",\r\n]/.test(s)) s = `"${s.replace(/"/g, '""')}"`;
  return s;
}
