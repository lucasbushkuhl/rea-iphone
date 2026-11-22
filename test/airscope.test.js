// Airscope: signatures (Remote ID, Eddystone, vehicles...), session, exports.
import { test } from "node:test";
import assert from "node:assert/strict";
import { classifyAdvert, decodeRemoteId, decodeEddystone, classifySsid, classifyWifi, setCustomSignatures, ouiOf, isRandomizedMac, wifiSecurity, wifiBand } from "../airscope/signatures.js";
import { Session, makeMatcher, csvCell } from "../airscope/session.js";

const full = (s) => `0000${s}-0000-1000-8000-00805f9b34fb`;
const le32 = (v) => [v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >>> 24) & 0xff];
const le16 = (v) => [v & 0xff, (v >> 8) & 0xff];
const altEnc = (m) => le16(Math.round((m + 1000) / 0.5));
const pad = (arr, n = 25) => [...arr, ...new Array(n - arr.length).fill(0)];
const ascii = (s, n) => [...s].map((c) => c.charCodeAt(0)).concat(new Array(n - s.length).fill(0));

// Open Drone ID messages (25 bytes each), protocol version 2.
const basicId = (serial, uaType = 2) => pad([0x02, (1 << 4) | uaType, ...ascii(serial, 20)]);
const location = ({ lat, lon, altGeo, status = 2, heading = 200, speed = 12.5 }) => {
  const ew = heading >= 180 ? 1 : 0;
  return pad([0x12, (status << 4) | (ew << 1), heading - (ew ? 180 : 0), Math.round(speed / 0.25), 4, ...le32(Math.round(lat * 1e7)), ...le32(Math.round(lon * 1e7)), ...altEnc(100), ...altEnc(altGeo), ...altEnc(60)]);
};
const system = (lat, lon) => pad([0x42, 0x01, ...le32(Math.round(lat * 1e7)), ...le32(Math.round(lon * 1e7))]);
const operator = (id) => pad([0x52, 0x00, ...ascii(id, 20)]);
const rid = (msg, counter = 1) => Uint8Array.from([0x0d, counter, ...msg]);

test("Remote ID: basic ID, location, system, operator, message pack", () => {
  const b = decodeRemoteId(rid(basicId("1581F5FKD229400ABCDE")));
  assert.equal(b.uasId, "1581F5FKD229400ABCDE");
  assert.equal(b.idType, "Serial number");
  assert.equal(b.uaType, "Multirotor or helicopter");

  const l = decodeRemoteId(rid(location({ lat: 40.7484405, lon: -73.9856644, altGeo: 120.5 })));
  assert.equal(l.status, "Airborne");
  assert.equal(l.latitude, 40.7484405);
  assert.equal(l.longitude, -73.9856644);
  assert.equal(l.altitudeGeo, 120.5);
  assert.equal(l.height, 60);
  assert.equal(l.heading, 200);
  assert.equal(l.speed, 12.5);
  assert.equal(l.verticalSpeed, 2);

  const s = decodeRemoteId(rid(system(40.75, -73.99)));
  assert.deepEqual([s.operatorLatitude, s.operatorLongitude], [40.75, -73.99]);
  assert.equal(decodeRemoteId(rid(operator("FIN87astrdge12k8"))).operatorId, "FIN87astrdge12k8");

  const pack = Uint8Array.from([0x0d, 9, 0xf2, 25, 2, ...basicId("SN-PACK-1"), ...location({ lat: 51.5, lon: -0.12, altGeo: 80 })]);
  const p = decodeRemoteId(pack);
  assert.deepEqual([p.uasId, p.latitude, p.longitude], ["SN-PACK-1", 51.5, -0.12]);

  assert.equal(decodeRemoteId(Uint8Array.from([0x0c, 1, 2])), null, "wrong application code");
  assert.equal(decodeRemoteId(Uint8Array.from([0x0d, 1, 2, 3])), null, "truncated");
});

test("classification: drones, beacons, vehicles, fleet, trackers, companies", () => {
  const drone = classifyAdvert({ serviceData: { [full("fffa")]: rid(basicId("1581F5FKD229400ABCDE")) } });
  assert.deepEqual([drone.category, drone.confidence], ["drone", "certain"]);
  assert.match(drone.label, /1581F5FKD229400ABCDE/);

  const url = decodeEddystone(Uint8Array.from([0x10, 0xeb, 0x03, ...[..."example"].map((c) => c.charCodeAt(0)), 0x07]));
  assert.equal(url.url, "https://example.com");
  assert.equal(classifyAdvert({ serviceData: { [full("feaa")]: [0x10, 0xeb, 0x01, 0x61, 0x00] } }).label, "Eddystone beacon (URL)");
  assert.equal(classifyAdvert({ serviceData: { [full("feaa")]: [0x41, 1] } }).category, "tracker", "Find My Device tag, not a beacon");
  assert.equal(classifyAdvert({ manufacturerData: { 0x0118: [0xbe, 0xac, 1, 2] } }).label, "AltBeacon");

  assert.deepEqual(Object.values((({ category, label, confidence }) => ({ category, label, confidence }))(classifyAdvert({ name: "S1a2b3c4d5e6f7a8bC" }))), ["vehicle", "Tesla vehicle", "likely"]);
  assert.equal(classifyAdvert({ name: "Uconnect 4C" }).category, "vehicle");
  assert.equal(classifyAdvert({ name: "Geotab GO9" }).category, "fleet");
  assert.equal(classifyAdvert({ name: "Axon Body 4" }).category, "publicsafety");
  assert.equal(classifyAdvert({ name: "DJI RC-N1" }).category, "drone");
  assert.equal(classifyAdvert({ name: "BlackVue DR970X" }).category, "camera");

  const tag = classifyAdvert({ manufacturerData: { 0x004c: [0x12, 0x19, 0x10, ...new Array(24).fill(1)] } });
  assert.deepEqual([tag.category, tag.concern], ["tracker", "high"]);
  assert.equal(classifyAdvert({ manufacturerData: { 0x0087: [1] } }).category, "wearable");
  assert.equal(classifyAdvert({ manufacturerData: { 0x009e: [1] } }).category, "audio");
  assert.equal(classifyAdvert({ serviceData: { [full("fd6f")]: [1] } }).label, "Exposure Notification (phone)");
  const unk = classifyAdvert({ manufacturerData: { 0x1234: [1] } });
  assert.deepEqual([unk.category, unk.vendor], ["unknown", "Company 0x1234"]);
});

test("Wi-Fi name classification", () => {
  assert.equal(classifySsid("DJI-MAVIC3-1234").category, "drone");
  assert.equal(classifySsid("IBR900-3a1").category, "fleet");
  assert.equal(classifySsid("Tesla Model Y").category, "vehicle");
  assert.equal(classifySsid("IPC-55812").category, "camera");
  assert.equal(classifySsid("Home WiFi").category, "unknown");
  assert.equal(classifySsid(""), null);
});

test("Wi-Fi networks: vehicle routers, Flock, phones, Remote ID beacons, security, band", () => {
  const cp = classifyWifi({ bssid: "00:30:44:1a:2b:3c", ssid: "Squad7", rssi: -62, frequency: 5180, capabilities: "[WPA2-PSK-CCMP][ESS]" });
  assert.deepEqual([cp.category, cp.label, cp.confidence], ["fleet", "Cradlepoint vehicle router", "likely"]);
  assert.match(cp.reason, /police, fire, EMS/);
  assert.deepEqual([cp.details.band, cp.details.security], ["5 GHz", "WPA2"]);
  const byName = classifyWifi({ bssid: "da:00:00:00:00:01", ssid: "IBR900-3a1" });
  assert.deepEqual([byName.label, byName.confidence], ["Cradlepoint vehicle router", "possible"]);
  assert.equal(classifyWifi({ bssid: "11:22:33:44:55:66", ssid: "MP70-ABC" }).label, "Sierra Wireless AirLink vehicle router");
  assert.equal(classifyWifi({ bssid: "11:22:33:44:55:66", ssid: "Flock-7781" }).category, "alpr");
  assert.equal(classifyWifi({ bssid: "11:22:33:44:55:66", ssid: "iPhone (2)" }).label, "Phone hotspot");
  assert.equal(classifyWifi({ bssid: "a2:00:00:00:00:01", ssid: "" }).label, "Hidden network");
  // A randomized address never matches a maker prefix.
  assert.equal(classifyWifi({ bssid: "02:30:44:00:00:01", ssid: "Home" }).category, "network");
  assert.equal(isRandomizedMac("da:a1:19:00:00:01"), true);
  assert.equal(isRandomizedMac("00:30:44:00:00:01"), false);
  assert.equal(ouiOf("00a0d5123456"), "00:A0:D5");
  assert.deepEqual([wifiSecurity("[WPA3-SAE]"), wifiSecurity("[ESS]"), wifiBand(2412), wifiBand(5955)], ["WPA3", "Open", "2.4 GHz", "6 GHz"]);
  // Remote ID in a Wi-Fi beacon vendor element: OUI FA:0B:BC, type 0x0D, counter, message pack.
  const pack = [0xf2, 25, 2, ...basicId("WIFI-SN-77"), ...location({ lat: 34.05, lon: -118.25, altGeo: 90 })];
  const ie = [0xfa, 0x0b, 0xbc, 0x0d, 5, ...pack].map((b) => b.toString(16).padStart(2, "0")).join("");
  const dr = classifyWifi({ bssid: "60:60:1f:00:00:01", ssid: "DJI-xyz", vendorIes: [ie] });
  assert.deepEqual([dr.category, dr.confidence, dr.details.remoteId.uasId, dr.details.remoteId.latitude], ["drone", "certain", "WIFI-SN-77", 34.05]);
  assert.equal(classifyWifi({ bssid: "60:60:1f:00:00:01", ssid: "x" }).label, "DJI drone or controller");
});

test("Bluetooth address prefixes and custom signatures", () => {
  assert.equal(classifyAdvert({ mac: "00:25:DF:11:22:33", rssi: -60 }).category, "publicsafety");
  assert.equal(classifyAdvert({ mac: "02:25:DF:11:22:33", rssi: -60 }).category, "unknown", "randomized address ignored");
  setCustomSignatures([{ kind: "mac", value: "B4:1E:52", category: "alpr", label: "Flock camera (my signature)" }, { kind: "name", value: "/^penguin/", category: "alpr", label: "Named camera" }, { kind: "mac", value: "x", category: "nope" }]);
  try {
    const c = classifyAdvert({ mac: "b4:1e:52:00:00:01" });
    assert.deepEqual([c.category, c.label, c.confidence], ["alpr", "Flock camera (my signature)", "custom"]);
    assert.equal(classifyWifi({ bssid: "b4-1e-52-00-00-02", ssid: "anything" }).label, "Flock camera (my signature)");
    assert.equal(classifyAdvert({ name: "Penguin-42" }).label, "Named camera");
  } finally {
    setCustomSignatures([]);
  }
  assert.equal(classifyAdvert({ mac: "b4:1e:52:00:00:01" }).category, "unknown");
});

test("session with Wi-Fi: alerts, address watch rules, exports", () => {
  const s = new Session({ watch: [{ id: "w", kind: "mac", value: "00:30:44" }], startedAt: 0 });
  const r = s.ingestWifi({ bssid: "00:30:44:1A:2B:3C", ssid: "Squad7", rssi: -66, frequency: 2437, capabilities: "[WPA2]" }, 1000, { latitude: 1, longitude: 2 });
  assert.equal(r.alerts.length, 1);
  assert.equal(r.device.radio, "wifi");
  s.ingestWifi({ bssid: "00:30:44:1A:2B:3C", ssid: "Squad7", rssi: -60, frequency: 2437 }, 2000);
  assert.equal(s.devices.get("wifi:00:30:44:1a:2b:3c").rssiMax, -60);
  s.ingest({ id: "ble1", mac: "00:25:DF:00:00:01", rssi: -70 }, 3000);
  const csv = s.toCSV();
  assert.match(csv, /Wi-Fi,wifi:00:30:44:1a:2b:3c,00:30:44:1A:2B:3C,2437,Squad7,Fleet & telematics,Cradlepoint vehicle router/);
  assert.match(csv, /Bluetooth,ble1,00:25:DF:00:00:01,,,Public-safety equipment/);
  assert.match(s.debrief(60000), /Bluetooth 1, Wi-Fi networks 1/);
  assert.equal(s.toJSON().devices.find((d) => d.radio === "wifi").security, "WPA2");
});

test("watch rule matching", () => {
  const d = { id: "abc", name: "Geotab GO9", label: "Fleet telematics (by name)", vendor: null, category: "fleet", companies: [0x004c], services: ["fffa"], drone: { uasId: "1581F5FK" } };
  assert.ok(makeMatcher({ kind: "keyword", value: "geotab" })(d));
  assert.ok(makeMatcher({ kind: "keyword", value: "/^1581F5/" })(d), "regex against drone serial");
  assert.ok(!makeMatcher({ kind: "keyword", value: "/[/" })(d), "bad regex falls back to plain text");
  assert.ok(makeMatcher({ kind: "device", value: "abc" })(d));
  assert.ok(makeMatcher({ kind: "company", value: "0x004C" })(d));
  assert.ok(makeMatcher({ kind: "company", value: "004c" })(d));
  assert.ok(makeMatcher({ kind: "service", value: "FFFA" })(d));
  assert.ok(makeMatcher({ kind: "category", value: "fleet" })(d));
  assert.ok(!makeMatcher({ kind: "keyword", value: "" })(d));
});

test("session: alerts on appear and reappear, mutes, Remote ID merge, places", () => {
  const s = new Session({ watch: [{ id: "w1", kind: "category", value: "drone", label: "Any drone" }, { id: "w2", kind: "keyword", value: "geotab" }], mute: [{ id: "m1", kind: "keyword", value: "noisy" }], startedAt: 0 });
  let t = 1000;
  const geoA = { latitude: 40.748, longitude: -73.985 };
  const geoB = { latitude: 40.758, longitude: -73.975 };

  let r = s.ingest({ id: "d1", rssi: -70, serviceData: { [full("fffa")]: rid(basicId("1581F5FKD229400ABCDE")) } }, (t += 100), geoA);
  assert.deepEqual(r.alerts.map((a) => [a.ruleId, a.kind]), [["w1", "appeared"]]);
  r = s.ingest({ id: "d1", rssi: -66, serviceData: { [full("fffa")]: rid(location({ lat: 40.7484405, lon: -73.9856644, altGeo: 120.5 })) } }, (t += 100), geoA);
  assert.equal(r.alerts.length, 0, "no repeat alert while continuously present");
  const drone = s.devices.get("d1");
  assert.equal(drone.drone.uasId, "1581F5FKD229400ABCDE", "ID kept from earlier message");
  assert.equal(drone.drone.latitude, 40.7484405, "location merged in");
  assert.match(drone.label, /Multirotor or helicopter · 1581F5FKD229400ABCDE/);

  r = s.ingest({ id: "d1", rssi: -60, serviceData: { [full("fffa")]: rid(basicId("1581F5FKD229400ABCDE")) } }, (t += 6 * 60000), geoB);
  assert.deepEqual(r.alerts.map((a) => a.kind), ["reappeared"]);
  assert.equal(s.devices.get("d1").places.size, 2);
  assert.equal(s.devices.get("d1").rssiMax, -60);

  r = s.ingest({ id: "n1", name: "Noisy Geotab", rssi: -50 }, t);
  assert.equal(r.alerts.length, 0, "muted devices never alert");
  assert.equal(s.list(t).some((d) => d.id === "n1"), false, "muted hidden by default");
  assert.equal(s.list(t, 60000, { includeMuted: true }).some((d) => d.id === "n1"), true);

  s.setRules([{ id: "w3", kind: "device", value: "x9" }], []);
  r = s.ingest({ id: "x9", rssi: -80 }, t + 1);
  assert.equal(r.alerts.length, 1, "rules can change mid-session");
  assert.deepEqual(s.list(t + 1).map((d) => d.id).slice(0, 1), ["x9"], "watched devices sort first");
  assert.equal(s.counts(t + 1).drone, 1);
});

test("exports: JSON, CSV (formula-safe), AI debrief", () => {
  const s = new Session({ watch: [{ id: "w", kind: "keyword", value: "tesla" }], startedAt: 0 });
  s.ingest({ id: "v1", name: "S1a2b3c4d5e6f7a8bC", rssi: -61 }, 1000, { latitude: 1.5, longitude: 2.5 });
  s.ingest({ id: "evil", name: '=HYPERLINK("http://x","click")', rssi: -70 }, 2000);
  s.ingest({ id: "d1", rssi: -75, serviceData: { [full("fffa")]: rid(basicId("SN123")) } }, 3000);
  const j = s.toJSON();
  assert.equal(j.devices.length, 3);
  assert.equal(j.devices.find((d) => d.id === "v1").label, "Tesla vehicle");
  assert.equal(j.devices.find((d) => d.id === "d1").drone.uasId, "SN123");
  assert.ok(JSON.stringify(j));
  const csv = s.toCSV();
  const lines = csv.trim().split("\r\n");
  assert.equal(lines.length, 4);
  assert.match(lines[0], /^time,radio,device_id,mac,frequency_mhz,name,category/);
  assert.ok(lines.some((l) => l.includes(`"'=HYPERLINK(""http://x"",""click"")"`)), "formula neutralized and quoted");
  assert.ok(lines.some((l) => /,1\.5,2\.5,/.test(l)), "location columns");
  const deb = s.debrief(10 * 60000);
  assert.match(deb, /passive wireless survey/);
  assert.match(deb, /Tesla vehicle/);
  assert.match(deb, /Watchlist alerts: 1/);
  assert.match(deb, /Don't speculate about individuals' identities/);
  assert.equal(csvCell("-42"), "-42", "negative numbers untouched");
  assert.equal(csvCell("+1 555"), "'+1 555");
  assert.equal(csvCell(null), "");
});

// ---- end-to-end in headless Chromium (skipped without Playwright)
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

let pw = null;
try { pw = createRequire(import.meta.url)("playwright"); } catch { /* optional */ }

test("Airscope in headless Chromium", { skip: !pw && "Playwright not installed", timeout: 90000 }, async () => {
  const root = fileURLToPath(new URL("..", import.meta.url));
  const site = mkdtempSync(join(tmpdir(), "airscope-site-"));
  execFileSync(process.execPath, [join(root, "scripts", "build-web.mjs"), site], { stdio: "pipe" });
  const { serve } = await import("../scripts/serve.mjs");
  const server = await serve(site, 8399);
  const ridBasic = [...rid(basicId("1581F5FKD229400ABCDE"))];
  const ridLoc = [...rid(location({ lat: 40.7484405, lon: -73.9856644, altGeo: 120.5 }))];
  const fake = `(() => {
    const L = [];
    const dv = (a) => new DataView(Uint8Array.from(a).buffer);
    const u = (s) => "0000" + s + "-0000-1000-8000-00805f9b34fb";
    Object.defineProperty(navigator, "bluetooth", { configurable: true, value: {
      addEventListener: (t, f) => L.push(f), removeEventListener: () => {},
      requestLEScan: async () => {
        let n = 0;
        const emit = (e) => L.forEach((f) => f({ manufacturerData: new Map(), serviceData: new Map(), uuids: [], ...e }));
        const timer = setInterval(() => {
          n++;
          emit({ device: { id: "drone" }, rssi: -78, serviceData: new Map([[u("fffa"), dv(n % 2 ? ${JSON.stringify(ridBasic)} : ${JSON.stringify(ridLoc)})]]) });
          emit({ device: { id: "tesla", name: "S1a2b3c4d5e6f7a8bC" }, rssi: -64 });
          emit({ device: { id: "fleet", name: "Geotab GO9" }, rssi: -71 });
          emit({ device: { id: "tag" }, rssi: -58, manufacturerData: new Map([[0x004c, dv([0x12, 0x19, 0x10].concat(new Array(24).fill(1)))]]) });
          emit({ device: { id: "beacon" }, rssi: -83, manufacturerData: new Map([[0x004c, dv([0x02, 0x15, 1, 2])]]) });
          emit({ device: { id: "phone" }, rssi: -49, manufacturerData: new Map([[0x004c, dv([0x10, 5, 1])]]) });
        }, 120);
        return { stop: () => clearInterval(timer) };
      },
    }});
  })();`;
  const browser = await pw.chromium.launch();
  try {
    const ctx = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 1, acceptDownloads: true });
    await ctx.addInitScript(fake);
    const page = await ctx.newPage();
    const errors = [];
    page.on("pageerror", (e) => errors.push(e.message));
    page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
    await page.goto("http://127.0.0.1:8399/airscope/");

    // A watchlist rule added before scanning.
    await page.click('nav.tabs [data-view="watch"]');
    await page.fill("#watch-value", "geotab");
    await page.click('#watch-form button[type="submit"]');
    await page.click('nav.tabs [data-view="live"]');

    await page.click("#start");
    try {
      await page.waitForFunction(() => document.querySelectorAll(".dev").length >= 6, null, { timeout: 10000 });
    } catch (err) {
      const state = await page.evaluate(() => ({ devs: [...document.querySelectorAll(".dev .t")].map((x) => x.textContent), status: document.querySelector("#status").textContent, support: document.querySelector("#support").textContent }));
      throw new Error(`devices never listed: ${JSON.stringify(state)} errors=${JSON.stringify(errors)}`);
    }
    await page.waitForTimeout(900);
    assert.equal(await page.$eval("#alertbar", (e) => e.hidden), false, "watchlist alert shown");
    assert.match(await page.$eval("#alert-text", (e) => e.textContent), /Fleet telematics.*geotab/i);
    const labels = await page.$$eval(".dev .t", (n) => n.map((x) => x.textContent));
    assert.equal(labels[0], "Fleet telematics (by name)", "watched device first");
    for (const want of ["Multirotor or helicopter · 1581F5FKD229400ABCDE", "Tesla vehicle", "AirTag, away from its owner", "iBeacon", "Apple device nearby"]) {
      assert.ok(labels.includes(want), `${want} listed`);
    }
    const counters = await page.$$eval(".counter span", (n) => n.map((x) => x.textContent));
    for (const c of ["Drone", "Vehicle", "Fleet & telematics", "Tracker", "Infrastructure & beacons"]) assert.ok(counters.includes(c), c);
    // Radar is drawing blips.
    const lit = await page.$eval("#radar", (c) => {
      const d = c.getContext("2d").getImageData(0, 0, c.width, c.height).data;
      let n = 0;
      for (let i = 0; i < d.length; i += 4) if (d[i] > 200 && d[i + 1] < 140) n++; // red-ish pixels
      return n;
    });
    assert.ok(lit > 20, "radar shows colored blips");
    await page.screenshot({ path: join(site, "live.png"), fullPage: true });

    // Drone detail sheet with decoded position.
    await page.click('.dev[data-dev="drone"]');
    const sheet = await page.$eval("#sheet-body", (e) => e.textContent);
    assert.match(sheet, /40\.748441, -73\.985664/);
    assert.match(sheet, /120\.5 m/);
    assert.match(sheet, /Airborne/);
    await page.screenshot({ path: join(site, "drone.png") });
    await page.click("#sheet-close");

    // Filter by category.
    await page.click('.counter[data-cat="vehicle"]');
    await page.waitForTimeout(900);
    assert.deepEqual(await page.$$eval(".dev .t", (n) => n.map((x) => x.textContent)), ["Tesla vehicle"]);
    await page.click('.counter[data-cat="vehicle"]');

    // Export CSV and the AI debrief.
    await page.click('nav.tabs [data-view="log"]');
    const [dl] = await Promise.all([page.waitForEvent("download"), page.click("#export-csv")]);
    const csv = readFileSync(await dl.path(), "utf8");
    assert.match(csv.split("\r\n")[0], /^time,radio,device_id,mac,frequency_mhz,name,category/);
    assert.match(csv, /1581F5FKD229400ABCDE/);
    await page.click("#debrief-make");
    const deb = await page.$eval("#debrief", (e) => e.textContent);
    assert.match(deb, /Drone 1/);
    assert.match(deb, /Watchlist alerts: 1/);

    for (const v of ["live", "watch", "log", "about"]) {
      await page.click(`nav.tabs [data-view="${v}"]`);
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth), 0, `${v} scrolls sideways`);
    }
    await page.click('nav.tabs [data-view="watch"]');
    await page.screenshot({ path: join(site, "watch.png"), fullPage: true });
    assert.deepEqual(errors, []);
    await ctx.close();

    // Bluefy-style: Bluetooth appears a moment after the page has loaded.
    const late = await browser.newContext({ ...pw.devices["iPhone 13"], deviceScaleFactor: 1 });
    await late.addInitScript(`setTimeout(() => Object.defineProperty(navigator, "bluetooth", { configurable: true, value: { addEventListener() {}, removeEventListener() {}, requestLEScan: async () => ({ stop() {} }) } }), 1000);`);
    const pl = await late.newPage();
    await pl.goto("http://127.0.0.1:8399/airscope/");
    assert.match(await pl.$eval("#support", (e) => e.textContent), /Waiting for Bluetooth/);
    await pl.waitForSelector("#start", { timeout: 5000 });
    await pl.goto("http://127.0.0.1:8399/scanner/");
    await pl.waitForSelector("#bt-start", { timeout: 5000 });
    await late.close();

    // Pick-only browsers (Bluefy): follow several devices picked one by one.
    const pickCtx = await browser.newContext({ viewport: { width: 390, height: 844 } });
    await pickCtx.addInitScript(`(() => {
      const devices = [
        { id: "p1", name: "Geotab GO9", live: true },
        { id: "p2", name: "S1a2b3c4d5e6f7a8bC", live: false },
        { id: "p1", name: "Geotab GO9", live: true },
      ];
      let i = 0;
      Object.defineProperty(navigator, "bluetooth", { configurable: true, value: { requestDevice: async () => {
        const spec = devices[i++];
        const listeners = [];
        const dev = { id: spec.id, name: spec.name, addEventListener: (t, f) => listeners.push(f), removeEventListener() {} };
        if (spec.live) dev.watchAdvertisements = async () => { setInterval(() => listeners.forEach((f) => f({ rssi: -60, manufacturerData: new Map(), serviceData: new Map(), uuids: [] })), 150); };
        return dev;
      } } });
    })();`);
    const pp = await pickCtx.newPage();
    await pp.goto("http://127.0.0.1:8399/airscope/");
    await pp.click("#pick");
    await pp.waitForFunction(() => /Following 1 device/.test(document.querySelector("#support").textContent));
    await pp.click("#pick");
    await pp.waitForFunction(() => /Following 2 devices/.test(document.querySelector("#support").textContent));
    assert.match(await pp.$eval("#support", (e) => e.textContent), /didn't send live signal strength for 1 of them/);
    await pp.waitForTimeout(1200);
    const followed = await pp.$$eval(".dev .t", (n) => n.map((x) => x.textContent).sort());
    assert.deepEqual(followed, ["Fleet telematics (by name)", "Tesla vehicle"]);
    assert.match(await pp.$eval('.dev[data-dev="p1"] .r', (e) => e.textContent), /-60/, "live device shows signal");
    await pp.click("#pick");
    await pp.waitForFunction(() => /Already following/.test(document.querySelector("#toast").textContent));
    assert.match(await pp.$eval("#support", (e) => e.textContent), /Following 2 devices/);
    await pp.click("#stop-all");
    assert.match(await pp.$eval("#support", (e) => e.textContent), /Pick the devices to follow/);
    await pickCtx.close();

    // Android app: the native core feeds Bluetooth + Wi-Fi events into the page.
    const droneIe = [0xfa, 0x0b, 0xbc, 0x0d, 5, 0xf2, 25, 2, ...basicId("WIFI-SN-77"), ...location({ lat: 34.05, lon: -118.25, altGeo: 90 })].map((b) => b.toString(16).padStart(2, "0")).join("");
    const andCtx = await browser.newContext({ viewport: { width: 390, height: 844 } });
    await andCtx.addInitScript(`(() => {
      window.__nativeCalls = [];
      const ev = (list) => window.__airscopeEvents && window.__airscopeEvents(list);
      let timer = null;
      window.AirscopeNative = {
        start() {
          window.__nativeCalls.push(["start"]);
          ev([{ type: "state", scanning: true, bluetooth: true, warnings: [] }]);
          timer = setInterval(() => ev([
            { type: "ble", id: "00:25:DF:AA:BB:01", mac: "00:25:DF:AA:BB:01", rssi: -67, manufacturerData: {}, serviceData: {}, uuids: [] },
            { type: "ble", id: "C4:00:00:00:00:09", mac: "C4:00:00:00:00:09", name: "S1a2b3c4d5e6f7a8bC", rssi: -60, manufacturerData: {}, serviceData: {}, uuids: [] },
            { type: "wifi", networks: [
              { bssid: "00:30:44:1A:2B:3C", ssid: "Squad7", rssi: -63, frequency: 5180, capabilities: "[WPA2-PSK-CCMP][ESS]", vendorIes: [] },
              { bssid: "B4:1E:52:00:00:02", ssid: "cam-unit", rssi: -71, frequency: 2437, capabilities: "[WPA2]", vendorIes: [] },
              { bssid: "11:22:33:44:55:66", ssid: "Flock-7781", rssi: -74, frequency: 2412, capabilities: "[WPA2]", vendorIes: [] },
              { bssid: "60:60:1F:00:00:01", ssid: "DJI-xyz", rssi: -80, frequency: 5745, capabilities: "[WPA2]", vendorIes: ["${droneIe}"] },
              { bssid: "AA:BB:CC:00:00:01", ssid: "Home", rssi: -50, frequency: 2462, capabilities: "[WPA3-SAE]", vendorIes: [] }
            ] },
            { type: "location", latitude: 34.0522, longitude: -118.2437 }
          ]), 200);
        },
        stop() { clearInterval(timer); window.__nativeCalls.push(["stop"]); ev([{ type: "state", scanning: false }]); },
        vibrate(ms) { window.__nativeCalls.push(["vibrate", ms]); },
        saveFile(name, mime, text) { window.__nativeCalls.push(["saveFile", name, mime, text.length]); },
        copy(text) { window.__nativeCalls.push(["copy", text.length]); },
      };
    })();`);
    const ap = await andCtx.newPage();
    const aerrors = [];
    ap.on("pageerror", (e) => aerrors.push(e.message));
    await ap.goto("http://127.0.0.1:8399/airscope/");
    // A custom signature and an address-prefix watch rule, set up first.
    await ap.click('nav.tabs [data-view="watch"]');
    await ap.fill("#custom-value", "B4:1E:52");
    await ap.selectOption("#custom-category", "alpr");
    await ap.fill("#custom-label", "Flock camera (my signature)");
    await ap.click('#custom-form button[type="submit"]');
    await ap.selectOption("#watch-kind", "mac");
    await ap.fill("#watch-value", "00:30:44");
    await ap.click('#watch-form button[type="submit"]');
    await ap.click('nav.tabs [data-view="live"]');
    await ap.click("#start");
    await ap.waitForFunction(() => document.querySelectorAll(".dev").length >= 7, null, { timeout: 8000 });
    await ap.waitForTimeout(900);
    const alabels = await ap.$$eval(".dev .t", (n) => n.map((x) => x.textContent));
    for (const want of ["Cradlepoint vehicle router", "Flock camera (my signature)", "Possible Flock Safety camera", "Axon device (body camera, TASER or Signal)", "Tesla vehicle", "Drone · WIFI-SN-77", "Home"]) {
      assert.ok(alabels.includes(want), `${want} listed (got ${alabels.join(" | ")})`);
    }
    assert.equal(alabels[0], "Cradlepoint vehicle router", "watched router first");
    assert.match(await ap.$eval("#alert-text", (e) => e.textContent), /Cradlepoint.*00:30:44/);
    assert.ok((await ap.evaluate(() => window.__nativeCalls)).some((c) => c[0] === "vibrate"), "alert vibrates natively");
    assert.match(await ap.$eval("#support", (e) => e.textContent), /Bluetooth: scanning · Wi-Fi: 5 networks/);
    assert.ok(await ap.$('.dev[data-dev="wifi:00:30:44:1a:2b:3c"] .badge'), "Wi-Fi badge");
    await ap.click('.dev[data-dev="wifi:00:30:44:1a:2b:3c"]');
    const asheet = await ap.$eval("#sheet-body", (e) => e.textContent);
    assert.match(asheet, /Wi-Fi · 5 GHz · 5180 MHz/);
    assert.match(asheet, /WPA2/);
    assert.match(asheet, /police, fire, EMS/);
    await ap.screenshot({ path: join(site, "android-sheet.png") });
    await ap.click("#sheet-close");
    await ap.screenshot({ path: join(site, "android-live.png"), fullPage: true });
    await ap.click('nav.tabs [data-view="log"]');
    await ap.click("#export-csv");
    const saved = (await ap.evaluate(() => window.__nativeCalls)).find((c) => c[0] === "saveFile");
    assert.ok(saved && /\.csv$/.test(saved[1]) && saved[2] === "text/csv" && saved[3] > 100, "CSV saved through the app");
    await ap.click('nav.tabs [data-view="live"]');
    await ap.click("#stop");
    assert.match(await ap.$eval("#support", (e) => e.textContent), /Start scan/);
    assert.deepEqual(aerrors, []);
    await andCtx.close();

    const ios = await browser.newContext({ ...pw.devices["iPhone 13"], deviceScaleFactor: 1 });
    const p2 = await ios.newPage();
    await p2.goto("http://127.0.0.1:8399/airscope/");
    assert.match(await p2.$eval("#support", (e) => e.textContent), /Bluefy/);
    await ios.close();
    console.log(`SCREENSHOTS ${site}`);
  } finally {
    await browser.close();
    server.close();
  }
});
