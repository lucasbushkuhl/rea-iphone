// Signal Sweep: tracker identification, device registry, lens/IR detection.
import { test } from "node:test";
import assert from "node:assert/strict";
import { classify, normalizeAdvert, shortUuid, proximity, checkNetworkName } from "../scanner/trackers.js";
import { DeviceRegistry, bluetoothSupport, explainBluetoothError } from "../scanner/ble.js";
import { findSpots, SpotTracker } from "../scanner/lens.js";

const full = (s) => `0000${s}-0000-1000-8000-00805f9b34fb`;
const findMy = (status, separated = true) =>
  separated ? [0x12, 0x19, status, ...new Array(22).fill(0xab), 0x00, 0x01] : [0x12, 0x02, status, 0x00];

test("Apple Find My: separated trackers are high concern, near-owner is low", () => {
  const airtag = classify({ manufacturerData: new Map([[0x004c, new DataView(Uint8Array.from(findMy(0x10)).buffer)]]) });
  assert.equal(airtag.label, "AirTag, away from its owner");
  assert.equal(airtag.concern, "high");
  assert.equal(airtag.category, "tracker");
  assert.equal(classify({ manufacturerData: { 0x004c: findMy(0x20) } }).label, "Find My accessory (third-party tracker), away from its owner");
  assert.equal(classify({ manufacturerData: { 0x004c: findMy(0x20) } }).concern, "high");
  const pods = classify({ manufacturerData: { 0x004c: findMy(0x30) } });
  assert.deepEqual([pods.category, pods.concern], ["audio", "medium"]);
  const phone = classify({ manufacturerData: { 0x004c: findMy(0x00) } });
  assert.deepEqual([phone.category, phone.concern], ["phone", "low"]);
  const near = classify({ manufacturerData: { 0x004c: findMy(0x10, false) } });
  assert.deepEqual([near.label, near.concern], ["Find My device, near its owner", "low"]);
});

test("other Apple advertisements", () => {
  assert.equal(classify({ manufacturerData: { 0x004c: [0x07, 0x19, 0x01] } }).label, "AirPods or Beats");
  assert.equal(classify({ manufacturerData: { 0x004c: [0x10, 0x05, 0x01] } }).label, "Apple device nearby");
  assert.equal(classify({ manufacturerData: { 0x004c: [0x02, 0x15] } }).label, "iBeacon");
});

test("Tile, SmartTag, Chipolo, Google Find My Device", () => {
  assert.equal(classify({ uuids: [full("feed")] }).label, "Tile tracker");
  assert.equal(classify({ serviceData: new Map([[full("feec"), new DataView(new ArrayBuffer(4))]]) }).label, "Tile tracker");
  assert.equal(classify({ serviceData: { [full("fd5a")]: [1, 2, 3] } }).label, "Samsung SmartTag");
  assert.equal(classify({ uuids: ["fe33"] }).label, "Chipolo tracker");
  const fmdn = classify({ serviceData: { [full("feaa")]: [0x41, 1, 2] } });
  assert.deepEqual([fmdn.category, fmdn.concern], ["tracker", "high"]);
  assert.equal(classify({ serviceData: { [full("feaa")]: [0x40, 1] } }).concern, "medium");
  assert.notEqual(classify({ serviceData: { [full("feaa")]: [0x10, 1] } }).category, "tracker", "Eddystone-URL is not a tracker");
});

test("names, vendors, unknowns", () => {
  assert.equal(classify({ name: "IPC-Cam 3341" }).category, "camera");
  assert.equal(classify({ name: "iTag" }).category, "tracker");
  assert.equal(classify({ name: "Kitchen Speaker" }).label, "Named device");
  assert.equal(classify({ manufacturerData: { 0x0075: [1, 2] } }).label, "Samsung device");
  const u = classify({});
  assert.deepEqual([u.category, u.concern], ["unknown", "none"]);
  assert.equal(shortUuid(full("FEED")), "feed");
  assert.equal(shortUuid("0xFD5A"), "fd5a");
  const n = normalizeAdvert({ device: { id: "x", name: "n" }, rssi: -60 });
  assert.deepEqual([n.id, n.name, n.rssi], ["x", "n", -60]);
});

test("proximity bands", () => {
  assert.equal(proximity(-50).band, "very close");
  assert.equal(proximity(-62).band, "near");
  assert.equal(proximity(-75).band, "in the room");
  assert.equal(proximity(-90).band, "far");
  assert.equal(proximity(-59).meters, 1);
  assert.equal(proximity(null).band, "unknown");
});

test("Wi-Fi network names from hidden cameras", () => {
  for (const s of ["IPC-12345", "V380_ABC123", "HD-CAM-55aa", "WIFICAM_01", "Yoosee-777", "CAM-a1b2c3", "spy hd"]) {
    assert.equal(checkNetworkName(s).suspicious, true, s);
  }
  for (const s of ["MyHomeWiFi", "NETGEAR42", "Starbucks WiFi", "Hilton Honors"]) assert.equal(checkNetworkName(s).suspicious, false, s);
  assert.equal(checkNetworkName("XX-A1B2C3D4E5").strength, "weak");
  assert.equal(checkNetworkName("  "), null);
});

test("registry: smoothing, trend, upgrade to the most concerning type, ordering, staleness", () => {
  const r = new DeviceRegistry();
  let t = 0;
  for (const rssi of [-85, -84, -80, -76, -72, -68, -64, -60]) r.ingest({ id: "tag", rssi, uuids: [] }, (t += 500));
  r.ingest({ id: "tag", rssi: -60, manufacturerData: { 0x004c: findMy(0x10) } }, (t += 500));
  r.ingest({ id: "phone", rssi: -40, manufacturerData: { 0x004c: [0x10, 5, 1] } }, t);
  const tag = r.devices.get("tag");
  assert.equal(tag.label, "AirTag, away from its owner", "upgraded once the Find My packet arrives");
  assert.ok(tag.trend > 5, `getting warmer (trend ${tag.trend})`);
  assert.ok(tag.rssi < -60 && tag.rssi > -80, "smoothed, not raw");
  assert.equal(tag.rssiMax, -60);
  const list = r.list(t);
  assert.deepEqual(list.map((d) => d.id), ["tag", "phone"], "high concern first despite weaker signal");
  assert.deepEqual(r.list(t + 60000).map((d) => d.id), [], "stale devices drop out");
  r.ingest({ id: "tag", rssi: -61 }, t + 5 * 60000);
  assert.equal(r.list(t + 5 * 60000)[0].minutesAround, 5);
});

test("bluetooth support detection and error messages", () => {
  assert.equal(bluetoothSupport({}).level, "none");
  assert.equal(bluetoothSupport({ bluetooth: { requestDevice() {} } }).level, "pick");
  assert.equal(bluetoothSupport({ bluetooth: { requestLEScan() {}, requestDevice() {} } }).level, "scan");
  assert.match(explainBluetoothError({ name: "NotAllowedError", message: "x" }), /permission/);
  assert.match(explainBluetoothError({ name: "InvalidStateError", message: "x" }), /turned off/);
});

// ---- synthetic camera frames

function frame(w, h, bg = 30, noise = 12, seed = 1) {
  let s = seed;
  const rnd = () => (s = (s * 1103515245 + 12345) % 2147483648) / 2147483648;
  const data = new Uint8ClampedArray(w * h * 4);
  for (let i = 0; i < w * h; i++) {
    const v = bg + (rnd() - 0.5) * noise;
    data[i * 4] = v; data[i * 4 + 1] = v; data[i * 4 + 2] = v; data[i * 4 + 3] = 255;
  }
  return { width: w, height: h, data };
}
function paint(f, x0, y0, w, h, [r, g, b]) {
  for (let y = y0; y < y0 + h; y++) for (let x = x0; x < x0 + w; x++) {
    const i = (y * f.width + x) * 4;
    f.data[i] = r; f.data[i + 1] = g; f.data[i + 2] = b;
  }
}

test("lens detector: finds small glints, ignores lamps/windows and edges", () => {
  const f = frame(320, 240);
  paint(f, 100, 80, 3, 3, [255, 255, 255]); // lens glint
  paint(f, 200, 150, 60, 60, [250, 250, 250]); // bright window
  paint(f, 20, 20, 1, 40, [255, 255, 255]); // bright edge / line
  paint(f, 260, 40, 3, 3, [230, 150, 245]); // purple IR LED
  const spots = findSpots(f);
  const near = (x, y) => spots.find((s) => Math.hypot(s.x - x, s.y - y) < 4);
  assert.ok(near(101.5, 81.5), "glint found");
  assert.ok(near(261.5, 41.5)?.purple, "IR LED found and flagged purple");
  assert.equal(spots.filter((s) => s.x > 195 && s.y > 145).length, 0, "large bright area ignored");
  assert.equal(spots.filter((s) => s.x < 25).length, 0, "thin line ignored");
  assert.equal(findSpots(frame(320, 240, 30, 12, 7)).length, 0, "noise alone gives nothing");
});

test("spot tracker: only steady spots are reported; blinking is counted", () => {
  const tr = new SpotTracker({ minFrames: 4 });
  let out;
  for (let i = 0; i < 4; i++) out = tr.update([{ x: 100 + i, y: 50, r: 3, contrast: 150, purple: false }]);
  assert.equal(out.length, 1);
  assert.equal(out[0].steady, true);
  // A one-frame flash elsewhere is not steady.
  out = tr.update([{ x: 104, y: 50, r: 3, contrast: 150 }, { x: 300, y: 200, r: 3, contrast: 90 }]);
  assert.deepEqual(out.map((t) => t.steady), [true, false]);
  // Blinking: gap then return.
  tr.update([]);
  out = tr.update([{ x: 104, y: 51, r: 3, contrast: 150 }]);
  assert.equal(out.find((t) => t.x > 100 && t.x < 110).blinks, 1);
});

// ---- end-to-end in headless Chromium (skipped without Playwright)
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

let pw = null;
try { pw = createRequire(import.meta.url)("playwright"); } catch { /* optional */ }

/** A Y4M video: dark noisy room with one small, steady, lens-like glint. */
function glintVideo(path, w = 320, h = 240, frames = 40) {
  const header = Buffer.from(`YUV4MPEG2 W${w} H${h} F15:1 Ip A1:1 C420jpeg\n`);
  const chunks = [header];
  let s = 7;
  const rnd = () => (s = (s * 1103515245 + 12345) % 2147483648) / 2147483648;
  for (let f = 0; f < frames; f++) {
    const y = Buffer.alloc(w * h);
    for (let i = 0; i < y.length; i++) y[i] = 28 + Math.floor(rnd() * 10);
    for (let dy = 0; dy < 4; dy++) for (let dx = 0; dx < 4; dx++) y[(150 + dy) * w + (210 + dx)] = 255;
    chunks.push(Buffer.from("FRAME\n"), y, Buffer.alloc((w / 2) * (h / 2), 128), Buffer.alloc((w / 2) * (h / 2), 128));
  }
  writeFileSync(path, Buffer.concat(chunks));
}

const FAKE_BLUETOOTH = `(() => {
  const listeners = [];
  const dv = (arr) => new DataView(Uint8Array.from(arr).buffer);
  const uuid = (s) => "0000" + s + "-0000-1000-8000-00805f9b34fb";
  let t = 0;
  window.navigator.__defineGetter__ && 0;
  Object.defineProperty(navigator, "bluetooth", { configurable: true, value: {
    addEventListener: (type, fn) => listeners.push(fn),
    removeEventListener: () => {},
    requestDevice: async () => { throw new Error("not used"); },
    requestLEScan: async () => {
      const emit = (e) => listeners.forEach((fn) => fn(e));
      const timer = setInterval(() => {
        t++;
        const airtag = [0x12, 0x19, 0x10].concat(new Array(22).fill(0xab), [0, 1]);
        emit({ device: { id: "tag-1" }, rssi: Math.min(-48, -90 + t * 3), manufacturerData: new Map([[0x004c, dv(airtag)]]), serviceData: new Map(), uuids: [] });
        emit({ device: { id: "tile-1", name: "Tile" }, rssi: -74, manufacturerData: new Map(), serviceData: new Map(), uuids: [uuid("feed")] });
        emit({ device: { id: "phone-1" }, rssi: -52, manufacturerData: new Map([[0x004c, dv([0x10, 5, 1])]]), serviceData: new Map(), uuids: [] });
      }, 150);
      return { stop: () => clearInterval(timer), active: true };
    },
  }});
})();`;

test("Signal Sweep in headless Chromium", { skip: !pw && "Playwright not installed", timeout: 90000 }, async () => {
  const root = fileURLToPath(new URL("..", import.meta.url));
  const site = mkdtempSync(join(tmpdir(), "sweep-site-"));
  execFileSync(process.execPath, [join(root, "scripts", "build-web.mjs"), site], { stdio: "pipe" });
  const video = join(site, "glint.y4m");
  glintVideo(video);
  const { serve } = await import("../scripts/serve.mjs");
  const server = await serve(site, 8299);
  const browser = await pw.chromium.launch({ args: ["--use-fake-ui-for-media-stream", "--use-fake-device-for-media-stream", `--use-file-for-fake-video-capture=${video}`] });
  try {
    const ctx = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 1, colorScheme: "dark", permissions: ["camera"] });
    await ctx.addInitScript(FAKE_BLUETOOTH);
    const page = await ctx.newPage();
    const errors = [];
    page.on("pageerror", (e) => errors.push(e.message));
    page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
    await page.goto("http://127.0.0.1:8299/scanner/");

    // Bluetooth
    await page.click("#bt-start");
    await page.waitForFunction(() => document.querySelectorAll(".dev").length >= 3, null, { timeout: 10000 });
    await page.waitForTimeout(1500);
    const rows = await page.$$eval(".dev .t", (n) => n.map((x) => x.textContent.trim()));
    assert.match(rows[0], /^AirTag, away from its owner/, "high-concern tracker listed first");
    assert.ok(rows.some((r) => r.startsWith("Tile tracker")));
    assert.ok(rows.some((r) => r.startsWith("Apple device nearby")));
    assert.equal(await page.$eval("#st-trackers b", (b) => b.textContent), "2");
    await page.click('.dev:first-child [data-find]');
    await page.waitForTimeout(1200);
    assert.match(await page.$eval("#f-trend", (e) => e.textContent), /Warmer/);
    await page.screenshot({ path: join(site, "finder.png") });
    await page.click("#f-close");
    await page.screenshot({ path: join(site, "bluetooth.png"), fullPage: true });

    // Lens finder on the synthetic glint video
    await page.click('nav.tabs [data-view="lens"]');
    await page.click("#lens-cam [data-start]");
    await page.waitForFunction(() => /1 bright point/.test(document.querySelector("#lens-cam .count")?.textContent ?? ""), null, { timeout: 15000 });
    await page.screenshot({ path: join(site, "lens.png") });

    // Wi-Fi names
    await page.click('nav.tabs [data-view="wifi"]');
    await page.fill("#wifi-in", "HomeWiFi\nIPC-38211\nV380_A1B2C3");
    assert.equal(await page.$$eval("#wifi-out .tag", (t) => t.length), 2);

    // Checklist persists
    await page.click('nav.tabs [data-view="check"]');
    await page.click('#ck-list input[data-i="0"]');
    await page.reload();
    await page.waitForSelector("#ck-list input");
    assert.equal(await page.$eval('#ck-list input[data-i="0"]', (i) => i.checked), true);
    assert.match(await page.$eval("#ck-count", (e) => e.textContent), /1 of 10/);

    for (const v of ["bluetooth", "lens", "ir", "wifi", "check", "limits"]) {
      await page.evaluate((name) => document.querySelector(`[data-view="${name}"]`).click(), v);
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth), 0, `${v} scrolls sideways`);
    }
    assert.deepEqual(errors, []);
    await ctx.close();

    // iPhone Safari: no Web Bluetooth, so it explains Bluefy.
    const ios = await browser.newContext({ ...pw.devices["iPhone 13"], deviceScaleFactor: 1 });
    const p2 = await ios.newPage();
    await p2.goto("http://127.0.0.1:8299/scanner/");
    assert.match(await p2.$eval("#bt-support", (e) => e.textContent), /Safari can't use Bluetooth[\s\S]*Bluefy/);
    await ios.close();
    process.env.SWEEP_SHOTS = site;
  } finally {
    await browser.close();
    server.close();
  }
});
