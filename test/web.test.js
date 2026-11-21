// Web app: build output, browser Buffer, the engine on the Blob/stream path,
// and (when Playwright is installed) the UI in headless Chromium.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { analyze } from "../src/analyze.js";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const SITE = mkdtempSync(join(tmpdir(), "rea-site-"));
const SAMPLE = join(ROOT, "examples", "Demo.ipa");

before(() => {
  execFileSync(process.execPath, [join(ROOT, "scripts", "build-web.mjs"), SITE], { stdio: "pipe" });
});

test("build: browser-only core, PWA document, offline precache", () => {
  for (const f of ["index.html", "app.html", "app.js", "engine.js", "worker.js", "buffer.js", "blobzip.js", "sw.js", "manifest.webmanifest", "sample/Demo.ipa.b64.txt", "icons/icon-180.png", "core/analyzeSource.js", "core/macho/fixups.js", "core/swift/demangle.js"]) {
    assert.ok(existsSync(join(SITE, f)), f);
  }
  assert.ok(!existsSync(join(SITE, "core", "target.js")), "Node-only loader is not shipped");
  assert.ok(!existsSync(join(SITE, "core", "mcp")), "MCP server is not shipped");
  const html = readFileSync(join(SITE, "index.html"), "utf8");
  assert.match(html, /^<!doctype html>/);
  assert.match(html, /<link rel="manifest" href="manifest.webmanifest">/);
  assert.match(html, /<link rel="apple-touch-icon" href="icons\/icon-180.png">/);
  assert.match(html, /<head>[\s\S]*<title>REA iPhone<\/title>[\s\S]*<\/head>/);
  const sw = readFileSync(join(SITE, "sw.js"), "utf8");
  assert.doesNotMatch(sw, /__VERSION__|__PRECACHE__/);
  assert.match(sw, /"core\/objc.js"/);
  const manifest = JSON.parse(readFileSync(join(SITE, "manifest.webmanifest"), "utf8"));
  assert.equal(manifest.display, "standalone");
});

test("BrowserBuffer matches Node's Buffer on every method the core uses", async () => {
  const { BrowserBuffer } = await import(join(SITE, "buffer.js"));
  const raw = randomBytes(4096);
  const n = Buffer.from(raw);
  const b = BrowserBuffer.from(raw);
  for (let o = 0; o < 4000; o += 7) {
    for (const m of ["readUInt8", "readUInt16LE", "readUInt16BE", "readUInt32LE", "readUInt32BE", "readInt32LE", "readInt32BE", "readBigUInt64LE", "readBigUInt64BE", "readDoubleBE", "readFloatBE"]) {
      const x = n[m](o);
      const y = b[m](o);
      assert.ok(Object.is(x, y) || (Number.isNaN(x) && Number.isNaN(y)), `${m}(${o})`);
    }
  }
  for (const enc of ["latin1", "ascii", "utf16le", "hex"]) assert.equal(b.toString(enc, 3, 999), n.toString(enc, 3, 999), enc);
  const text = Buffer.from("héllo wörld ✓ \u{1F600}", "utf8");
  assert.equal(BrowserBuffer.from(text).toString("utf8"), text.toString("utf8"));
  assert.equal(BrowserBuffer.from("abcÿ", "latin1").toString("hex"), "616263ff");
  const sub = b.subarray(100, 200);
  assert.ok(sub instanceof BrowserBuffer);
  assert.equal(sub.readUInt32LE(0), n.readUInt32LE(100));
  assert.throws(() => b.readUInt32LE(4094), RangeError);
  assert.throws(() => sub.readUInt32LE(98), RangeError);
});

test("engine: Blob path reproduces the CLI's deep analysis", async () => {
  const engine = await import(join(SITE, "engine.js"));
  const r = await engine.openFile(new Blob([readFileSync(SAMPLE)]), "Demo.ipa");
  const cli = analyze(SAMPLE, { deep: true });
  const full = cli.apps[0]._deepFull;
  assert.equal(r.report.apps[0].bundle.identifier, cli.apps[0].bundle.identifier);
  assert.equal(r.report.apps[0].executable.sha256, cli.apps[0].executable.sha256);
  assert.deepEqual(r.binaries.map((b) => b.path), cli.binaries.map((b) => b.path));
  assert.deepEqual(r.deep.objc.classes.map((c) => c.name), full.objc.classes.map((c) => c.name));
  assert.deepEqual(r.deep.swift.types.map((t) => t.fullName), full.swift.types.map((t) => t.fullName));
  assert.deepEqual(Object.keys(r.deep.strings.findings).sort(), Object.keys(full.strings.findings).sort());
  assert.match(r.deep.objc.classes[0].header, /^@interface Wallet : NSObject <Greeter>/);
  assert.match(r.text, /Deep static analysis|REA-iPhone/);

  const fw = await engine.analyzeBinary("Payload/Demo.app/Frameworks/Flutter.framework/Flutter", null);
  assert.equal(fw.image.encrypted, true);
  const sim = await engine.analyzeBinary(r.binaries[0].path, "x86_64");
  assert.equal(sim.arch, "x86_64");
  assert.match(engine.fridaScript("network", {}), /mode: network/);
  assert.equal(engine.demangle(["_$sSHMp"])[0].demangled, "protocol descriptor for Swift.Hashable");
});

test("engine: gzip fallback when raw-deflate streams are unavailable", async () => {
  const Real = globalThis.DecompressionStream;
  globalThis.DecompressionStream = class extends Real {
    constructor(format) {
      if (format === "deflate-raw") throw new TypeError("unsupported format");
      super(format);
    }
  };
  try {
    const engine = await import(`${join(SITE, "engine.js")}?gzip`);
    const r = await engine.openFile(new Blob([readFileSync(SAMPLE)]), "Demo.ipa");
    assert.equal(r.deep.objc.classes.length, 3);
  } finally {
    globalThis.DecompressionStream = Real;
  }
});

test("engine: clear errors for files that aren't apps", async () => {
  const engine = await import(join(SITE, "engine.js"));
  await assert.rejects(engine.openFile(new Blob([]), "empty"), /empty or too small/);
  await assert.rejects(engine.openFile(new Blob(["just some text"]), "notes.txt"), /isn't an \.ipa/);
  await assert.rejects(engine.openFile(new Blob([readFileSync(SAMPLE).subarray(0, 4000)]), "cut.ipa"), /incomplete or damaged/);
});

let playwright = null;
try { playwright = createRequire(import.meta.url)("playwright"); } catch { /* optional */ }
let server;
after(() => server?.close());

test("UI in headless Chromium at iPhone size", { skip: !playwright && "Playwright not installed" }, async () => {
  const { serve } = await import("../scripts/serve.mjs");
  server = await serve(SITE, 8199);
  const browser = await playwright.chromium.launch();
  try {
    for (const colorScheme of ["light", "dark"]) {
      const ctx = await browser.newContext({ ...playwright.devices["iPhone 13"], colorScheme, deviceScaleFactor: 1 });
      const page = await ctx.newPage();
      const errors = [];
      page.on("pageerror", (e) => errors.push(e.message));
      page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
      await page.goto("http://127.0.0.1:8199/");
      await page.waitForSelector("#panel-overview h1", { timeout: 20000 });
      assert.equal(await page.$eval("#panel-overview h1", (h) => h.textContent), "Demo App");
      assert.ok(page.workers().some((w) => w.url().endsWith("/worker.js")), "analysis runs in a worker");
      for (const tab of ["classes", "swift", "strings", "symbols", "frida", "demangle", "overview"]) {
        await page.click(`#tab-${tab}`);
        const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
        assert.equal(overflow, 0, `${colorScheme}/${tab} scrolls sideways`);
      }
      await page.click("#tab-frida");
      await page.click("#f-gen");
      await page.waitForSelector("#frida-js-src");
      await page.setInputFiles("#file", join(ROOT, "test", "fixtures", "bin", "WalletKit-classic"));
      await page.waitForFunction(() => document.querySelector("#filebar .name")?.textContent === "WalletKit-classic");
      assert.equal(await page.$eval("#notice", (n) => n.hidden), true, "sample notice clears after opening a file");
      assert.deepEqual(errors, []);
      if (colorScheme === "light") {
        // Offline: once the service worker has cached the app, it reloads and
        // analyzes with no network at all.
        await page.waitForFunction(() => navigator.serviceWorker?.controller || navigator.serviceWorker?.ready.then(() => true), null, { timeout: 15000 });
        await page.evaluate(() => navigator.serviceWorker.ready);
        await page.reload();
        await page.waitForFunction(() => !!navigator.serviceWorker.controller, null, { timeout: 15000 });
        await ctx.setOffline(true);
        await page.reload();
        await page.waitForSelector("#panel-overview h1", { state: "attached", timeout: 20000 });
        assert.equal(await page.$eval("#panel-overview h1", (h) => h.textContent), "Demo App", "works offline");
        assert.equal(await page.$eval('.tab[aria-selected="true"]', (t) => t.dataset.tab), "frida", "remembers the last tab");
        await ctx.setOffline(false);
      }
      await ctx.close();
    }
  } finally {
    await browser.close();
  }
});
