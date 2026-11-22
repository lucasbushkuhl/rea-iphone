#!/usr/bin/env node
// Build the static web app into site/ (zero dependencies).
//
//   site/index.html        full document with PWA head (GitHub Pages / any host)
//   site/app.html          page content only (for hosts that supply the skeleton)
//   site/*.js              web app modules
//   site/core/**           the analysis core, copied from src/ by import graph
//   site/sample/Demo.ipa   the bundled sample app
//
// Fails if any module bound for the browser imports a Node built-in.

import { readFileSync, writeFileSync, mkdirSync, rmSync, copyFileSync, existsSync, readdirSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const WEB = join(ROOT, "web");
const SRC = join(ROOT, "src");
const OUT = resolve(process.argv[2] ?? join(ROOT, "site"));

const IMPORT_RE = /^\s*(?:import|export)\s[^;]*?from\s+["']([^"']+)["']|^\s*import\s+["']([^"']+)["']/gm;
const specifiers = (code) => [...code.matchAll(IMPORT_RE)].map((m) => m[1] ?? m[2]);

rmSync(OUT, { recursive: true, force: true });
mkdirSync(join(OUT, "core"), { recursive: true });

// 1. Web modules, and the core modules they reach.
const webModules = readdirSync(WEB).filter((f) => f.endsWith(".js") && f !== "sw.js");
const coreQueue = [];
for (const f of webModules) {
  const code = readFileSync(join(WEB, f), "utf8");
  for (const s of specifiers(code)) {
    if (s.startsWith("node:")) throw new Error(`web/${f} imports ${s}`);
    if (s.startsWith("./core/")) coreQueue.push(join(SRC, s.slice("./core/".length)));
  }
  writeFileSync(join(OUT, f), code);
}
const copied = new Set();
while (coreQueue.length) {
  const file = coreQueue.pop();
  if (copied.has(file)) continue;
  copied.add(file);
  const code = readFileSync(file, "utf8");
  for (const s of specifiers(code)) {
    if (s.startsWith("node:")) throw new Error(`${relative(ROOT, file)} imports ${s}, so it can't run in a browser`);
    if (s.startsWith(".")) coreQueue.push(resolve(dirname(file), s));
  }
  const dest = join(OUT, "core", relative(SRC, file));
  mkdirSync(dirname(dest), { recursive: true });
  writeFileSync(dest, code);
}

// 2. Static assets.
mkdirSync(join(OUT, "icons"), { recursive: true });
for (const f of readdirSync(join(WEB, "icons"))) copyFileSync(join(WEB, "icons", f), join(OUT, "icons", f));
copyFileSync(join(WEB, "manifest.webmanifest"), join(OUT, "manifest.webmanifest"));
// The sample ships as base64 text: every static host (including ones that
// refuse archive types) serves .txt, and the app decodes it in the browser.
mkdirSync(join(OUT, "sample"), { recursive: true });
writeFileSync(join(OUT, "sample", "Demo.ipa.b64.txt"), readFileSync(join(ROOT, "examples", "Demo.ipa")).toString("base64"));

// 3. Pages: the content file is self-contained page markup (title, meta,
// style, body). The full document moves the head-only parts into <head>.
const page = readFileSync(join(WEB, "index.html"), "utf8");
writeFileSync(join(OUT, "app.html"), page);
const [headPart, bodyPart] = page.split("<!-- end-head -->");
if (bodyPart === undefined) throw new Error("web/index.html needs an <!-- end-head --> marker");
const pwaHead = `<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#f4f6f9" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#0b1017" media="(prefers-color-scheme: dark)">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-title" content="REA iPhone">
<meta name="apple-mobile-web-app-status-bar-style" content="default">
<meta name="description" content="Reverse-engineer iOS apps on your iPhone: class-dump, Swift metadata, strings, symbols and entitlements. Runs on your device; nothing is uploaded.">
<link rel="manifest" href="manifest.webmanifest">
<link rel="apple-touch-icon" href="icons/icon-180.png">
<link rel="icon" type="image/png" sizes="192x192" href="icons/icon-192.png">`;
writeFileSync(join(OUT, "index.html"), `<!doctype html>
<html lang="en">
<head>
${pwaHead}
${headPart.trim()}
</head>
<body>
${bodyPart.trim()}
</body>
</html>
`);

// 4. Service worker: precache every file, keyed by a content hash so each
// deploy replaces the previous cache.
const files = [];
const walk = (d) => {
  for (const f of readdirSync(d, { withFileTypes: true })) {
    const p = join(d, f.name);
    if (f.isDirectory()) walk(p);
    else files.push(relative(OUT, p).split("\\").join("/"));
  }
};
walk(OUT);
const hash = createHash("sha256");
for (const f of files.sort()) hash.update(f).update(readFileSync(join(OUT, f)));
const version = hash.digest("hex").slice(0, 12);
const sw = readFileSync(join(WEB, "sw.js"), "utf8")
  .replaceAll("__VERSION__", version)
  .replaceAll("__PRECACHE__", JSON.stringify(["./", ...files.filter((f) => f !== "app.html")], null, 2));
if (/__VERSION__|__PRECACHE__/.test(sw)) throw new Error("sw.js placeholders were not filled");
writeFileSync(join(OUT, "sw.js"), sw);

if (!existsSync(join(OUT, "core", "analyzeSource.js"))) throw new Error("core was not copied");
console.log(`Built ${relative(ROOT, OUT) || "."}: ${files.length + 1} files, ${copied.size} core modules, version ${version}`);

// 5. Standalone phone apps, each in its own folder with its own offline
// cache. Modules may import their own files and, for Airscope, Signal
// Sweep's shared Bluetooth modules.
function buildApp(dir, { shared = [] } = {}) {
  const SRCDIR = join(ROOT, dir);
  const DEST = join(OUT, dir);
  mkdirSync(join(DEST, "icons"), { recursive: true });
  const files = [];
  for (const f of readdirSync(SRCDIR)) {
    if (f === "sw.js" || f === "icons") continue;
    const code = readFileSync(join(SRCDIR, f));
    if (f.endsWith(".js")) {
      for (const spec of specifiers(code.toString("utf8"))) {
        const ok = spec.startsWith("./") || shared.some((p) => spec === `../${p}`);
        if (!ok) throw new Error(`${dir}/${f} imports ${spec}; not allowed in a browser app`);
      }
    }
    writeFileSync(join(DEST, f), code);
    files.push(f);
  }
  for (const f of readdirSync(join(SRCDIR, "icons"))) {
    copyFileSync(join(SRCDIR, "icons", f), join(DEST, "icons", f));
    files.push(`icons/${f}`);
  }
  const precache = ["./", ...files, ...shared.map((p) => `../${p}`)];
  const h = createHash("sha256");
  for (const f of files.sort()) h.update(f).update(readFileSync(join(DEST, f)));
  for (const p of shared) h.update(p).update(readFileSync(join(ROOT, p)));
  const v = h.digest("hex").slice(0, 12);
  const sw = readFileSync(join(SRCDIR, "sw.js"), "utf8").replaceAll("__VERSION__", v).replaceAll("__PRECACHE__", JSON.stringify(precache, null, 2));
  if (/__VERSION__|__PRECACHE__/.test(sw)) throw new Error(`${dir}/sw.js placeholders were not filled`);
  writeFileSync(join(DEST, "sw.js"), sw);
  console.log(`Built ${relative(ROOT, DEST)}: ${files.length + 1} files, version ${v}`);
}
buildApp("scanner");
buildApp("airscope", { shared: ["scanner/ble.js", "scanner/trackers.js"] });
