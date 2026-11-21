// App-bundle logic shared by every environment (pure; no Node imports).
// A "source" is { container, list(), has(name), read(name) -> Buffer }.

import { parsePlist } from "./plist.js";
import { isMachO } from "./macho.js";

const baseName = (p) => p.replace(/\/+$/, "").split("/").pop();

/** A source over in-memory files: files is Map<path, Buffer>; listing may include unloaded members. */
export function memorySource(container, files, listing = null) {
  const entries = listing ?? [...files.entries()].map(([path, buf]) => ({ path, size: buf.length }));
  const names = new Set(entries.map((e) => e.path));
  return {
    container,
    list: () => entries,
    has: (name) => names.has(name),
    read: (name) => {
      const b = files.get(name);
      if (!b) throw new Error(names.has(name) ? `${name} is not loaded` : `no such file: ${name}`);
      return b;
    },
  };
}

export function machoSource(name, buf) {
  return memorySource("macho", new Map([[name, buf]]));
}

/** Application roots: each Payload/<Name>.app (IPA) or top-level <Name>.app (zipped bundle). */
export function findAppRoots(paths) {
  const roots = new Set();
  for (const p of paths) {
    const m = p.match(/^(Payload\/[^/]+\.app)\//) ?? p.match(/^([^/]+\.app)\//);
    if (m) roots.add(m[1]);
  }
  // A zipped bundle may also contain Payload-style roots; prefer those.
  const payload = [...roots].filter((r) => r.startsWith("Payload/"));
  return (payload.length ? payload : [...roots]).sort();
}

/** Files whose contents bundle discovery needs before any binary is read. */
export function isBundleMetadata(path) {
  return /(^|\/)Info\.plist$/.test(path) || /(^|\/)embedded\.mobileprovision$/.test(path);
}

function bundleExecutable(src, bundleDir) {
  const info = `${bundleDir}/Info.plist`;
  let exe = baseName(bundleDir).replace(/\.(app|appex|framework)$/, "");
  if (src.has(info)) {
    try {
      const p = parsePlist(src.read(info));
      if (p?.CFBundleExecutable) exe = p.CFBundleExecutable;
    } catch { /* fall back to the bundle name */ }
  }
  return `${bundleDir}/${exe}`;
}

/** Every analyzable binary: role "main" | "framework" | "dylib" | "extension" | "file". */
export function listBinaries(src) {
  const paths = src.list().map((e) => e.path);
  if (src.container === "macho") return [{ role: "file", path: paths[0] }];
  const out = [];
  for (const root of findAppRoots(paths)) {
    const main = bundleExecutable(src, root);
    if (src.has(main)) out.push({ role: "main", path: main, root });
    const nested = new Set();
    const fwRe = new RegExp(`^(${escapeRe(root)}/Frameworks/[^/]+\\.framework)/`);
    const exRe = new RegExp(`^(${escapeRe(root)}/PlugIns/[^/]+\\.appex)/`);
    const dyRe = new RegExp(`^${escapeRe(root)}/Frameworks/[^/]+\\.dylib$`);
    for (const p of paths) {
      const fw = p.match(fwRe);
      if (fw) nested.add(`framework\u0000${fw[1]}`);
      const ext = p.match(exRe);
      if (ext) nested.add(`extension\u0000${ext[1]}`);
      if (dyRe.test(p)) out.push({ role: "dylib", path: p, root });
    }
    for (const key of [...nested].sort()) {
      const [role, dir] = key.split("\u0000");
      const exe = bundleExecutable(src, dir);
      if (src.has(exe)) out.push({ role, path: exe, root });
    }
  }
  const rank = { main: 0, framework: 1, dylib: 2, extension: 3, file: 0 };
  return out.sort((a, b) => (a.root ?? "").localeCompare(b.root ?? "") || rank[a.role] - rank[b.role] || a.path.localeCompare(b.path));
}

/** Choose a binary by role ("main"), exact path, or path suffix. */
export function pickBinary(bins, binary) {
  if (bins.length === 0) throw new Error("no Mach-O binaries found in target");
  let pick;
  if (!binary || binary === "main") pick = bins.find((b) => b.role === "main" || b.role === "file") ?? bins[0];
  else pick = bins.find((b) => b.path === binary) ?? bins.find((b) => b.path.endsWith(`/${binary}`) || b.path.endsWith(binary));
  if (!pick) throw new Error(`binary not found: ${binary}. Available: ${bins.map((b) => b.path).join(", ")}`);
  return pick;
}

export function loadBinaryFromSource(src, binary) {
  const bins = listBinaries(src);
  const pick = pickBinary(bins, binary);
  const buf = src.read(pick.path);
  if (!isMachO(buf)) throw new Error(`${pick.path} is not a Mach-O file`);
  return { src, binaries: bins, binary: pick, buf };
}

export function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
