// Target loading: an .ipa archive, an unpacked .app bundle, or a bare
// Mach-O file. Provides a uniform file source and locates the binaries inside
// an app (main executable, embedded frameworks, app extensions).

import { readFileSync, readdirSync, statSync, lstatSync } from "node:fs";
import { join, basename, relative, sep } from "node:path";
import { readZip } from "./zip.js";
import { parsePlist } from "./plist.js";
import { isMachO } from "./macho.js";

function ipaSource(buf) {
  const zip = readZip(buf);
  const files = zip.entries.filter((e) => !e.isDir);
  const byName = new Map(files.map((e) => [e.name, e]));
  return {
    container: "ipa",
    list: () => files.map((e) => ({ path: e.name, size: e.uncompSize })),
    has: (name) => byName.has(name),
    read: (name) => {
      const e = byName.get(name);
      if (!e) throw new Error(`no such member: ${name}`);
      return zip.extract(e);
    },
  };
}

function dirSource(root) {
  const out = [];
  const walk = (d) => {
    for (const name of readdirSync(d)) {
      const full = join(d, name);
      const st = lstatSync(full);
      if (st.isSymbolicLink()) continue; // never follow links out of the bundle
      if (st.isDirectory()) walk(full);
      else if (st.isFile()) out.push({ full, rel: relative(root, full).split(sep).join("/"), size: st.size });
    }
  };
  walk(root);
  const prefix = `Payload/${basename(root)}`;
  const byName = new Map(out.map((e) => [`${prefix}/${e.rel}`, e]));
  return {
    container: "app-directory",
    list: () => [...byName.entries()].map(([path, e]) => ({ path, size: e.size })),
    has: (name) => byName.has(name),
    read: (name) => {
      const e = byName.get(name);
      if (!e) throw new Error(`no such file: ${name}`);
      return readFileSync(e.full);
    },
  };
}

function machoSource(path, buf) {
  const name = basename(path);
  return {
    container: "macho",
    list: () => [{ path: name, size: buf.length }],
    has: (n) => n === name,
    read: (n) => {
      if (n !== name) throw new Error(`no such file: ${n}`);
      return buf;
    },
  };
}

export function openSource(path) {
  const st = statSync(path);
  if (st.isDirectory()) {
    if (!path.replace(/\/+$/, "").endsWith(".app")) throw new Error(`directory target must be a .app bundle: ${path}`);
    return dirSource(path.replace(/\/+$/, ""));
  }
  const buf = readFileSync(path);
  if (buf.length >= 4 && buf.toString("latin1", 0, 2) === "PK") return ipaSource(buf);
  if (isMachO(buf)) return machoSource(path, buf);
  throw new Error(`unrecognized target (expected .ipa, .app directory, or Mach-O): ${path}`);
}

/** Application roots: each Payload/<Name>.app. */
export function findAppRoots(paths) {
  const roots = new Set();
  for (const p of paths) {
    const m = p.match(/^(Payload\/[^/]+\.app)\//);
    if (m) roots.add(m[1]);
  }
  return [...roots].sort();
}

function bundleExecutable(src, bundleDir) {
  const info = `${bundleDir}/Info.plist`;
  let exe = basename(bundleDir).replace(/\.(app|appex|framework)$/, "");
  if (src.has(info)) {
    try {
      const p = parsePlist(src.read(info));
      if (p?.CFBundleExecutable) exe = p.CFBundleExecutable;
    } catch { /* fall back to the bundle name */ }
  }
  return `${bundleDir}/${exe}`;
}

/**
 * Every analyzable binary inside a target:
 *  role "main" | "framework" | "extension" | "dylib" | "file".
 */
export function listBinaries(src) {
  const paths = src.list().map((e) => e.path);
  if (src.container === "macho") return [{ role: "file", path: paths[0] }];
  const out = [];
  for (const root of findAppRoots(paths)) {
    const main = bundleExecutable(src, root);
    if (src.has(main)) out.push({ role: "main", path: main, root });
    const nested = new Set();
    for (const p of paths) {
      const fw = p.match(new RegExp(`^(${escapeRe(root)}/Frameworks/[^/]+\\.framework)/`));
      if (fw) nested.add(`framework\u0000${fw[1]}`);
      const ext = p.match(new RegExp(`^(${escapeRe(root)}/PlugIns/[^/]+\\.appex)/`));
      if (ext) nested.add(`extension\u0000${ext[1]}`);
      if (new RegExp(`^${escapeRe(root)}/Frameworks/[^/]+\\.dylib$`).test(p)) out.push({ role: "dylib", path: p, root });
    }
    for (const key of [...nested].sort()) {
      const [role, dir] = key.split("\u0000");
      const exe = bundleExecutable(src, dir);
      if (src.has(exe)) out.push({ role, path: exe, root });
    }
  }
  // Deterministic order: per app, main executable, frameworks, dylibs, extensions.
  const rank = { main: 0, framework: 1, dylib: 2, extension: 3, file: 0 };
  return out.sort((a, b) => (a.root ?? "").localeCompare(b.root ?? "") || rank[a.role] - rank[b.role] || a.path.localeCompare(b.path));
}

/**
 * Load one Mach-O from a target. `binary` selects by exact path, by suffix
 * (e.g. "Flutter.framework/Flutter"), or by role ("main", default).
 */
export function loadBinary(path, binary) {
  const src = openSource(path);
  const bins = listBinaries(src);
  if (bins.length === 0) throw new Error("no Mach-O binaries found in target");
  let pick;
  if (!binary || binary === "main") pick = bins.find((b) => b.role === "main" || b.role === "file") ?? bins[0];
  else pick = bins.find((b) => b.path === binary) ?? bins.find((b) => b.path.endsWith(`/${binary}`) || b.path.endsWith(binary));
  if (!pick) throw new Error(`binary not found: ${binary}. Available: ${bins.map((b) => b.path).join(", ")}`);
  const buf = src.read(pick.path);
  if (!isMachO(buf)) throw new Error(`${pick.path} is not a Mach-O file`);
  return { src, binaries: bins, binary: pick, buf };
}

export function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
