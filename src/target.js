// Node target loading: .ipa archives and .app directories from disk, plus
// bare Mach-O files. Bundle logic lives in bundle.js (shared with the web app).

import { readFileSync, readdirSync, statSync, lstatSync } from "node:fs";
import { join, basename, relative, sep } from "node:path";
import { inflateRawSync, inflateSync } from "node:zlib";
import { readZip } from "./zip.js";
import { isMachO } from "./macho.js";
import { setSyncInflate } from "./macho/fixups.js";
import { machoSource, loadBinaryFromSource } from "./bundle.js";

export { findAppRoots, listBinaries, escapeRe, memorySource, machoSource, pickBinary, loadBinaryFromSource } from "./bundle.js";

setSyncInflate(inflateSync);

function ipaSource(buf) {
  const zip = readZip(buf, { inflateRaw: inflateRawSync });
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

const isSource = (x) => x && typeof x === "object" && typeof x.read === "function" && typeof x.list === "function";

export function openSource(path) {
  if (isSource(path)) return path;
  const st = statSync(path);
  if (st.isDirectory()) {
    if (!path.replace(/\/+$/, "").endsWith(".app")) throw new Error(`directory target must be a .app bundle: ${path}`);
    return dirSource(path.replace(/\/+$/, ""));
  }
  const buf = readFileSync(path);
  if (buf.length >= 4 && buf.toString("latin1", 0, 2) === "PK") return ipaSource(buf);
  if (isMachO(buf)) return machoSource(basename(path), buf);
  throw new Error(`unrecognized target (expected .ipa, .app directory, or Mach-O): ${path}`);
}

/** Load one Mach-O from a path (or an already-open source). */
export function loadBinary(path, binary) {
  return loadBinaryFromSource(openSource(path), binary);
}
