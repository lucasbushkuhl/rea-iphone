// Symbol table (LC_SYMTAB nlist entries) and export trie (LC_DYLD_INFO
// export data or LC_DYLD_EXPORTS_TRIE) — static, execution-free.

import { libraryName } from "./fixups.js";

const N_STAB = 0xe0;
const N_PEXT = 0x10;
const N_TYPE = 0x0e;
const N_EXT = 0x01;
const N_UNDF = 0x0;
const N_ABS = 0x2;
const N_SECT = 0xe;
const N_INDR = 0xa;
const N_WEAK_REF = 0x0040;
const N_WEAK_DEF = 0x0080;

/** Parse every nlist entry. Debug (stab) entries are counted, not returned. */
export function readSymbols(image) {
  const st = image.symtab;
  if (!st) return { symbols: [], stabCount: 0, limitations: ["No LC_SYMTAB."] };
  const { buf } = image;
  const entSize = image.is64 ? 16 : 12;
  const symBase = image.base + st.symoff;
  const strBase = image.base + st.stroff;
  const strEnd = Math.min(strBase + st.strsize, image.sliceEnd);
  const symbols = [];
  let stabCount = 0;

  for (let i = 0; i < st.nsyms; i++) {
    const o = symBase + i * entSize;
    if (o + entSize > image.sliceEnd) break;
    const strx = image.u32(o);
    const type = buf[o + 4];
    const sect = buf[o + 5];
    const desc = image.u16(o + 6);
    const value = image.is64 ? Number(image.u64(o + 8)) : image.u32(o + 8);
    if (type & N_STAB) { stabCount++; continue; }

    let name = "";
    if (strx > 0 && strBase + strx < strEnd) {
      let e = strBase + strx;
      while (e < strEnd && buf[e] !== 0) e++;
      name = buf.toString("utf8", strBase + strx, e);
    }
    const kindBits = type & N_TYPE;
    const external = (type & N_EXT) !== 0;
    const kind = kindBits === N_UNDF ? "undefined"
      : kindBits === N_SECT ? "defined"
        : kindBits === N_ABS ? "absolute"
          : kindBits === N_INDR ? "indirect" : "other";

    const sym = {
      name,
      kind,
      external,
      privateExternal: (type & N_PEXT) !== 0,
      address: kind === "defined" ? value : null,
      section: kind === "defined" && sect > 0 ? image.sections[sect - 1]?.name ?? null : null,
    };
    if (kind === "undefined" && external) {
      const ord = (desc >> 8) & 0xff;
      sym.library = libraryName(image, ord === 0xfe ? -2 : ord === 0xff ? -1 : ord);
      sym.weakReference = (desc & N_WEAK_REF) !== 0;
    }
    if (kind === "defined") sym.weakDefinition = (desc & N_WEAK_DEF) !== 0;
    symbols.push(sym);
  }
  return { symbols, stabCount, limitations: [] };
}

function uleb(buf, p, end) {
  let v = 0;
  let shift = 0;
  for (;;) {
    if (p >= end) throw new Error("truncated ULEB128 in export trie");
    const b = buf[p++];
    v += (b & 0x7f) * 2 ** shift;
    shift += 7;
    if ((b & 0x80) === 0) break;
  }
  return [v, p];
}

/** Walk the export trie into a flat list of exported symbols. */
export function readExports(image) {
  let off = null;
  let size = 0;
  if (image.exportsTrie) { off = image.exportsTrie.dataoff; size = image.exportsTrie.datasize; }
  else if (image.dyldInfo?.export_size) { off = image.dyldInfo.export_off; size = image.dyldInfo.export_size; }
  if (off == null || size === 0) return { exports: [], limitations: [] };

  const { buf } = image;
  const start = image.base + off;
  const end = Math.min(start + size, image.sliceEnd);
  const exports = [];
  const limitations = [];
  const stack = [{ node: start, prefix: "" }];
  const visited = new Set();

  while (stack.length) {
    const { node, prefix } = stack.pop();
    if (node >= end || visited.has(node)) continue;
    visited.add(node);
    try {
      let [termSize, p] = uleb(buf, node, end);
      const childrenStart = p + termSize;
      if (termSize > 0) {
        let flags;
        [flags, p] = uleb(buf, p, end);
        const entry = { name: prefix, kind: ["regular", "thread-local", "absolute"][flags & 0x3] ?? "regular" };
        if (flags & 0x08) {
          let ord;
          [ord, p] = uleb(buf, p, end);
          let e = p;
          while (e < end && buf[e] !== 0) e++;
          entry.reexport = { library: libraryName(image, ord), as: buf.toString("utf8", p, e) || prefix };
        } else {
          let addr;
          [addr, p] = uleb(buf, p, end);
          entry.address = image.imageBase + addr;
          if (flags & 0x10) entry.stubAndResolver = true;
        }
        if (flags & 0x04) entry.weakDefinition = true;
        exports.push(entry);
      }
      p = childrenStart;
      const childCount = buf[p++];
      for (let c = 0; c < childCount; c++) {
        let e = p;
        while (e < end && buf[e] !== 0) e++;
        const edge = buf.toString("utf8", p, e);
        let childOff;
        [childOff, p] = uleb(buf, e + 1, end);
        stack.push({ node: start + childOff, prefix: prefix + edge });
      }
    } catch (err) {
      limitations.push(`Export trie node unreadable: ${err.message}`);
    }
  }
  exports.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  return { exports, limitations };
}

/** Imports grouped by library, from undefined external symbols. */
export function groupImports(symbols) {
  const byLib = new Map();
  for (const s of symbols) {
    if (s.kind !== "undefined" || !s.external) continue;
    const lib = s.library ?? "unknown";
    if (!byLib.has(lib)) byLib.set(lib, []);
    byLib.get(lib).push(s.name);
  }
  return [...byLib.entries()].map(([library, names]) => ({ library, count: names.length, symbols: names.sort() }));
}
