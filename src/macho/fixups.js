// Pointer resolution through dyld fixups — static, execution-free.
//
// On disk, a pointer slot in __DATA / __DATA_CONST is not a usable address
// until dyld processes fixups. Two encodings exist:
//
//  * Classic (LC_DYLD_INFO[_ONLY]): rebased slots hold the unslid target
//    vmaddr; bound slots hold 0 (or an addend) and are named by a bind
//    opcode stream (bind / weak_bind / lazy_bind).
//  * Chained (LC_DYLD_CHAINED_FIXUPS, iOS 15+ default): every slot holds an
//    encoded value carrying the target (or an import ordinal), a link to the
//    next fixup on the page, and on arm64e pointer-authentication fields.
//
// createPointerResolver(image).resolve(vm) returns
//   { kind: "rebase", target }                       internal pointer
//   { kind: "bind", symbol, library, addend, weak }  external symbol
//   { kind: "null" }                                 zero slot, no fixup
//   null                                             unmapped address

// Optional synchronous zlib inflater for the rare compressed chained-fixup
// symbol pool. Node installs one (see target.js); elsewhere it is reported.
let syncInflate = null;
export function setSyncInflate(fn) { syncInflate = fn; }

const PTR_FORMAT = {
  1: "DYLD_CHAINED_PTR_ARM64E",
  2: "DYLD_CHAINED_PTR_64",
  3: "DYLD_CHAINED_PTR_32",
  4: "DYLD_CHAINED_PTR_32_CACHE",
  5: "DYLD_CHAINED_PTR_32_FIRMWARE",
  6: "DYLD_CHAINED_PTR_64_OFFSET",
  7: "DYLD_CHAINED_PTR_ARM64E_KERNEL",
  8: "DYLD_CHAINED_PTR_64_KERNEL_CACHE",
  9: "DYLD_CHAINED_PTR_ARM64E_USERLAND",
  10: "DYLD_CHAINED_PTR_ARM64E_FIRMWARE",
  11: "DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE",
  12: "DYLD_CHAINED_PTR_ARM64E_USERLAND24",
};

const SUPPORTED_FORMATS = new Set([1, 2, 6, 9, 12]);
const STRIDE = { 1: 8, 2: 4, 6: 4, 9: 8, 12: 8 };
const MASK64 = (1n << 64n) - 1n;
const bits = (v, lo, n) => Number((v >> BigInt(lo)) & ((1n << BigInt(n)) - 1n));
const bitsBig = (v, lo, n) => (v >> BigInt(lo)) & ((1n << BigInt(n)) - 1n);
const signExtend = (v, n) => (v & (1 << (n - 1)) ? v - (1 << n) : v);

export function libraryName(image, ordinal) {
  if (ordinal === 0) return "self";
  if (ordinal === -1) return "main-executable";
  if (ordinal === -2) return "flat-lookup";
  if (ordinal === -3) return "weak-lookup";
  return image.dylibs[ordinal - 1]?.name ?? `ordinal(${ordinal})`;
}

function readUleb(buf, p, end) {
  let result = 0n;
  let shift = 0n;
  for (;;) {
    if (p >= end) throw new Error("truncated ULEB128");
    const b = buf[p++];
    result |= BigInt(b & 0x7f) << shift;
    shift += 7n;
    if ((b & 0x80) === 0) break;
  }
  return { value: result, next: p };
}

function readSleb(buf, p, end) {
  let result = 0n;
  let shift = 0n;
  let b;
  do {
    if (p >= end) throw new Error("truncated SLEB128");
    b = buf[p++];
    result |= BigInt(b & 0x7f) << shift;
    shift += 7n;
  } while (b & 0x80);
  if (b & 0x40) result -= 1n << shift;
  return { value: result, next: p };
}

/** Interpret one classic bind opcode stream into binding records. */
export function parseBindOpcodes(image, off, size, { lazy = false, weak = false } = {}) {
  const out = [];
  const limitations = [];
  if (!size) return { binds: out, limitations };
  const { buf } = image;
  let p = image.base + off;
  const end = Math.min(p + size, image.sliceEnd);
  const ptr = image.ptrSize;
  let segIndex = 0;
  let segOffset = 0n;
  let ordinal = 0;
  let symbol = "";
  let addend = 0n;
  let weakImport = false;

  const maxBinds = Math.max(1024, Math.floor((image.sliceEnd - image.base) / ptr));
  const bindHere = () => {
    if (out.length >= maxBinds) throw new Error("bind opcode stream produces more binds than the image has pointer slots");
    const seg = image.segments[segIndex];
    if (!seg) return;
    out.push({
      vm: seg.vmaddr + Number(BigInt.asIntN(64, segOffset)),
      symbol,
      ordinal,
      addend: Number(addend),
      weak: weak || weakImport,
      lazy,
    });
  };

  while (p < end) {
    const byte = buf[p++];
    const op = byte & 0xf0;
    const imm = byte & 0x0f;
    switch (op) {
      case 0x00: // DONE
        if (!lazy) return { binds: out, limitations };
        break;
      case 0x10: ordinal = imm; break;
      case 0x20: { const r = readUleb(buf, p, end); ordinal = Number(r.value); p = r.next; break; }
      case 0x30: ordinal = imm === 0 ? 0 : signExtend(imm | 0xf0, 8); break;
      case 0x40: {
        let e = p;
        while (e < end && buf[e] !== 0) e++;
        symbol = buf.toString("utf8", p, e);
        weakImport = (imm & 0x1) !== 0;
        p = e + 1;
        break;
      }
      case 0x50: break; // SET_TYPE_IMM (pointer binds only in practice)
      case 0x60: { const r = readSleb(buf, p, end); addend = r.value; p = r.next; break; }
      case 0x70: { segIndex = imm; const r = readUleb(buf, p, end); segOffset = r.value; p = r.next; break; }
      case 0x80: { const r = readUleb(buf, p, end); segOffset = (segOffset + r.value) & MASK64; p = r.next; break; }
      case 0x90: bindHere(); segOffset = (segOffset + BigInt(ptr)) & MASK64; break;
      case 0xa0: {
        bindHere();
        const r = readUleb(buf, p, end);
        segOffset = (segOffset + r.value + BigInt(ptr)) & MASK64;
        p = r.next;
        break;
      }
      case 0xb0: bindHere(); segOffset = (segOffset + BigInt(imm * ptr + ptr)) & MASK64; break;
      case 0xc0: {
        const c = readUleb(buf, p, end);
        const s = readUleb(buf, c.next, end);
        p = s.next;
        if (c.value > BigInt(maxBinds)) throw new Error("bind repeat count exceeds image size");
        for (let i = 0n; i < c.value; i++) {
          bindHere();
          segOffset = (segOffset + s.value + BigInt(ptr)) & MASK64;
        }
        break;
      }
      case 0xd0:
        limitations.push("Threaded bind opcodes (BIND_OPCODE_THREADED) are not interpreted.");
        return { binds: out, limitations };
      default:
        limitations.push(`Unknown bind opcode 0x${byte.toString(16)}; stream truncated.`);
        return { binds: out, limitations };
    }
  }
  return { binds: out, limitations };
}

/** Parse LC_DYLD_CHAINED_FIXUPS: per-segment pointer formats and the import table. */
export function parseChainedFixups(image) {
  const { buf } = image;
  const h = image.base + image.chainedFixups.dataoff;
  const startsOff = image.u32(h + 4);
  const importsOff = image.u32(h + 8);
  const symbolsOff = image.u32(h + 12);
  const importsCount = image.u32(h + 16);
  const importsFormat = image.u32(h + 20);
  const symbolsFormat = image.u32(h + 24);
  const limitations = [];

  let symbolPool = buf.subarray(h + symbolsOff, h + image.chainedFixups.datasize);
  if (symbolsFormat === 1) {
    try {
      if (!syncInflate) throw new Error("no zlib inflater in this environment");
      symbolPool = syncInflate(symbolPool);
    } catch (err) {
      limitations.push(`Compressed chained-fixup symbol pool could not be inflated: ${err.message}`);
    }
  }
  const symName = (o) => {
    let e = o;
    while (e < symbolPool.length && symbolPool[e] !== 0) e++;
    return symbolPool.toString("utf8", o, e);
  };

  const imports = [];
  let ip = h + importsOff;
  for (let i = 0; i < importsCount; i++) {
    if (importsFormat === 1 || importsFormat === 2) {
      const v = image.u32(ip);
      const lib = signExtend(v & 0xff, 8);
      imports.push({
        ordinal: lib,
        weak: ((v >>> 8) & 1) === 1,
        symbol: symName(v >>> 9),
        addend: importsFormat === 2 ? image.i32(ip + 4) : 0,
      });
      ip += importsFormat === 2 ? 8 : 4;
    } else if (importsFormat === 3) {
      const v = image.u64(ip);
      imports.push({
        ordinal: signExtend(bits(v, 0, 16), 16),
        weak: bits(v, 16, 1) === 1,
        symbol: symName(Number(bitsBig(v, 32, 32))),
        addend: Number(image.u64(ip + 8)),
      });
      ip += 16;
    } else {
      limitations.push(`Unknown chained imports format ${importsFormat}.`);
      break;
    }
  }

  // starts_in_image -> per-segment starts_in_segment
  const sii = h + startsOff;
  const segCount = image.u32(sii);
  const segStarts = [];
  for (let i = 0; i < segCount; i++) {
    const so = image.u32(sii + 4 + i * 4);
    if (so === 0) { segStarts.push(null); continue; }
    const s = sii + so;
    const pageCount = image.u16(s + 20);
    const pageStarts = [];
    for (let pg = 0; pg < pageCount; pg++) pageStarts.push(image.u16(s + 22 + pg * 2));
    segStarts.push({
      segIndex: i,
      pageSize: image.u16(s + 4),
      pointerFormat: image.u16(s + 6),
      segmentOffset: Number(image.u64(s + 8)),
      maxValidPointer: image.u32(s + 16),
      pageStarts,
    });
  }

  const formats = new Set(segStarts.filter(Boolean).map((s) => s.pointerFormat));
  for (const f of formats) {
    if (!SUPPORTED_FORMATS.has(f)) limitations.push(`Pointer format ${PTR_FORMAT[f] ?? f} is not decoded.`);
  }
  return { imports, segStarts, formats: [...formats].map((f) => PTR_FORMAT[f] ?? String(f)), limitations };
}

/** Decode one chained-fixup slot value for a given pointer format. */
export function decodeChainedPointer(raw, format, imageBase) {
  if (format === 2 || format === 6) {
    if (bits(raw, 63, 1)) {
      return { bind: true, ordinal: bits(raw, 0, 24), addend: bits(raw, 24, 8), next: bits(raw, 51, 12) };
    }
    const target = Number(bitsBig(raw, 0, 36));
    const high8 = bits(raw, 36, 8);
    const t = format === 6 ? imageBase + target : target;
    return { bind: false, target: high8 ? Number((BigInt(high8) << 56n) | BigInt(t)) : t, next: bits(raw, 51, 12) };
  }
  if (format === 1 || format === 9 || format === 12) {
    const auth = bits(raw, 63, 1) === 1;
    const isBind = bits(raw, 62, 1) === 1;
    const next = bits(raw, 51, 11);
    const ordBits = format === 12 ? 24 : 16;
    if (isBind) {
      const ordinal = bits(raw, 0, ordBits);
      const addend = auth ? 0 : signExtend(bits(raw, 32, 19), 19);
      return { bind: true, ordinal, addend, next, auth };
    }
    if (auth) {
      // Auth rebase target is always a runtime offset from the image base.
      return { bind: false, target: imageBase + bits(raw, 0, 32), next, auth: true, key: bits(raw, 49, 2) };
    }
    const target = Number(bitsBig(raw, 0, 43));
    const high8 = bits(raw, 43, 8);
    const t = format === 1 ? target : imageBase + target;
    return { bind: false, target: high8 ? Number((BigInt(high8) << 56n) | BigInt(t)) : t, next, auth: false };
  }
  return null;
}

/** Build a resolver for one image. Bind maps and chained metadata are parsed once. */
export function createPointerResolver(image) {
  const limitations = [];
  const imageBase = image.imageBase;
  let mode = "none";
  let chained = null;
  const bindMap = new Map(); // vm -> bind (classic)

  if (image.chainedFixups) {
    mode = "chained";
    try {
      chained = parseChainedFixups(image);
      limitations.push(...chained.limitations);
    } catch (err) {
      limitations.push(`Chained fixups unreadable: ${err.message}`);
      chained = null;
    }
  } else if (image.dyldInfo) {
    mode = "dyld-info";
    const d = image.dyldInfo;
    for (const [off, size, opts] of [
      [d.bind_off, d.bind_size, {}],
      [d.weak_bind_off, d.weak_bind_size, { weak: true }],
      [d.lazy_bind_off, d.lazy_bind_size, { lazy: true }],
    ]) {
      try {
        const r = parseBindOpcodes(image, off, size, opts);
        limitations.push(...r.limitations);
        for (const b of r.binds) if (!bindMap.has(b.vm) || !b.weak) bindMap.set(b.vm, b);
      } catch (err) {
        limitations.push(`Bind opcodes unreadable: ${err.message}`);
      }
    }
  }

  const segFormat = (vm) => {
    if (!chained) return null;
    const seg = image.segmentForVm(vm);
    if (!seg) return null;
    const st = chained.segStarts[seg.index];
    return st ? st.pointerFormat : null;
  };

  const resolve = (vm) => {
    const off = image.vmToOffset(vm);
    if (off == null || off + image.ptrSize > image.sliceEnd) return null;
    const raw = image.rawPtr(off);

    if (mode === "dyld-info") {
      const b = bindMap.get(vm);
      if (b) return { kind: "bind", symbol: b.symbol, library: libraryName(image, b.ordinal), addend: b.addend, weak: b.weak };
      if (raw === 0n) return { kind: "null" };
      return { kind: "rebase", target: Number(raw) };
    }

    if (mode === "chained") {
      if (raw === 0n) return { kind: "null" };
      const fmt = segFormat(vm);
      if (fmt == null || !SUPPORTED_FORMATS.has(fmt)) {
        // Segment without chained starts: plain (unfixed) data.
        return { kind: "rebase", target: Number(raw), unfixed: true };
      }
      const d = decodeChainedPointer(raw, fmt, imageBase);
      if (!d) return { kind: "rebase", target: Number(raw), unfixed: true };
      if (d.bind) {
        const imp = chained.imports[d.ordinal];
        if (!imp) return { kind: "bind", symbol: `import#${d.ordinal}`, library: "unknown", addend: d.addend, weak: false };
        return { kind: "bind", symbol: imp.symbol, library: libraryName(image, imp.ordinal), addend: d.addend + imp.addend, weak: imp.weak };
      }
      return { kind: "rebase", target: d.target, auth: d.auth ?? false };
    }

    // No fixup info (e.g. MH_OBJECT or static): treat raw as an address.
    if (raw === 0n) return { kind: "null" };
    return { kind: "rebase", target: Number(raw) };
  };

  /** Resolve and return only an internal target vm (null for binds / null slots). */
  const target = (vm) => {
    const r = resolve(vm);
    return r && r.kind === "rebase" ? r.target : null;
  };

  /** Enumerate every fixup location (chained: by walking chains; classic: binds only). */
  const enumerate = (maxFixups = 4_000_000) => {
    const out = [];
    if (mode === "dyld-info") {
      for (const b of bindMap.values()) out.push({ vm: b.vm, kind: "bind", symbol: b.symbol, library: libraryName(image, b.ordinal) });
      return out;
    }
    if (mode !== "chained" || !chained) return out;
    for (const st of chained.segStarts) {
      if (!st || !SUPPORTED_FORMATS.has(st.pointerFormat)) continue;
      const stride = STRIDE[st.pointerFormat];
      st.pageStarts.forEach((start, pg) => {
        if (start === 0xffff) return;
        let vm = imageBase + st.segmentOffset + pg * st.pageSize + start;
        for (let guard = 0; guard < 1 << 16; guard++) {
          const off = image.vmToOffset(vm);
          if (off == null) break;
          const d = decodeChainedPointer(image.rawPtr(off), st.pointerFormat, imageBase);
          if (!d) break;
          if (d.bind) {
            const imp = chained.imports[d.ordinal];
            out.push({ vm, kind: "bind", symbol: imp?.symbol ?? `import#${d.ordinal}`, library: imp ? libraryName(image, imp.ordinal) : "unknown" });
          } else {
            out.push({ vm, kind: "rebase", target: d.target });
          }
          if (d.next === 0 || out.length >= maxFixups) break;
          vm += d.next * stride;
        }
      });
    }
    return out;
  };

  return {
    mode,
    imageBase,
    formats: chained ? chained.formats : mode === "dyld-info" ? ["classic-rebase-bind"] : [],
    imports: chained ? chained.imports.map((i) => ({ ...i, library: libraryName(image, i.ordinal) })) : null,
    limitations,
    resolve,
    target,
    enumerate,
  };
}
