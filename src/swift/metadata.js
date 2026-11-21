// Swift 5 runtime metadata reader — static, execution-free.
//
// Recovers types (struct / class / enum), their stored properties or enum
// cases with demangled types, superclasses, protocols, and protocol
// conformances from the reflection sections swiftc always emits:
//   __swift5_types   relative pointers to nominal type context descriptors
//   __swift5_protos  relative pointers to protocol descriptors
//   __swift5_proto   relative pointers to protocol conformance descriptors
//   __swift5_fieldmd field descriptors (stored properties / enum cases)
// Layouts follow swift/ABI/Metadata.h. All links are 32-bit relative
// pointers; "indirectable" ones (low bit set) point at a pointer slot that is
// resolved through dyld fixups, which is how references to types and
// protocols in other modules (e.g. Swift.Hashable) appear.

import { createPointerResolver } from "../macho/fixups.js";
import { demangleSymbol, demangleType } from "./demangle.js";

const KIND = { 0: "module", 1: "extension", 2: "anonymous", 3: "protocol", 4: "opaque-type", 16: "class", 17: "struct", 18: "enum" };
const FIELD_KIND = { 0: "struct", 1: "class", 2: "enum", 3: "multi-payload-enum", 4: "protocol", 5: "class-protocol", 6: "objc-protocol", 7: "objc-class" };
const REQ_KIND = { 0: "base-protocol", 1: "method", 2: "init", 3: "getter", 4: "setter", 5: "read-coroutine", 6: "modify-coroutine", 7: "associated-type-access", 8: "associated-conformance-access" };
const TYPE_REF_KIND = { 0: "direct-type-descriptor", 1: "indirect-type-descriptor", 2: "direct-objc-class-name", 3: "indirect-objc-class" };
const MAX_FIELDS = 4096;

const stripPrefix = (s, prefixes) => {
  for (const p of prefixes) if (s?.startsWith(p)) return s.slice(p.length);
  return s;
};
const DESCRIPTOR_PREFIXES = ["nominal type descriptor for ", "protocol descriptor for ", "type metadata for "];

export function dumpSwift(image, options = {}) {
  const limitations = [];
  const R = options.resolver ?? createPointerResolver(image);
  const encrypted = image.encryption.encrypted;
  if (encrypted) limitations.push("Binary is FairPlay-encrypted: Swift metadata in __TEXT is unreadable without a decrypted copy.");

  const i32At = (vm) => { const o = image.vmToOffset(vm); return o == null ? null : image.i32(o); };
  const u32At = (vm) => { const o = image.vmToOffset(vm); return o == null ? null : image.u32(o); };
  const u16At = (vm) => { const o = image.vmToOffset(vm); return o == null ? null : image.u16(o); };
  const str = (vm) => (vm == null ? null : image.cstringAt(vm));

  /** Plain relative pointer at vm -> target vm. */
  const rel = (vm) => {
    const r = i32At(vm);
    return r ? vm + r : null;
  };

  /**
   * Indirectable relative pointer at vm. Returns { vm } for a local target or
   * { external } (symbol) for a bound one.
   */
  const relIndirect = (vm) => {
    const r = i32At(vm);
    if (!r) return null;
    const indirect = (r & 1) === 1;
    const target = vm + (r & ~1);
    if (!indirect) return { vm: target };
    const p = R.resolve(target);
    if (!p || p.kind === "null") return null;
    if (p.kind === "bind") return { external: p.symbol, library: p.library };
    return { vm: p.target };
  };

  const externalName = (sym) => {
    const d = demangleSymbol(sym);
    return d ? stripPrefix(d, DESCRIPTOR_PREFIXES) : sym.replace(/^_OBJC_CLASS_\$_/, "");
  };

  // ---- context descriptors and names

  const ctxCache = new Map();
  const readContext = (vm, depth = 0) => {
    if (ctxCache.has(vm)) return ctxCache.get(vm);
    const flags = u32At(vm);
    if (flags == null) return null;
    const kindId = flags & 0x1f;
    const ctx = {
      vm,
      kind: KIND[kindId] ?? `kind(${kindId})`,
      isGeneric: (flags & 0x80) !== 0,
      isUnique: (flags & 0x40) !== 0,
      flags,
      name: null,
      parent: null,
      fullName: null,
    };
    ctxCache.set(vm, ctx); // guard cycles
    const parent = relIndirect(vm + 4);
    if (depth < 32 && parent) {
      ctx.parent = parent.vm != null ? readContext(parent.vm, depth + 1) : { kind: "external", fullName: externalName(parent.external) };
    }
    if (kindId === 1) {
      // Extension: ExtendedContext is a mangled type name.
      const ext = mangledAt(rel(vm + 8));
      const module = ctx.parent?.fullName ?? "?";
      ctx.name = null;
      ctx.fullName = `(extension in ${module}):${ext ?? "?"}`;
    } else if (kindId === 2) {
      ctx.fullName = `${ctx.parent?.fullName ? `${ctx.parent.fullName}.` : ""}(anonymous context)`;
    } else {
      ctx.name = str(rel(vm + 8));
      const pn = ctx.parent?.fullName;
      ctx.fullName = pn ? `${pn}.${ctx.name}` : ctx.name;
    }
    return ctx;
  };

  // ---- mangled names (may contain symbolic references and embedded NULs)

  function mangledBytes(vm) {
    const off = image.vmToOffset(vm);
    if (off == null) return null;
    const { buf } = image;
    const out = [];
    let p = off;
    const end = Math.min(image.sliceEnd, off + 4096);
    while (p < end) {
      const b = buf[p];
      if (b === 0) break;
      if (b >= 1 && b <= 0x17) { out.push(...buf.subarray(p, p + 5)); p += 5; continue; }
      if (b >= 0x18 && b <= 0x1f) { out.push(...buf.subarray(p, p + 9)); p += 9; continue; }
      out.push(b);
      p++;
    }
    return out;
  }

  function mangledAt(vm) {
    if (vm == null) return null;
    const bytes = mangledBytes(vm);
    if (!bytes || bytes.length === 0) return null;
    const symbolic = (kind, index, relOff) => {
      const fieldVm = vm + index;
      const target = fieldVm + relOff;
      if (kind === 0x01) return readContext(target)?.fullName ?? null;
      if (kind === 0x02) {
        const p = R.resolve(target);
        if (!p || p.kind === "null") return null;
        if (p.kind === "bind") return externalName(p.symbol);
        return readContext(p.target)?.fullName ?? null;
      }
      return null;
    };
    const demangled = demangleType(bytes, symbolic);
    if (demangled) return demangled;
    // Fallback: printable form with symbolic references marked.
    return bytes.map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : "·")).join("");
  }

  // ---- field descriptors

  const readFields = (fmdVm) => {
    if (fmdVm == null) return { kind: null, superclass: null, fields: [] };
    const kind = u16At(fmdVm + 8);
    const recSize = u16At(fmdVm + 10) || 12;
    const count = Math.min(u32At(fmdVm + 12) ?? 0, MAX_FIELDS);
    const fields = [];
    for (let i = 0; i < count; i++) {
      const r = fmdVm + 16 + i * recSize;
      const flags = u32At(r);
      const typeVm = rel(r + 4);
      fields.push({
        name: str(rel(r + 8)),
        type: typeVm == null ? null : mangledAt(typeVm),
        isVar: (flags & 0x2) !== 0,
        isIndirectCase: (flags & 0x1) !== 0,
        isArtificial: (flags & 0x4) !== 0,
      });
    }
    return { kind: FIELD_KIND[kind] ?? `kind(${kind})`, superclass: mangledAt(rel(fmdVm + 4)), fields };
  };

  const listSection = (name) => {
    const out = [];
    for (const sect of image.sections.filter((s) => s.name === name)) {
      const range = image.sectionRange(sect);
      if (!range) continue;
      if (image.isEncryptedOffset(range.start)) {
        limitations.push(`${sect.name} is in the encrypted range; skipped.`);
        continue;
      }
      out.push(...image.sectionSlots(sect, 4));
    }
    return out;
  };

  // ---- types
  const types = [];
  for (const slot of listSection("__swift5_types")) {
    try {
    const r = i32At(slot);
    if (!r) continue;
    const refKind = r & 3;
    let dvm = slot + (r & ~3);
    if (refKind === 1) {
      const p = R.target(dvm);
      if (p == null) continue;
      dvm = p;
    }
    const ctx = readContext(dvm);
    if (!ctx) continue;
    const entry = {
      kind: ctx.kind,
      name: ctx.name,
      fullName: ctx.fullName,
      module: moduleOf(ctx),
      generic: ctx.isGeneric,
      address: `0x${dvm.toString(16)}`,
    };
    const fmd = rel(dvm + 16);
    const f = readFields(fmd);

    if (ctx.kind === "class") {
      const superName = mangledAt(rel(dvm + 20));
      entry.superclass = superName ?? f.superclass ?? null;
      entry.immediateMembers = u32At(dvm + 32);
      entry.fields = f.fields.map(stripCase);
      if (ctx.isGeneric) entry.genericParams = u16At(dvm + 44 + 8);
    } else if (ctx.kind === "struct") {
      entry.fields = f.fields.map(stripCase);
      if (ctx.isGeneric) entry.genericParams = u16At(dvm + 28 + 8);
    } else if (ctx.kind === "enum") {
      const payload = u32At(dvm + 20) ?? 0;
      entry.payloadCases = payload % (1 << 24);
      entry.emptyCases = u32At(dvm + 24);
      entry.cases = f.fields.map((c) => ({ name: c.name, payload: c.type, indirect: c.isIndirectCase }));
      if (ctx.isGeneric) entry.genericParams = u16At(dvm + 28 + 8);
    }
    types.push(entry);
    } catch (err) {
      limitations.push(`Swift type descriptor reference at 0x${slot.toString(16)} is malformed and was skipped: ${err.message}`);
    }
  }

  // ---- protocols
  const protocols = [];
  for (const slot of listSection("__swift5_protos")) {
    try {
    const t = relIndirect(slot);
    if (!t || t.vm == null) continue;
    const ctx = readContext(t.vm);
    if (!ctx) continue;
    const numReqSig = u32At(t.vm + 12) ?? 0;
    const numReq = Math.min(u32At(t.vm + 16) ?? 0, MAX_FIELDS);
    const assoc = str(rel(t.vm + 20));
    const reqBase = t.vm + 24 + numReqSig * 12;
    const requirements = {};
    for (let i = 0; i < numReq; i++) {
      const fl = u32At(reqBase + i * 8);
      if (fl == null) break;
      const k = REQ_KIND[fl & 0xf] ?? `kind(${fl & 0xf})`;
      const key = `${(fl & 0x10) ? "instance" : "static"}-${k}`;
      requirements[key] = (requirements[key] ?? 0) + 1;
    }
    protocols.push({
      name: ctx.name,
      fullName: ctx.fullName,
      module: moduleOf(ctx),
      address: `0x${t.vm.toString(16)}`,
      requirementCount: numReq,
      requirements,
      associatedTypes: assoc ? assoc.split(" ").filter(Boolean) : [],
    });
    } catch (err) {
      limitations.push(`Swift protocol descriptor reference at 0x${slot.toString(16)} is malformed and was skipped: ${err.message}`);
    }
  }

  // ---- conformances
  const conformances = [];
  for (const slot of listSection("__swift5_proto")) {
    try {
    const cvm = rel(slot);
    if (cvm == null) continue;
    const p = relIndirect(cvm);
    const protocol = !p ? null : p.vm != null ? readContext(p.vm)?.fullName : externalName(p.external);
    const flags = u32At(cvm + 12) ?? 0;
    const trk = (flags >>> 3) & 7;
    let type = null;
    const tvm = rel(cvm + 4);
    if (tvm != null) {
      if (trk === 0) type = readContext(tvm)?.fullName ?? null;
      else if (trk === 1) {
        const q = R.resolve(tvm);
        type = q?.kind === "rebase" ? readContext(q.target)?.fullName : q?.kind === "bind" ? externalName(q.symbol) : null;
      } else if (trk === 2) type = str(tvm);
      else if (trk === 3) {
        const q = R.resolve(tvm);
        type = q?.kind === "bind" ? externalName(q.symbol) : null;
      }
    }
    conformances.push({
      type,
      protocol,
      protocolExternal: !!p?.external,
      typeReference: TYPE_REF_KIND[trk],
      retroactive: (flags & 0x40) !== 0,
      synthesizedNonUnique: (flags & 0x80) !== 0,
      conditionalRequirements: (flags >>> 8) & 0xff,
      address: `0x${cvm.toString(16)}`,
    });
    } catch (err) {
      limitations.push(`Swift protocol conformance reference at 0x${slot.toString(16)} is malformed and was skipped: ${err.message}`);
    }
  }

  return { types, protocols, conformances, limitations };
}

function stripCase(f) {
  return { name: f.name, type: f.type, isVar: f.isVar };
}

function moduleOf(ctx) {
  let c = ctx;
  for (let i = 0; c && i < 32; i++) {
    if (c.kind === "module") return c.name;
    if (c.kind === "external") return c.fullName?.split(".")[0] ?? null;
    c = c.parent;
  }
  return null;
}

/** Render a Swift-like interface for the recovered metadata. */
export function renderSwiftInterface(dump) {
  const L = ["// Generated by rea-iphone from Swift 5 reflection metadata (static).", ""];
  for (const p of dump.protocols) {
    L.push(`protocol ${p.fullName} {${p.requirementCount ? ` // ${p.requirementCount} requirement(s)` : " }"}`);
    for (const a of p.associatedTypes) L.push(`  associatedtype ${a}`);
    if (p.requirementCount) L.push("}");
    L.push("");
  }
  for (const t of dump.types) {
    const generic = t.generic ? `<${Array.from({ length: t.genericParams || 1 }, (_, i) => `T${i}`).join(", ")}>` : "";
    const sup = t.superclass ? ` : ${t.superclass}` : "";
    L.push(`${t.kind} ${t.fullName}${generic}${sup} {`);
    if (t.kind === "enum") {
      for (const c of t.cases) L.push(`  ${c.indirect ? "indirect " : ""}case ${c.name}${c.payload ? (c.payload.startsWith("(") ? c.payload : `(${c.payload})`) : ""}`);
    } else {
      for (const f of t.fields ?? []) L.push(`  ${f.isVar ? "var" : "let"} ${f.name}: ${f.type ?? "<unknown>"}`);
    }
    L.push("}");
    L.push("");
  }
  for (const c of dump.conformances) {
    L.push(`extension ${c.type ?? "<unknown>"} : ${c.protocol ?? "<unknown>"} {}${c.typeReference.includes("objc") ? " // Objective-C class" : ""}`);
  }
  return `${L.join("\n")}\n`;
}
