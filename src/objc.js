// Objective-C class-dump — static, execution-free.
//
// Walks __objc_classlist / __objc_catlist / __objc_protolist through the
// fixup resolver, so it works on both classic (LC_DYLD_INFO) and chained
// (LC_DYLD_CHAINED_FIXUPS) binaries, including external superclasses and
// category targets that are dyld binds. Handles pointer-based (24-byte) and
// relative (12-byte, iOS 14+) method lists. 64-bit images only.
//
// NOTE: addresses exceed 2^32, so never use JS bitwise operators on them —
// all masking below is arithmetic.

import { createPointerResolver } from "./macho/fixups.js";
import { demangleObjCRuntimeName } from "./swift/demangle.js";

const RO_FLAGS = {
  0x1: "meta", 0x2: "root", 0x4: "has-cxx-structors", 0x10: "hidden",
  0x20: "exception", 0x40: "has-swift-initializer", 0x80: "arc",
  0x100: "has-cxx-dtor-only", 0x200: "has-weak-without-arc", 0x400: "forbids-associated-objects",
};
const MAX_LIST = 1 << 16;
const alignDown8 = (v) => v - (v % 8);
const stripClassSym = (s) => s.replace(/^_OBJC_(?:CLASS|METACLASS)_\$_/, "");

// ---------------------------------------------------------------- types

const PRIMS = {
  c: "char", i: "int", s: "short", l: "long", q: "long long",
  C: "unsigned char", I: "unsigned int", S: "unsigned short", L: "unsigned long", Q: "unsigned long long",
  f: "float", d: "double", D: "long double", B: "_Bool", v: "void", "*": "char *",
  "#": "Class", ":": "SEL", "?": "void /* unknown */", t: "__int128", T: "unsigned __int128",
};
const QUALS = { r: "const", n: "in", N: "inout", o: "out", O: "bycopy", R: "byref", V: "oneway", A: "_Atomic", j: "_Complex" };

/** Decode one type encoding starting at index i. Returns { type, decl(name), next }. */
export function decodeType(enc, i = 0) {
  const quals = [];
  while (i < enc.length && QUALS[enc[i]]) quals.push(QUALS[enc[i++]]);
  const q = quals.filter((x) => x === "const" || x === "_Atomic" || x === "_Complex");
  const pre = q.length ? `${q.join(" ")} ` : "";
  const c = enc[i];
  const mk = (type, next, declFn) => ({
    type: pre + type,
    decl: declFn ? (n) => pre + declFn(n) : (n) => (n ? `${pre + type}${type.endsWith("*") ? "" : " "}${n}` : pre + type),
    next,
  });

  if (c === undefined) return mk("void", i);
  if (c === "@") {
    if (enc[i + 1] === "?") return mk("id /* block */", i + 2);
    if (enc[i + 1] === '"') {
      const end = enc.indexOf('"', i + 2);
      const inner = enc.slice(i + 2, end);
      let t;
      if (inner.startsWith("<")) t = `id${inner}`;
      else t = `${inner} *`;
      return mk(t, end + 1);
    }
    return mk("id", i + 1);
  }
  if (c === "^") {
    const sub = decodeType(enc, i + 1);
    const t = sub.type.endsWith("*") ? `${sub.type}*` : `${sub.type} *`;
    return mk(t, sub.next);
  }
  if (c === "[") {
    let j = i + 1;
    let n = "";
    while (/\d/.test(enc[j])) n += enc[j++];
    const sub = decodeType(enc, j);
    const close = enc[sub.next] === "]" ? sub.next + 1 : sub.next;
    return mk(`${sub.type} [${n}]`, close, (name) => `${sub.type} ${name ?? ""}[${n}]`);
  }
  if (c === "{" || c === "(") {
    const open = c;
    const close = c === "{" ? "}" : ")";
    let depth = 0;
    let j = i;
    for (; j < enc.length; j++) {
      if (enc[j] === '"') { j = enc.indexOf('"', j + 1); continue; }
      if (enc[j] === open) depth++;
      else if (enc[j] === close && --depth === 0) break;
    }
    const body = enc.slice(i + 1, j);
    const eq = body.indexOf("=");
    const name = eq >= 0 ? body.slice(0, eq) : body;
    const kw = open === "{" ? "struct" : "union";
    const t = name && name !== "?" ? `${kw} ${name}` : `${kw} { /* anonymous */ }`;
    return mk(t, j + 1);
  }
  if (c === "b") {
    let j = i + 1;
    let n = "";
    while (/\d/.test(enc[j])) n += enc[j++];
    return mk("unsigned int", j, (name) => `unsigned int ${name ?? ""} : ${n}`);
  }
  if (PRIMS[c]) return mk(PRIMS[c], i + 1);
  return mk(`/* ${c} */ void`, i + 1);
}

/** Split a method type encoding into [return, self, _cmd, ...args] decoded types. */
export function decodeMethodTypes(enc) {
  const out = [];
  let i = 0;
  while (enc && i < enc.length) {
    const t = decodeType(enc, i);
    out.push(t);
    i = t.next;
    while (i < enc.length && /[\d-]/.test(enc[i])) i++;
    if (out.length > 64) break;
  }
  return out;
}

export function methodDeclaration(selector, types, isClass) {
  const parts = decodeMethodTypes(types ?? "");
  const ret = parts[0]?.type ?? "id";
  const args = parts.slice(3);
  const prefix = isClass ? "+" : "-";
  if (!selector.includes(":")) return `${prefix} (${ret})${selector};`;
  const pieces = selector.split(":").slice(0, -1);
  const rendered = pieces.map((p, idx) => `${p}:(${args[idx]?.type ?? "id"})arg${idx + 1}`);
  return `${prefix} (${ret})${rendered.join(" ")};`;
}

export function parsePropertyAttributes(attrs) {
  const out = { type: null, readonly: false, copy: false, retain: false, weak: false, nonatomic: false, dynamic: false, getter: null, setter: null, ivar: null };
  if (!attrs) return out;
  for (const part of attrs.split(",")) {
    const k = part[0];
    const v = part.slice(1);
    if (k === "T") out.type = v;
    else if (k === "R") out.readonly = true;
    else if (k === "C") out.copy = true;
    else if (k === "&") out.retain = true;
    else if (k === "W") out.weak = true;
    else if (k === "N") out.nonatomic = true;
    else if (k === "D") out.dynamic = true;
    else if (k === "G") out.getter = v;
    else if (k === "S") out.setter = v;
    else if (k === "V") out.ivar = v;
  }
  return out;
}

export function propertyDeclaration(name, attrs, isClass = false) {
  const a = parsePropertyAttributes(attrs);
  const words = [];
  if (isClass) words.push("class");
  if (a.nonatomic) words.push("nonatomic");
  if (a.readonly) words.push("readonly");
  if (a.copy) words.push("copy");
  else if (a.retain) words.push("strong");
  else if (a.weak) words.push("weak");
  if (a.getter) words.push(`getter=${a.getter}`);
  if (a.setter) words.push(`setter=${a.setter}`);
  const t = a.type ? decodeType(a.type) : { decl: (n) => `id ${n}` };
  const attrStr = words.length ? ` (${words.join(", ")})` : "";
  const comment = a.dynamic ? " // @dynamic" : a.ivar ? ` // @synthesize ${name}=${a.ivar}` : "";
  return `@property${attrStr} ${t.decl(name)};${comment}`;
}

// ---------------------------------------------------------------- reader

export function dumpObjC(image, options = {}) {
  const limitations = [];
  if (!image.is64) {
    return { classes: [], categories: [], protocols: [], externalClassRefs: [], selectorRefs: [], limitations: ["Objective-C class-dump supports 64-bit images only."] };
  }
  const R = options.resolver ?? createPointerResolver(image);
  limitations.push(...R.limitations);
  const encrypted = image.encryption.encrypted;
  if (encrypted) {
    limitations.push("Binary is FairPlay-encrypted: class/selector/type strings in __TEXT are unreadable; structure is still recovered from __DATA.");
  }

  const str = (vm) => (vm == null ? null : image.cstringAt(vm) ?? (encrypted ? "<encrypted>" : null));
  const u32At = (vm) => { const o = image.vmToOffset(vm); return o == null ? null : image.u32(o); };
  const ptrName = (vm) => str(R.target(vm));

  // Structural plausibility, as a loader would enforce it. Metadata structs
  // live in non-executable, file-backed data segments; lists must fit in
  // their segment. Garbage pointers are rejected before they cost any work.
  const fits = (vm, bytes) => {
    if (vm == null) return false;
    const seg = image.segmentForVm(vm);
    return !!seg && seg.filesize > 0 && seg.name !== "__LINKEDIT" && vm + bytes <= seg.vmaddr + seg.filesize;
  };
  const isDataStruct = (vm, bytes) => {
    if (!fits(vm, bytes)) return false;
    return (image.segmentForVm(vm).initprot & 0x4) === 0; // not executable
  };
  let budget = 1_000_000; // total list entries this dump will examine
  const spend = (n) => {
    budget -= n;
    if (budget < 0) throw new Error("work budget exhausted (implausibly large Objective-C metadata)");
  };

  const readMethodList = (listVm, isClass) => {
    if (listVm == null) return [];
    const off = image.vmToOffset(listVm);
    if (off == null) return [];
    const eflags = image.u32(off);
    const count = image.u32(off + 4);
    if (count > MAX_LIST) { limitations.push(`Method list at 0x${listVm.toString(16)} claims ${count} entries; skipped.`); return []; }
    const small = eflags >= 0x80000000 || (eflags & 0x80000000) !== 0;
    const usesSelectorOffsets = (eflags & 0x40000000) !== 0;
    const entsize = eflags & 0xfffc;
    if (entsize !== (small ? 12 : 24) || !fits(listVm, 8 + count * entsize)) {
      limitations.push(`Implausible method list at 0x${listVm.toString(16)} (entsize ${entsize}, count ${count}); skipped.`);
      return [];
    }
    spend(count);
    const methods = [];
    for (let i = 0; i < count; i++) {
      const e = listVm + 8 + i * entsize;
      let selector;
      let types;
      let imp;
      if (small) {
        const nameRef = image.relativeAt(e);
        if (usesSelectorOffsets) selector = null;
        else selector = nameRef == null ? null : str(R.target(nameRef));
        types = str(image.relativeAt(e + 4));
        imp = image.relativeAt(e + 8);
      } else {
        selector = ptrName(e);
        types = ptrName(e + 8);
        imp = R.target(e + 16);
      }
      selector ??= "<unknown-selector>";
      methods.push({
        selector,
        types,
        imp: imp == null ? null : `0x${imp.toString(16)}`,
        declaration: methodDeclaration(selector, types, isClass),
      });
    }
    return { methods, format: small ? "relative" : "pointer" };
  };

  const methodsOf = (vm, isClass) => {
    const r = readMethodList(vm, isClass);
    return Array.isArray(r) ? [] : r.methods;
  };

  const readIvars = (listVm) => {
    if (listVm == null) return [];
    const off = image.vmToOffset(listVm);
    if (off == null) return [];
    const entsize = image.u32(off);
    const count = image.u32(off + 4);
    if (entsize !== 32 || count > MAX_LIST || !fits(listVm, 8 + count * 32)) {
      limitations.push(`Implausible ivar list at 0x${listVm.toString(16)}; skipped.`);
      return [];
    }
    spend(count);
    const ivars = [];
    for (let i = 0; i < count; i++) {
      const e = listVm + 8 + i * entsize;
      const offPtr = R.target(e);
      const name = ptrName(e + 8);
      const type = ptrName(e + 16);
      const eo = image.vmToOffset(e);
      const size = eo == null ? null : image.u32(eo + 28);
      const t = decodeType(type ?? "");
      ivars.push({
        name,
        type,
        offset: offPtr == null ? null : u32At(offPtr),
        size,
        declaration: `${t.decl(name)};`,
      });
    }
    return ivars;
  };

  const readProperties = (listVm, isClass) => {
    if (listVm == null) return [];
    const off = image.vmToOffset(listVm);
    if (off == null) return [];
    const entsize = image.u32(off);
    const count = image.u32(off + 4);
    if (entsize !== 16 || count > MAX_LIST || !fits(listVm, 8 + count * 16)) {
      limitations.push(`Implausible property list at 0x${listVm.toString(16)}; skipped.`);
      return [];
    }
    spend(count);
    const props = [];
    for (let i = 0; i < count; i++) {
      const e = listVm + 8 + i * entsize;
      const name = ptrName(e);
      const attributes = ptrName(e + 8);
      props.push({ name, attributes, declaration: propertyDeclaration(name, attributes, isClass) });
    }
    return props;
  };

  const protoNameCache = new Map();
  const protocolName = (pvm) => {
    if (pvm == null) return null;
    if (!protoNameCache.has(pvm)) protoNameCache.set(pvm, ptrName(pvm + 8));
    return protoNameCache.get(pvm);
  };

  const readProtocolList = (listVm) => {
    if (listVm == null) return [];
    const off = image.vmToOffset(listVm);
    if (off == null) return [];
    const count = Number(image.u64(off));
    if (count > MAX_LIST || !fits(listVm, 8 + count * 8)) {
      limitations.push(`Implausible protocol list at 0x${listVm.toString(16)}; skipped.`);
      return [];
    }
    spend(count);
    const names = [];
    for (let i = 0; i < count; i++) {
      const r = R.resolve(listVm + 8 + i * 8);
      if (!r) continue;
      if (r.kind === "rebase") names.push(protocolName(r.target));
      else if (r.kind === "bind") names.push(r.symbol.replace(/^__OBJC_PROTOCOL_\$_|^_OBJC_PROTOCOL_\$_/, ""));
    }
    return names.filter(Boolean);
  };

  // class_t: isa, superclass, cache, vtable, data(class_ro_t | flags)
  const classNameCache = new Map();
  const readRo = (clsVm) => {
    const d = R.target(clsVm + 32);
    if (d == null) return null;
    const swiftBits = d % 4; // FAST_IS_SWIFT_LEGACY | FAST_IS_SWIFT_STABLE
    const ro = alignDown8(d);
    if (!isDataStruct(ro, 72)) return null;
    const o = image.vmToOffset(ro);
    if (o == null) return null;
    return {
      vm: ro,
      swiftBits,
      flags: image.u32(o),
      instanceStart: image.u32(o + 4),
      instanceSize: image.u32(o + 8),
      name: ptrName(ro + 24),
      baseMethods: R.target(ro + 32),
      baseProtocols: R.target(ro + 40),
      ivars: R.target(ro + 48),
      baseProperties: R.target(ro + 64),
    };
  };
  const classNameAt = (clsVm) => {
    if (!classNameCache.has(clsVm)) classNameCache.set(clsVm, readRo(clsVm)?.name ?? null);
    return classNameCache.get(clsVm);
  };
  const refName = (slotVm) => {
    const r = R.resolve(slotVm);
    if (!r || r.kind === "null") return { name: null, external: false };
    if (r.kind === "bind") return { name: stripClassSym(r.symbol), external: true, library: r.library };
    return { name: classNameAt(r.target), external: false };
  };

  const flagNames = (f) => Object.entries(RO_FLAGS).filter(([b]) => f & Number(b)).map(([, n]) => n);

  const listSection = (name) => {
    const out = [];
    for (const sect of image.sections.filter((s) => s.name === name)) out.push(...image.sectionSlots(sect, 8));
    return out;
  };

  // ---- classes
  const classes = [];
  const methodListFormats = new Set();
  for (const slot of listSection("__objc_classlist")) {
    try {
    const cls = R.target(slot);
    if (cls == null) continue;
    if (!isDataStruct(cls, 40)) { limitations.push(`Class pointer 0x${cls.toString(16)} is not in a data segment; skipped.`); continue; }
    const ro = readRo(cls);
    if (!ro) { limitations.push(`Class at 0x${cls.toString(16)} has an unreadable class_ro_t.`); continue; }
    const sup = refName(cls + 8);
    const metaVm = R.target(cls);
    const metaRo = metaVm != null ? readRo(metaVm) : null;
    const im = readMethodList(ro.baseMethods, false);
    const cm = metaRo ? readMethodList(metaRo.baseMethods, true) : [];
    if (!Array.isArray(im)) methodListFormats.add(im.format);
    if (!Array.isArray(cm)) methodListFormats.add(cm.format);
    const swiftName = ro.name?.startsWith("_Tt") ? demangleObjCRuntimeName(ro.name) : null;
    classes.push({
      name: ro.name,
      swiftName,
      isSwift: ro.swiftBits !== 0 || swiftName !== null,
      address: `0x${cls.toString(16)}`,
      superclass: sup.name,
      superclassExternal: sup.external,
      superclassLibrary: sup.library ?? null,
      flags: flagNames(ro.flags),
      instanceSize: ro.instanceSize,
      protocols: readProtocolList(ro.baseProtocols),
      ivars: readIvars(ro.ivars),
      properties: readProperties(ro.baseProperties, false),
      classProperties: metaRo ? readProperties(metaRo.baseProperties, true) : [],
      instanceMethods: Array.isArray(im) ? [] : im.methods,
      classMethods: Array.isArray(cm) ? [] : cm.methods,
    });
    } catch (err) {
      limitations.push(`Objective-C class entry at 0x${slot.toString(16)} is malformed and was skipped: ${err.message}`);
    }
  }

  // ---- categories (category_t: name, cls, instMethods, classMethods, protocols, props, classProps)
  const imageInfo = image.section("__objc_imageinfo");
  let catHasClassProps = true;
  if (imageInfo) {
    const io = image.vmToOffset(imageInfo.addr);
    if (io != null) catHasClassProps = (image.u32(io + 4) & 0x40) !== 0;
  }
  const categories = [];
  for (const slot of listSection("__objc_catlist")) {
    try {
    const cat = R.target(slot);
    if (cat == null) continue;
    if (!isDataStruct(cat, 48)) { limitations.push(`Category pointer 0x${cat.toString(16)} is not in a data segment; skipped.`); continue; }
    const catName = ptrName(cat);
    if (catName !== "<encrypted>" && !/^[A-Za-z_$][\w$]{0,255}$/.test(catName ?? "")) {
      limitations.push(`Category at 0x${cat.toString(16)} has no valid name; skipped.`);
      continue;
    }
    const target = refName(cat + 8);
    categories.push({
      name: catName,
      class: target.name,
      classExternal: target.external,
      address: `0x${cat.toString(16)}`,
      instanceMethods: methodsOf(R.target(cat + 16), false),
      classMethods: methodsOf(R.target(cat + 24), true),
      protocols: readProtocolList(R.target(cat + 32)),
      properties: readProperties(R.target(cat + 40), false),
      classProperties: catHasClassProps ? readProperties(R.target(cat + 48), true) : [],
    });
    } catch (err) {
      limitations.push(`Objective-C category entry at 0x${slot.toString(16)} is malformed and was skipped: ${err.message}`);
    }
  }

  // ---- protocols
  const protocols = [];
  const seenProto = new Set();
  for (const slot of listSection("__objc_protolist")) {
    try {
    const p = R.target(slot);
    if (p == null || seenProto.has(p)) continue;
    if (!isDataStruct(p, 72)) { limitations.push(`Protocol pointer 0x${p.toString(16)} is not in a data segment; skipped.`); continue; }
    seenProto.add(p);
    protocols.push({
      name: protocolName(p),
      address: `0x${p.toString(16)}`,
      protocols: readProtocolList(R.target(p + 16)),
      instanceMethods: methodsOf(R.target(p + 24), false),
      classMethods: methodsOf(R.target(p + 32), true),
      optionalInstanceMethods: methodsOf(R.target(p + 40), false),
      optionalClassMethods: methodsOf(R.target(p + 48), true),
      properties: readProperties(R.target(p + 56), false),
    });
    } catch (err) {
      limitations.push(`Objective-C protocol entry at 0x${slot.toString(16)} is malformed and was skipped: ${err.message}`);
    }
  }

  // ---- external classes referenced, and selectors messaged
  const ext = new Map();
  for (const name of ["__objc_classrefs", "__objc_superrefs"]) {
    for (const slot of listSection(name)) {
      const r = R.resolve(slot);
      if (r?.kind === "bind") ext.set(stripClassSym(r.symbol), r.library);
    }
  }
  for (const c of classes) if (c.superclassExternal) ext.set(c.superclass, c.superclassLibrary);
  for (const c of categories) if (c.classExternal) ext.set(c.class, null);
  const externalClassRefs = [...ext.entries()].map(([name, library]) => ({ name, library })).sort((a, b) => a.name.localeCompare(b.name));

  const selectorRefs = [];
  try {
    for (const slot of listSection("__objc_selrefs")) {
      const s = str(R.target(slot));
      if (s) selectorRefs.push(s);
    }
  } catch (err) {
    limitations.push(`Selector references unreadable: ${err.message}`);
  }

  return {
    classes,
    categories,
    protocols,
    externalClassRefs,
    selectorRefs: [...new Set(selectorRefs)].sort(),
    methodListFormats: [...methodListFormats],
    fixupMode: R.mode,
    limitations: capLimitations(limitations),
  };
}

function capLimitations(list, max = 50) {
  const uniq = [...new Set(list)];
  return uniq.length > max ? [...uniq.slice(0, max), `… ${uniq.length - max} more limitation(s) of the same kinds`] : uniq;
}

// --------------------------------------------------------------- render

function renderMethods(lines, methods) {
  for (const m of methods) lines.push(`${m.declaration}${m.imp ? ` // IMP ${m.imp}` : ""}`);
}

/** Render a class-dump style Objective-C header for the whole dump. */
export function renderObjCHeader(dump) {
  const L = [];
  L.push("//");
  L.push("// Generated by rea-iphone (static, execution-free class-dump).");
  L.push("//");
  if (dump.externalClassRefs.length) {
    L.push("");
    L.push(`@class ${dump.externalClassRefs.map((c) => c.name).join(", ")};`);
  }
  for (const p of dump.protocols) {
    L.push("");
    L.push(`@protocol ${p.name}${p.protocols.length ? ` <${p.protocols.join(", ")}>` : ""}`);
    for (const pr of p.properties) L.push(pr.declaration);
    renderMethods(L, p.classMethods);
    renderMethods(L, p.instanceMethods);
    if (p.optionalClassMethods.length || p.optionalInstanceMethods.length) {
      L.push("");
      L.push("@optional");
      renderMethods(L, p.optionalClassMethods);
      renderMethods(L, p.optionalInstanceMethods);
    }
    L.push("@end");
  }
  for (const c of dump.classes) {
    L.push("");
    if (c.swiftName) L.push(`// Swift class ${c.swiftName}`);
    const sup = c.superclass ? ` : ${c.superclass}` : "";
    const protos = c.protocols.length ? ` <${c.protocols.join(", ")}>` : "";
    L.push(`@interface ${c.name}${sup}${protos}`);
    if (c.ivars.length) {
      L.push("{");
      for (const iv of c.ivars) L.push(`    ${iv.declaration}${iv.offset != null ? ` // +${iv.offset}` : ""}`);
      L.push("}");
    }
    if (c.classProperties.length || c.properties.length) L.push("");
    for (const pr of c.classProperties) L.push(pr.declaration);
    for (const pr of c.properties) L.push(pr.declaration);
    if (c.classMethods.length || c.instanceMethods.length) L.push("");
    renderMethods(L, c.classMethods);
    renderMethods(L, c.instanceMethods);
    L.push("@end");
  }
  for (const cat of dump.categories) {
    L.push("");
    const protos = cat.protocols.length ? ` <${cat.protocols.join(", ")}>` : "";
    L.push(`@interface ${cat.class ?? "<unknown>"} (${cat.name})${protos}`);
    for (const pr of [...cat.classProperties, ...cat.properties]) L.push(pr.declaration);
    renderMethods(L, cat.classMethods);
    renderMethods(L, cat.instanceMethods);
    L.push("@end");
  }
  return `${L.join("\n")}\n`;
}
