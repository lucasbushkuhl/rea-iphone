// Swift 5 demangler (subset) — pure, static.
//
// A stack-based demangler structured like swift/lib/Demangling/Demangler.cpp:
// operators push nodes, entity operators pop their components, and
// substitutions/word-substitutions are tracked exactly as the mangler emits
// them. Covered: identifiers (incl. word substitutions), multi-substitutions,
// standard types and protocols, Swift / __C modules, nominal types
// (class/struct/enum/protocol/typealias), bound generics with Array /
// Dictionary / Optional sugar, tuples (labels, variadics), function types
// (async, throws), metatypes, inout, functions with argument labels,
// variables and accessors, init / __allocating_init / deinit, metadata and
// descriptor symbols, protocol conformances, common thunks, and symbolic
// references (for type strings in Swift reflection metadata).
//
// Anything outside the subset (generic signatures, dependent types, opaque
// types, closures, specializations, ...) throws, and callers fall back to the
// raw mangled name — an honest "unknown" rather than a wrong answer.

class Unsupported extends Error {}

// Bounds that keep hostile input from exhausting time or memory. Swift's own
// demangler caps substitution repeats at 2048 (SubstitutionMerging).
const MAX_REPEAT = 2048;
const MAX_STACK = 4096;
const MAX_INPUT = 16384;

const isDigit = (c) => c >= 48 && c <= 57;
const isLower = (c) => c >= 97 && c <= 122;
const isUpper = (c) => c >= 65 && c <= 90;
const isLetter = (c) => isLower(c) || isUpper(c);

const T = (inner) => ({ k: "Type", t: inner });
const SWIFT = { k: "Module", text: "Swift" };
const nominal = (nk, name, ctx = SWIFT) => T({ k: "Nominal", nk, ctx, name });

const STD = {
  A: ["struct", "AutoreleasingUnsafeMutablePointer"], a: ["struct", "Array"], b: ["struct", "Bool"],
  D: ["struct", "Dictionary"], d: ["struct", "Double"], f: ["struct", "Float"], h: ["struct", "Set"],
  I: ["struct", "DefaultIndices"], i: ["struct", "Int"], J: ["struct", "Character"], N: ["struct", "ClosedRange"],
  n: ["struct", "Range"], O: ["struct", "ObjectIdentifier"], P: ["struct", "UnsafePointer"],
  p: ["struct", "UnsafeMutablePointer"], R: ["struct", "UnsafeBufferPointer"], r: ["struct", "UnsafeMutableBufferPointer"],
  S: ["struct", "String"], s: ["struct", "Substring"], u: ["struct", "UInt"], V: ["struct", "UnsafeRawPointer"],
  v: ["struct", "UnsafeMutableRawPointer"], W: ["struct", "UnsafeRawBufferPointer"], w: ["struct", "UnsafeMutableRawBufferPointer"],
  q: ["enum", "Optional"],
  B: ["protocol", "BinaryFloatingPoint"], E: ["protocol", "Encodable"], e: ["protocol", "Decodable"],
  F: ["protocol", "FloatingPoint"], G: ["protocol", "RandomNumberGenerator"], H: ["protocol", "Hashable"],
  j: ["protocol", "Numeric"], K: ["protocol", "BidirectionalCollection"], k: ["protocol", "RandomAccessCollection"],
  L: ["protocol", "Comparable"], l: ["protocol", "Collection"], M: ["protocol", "MutableCollection"],
  m: ["protocol", "RangeReplaceableCollection"], Q: ["protocol", "Equatable"], T: ["protocol", "Sequence"],
  t: ["protocol", "IteratorProtocol"], U: ["protocol", "UnsignedInteger"], X: ["protocol", "RangeExpression"],
  x: ["protocol", "Strideable"], Y: ["protocol", "RawRepresentable"], y: ["protocol", "StringProtocol"],
  Z: ["protocol", "SignedInteger"], z: ["protocol", "BinaryInteger"],
};
const STD_CONCURRENCY = {
  A: ["protocol", "Actor"], M: ["class", "MainActor"], T: ["struct", "Task"], G: ["struct", "TaskGroup"],
  g: ["struct", "ThrowingTaskGroup"], C: ["struct", "CheckedContinuation"], c: ["struct", "UnsafeContinuation"],
  E: ["struct", "CancellationError"],
};

const ACCESSORS = { g: "getter", s: "setter", M: "modify", r: "read", w: "willset", W: "didset", m: "materializeForSet", G: "global getter" };

class Demangler {
  constructor(bytes, symbolic) {
    this.b = bytes;
    this.pos = 0;
    this.stack = [];
    this.subs = [];
    this.words = [];
    this.symbolic = symbolic;
  }

  peek() { return this.pos < this.b.length ? this.b[this.pos] : 0; }
  next() { if (this.pos >= this.b.length) throw new Unsupported("unexpected end"); return this.b[this.pos++]; }
  nextIf(ch) { if (this.peek() === ch.charCodeAt(0)) { this.pos++; return true; } return false; }
  push(n) {
    if (this.stack.length >= MAX_STACK) throw new Unsupported("node stack limit");
    this.stack.push(n);
  }
  pop(pred) {
    const top = this.stack[this.stack.length - 1];
    if (top && (!pred || pred(top))) return this.stack.pop();
    return null;
  }
  popKind(k) { return this.pop((n) => n.k === k); }
  popType() { return this.pop((n) => n.k === "Type"); }
  need(n, what) { if (!n) throw new Unsupported(`expected ${what}`); return n; }

  natural() {
    if (!isDigit(this.peek())) return -1;
    let v = 0;
    while (isDigit(this.peek())) {
      v = v * 10 + (this.next() - 48);
      if (v > 1e9) throw new Unsupported("number too large");
    }
    return v;
  }

  run() {
    while (this.pos < this.b.length) {
      const n = this.operator();
      if (n) this.push(n);
    }
    return this.stack;
  }

  // ---- identifiers and substitutions

  identifier() {
    let hasWordSubsts = false;
    if (this.peek() === 48 /* '0' */) {
      this.pos++;
      if (this.peek() === 48) throw new Unsupported("punycode identifier");
      hasWordSubsts = true;
    }
    let text = "";
    do {
      while (hasWordSubsts && isLetter(this.peek())) {
        const c = this.next();
        let idx;
        if (isLower(c)) idx = c - 97;
        else { idx = c - 65; hasWordSubsts = false; }
        if (idx >= this.words.length) throw new Unsupported("bad word substitution");
        text += this.words[idx];
      }
      if (this.nextIf("0")) break;
      const n = this.natural();
      if (n <= 0) throw new Unsupported("bad identifier length");
      if (this.pos + n > this.b.length) throw new Unsupported("identifier overruns input");
      const slice = String.fromCharCode(...this.b.slice(this.pos, this.pos + n));
      text += slice;
      // Record words of length >= 2, exactly as the mangler does.
      let wordStart = -1;
      for (let i = 0; i <= slice.length; i++) {
        const c = i < slice.length ? slice.charCodeAt(i) : 0;
        if (wordStart >= 0) {
          const prev = slice.charCodeAt(i - 1);
          const isEnd = c === 95 || c === 0 || (!isUpper(prev) && isUpper(c));
          if (isEnd) {
            if (i - wordStart >= 2 && this.words.length < 26) this.words.push(slice.slice(wordStart, i));
            wordStart = -1;
          }
        }
        if (wordStart < 0 && c !== 0 && c !== 95 && !isDigit(c)) wordStart = i;
      }
      this.pos += n;
    } while (hasWordSubsts);
    const node = { k: "Identifier", text };
    this.subs.push(node);
    return node;
  }

  substitution() {
    let repeat = -1;
    for (;;) {
      const c = this.next();
      if (isLower(c)) {
        const nd = this.subs[c - 97];
        if (!nd) throw new Unsupported("bad substitution index");
        for (let i = 1; i < repeat; i++) this.push(nd);
        this.push(nd);
        repeat = -1;
        continue;
      }
      if (isUpper(c)) {
        const nd = this.subs[c - 65];
        if (!nd) throw new Unsupported("bad substitution index");
        for (let i = 1; i < repeat; i++) this.push(nd);
        return nd;
      }
      if (c === 95 /* _ */) {
        const nd = this.subs[repeat + 27];
        if (!nd) throw new Unsupported("bad substitution index");
        return nd;
      }
      this.pos--;
      repeat = this.natural();
      if (repeat < 0 || repeat > MAX_REPEAT) throw new Unsupported("bad substitution repeat count");
    }
  }

  standard() {
    const c = this.next();
    if (c === 111 /* o */) return { k: "Module", text: "__C" };
    if (c === 67 /* C */) return { k: "Module", text: "__C_Synthesized" };
    if (c === 103 /* g */) {
      const inner = this.need(this.popType(), "type for Optional sugar");
      const n = T({ k: "BoundGeneric", base: STD_TYPE("q"), args: [inner] });
      this.subs.push(n);
      return n;
    }
    if (c === 99 /* c */) {
      const d = String.fromCharCode(this.next());
      const e = STD_CONCURRENCY[d];
      if (!e) throw new Unsupported(`Sc${d}`);
      return nominal(e[0], e[1]);
    }
    this.pos--;
    let repeat = this.natural();
    if (repeat > MAX_REPEAT) throw new Unsupported("repeat count too large");
    const ch = String.fromCharCode(this.next());
    if (!STD[ch]) throw new Unsupported(`S${ch}`);
    const nd = STD_TYPE(ch);
    while (repeat-- > 1) this.push(nd);
    return nd;
  }

  // ---- contexts

  popContext() {
    const n = this.stack.pop();
    if (!n) throw new Unsupported("missing context");
    if (n.k === "Identifier") return { k: "Module", text: n.text };
    if (n.k === "Type") return n.t;
    if (["Module", "Extension", "Function", "Variable", "Nominal", "Symbolic"].includes(n.k)) return n;
    throw new Unsupported(`bad context ${n.k}`);
  }

  popModule() {
    const n = this.stack.pop();
    if (n?.k === "Identifier") return { k: "Module", text: n.text };
    if (n?.k === "Module") return n;
    throw new Unsupported("expected module");
  }

  anyGeneric(nk) {
    const name = this.need(this.popKind("Identifier"), "decl name");
    const ctx = this.popContext();
    const n = T({ k: "Nominal", nk, ctx, name: name.text });
    this.subs.push(n);
    return n;
  }

  // ---- composite types

  tuple() {
    const elems = [];
    if (!this.popKind("EmptyList")) {
      let first = false;
      do {
        first = this.popKind("FEM") !== null;
        const variadic = this.popKind("Variadic") !== null;
        const label = this.popKind("Identifier");
        const ty = this.need(this.popType(), "tuple element type");
        elems.push({ label: label?.text ?? null, type: ty, variadic });
      } while (!first);
      elems.reverse();
    }
    return T({ k: "Tuple", elems });
  }

  boundGeneric() {
    const lists = [];
    for (;;) {
      const list = [];
      let ty;
      while ((ty = this.popType())) list.push(ty);
      list.reverse();
      lists.push(list);
      if (this.popKind("EmptyList")) break;
      if (!this.popKind("FEM")) throw new Unsupported("bound generic list");
    }
    const base = this.need(this.popType(), "generic base type");
    const n = T({ k: "BoundGeneric", base, args: lists[0] });
    this.subs.push(n);
    return n;
  }

  functionParams() {
    if (this.popKind("EmptyList")) return T({ k: "Tuple", elems: [] });
    return this.need(this.popType(), "function params");
  }

  popFunctionType() {
    const throws = this.popKind("Throws") !== null;
    const sendable = this.popKind("Sendable") !== null;
    const async = this.popKind("Async") !== null;
    const params = this.functionParams();
    const result = this.functionParams();
    return T({ k: "FunctionType", params, result, async, throws, sendable });
  }

  popLabels(fnType) {
    if (this.popKind("EmptyList")) return [];
    const ft = fnType?.t;
    if (!ft || ft.k !== "FunctionType") return null;
    const p = ft.params.t;
    const count = p.k === "Tuple" ? p.elems.length : 1;
    if (count === 0) return null;
    const labels = [];
    for (let i = 0; i < count; i++) {
      const n = this.pop((x) => x.k === "Identifier" || x.k === "FEM");
      if (!n) throw new Unsupported("missing argument label");
      labels.push(n.k === "Identifier" ? n.text : "_");
    }
    return labels.reverse();
  }

  // ---- operators

  operator() {
    const c = this.next();
    if (c >= 1 && c <= 0x17) {
      // Symbolic reference: 4-byte relative offset follows.
      if (this.pos + 4 > this.b.length) throw new Unsupported("truncated symbolic reference");
      const at = this.pos;
      const b = this.b;
      const rel = (b[at] | (b[at + 1] << 8) | (b[at + 2] << 16) | (b[at + 3] << 24)) | 0;
      this.pos += 4;
      const name = this.symbolic ? this.symbolic(c, at, rel) : null;
      const n = T({ k: "Symbolic", text: name ?? `<symbolic 0x${c.toString(16)}>` });
      this.subs.push(n);
      return n;
    }
    if (c >= 0x18 && c <= 0x1f) throw new Unsupported("absolute symbolic reference");
    if (isDigit(c)) { this.pos--; return this.identifier(); }

    switch (String.fromCharCode(c)) {
      case "A": return this.substitution();
      case "C": return this.anyGeneric("class");
      case "V": return this.anyGeneric("struct");
      case "O": return this.anyGeneric("enum");
      case "P": return this.anyGeneric("protocol");
      case "a": return this.anyGeneric("typealias");
      case "S": return this.standard();
      case "s": return { k: "Module", text: "Swift" };
      case "y": return { k: "EmptyList" };
      case "_": return { k: "FEM" };
      case "d": return { k: "Variadic" };
      case "t": return this.tuple();
      case "G": return this.boundGeneric();
      case "K": return { k: "Throws" };
      case "c": return this.popFunctionType();
      case "m": return T({ k: "Metatype", of: this.need(this.popType(), "metatype base") });
      case "z": return T({ k: "InOut", of: this.need(this.popType(), "inout base") });
      case "n": case "h": return this.need(this.popType(), "ownership base"); // __owned / __shared
      case "D": return { k: "TypeMangling", type: this.need(this.popType(), "type") };
      case "Y": {
        const d = String.fromCharCode(this.next());
        if (d === "a") return { k: "Async" };
        if (d === "b") return { k: "Sendable" };
        throw new Unsupported(`Y${d}`);
      }
      case "E": {
        const module = this.popModule();
        const ext = this.popContext();
        return { k: "Extension", module, of: ext };
      }
      case "F": {
        const type = this.popFunctionType();
        const labels = this.popLabels(type);
        const name = this.need(this.popKind("Identifier"), "function name");
        const ctx = this.popContext();
        return { k: "Function", ctx, name: name.text, labels, type };
      }
      case "v": {
        const type = this.need(this.popType(), "variable type");
        const name = this.need(this.popKind("Identifier"), "variable name");
        const ctx = this.popContext();
        const variable = { k: "Variable", ctx, name: name.text, type };
        const a = String.fromCharCode(this.next());
        if (a === "p") return variable;
        if (!ACCESSORS[a]) throw new Unsupported(`accessor ${a}`);
        return { k: "Accessor", accessor: ACCESSORS[a], of: variable };
      }
      case "f": {
        const d = String.fromCharCode(this.next());
        if (d === "D" || d === "d") return { k: "Destructor", deallocating: d === "D", ctx: this.popContext() };
        if (d === "C" || d === "c") {
          const type = this.need(this.popType(), "initializer type");
          const labels = this.popLabels(type);
          return { k: "Constructor", allocating: d === "C", ctx: this.popContext(), labels, type };
        }
        if (d === "E") return { k: "Prefix", prefix: "ivar destroyer for", of: this.popContext() };
        if (d === "e") return { k: "Prefix", prefix: "ivar initializer for", of: this.popContext() };
        if (d === "i") return { k: "Prefix", prefix: "variable initialization expression of", of: this.popContext() };
        throw new Unsupported(`f${d}`);
      }
      case "N": return { k: "Prefix", prefix: "type metadata for", of: this.need(this.popType(), "type") };
      case "M": {
        const d = String.fromCharCode(this.next());
        const pre = { a: "type metadata accessor for", n: "nominal type descriptor for", f: "full type metadata for", m: "metaclass for", p: "protocol descriptor for", L: "type metadata lazy cache variable for" }[d];
        if (pre) return { k: "Prefix", prefix: pre, of: this.need(this.popType(), "type") };
        if (d === "c") return { k: "Prefix", prefix: "protocol conformance descriptor for", of: this.conformance() };
        if (d === "V") return { k: "Prefix", prefix: "property descriptor for", of: this.need(this.stack.pop(), "entity") };
        throw new Unsupported(`M${d}`);
      }
      case "W": {
        const d = String.fromCharCode(this.next());
        if (d === "P") return { k: "Prefix", prefix: "protocol witness table for", of: this.conformance() };
        if (d === "p") return { k: "Prefix", prefix: "protocol witness table pattern for", of: this.conformance() };
        if (d === "v") {
          const e = String.fromCharCode(this.next());
          const pre = e === "d" ? "direct field offset for" : e === "i" ? "indirect field offset for" : null;
          if (!pre) throw new Unsupported(`Wv${e}`);
          return { k: "Prefix", prefix: pre, of: this.need(this.stack.pop(), "entity") };
        }
        throw new Unsupported(`W${d}`);
      }
      case "T": {
        const d = String.fromCharCode(this.next());
        const pre = { o: "@objc", O: "@nonobjc", D: "dynamic", j: "dispatch thunk of", q: "method descriptor for", A: "partial apply forwarder for", s: "reabstraction thunk" }[d];
        if (!pre || d === "s") throw new Unsupported(`T${d}`);
        return { k: "Prefix", prefix: pre, of: this.need(this.stack.pop(), "entity") };
      }
      default:
        throw new Unsupported(`operator ${String.fromCharCode(c)}`);
    }
  }

  conformance() {
    const module = this.popModule();
    const proto = this.need(this.popType(), "protocol");
    const type = this.need(this.popType(), "conforming type");
    return { k: "Conformance", type, proto, module };
  }
}

function STD_TYPE(ch) {
  const [nk, name] = STD[ch];
  return nominal(nk, name);
}

// ------------------------------------------------------------- printing

function ctxStr(n) {
  switch (n.k) {
    case "Module": return n.text;
    case "Nominal": return `${ctxStr(n.ctx)}.${n.name}`;
    case "Symbolic": return n.text;
    case "Extension": return `(extension in ${n.module.text}):${ctxStr(n.of)}`;
    case "Function": return entityStr(n);
    case "Variable": return `${ctxStr(n.ctx)}.${n.name}`;
    default: return "?";
  }
}

function paramList(params) {
  const p = params.t;
  if (p.k === "Tuple") return p.elems.map((e) => typeStr(e.type) + (e.variadic ? "..." : ""));
  return [typeStr(params)];
}

function typeStr(n) {
  const t = n.k === "Type" ? n.t : n;
  switch (t.k) {
    case "Nominal": return ctxStr(t);
    case "Symbolic": return t.text;
    case "BoundGeneric": {
      const base = typeStr(t.base);
      const args = t.args.map(typeStr);
      if (base === "Swift.Optional" && args.length === 1) {
        const inner = t.args[0].t;
        return inner.k === "FunctionType" ? `(${args[0]})?` : `${args[0]}?`;
      }
      if (base === "Swift.Array" && args.length === 1) return `[${args[0]}]`;
      if (base === "Swift.Dictionary" && args.length === 2) return `[${args[0]} : ${args[1]}]`;
      return `${base}<${args.join(", ")}>`;
    }
    case "Tuple":
      return `(${t.elems.map((e) => (e.label ? `${e.label}: ` : "") + typeStr(e.type) + (e.variadic ? "..." : "")).join(", ")})`;
    case "FunctionType":
      return `(${paramList(t.params).join(", ")})${fnEffects(t)} -> ${typeStr(t.result)}`;
    case "Metatype": return `${typeStr(t.of)}.Type`;
    case "InOut": return `inout ${typeStr(t.of)}`;
    case "Module": return t.text;
    default: return "?";
  }
}

const fnEffects = (ft) => `${ft.async ? " async" : ""}${ft.throws ? " throws" : ""}`;

function signature(labels, fnType) {
  const ft = fnType.t;
  const params = paramList(ft.params);
  const rendered = params.map((p, i) => (labels && labels.length ? `${labels[i]}: ${p}` : p));
  return `(${rendered.join(", ")})${fnEffects(ft)} -> ${typeStr(ft.result)}`;
}

function entityStr(n) {
  switch (n.k) {
    case "Function": return `${ctxStr(n.ctx)}.${n.name}${signature(n.labels, n.type)}`;
    case "Variable": return `${ctxStr(n.ctx)}.${n.name} : ${typeStr(n.type)}`;
    case "Accessor": return `${ctxStr(n.of.ctx)}.${n.of.name}.${n.accessor} : ${typeStr(n.of.type)}`;
    // As in Swift's NodePrinter: "__allocating_init" only for class contexts.
    case "Constructor": return `${ctxStr(n.ctx)}.${n.allocating && n.ctx.nk === "class" ? "__allocating_init" : "init"}${signature(n.labels, n.type)}`;
    case "Destructor": return `${ctxStr(n.ctx)}.${n.deallocating ? "__deallocating_deinit" : "deinit"}`;
    case "Conformance": return `${typeStr(n.type)} : ${typeStr(n.proto)} in ${n.module.text}`;
    case "Prefix": return `${n.prefix} ${entityStr(n.of)}`;
    case "TypeMangling": return typeStr(n.type);
    case "Type": return typeStr(n);
    case "Module": return n.text;
    case "Nominal": case "Extension": return ctxStr(n);
    default: throw new Unsupported(`cannot print ${n.k}`);
  }
}

// ------------------------------------------------------------- public API

const toBytes = (s) => {
  const b = typeof s === "string" ? [...s].map((ch) => ch.charCodeAt(0) & 0xff) : [...s];
  if (b.length > MAX_INPUT) throw new Unsupported("input too long");
  return b;
};

/** True when a (possibly underscore-prefixed) symbol uses Swift 5 / 4.2 mangling. */
export function isSwiftSymbol(sym) {
  return /^_?\$[sS]/.test(sym);
}

/** Demangle a full Swift symbol ("$s…" / "_$s…"). Returns null when unsupported. */
export function demangleSymbol(sym) {
  const m = /^_?\$[sS](.*)$/s.exec(sym);
  if (!m) return null;
  try {
    const d = new Demangler(toBytes(m[1]));
    const stack = d.run();
    if (stack.length === 0) return null;
    // Thunk prefixes like @objc read naturally when joined in order.
    return stack.map((n) => entityStr(n)).join(" ");
  } catch {
    return null;
  }
}

/**
 * Demangle a mangled *type* string, as stored in Swift reflection metadata
 * (no "$s" prefix; may contain symbolic references). `symbolic(kind, index,
 * rel)` resolves a symbolic reference whose 4-byte offset starts at byte
 * `index` of the input.
 */
export function demangleType(bytes, symbolic) {
  try {
    const d = new Demangler(toBytes(bytes), symbolic);
    const stack = d.run();
    if (stack.length !== 1) return null;
    const n = stack[0];
    if (n.k === "Type") return typeStr(n);
    if (n.k === "Module") return n.text;
    return entityStr(n);
  } catch {
    return null;
  }
}

/**
 * Demangle an Objective-C runtime name of a Swift class/protocol
 * ("_TtC9WalletKit15TransferService", "_TtP9WalletKit12Transferable_",
 * or a "$s…" mangled name). Returns null if not recognized.
 */
export function demangleObjCRuntimeName(name) {
  if (isSwiftSymbol(name)) {
    const d = demangleSymbol(name);
    return d ? d.replace(/^type metadata for /, "") : null;
  }
  const m = /^_Tt([CVOP]+)(.*)$/.exec(name);
  if (!m) return null;
  let rest = m[2];
  const parts = [];
  const read = () => {
    if (rest.startsWith("s")) { rest = rest.slice(1); return "Swift"; }
    const n = /^(\d+)/.exec(rest);
    if (!n) return null;
    const len = Number(n[1]);
    const id = rest.slice(n[1].length, n[1].length + len);
    if (id.length !== len) return null;
    rest = rest.slice(n[1].length + len);
    return id;
  };
  const count = m[1].length + 1;
  for (let i = 0; i < count; i++) {
    const id = read();
    if (id == null) return null;
    parts.push(id);
  }
  if (m[1].endsWith("P") && rest !== "_" && rest !== "") return null;
  if (!m[1].endsWith("P") && rest !== "") return null;
  return parts.join(".");
}
