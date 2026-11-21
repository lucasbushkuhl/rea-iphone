// Frida agent-script generators for observing an iOS app you are authorized
// to test, on a device you control. Scripts are observational: they log
// calls, arguments and return values; they do not patch behavior or bypass
// protections.
//
// Events are printed as `REA_EVT <json>` lines, which runner.js parses from
// the frida CLI's output. Written against the instance-method API
// (ptr.readUtf8String(), Module.getGlobalExportByName with a fallback) so the
// same script runs on Frida 16 and Frida 17.

export const MODES = ["objc-trace", "native-trace", "network", "classes", "modules"];

const PRELUDE = String.raw`
"use strict";
const REA = { max: __MAX__, perHook: __PER_HOOK__, n: 0, counts: {}, backtrace: __BACKTRACE__, redact: __REDACT__ };
function emit(e) {
  if (REA.n >= REA.max) return;
  REA.n++;
  e.t = Date.now();
  console.log("REA_EVT " + JSON.stringify(e));
  if (REA.n === REA.max) console.log("REA_EVT " + JSON.stringify({ type: "limit", max: REA.max }));
}
function allow(key) {
  const c = (REA.counts[key] = (REA.counts[key] || 0) + 1);
  return c <= REA.perHook;
}
function findExport(name) {
  try { if (Module.getGlobalExportByName) return Module.getGlobalExportByName(name); } catch (e) { return null; }
  try { return Module.findExportByName(null, name); } catch (e) { return null; }
}
function mainModule() {
  try { if (Process.mainModule) return Process.mainModule; } catch (e) {}
  return Process.enumerateModules()[0];
}
function bt(ctx) {
  if (!REA.backtrace) return undefined;
  try { return Thread.backtrace(ctx, Backtracer.ACCURATE).slice(0, 12).map(function (a) { return DebugSymbol.fromAddress(a).toString(); }); } catch (e) { return undefined; }
}
// Split an Objective-C type encoding into one leading type char per slot
// (return, self, _cmd, args...). Pointers report "^".
const QUALS = "rnNoORVAj";
function skipType(enc, i) {
  while (i < enc.length && QUALS.indexOf(enc[i]) >= 0) i++;
  const c = enc[i];
  if (c === "^") return skipType(enc, i + 1);
  if (c === "@") {
    i++;
    if (enc[i] === '"') return enc.indexOf('"', i + 1) + 1;
    if (enc[i] === "?") return i + 1;
    return i;
  }
  if (c === "{" || c === "(" || c === "[") {
    const close = c === "{" ? "}" : c === "(" ? ")" : "]";
    let depth = 0;
    for (; i < enc.length; i++) {
      if (enc[i] === '"') { i = enc.indexOf('"', i + 1); continue; }
      if (enc[i] === c) depth++;
      else if (enc[i] === close && --depth === 0) return i + 1;
    }
    return i;
  }
  if (c === "b") { i++; while (i < enc.length && enc[i] >= "0" && enc[i] <= "9") i++; return i; }
  return i + 1;
}
function splitEncoding(enc) {
  const out = [];
  let i = 0;
  while (i < enc.length && out.length <= 64) {
    while (i < enc.length && QUALS.indexOf(enc[i]) >= 0) i++;
    if (i >= enc.length) break;
    out.push(enc[i] === "^" ? "^" : enc[i]);
    i = skipType(enc, i);
    while (i < enc.length && ((enc[i] >= "0" && enc[i] <= "9") || enc[i] === "-")) i++;
  }
  return out;
}
function objcDescribe(p) {
  try {
    if (p.isNull()) return "nil";
    const o = new ObjC.Object(p);
    let s = String(o);
    if (s.length > 300) s = s.slice(0, 300) + "…";
    return s + " <" + o.$className + ">";
  } catch (e) { return p.toString(); }
}
function decodeArg(kind, v) {
  try {
    switch (kind) {
      case "@": return objcDescribe(v);
      case "#": return v.isNull() ? "Nil" : new ObjC.Object(v).$className;
      case ":": return ObjC.selectorAsString(v);
      case "*": return v.isNull() ? null : v.readUtf8String();
      case "B": case "c": case "C": return v.toInt32() & 0xff;
      case "i": case "s": case "I": case "S": return v.toInt32();
      case "q": case "l": {
        try {
          const u = BigInt(v.toString(10));
          return (u >= 9223372036854775808n ? u - 18446744073709551616n : u).toString();
        } catch (e) { return v.toString(); }
      }
      case "Q": case "L": return v.toString(10);
      case "d": case "f": return "<floating-point register>";
      case "v": return undefined;
      default: return v.toString();
    }
  } catch (e) { return v.toString(); }
}
`;

const OBJC_TRACE = String.raw`
if (typeof ObjC === "undefined" || !ObjC.available) {
  emit({ type: "error", message: "Objective-C runtime not available in this process" });
} else {
  const resolver = new ApiResolver("objc");
  let hooks = 0;
  for (const pattern of __PATTERNS__) {
    let matches = [];
    try { matches = resolver.enumerateMatches(pattern); } catch (e) { emit({ type: "error", pattern: pattern, message: String(e) }); }
    for (const m of matches) {
      if (hooks >= __MAX_HOOKS__) break;
      const mm = /^([+-])\[(\S+) (.+)\]$/.exec(m.name);
      if (!mm) continue;
      const isClass = mm[1] === "+", cls = mm[2], sel = mm[3];
      let kinds = null;
      try {
        const method = ObjC.classes[cls][(isClass ? "+ " : "- ") + sel];
        kinds = splitEncoding(ObjC.api.method_getTypeEncoding(method.handle).readUtf8String());
      } catch (e) { kinds = null; }
      const nargs = (sel.match(/:/g) || []).length;
      try {
        Interceptor.attach(m.address, {
          onEnter(args) {
            this.on = allow(m.name);
            if (!this.on) return;
            const a = [];
            for (let i = 0; i < nargs; i++) a.push(kinds ? decodeArg(kinds[i + 3], args[i + 2]) : args[i + 2].toString());
            emit({ type: "call", method: m.name, receiver: isClass ? cls : objcDescribe(args[0]), args: a, thread: Process.getCurrentThreadId(), backtrace: bt(this.context) });
          },
          onLeave(retval) {
            if (!this.on) return;
            const k = kinds ? kinds[0] : "^";
            if (k !== "v") emit({ type: "return", method: m.name, value: decodeArg(k, retval) });
          },
        });
        hooks++;
      } catch (e) { emit({ type: "error", method: m.name, message: String(e) }); }
    }
  }
  emit({ type: "ready", mode: "objc-trace", hooks: hooks });
}
`;

const NATIVE_TRACE = String.raw`
{
  const resolver = new ApiResolver("module");
  let hooks = 0;
  for (const pattern of __PATTERNS__) {
    let matches = [];
    try { matches = resolver.enumerateMatches(pattern); } catch (e) { emit({ type: "error", pattern: pattern, message: String(e) }); }
    for (const m of matches) {
      if (hooks >= __MAX_HOOKS__) break;
      try {
        Interceptor.attach(m.address, {
          onEnter(args) {
            this.on = allow(m.name);
            if (!this.on) return;
            const a = [];
            for (let i = 0; i < 4; i++) a.push(args[i].toString());
            emit({ type: "call", function: m.name, args: a, thread: Process.getCurrentThreadId(), backtrace: bt(this.context) });
          },
          onLeave(retval) { if (this.on) emit({ type: "return", function: m.name, value: retval.toString() }); },
        });
        hooks++;
      } catch (e) { emit({ type: "error", function: m.name, message: String(e) }); }
    }
  }
  emit({ type: "ready", mode: "native-trace", hooks: hooks });
}
`;

const NETWORK = String.raw`
const SENSITIVE = /^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|api-key)$/i;
function headersOf(req) {
  const out = {};
  try {
    const h = req.allHTTPHeaderFields();
    if (!h || h.isNull && h.isNull()) return out;
    const keys = h.allKeys();
    for (let i = 0; i < keys.count(); i++) {
      const k = keys.objectAtIndex_(i).toString();
      const v = h.objectForKey_(k).toString();
      out[k] = REA.redact && SENSITIVE.test(k) ? "<redacted>" : v;
    }
  } catch (e) {}
  return out;
}
function describeRequestish(p) {
  const o = new ObjC.Object(p);
  if (o.isKindOfClass_(ObjC.classes.NSURLRequest)) {
    let body = null;
    try { const b = o.HTTPBody(); body = b && !b.isNull() ? b.length() : null; } catch (e) {}
    return { url: o.URL().absoluteString().toString(), method: o.HTTPMethod() ? o.HTTPMethod().toString() : "GET", headers: headersOf(o), body_bytes: body };
  }
  if (o.isKindOfClass_(ObjC.classes.NSURL)) return { url: o.absoluteString().toString(), method: "GET", headers: {} };
  return { url: String(o) };
}
let hooks = 0;
if (typeof ObjC !== "undefined" && ObjC.available) {
  const resolver = new ApiResolver("objc");
  const patterns = ["-[NSURLSession *TaskWithRequest:*]", "-[NSURLSession *TaskWithURL:*]", "-[WKWebView loadRequest:]"];
  for (const pattern of patterns) {
    let matches = [];
    try { matches = resolver.enumerateMatches(pattern); } catch (e) {}
    for (const m of matches) {
      try {
        Interceptor.attach(m.address, {
          onEnter(args) {
            if (!allow(m.name)) return;
            try { emit(Object.assign({ type: "http", api: m.name }, describeRequestish(args[2]))); }
            catch (e) { emit({ type: "error", api: m.name, message: String(e) }); }
          },
        });
        hooks++;
      } catch (e) {}
    }
  }
}
const gai = findExport("getaddrinfo");
if (gai) {
  Interceptor.attach(gai, {
    onEnter(args) {
      if (!allow("getaddrinfo")) return;
      try { emit({ type: "dns", host: args[0].isNull() ? null : args[0].readUtf8String(), service: args[1].isNull() ? null : args[1].readUtf8String() }); } catch (e) {}
    },
  });
  hooks++;
}
emit({ type: "ready", mode: "network", hooks: hooks });
`;

const CLASSES = String.raw`
if (typeof ObjC === "undefined" || !ObjC.available) {
  emit({ type: "error", message: "Objective-C runtime not available in this process" });
} else {
  const main = mainModule();
  const appDir = main.path.substring(0, main.path.lastIndexOf("/"));
  const owned = ObjC.enumerateLoadedClassesSync({ ownedBy: new ModuleMap(function (m) { return m.path.indexOf(appDir) === 0; }) });
  let total = 0;
  for (const modPath of Object.keys(owned)) {
    for (const name of owned[modPath]) {
      let methods = [];
      try { methods = ObjC.classes[name].$ownMethods.slice(0, __MAX_METHODS__); } catch (e) {}
      emit({ type: "class", module: modPath.substring(modPath.lastIndexOf("/") + 1), name: name, methods: methods });
      total++;
    }
  }
  emit({ type: "ready", mode: "classes", classes: total });
}
`;

const MODULES = String.raw`
const mods = Process.enumerateModules();
for (const m of mods) emit({ type: "module", name: m.name, base: m.base.toString(), size: m.size, path: m.path });
emit({ type: "ready", mode: "modules", modules: mods.length });
`;

/**
 * Generate an agent script.
 * opts: { patterns: string[], maxEvents = 1000, perHook = 100, maxHooks = 200,
 *         backtrace = false, redact = true, maxMethods = 200 }
 */
export function generateScript(mode, opts = {}) {
  const body = { "objc-trace": OBJC_TRACE, "native-trace": NATIVE_TRACE, network: NETWORK, classes: CLASSES, modules: MODULES }[mode];
  if (!body) throw new Error(`unknown mode "${mode}" (expected one of: ${MODES.join(", ")})`);
  const patterns = opts.patterns ?? [];
  if ((mode === "objc-trace" || mode === "native-trace") && patterns.length === 0) {
    throw new Error(`${mode} needs at least one pattern, e.g. ${mode === "objc-trace" ? '"-[NSURLSession *]"' : '"exports:*!SecItem*"'}`);
  }
  for (const p of patterns) {
    if (typeof p !== "string" || p.length > 512) throw new Error("patterns must be strings of at most 512 characters");
  }
  const int = (v, d, lo, hi) => Math.min(hi, Math.max(lo, Number.isFinite(Number(v)) ? Math.trunc(Number(v)) : d));
  const fill = (s) => s
    .replaceAll("__MAX__", String(int(opts.maxEvents, 1000, 1, 100000)))
    .replaceAll("__PER_HOOK__", String(int(opts.perHook, 100, 1, 100000)))
    .replaceAll("__MAX_HOOKS__", String(int(opts.maxHooks, 200, 1, 5000)))
    .replaceAll("__MAX_METHODS__", String(int(opts.maxMethods, 200, 0, 10000)))
    .replaceAll("__BACKTRACE__", opts.backtrace ? "true" : "false")
    .replaceAll("__REDACT__", opts.redact === false ? "false" : "true")
    .replaceAll("__PATTERNS__", JSON.stringify(patterns));
  return `// rea-iphone Frida agent — mode: ${mode}\n${fill(PRELUDE)}\n${fill(body)}`;
}
