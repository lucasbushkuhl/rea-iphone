// MCP server over stdio (newline-delimited JSON-RPC 2.0). Zero dependencies.
// Exposes rea-iphone's static analysis, device layer and Frida bridge as MCP
// tools so an agent (Claude Code, Codex, Cursor, ...) can investigate iOS apps
// the same way REA's tools work for other targets.

import { createInterface } from "node:readline";
import { readFileSync } from "node:fs";
import { analyze } from "../analyze.js";
import { loadBinary } from "../target.js";
import { openMachO, selectImage } from "../macho.js";
import { createPointerResolver } from "../macho/fixups.js";
import { dumpObjC, renderObjCHeader } from "../objc.js";
import { dumpSwift, renderSwiftInterface } from "../swift/metadata.js";
import { demangleSymbol } from "../swift/demangle.js";
import { readSymbols, readExports, groupImports } from "../macho/symbols.js";
import { extractStrings } from "../strings.js";
import * as device from "../device/idevice.js";
import { generateScript, MODES } from "../frida/scripts.js";
import { runFridaSession } from "../frida/runner.js";

const VERSION = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8")).version;
const PROTOCOL_VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"];
const MAX_TEXT = 200_000;

// ------------------------------------------------------------ helpers

function openImage({ path, binary, arch }) {
  const { buf, binary: picked, binaries } = loadBinary(path, binary);
  const { images } = openMachO(buf);
  const image = selectImage(images, arch);
  if (!image) throw new Error(`architecture ${arch} not present (have: ${images.map((i) => i.arch).join(", ")})`);
  return { image, binary: picked.path, binaries: binaries.map((b) => b.path), archs: images.map((i) => i.arch) };
}

const limit = (arr, n) => ({ items: arr.slice(0, n), total: arr.length, truncated: arr.length > n });
const filterRe = (f) => {
  if (!f) return null;
  try { return new RegExp(f, "i"); } catch { throw new Error(`invalid filter regex: ${f}`); }
};

const PATH_PROPS = {
  path: { type: "string", description: "Absolute path to an .ipa, an unpacked .app directory, or a Mach-O file." },
  binary: { type: "string", description: 'Which binary inside an app: "main" (default), an exact path, or a suffix such as "Flutter.framework/Flutter".' },
  arch: { type: "string", description: "Architecture slice for fat binaries (default: arm64e, then arm64)." },
};
const UDID = { udid: { type: "string", description: "Device UDID (default: the only attached device)." } };
const RO = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false };

// ------------------------------------------------------------- tools

const TOOLS = [
  {
    name: "analyze_ios_application",
    title: "Analyze iOS application",
    description: "Static, execution-free analysis of an iOS app: bundle identity, Info.plist (URL schemes, ATS, privacy usage strings), Mach-O slices (arch, platform/min OS, FairPlay encryption, fixup format), entitlements, provisioning profile, embedded frameworks/extensions, runtime families and third-party SDKs. With deep=true also summarizes class-dump, Swift metadata, symbols and classified strings for the main executable.",
    inputSchema: { type: "object", properties: { path: PATH_PROPS.path, deep: { type: "boolean", default: false }, arch: PATH_PROPS.arch }, required: ["path"] },
    annotations: RO,
    handler: (a) => analyze(a.path, { deep: !!a.deep, arch: a.arch }),
  },
  {
    name: "dump_objc_classes",
    title: "Objective-C class-dump",
    description: "Recover Objective-C classes, metaclass methods, categories, protocols, ivars and properties (works with classic and chained fixups, pointer and relative method lists). format=header returns a class-dump style header; json returns structured data.",
    inputSchema: {
      type: "object",
      properties: { ...PATH_PROPS, format: { type: "string", enum: ["header", "json"], default: "header" }, filter: { type: "string", description: "Case-insensitive regex on class/category/protocol names." }, limit: { type: "integer", default: 200, minimum: 1, maximum: 5000 } },
      required: ["path"],
    },
    annotations: RO,
    handler: (a) => {
      const { image, binary } = openImage(a);
      const d = dumpObjC(image);
      const re = filterRe(a.filter);
      if (re) {
        d.classes = d.classes.filter((c) => re.test(c.name) || re.test(c.swiftName ?? ""));
        d.categories = d.categories.filter((c) => re.test(c.name) || re.test(c.class ?? ""));
        d.protocols = d.protocols.filter((p) => re.test(p.name));
      }
      const n = a.limit ?? 200;
      d.classes = d.classes.slice(0, n);
      if ((a.format ?? "header") === "header") return { binary, arch: image.arch, header: renderObjCHeader(d), limitations: d.limitations };
      return { binary, arch: image.arch, ...d };
    },
  },
  {
    name: "dump_swift_types",
    title: "Swift metadata",
    description: "Recover Swift types (struct/class/enum) with stored properties or enum cases and their demangled types, superclasses, protocols and protocol conformances from Swift 5 reflection metadata. format=interface returns Swift-like declarations; json returns structured data.",
    inputSchema: { type: "object", properties: { ...PATH_PROPS, format: { type: "string", enum: ["interface", "json"], default: "interface" }, filter: { type: "string" } }, required: ["path"] },
    annotations: RO,
    handler: (a) => {
      const { image, binary } = openImage(a);
      const d = dumpSwift(image);
      const re = filterRe(a.filter);
      if (re) {
        d.types = d.types.filter((t) => re.test(t.fullName ?? ""));
        d.protocols = d.protocols.filter((p) => re.test(p.fullName ?? ""));
        d.conformances = d.conformances.filter((c) => re.test(c.type ?? "") || re.test(c.protocol ?? ""));
      }
      if ((a.format ?? "interface") === "interface") return { binary, arch: image.arch, interface: renderSwiftInterface(d), limitations: d.limitations };
      return { binary, arch: image.arch, ...d };
    },
  },
  {
    name: "extract_strings",
    title: "Extract and classify strings",
    description: "Extract C strings, CFString/NSString literals, selectors, Swift reflection and os_log strings, classified into urls, custom_url_schemes, emails, ip_addresses, credential_candidates, integrity_checks, tls_pinning and high_entropy. Returns findings by default; set include_all to also list raw strings.",
    inputSchema: {
      type: "object",
      properties: { ...PATH_PROPS, category: { type: "string", description: "Only this finding category." }, include_all: { type: "boolean", default: false }, filter: { type: "string", description: "Regex applied to raw strings when include_all is true." }, min_length: { type: "integer", default: 4, minimum: 1 }, limit: { type: "integer", default: 500, minimum: 1, maximum: 20000 } },
      required: ["path"],
    },
    annotations: RO,
    handler: (a) => {
      const { image, binary } = openImage(a);
      const s = extractStrings(image, { minLength: a.min_length ?? 4 });
      const findings = a.category ? { [a.category]: s.findings[a.category] ?? [] } : s.findings;
      const out = { binary, arch: image.arch, counts: s.counts, findings, limitations: s.limitations };
      if (a.include_all) {
        const re = filterRe(a.filter);
        const list = s.strings.filter((x) => !re || re.test(x.value)).map((x) => ({ value: x.value, source: x.source, address: `0x${x.vm.toString(16)}` }));
        out.strings = limit(list, a.limit ?? 500);
      }
      return out;
    },
  },
  {
    name: "list_symbols",
    title: "Symbols, imports and exports",
    description: "List imported symbols grouped by library, exported symbols (export trie), or defined symbols, with Swift symbols demangled.",
    inputSchema: {
      type: "object",
      properties: { ...PATH_PROPS, kind: { type: "string", enum: ["imports", "exports", "defined", "all"], default: "imports" }, filter: { type: "string" }, demangle: { type: "boolean", default: true }, limit: { type: "integer", default: 500, minimum: 1, maximum: 50000 } },
      required: ["path"],
    },
    annotations: RO,
    handler: (a) => {
      const { image, binary } = openImage(a);
      const kind = a.kind ?? "imports";
      const re = filterRe(a.filter);
      const dm = a.demangle !== false;
      const decorate = (name) => (dm ? { name, demangled: demangleSymbol(name) } : { name });
      const n = a.limit ?? 500;
      if (kind === "imports") {
        const groups = groupImports(readSymbols(image).symbols).map((g) => {
          const names = g.symbols.filter((s) => !re || re.test(s));
          return { library: g.library, count: names.length, symbols: names.slice(0, n).map(decorate) };
        }).filter((g) => g.count > 0);
        return { binary, arch: image.arch, imports: groups };
      }
      if (kind === "exports") {
        const ex = readExports(image).exports.filter((e) => !re || re.test(e.name));
        return { binary, arch: image.arch, exports: limit(ex.map((e) => ({ ...decorate(e.name), address: e.address != null ? `0x${e.address.toString(16)}` : null, kind: e.kind, reexport: e.reexport ?? null })), n) };
      }
      const syms = readSymbols(image).symbols.filter((s) => (kind === "all" || s.kind === "defined") && (!re || re.test(s.name)));
      return { binary, arch: image.arch, symbols: limit(syms.map((s) => ({ ...decorate(s.name), kind: s.kind, external: s.external, address: s.address != null ? `0x${s.address.toString(16)}` : null, section: s.section, library: s.library ?? null })), n) };
    },
  },
  {
    name: "demangle_swift",
    title: "Demangle Swift symbols",
    description: "Demangle Swift 5 symbols ($s… / _$s…) and Swift ObjC runtime names. Unsupported constructs return null rather than a guess.",
    inputSchema: { type: "object", properties: { symbols: { type: "array", items: { type: "string" }, minItems: 1, maxItems: 5000 } }, required: ["symbols"] },
    annotations: RO,
    handler: (a) => ({ results: a.symbols.map((s) => ({ symbol: s, demangled: demangleSymbol(s) })) }),
  },
  {
    name: "inspect_fixups",
    title: "Inspect dyld fixups",
    description: "Report the fixup format (classic rebase/bind or chained fixups and pointer formats), imported symbols with libraries, and optionally every bind location.",
    inputSchema: { type: "object", properties: { ...PATH_PROPS, include_locations: { type: "boolean", default: false }, limit: { type: "integer", default: 1000 } }, required: ["path"] },
    annotations: RO,
    handler: (a) => {
      const { image, binary } = openImage(a);
      const r = createPointerResolver(image);
      const out = { binary, arch: image.arch, mode: r.mode, formats: r.formats, imports: r.imports, limitations: r.limitations };
      if (a.include_locations) {
        const locs = r.enumerate().filter((l) => l.kind === "bind").map((l) => ({ address: `0x${l.vm.toString(16)}`, symbol: l.symbol, library: l.library }));
        out.binds = limit(locs, a.limit ?? 1000);
      }
      return out;
    },
  },
  // ---- device layer
  {
    name: "list_ios_devices",
    title: "List iOS devices",
    description: "List iPhones/iPads paired with this computer over USB or network (libimobiledevice).",
    inputSchema: { type: "object", properties: {} },
    annotations: { ...RO, idempotentHint: false, openWorldHint: true },
    handler: () => device.listDevices(),
  },
  {
    name: "ios_device_info",
    title: "iOS device info",
    description: "Device properties (model, iOS version, build, CPU architecture, ...) via ideviceinfo.",
    inputSchema: { type: "object", properties: { ...UDID, full: { type: "boolean", default: false } } },
    annotations: { ...RO, openWorldHint: true },
    handler: async (a) => {
      const r = await device.deviceInfo(a.udid);
      if (r.ok && !a.full) delete r.properties;
      return r;
    },
  },
  {
    name: "list_installed_apps",
    title: "List installed apps",
    description: "Installed applications on a paired device with bundle ID, version, type, executable and entitlement keys.",
    inputSchema: { type: "object", properties: { ...UDID, type: { type: "string", enum: ["user", "system", "all"], default: "user" } } },
    annotations: { ...RO, openWorldHint: true },
    handler: (a) => device.listApps(a.udid, { type: a.type ?? "user" }),
  },
  {
    name: "capture_device_syslog",
    title: "Capture device syslog",
    description: "Capture the device system log for a bounded time (1-300 s), optionally filtered by process name or regex.",
    inputSchema: { type: "object", properties: { ...UDID, seconds: { type: "integer", default: 10, minimum: 1, maximum: 300 }, process: { type: "string" }, match: { type: "string" }, max_lines: { type: "integer", default: 2000 } } },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    handler: (a) => device.captureSyslog(a.udid, { seconds: a.seconds, process: a.process, match: a.match, maxLines: a.max_lines ?? 2000 }),
  },
  {
    name: "pull_crash_reports",
    title: "Pull crash reports",
    description: "Copy crash reports from the device into out_dir (reports are kept on the device) and summarize them: exception, termination reason, faulting-thread frames.",
    inputSchema: { type: "object", properties: { ...UDID, out_dir: { type: "string" }, filter: { type: "string", description: "Only reports whose name contains this (e.g. the app's process name)." } }, required: ["out_dir"] },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    handler: (a) => device.pullCrashReports(a.udid, a.out_dir, { filter: a.filter }),
  },
  // ---- Frida
  {
    name: "generate_frida_script",
    title: "Generate Frida agent script",
    description: `Generate an observational Frida agent script. Modes: ${MODES.join(", ")}. objc-trace takes ObjC patterns like "-[NSURLSession *]"; native-trace takes module patterns like "exports:*!SecItem*".`,
    inputSchema: {
      type: "object",
      properties: { mode: { type: "string", enum: MODES }, patterns: { type: "array", items: { type: "string" } }, max_events: { type: "integer", default: 1000 }, per_hook: { type: "integer", default: 100 }, backtrace: { type: "boolean", default: false }, redact: { type: "boolean", default: true, description: "Redact credential headers in network mode." } },
      required: ["mode"],
    },
    annotations: RO,
    handler: (a) => ({ mode: a.mode, script: generateScript(a.mode, { patterns: a.patterns, maxEvents: a.max_events, perHook: a.per_hook, backtrace: a.backtrace, redact: a.redact }) }),
  },
  {
    name: "run_frida_session",
    title: "Run Frida session",
    description: "Spawn or attach to an app on a device you control with frida-server running, run an observational agent for a bounded time, and return the events (calls, returns, HTTP requests, DNS lookups, classes, modules).",
    inputSchema: {
      type: "object",
      properties: {
        mode: { type: "string", enum: MODES },
        patterns: { type: "array", items: { type: "string" } },
        bundle_id: { type: "string", description: "Spawn (default) or attach to this app." },
        attach: { type: "boolean", default: false, description: "Attach to the running app instead of spawning it." },
        process_name: { type: "string" },
        pid: { type: "integer" },
        device_id: { type: "string", description: "Frida device ID; default USB." },
        host: { type: "string", description: "Remote frida-server host:port." },
        seconds: { type: "integer", default: 20, minimum: 1, maximum: 600 },
        max_events: { type: "integer", default: 1000 },
        backtrace: { type: "boolean", default: false },
        redact: { type: "boolean", default: true },
      },
      required: ["mode"],
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    handler: (a) => {
      const target = a.bundle_id ? { bundleId: a.bundle_id, spawn: !a.attach } : a.process_name ? { name: a.process_name } : a.pid != null ? { pid: a.pid } : { frontmost: true };
      const dev = a.device_id ? { id: a.device_id } : a.host ? { host: a.host } : "usb";
      return runFridaSession({ mode: a.mode, patterns: a.patterns, device: dev, target, seconds: a.seconds, scriptOptions: { maxEvents: a.max_events, backtrace: a.backtrace, redact: a.redact } });
    },
  },
];

const BY_NAME = new Map(TOOLS.map((t) => [t.name, t]));

// ---------------------------------------------------------- validation

function validate(schema, args) {
  const errs = [];
  const props = schema.properties ?? {};
  for (const r of schema.required ?? []) if (args[r] === undefined || args[r] === null) errs.push(`missing required argument "${r}"`);
  for (const [k, v] of Object.entries(args)) {
    const p = props[k];
    if (!p) { errs.push(`unknown argument "${k}"`); continue; }
    const t = p.type;
    if (t === "string" && typeof v !== "string") errs.push(`"${k}" must be a string`);
    if (t === "boolean" && typeof v !== "boolean") errs.push(`"${k}" must be a boolean`);
    if (t === "integer" && !Number.isInteger(v)) errs.push(`"${k}" must be an integer`);
    if (t === "array" && !Array.isArray(v)) errs.push(`"${k}" must be an array`);
    if (p.enum && !p.enum.includes(v)) errs.push(`"${k}" must be one of ${p.enum.join(", ")}`);
    if (t === "integer" && Number.isInteger(v)) {
      if (p.minimum != null && v < p.minimum) errs.push(`"${k}" must be >= ${p.minimum}`);
      if (p.maximum != null && v > p.maximum) errs.push(`"${k}" must be <= ${p.maximum}`);
    }
  }
  return errs;
}

// ------------------------------------------------------------ protocol

export async function handleMessage(msg) {
  if (msg === null || typeof msg !== "object" || Array.isArray(msg)) {
    return { jsonrpc: "2.0", id: null, error: { code: -32600, message: "Invalid Request" } };
  }
  const { id, method, params } = msg;
  const isRequest = id !== undefined && id !== null;
  const reply = (result) => ({ jsonrpc: "2.0", id, result });
  const error = (code, message) => ({ jsonrpc: "2.0", id: id ?? null, error: { code, message } });

  if (msg.jsonrpc !== "2.0" || typeof method !== "string") return isRequest ? error(-32600, "Invalid Request") : null;

  switch (method) {
    case "initialize": {
      const requested = params?.protocolVersion;
      return reply({
        protocolVersion: PROTOCOL_VERSIONS.includes(requested) ? requested : PROTOCOL_VERSIONS[0],
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: "rea-iphone", title: "REA-iPhone", version: VERSION },
        instructions: "Static, evidence-based reverse engineering of iOS apps (IPA/.app/Mach-O), plus device (libimobiledevice) and Frida observation tools. Start with analyze_ios_application (deep=true), then dump_objc_classes / dump_swift_types / extract_strings / list_symbols for detail. Use only on apps and devices you own or are authorized to examine.",
      });
    }
    case "notifications/initialized":
    case "notifications/cancelled":
      return null;
    case "ping":
      return reply({});
    case "tools/list":
      return reply({ tools: TOOLS.map(({ handler, ...t }) => t) });
    case "tools/call": {
      const tool = BY_NAME.get(params?.name);
      if (!tool) return error(-32602, `Unknown tool: ${params?.name}`);
      const args = params?.arguments ?? {};
      const errs = validate(tool.inputSchema, args);
      if (errs.length) return reply({ content: [{ type: "text", text: `Invalid arguments: ${errs.join("; ")}` }], isError: true });
      try {
        const result = await tool.handler(args);
        let text = JSON.stringify(result, null, 2);
        if (text.length > MAX_TEXT) text = `${text.slice(0, MAX_TEXT)}\n… [truncated ${text.length - MAX_TEXT} characters; narrow the request with filter/limit]`;
        const isError = result && result.ok === false;
        return reply({ content: [{ type: "text", text }], isError: !!isError });
      } catch (err) {
        return reply({ content: [{ type: "text", text: `Error: ${err.message}` }], isError: true });
      }
    }
    default:
      return isRequest ? error(-32601, `Method not found: ${method}`) : null;
  }
}

export function startServer(input = process.stdin, output = process.stdout) {
  const rl = createInterface({ input, crlfDelay: Infinity });
  const write = (obj) => output.write(`${JSON.stringify(obj)}\n`);
  rl.on("line", async (line) => {
    if (!line.trim()) return;
    let msg;
    try { msg = JSON.parse(line); } catch { write({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }); return; }
    if (Array.isArray(msg) && msg.length === 0) { write({ jsonrpc: "2.0", id: null, error: { code: -32600, message: "Invalid Request" } }); return; }
    const batch = Array.isArray(msg) ? msg : [msg];
    for (const m of batch) {
      const res = await handleMessage(m);
      if (res) write(res);
    }
  });
  return rl;
}

export { TOOLS };
