#!/usr/bin/env node
// REA-iPhone CLI — reverse-engineer iPhone apps: static analysis (execution-
// free), device access via libimobiledevice, and Frida runtime observation.

import { readFileSync, writeFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { analyze } from "../src/analyze.js";
import { renderText } from "../src/report.js";
import { loadBinary } from "../src/target.js";
import { openMachO, selectImage } from "../src/macho.js";
import { createPointerResolver } from "../src/macho/fixups.js";
import { dumpObjC, renderObjCHeader } from "../src/objc.js";
import { dumpSwift, renderSwiftInterface } from "../src/swift/metadata.js";
import { demangleSymbol } from "../src/swift/demangle.js";
import { readSymbols, readExports, groupImports } from "../src/macho/symbols.js";
import { extractStrings } from "../src/strings.js";
import * as device from "../src/device/idevice.js";
import { generateScript, MODES } from "../src/frida/scripts.js";
import { runFridaSession } from "../src/frida/runner.js";
import { startServer } from "../src/mcp/server.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const VERSION = JSON.parse(readFileSync(resolve(HERE, "../package.json"), "utf8")).version;

const USAGE = `rea-iphone ${VERSION} — reverse-engineer iPhone apps

STATIC ANALYSIS (execution-free; TARGET = .ipa | .app directory | Mach-O file)
  analyze   TARGET [--deep] [--arch A] [--json]     Bundle, Mach-O, entitlements, provisioning,
                                                    frameworks, SDKs; --deep adds everything below
  classdump TARGET [--json] [--filter RE]           Objective-C classes/categories/protocols header
  swift     TARGET [--json] [--filter RE]           Swift types, fields, enums, conformances
  strings   TARGET [--all] [--category C] [--min N] [--filter RE] [--json]
                                                    Classified strings (urls, credentials, ...)
  symbols   TARGET [--imports|--exports|--defined|--all] [--filter RE] [--no-demangle] [--json]
  fixups    TARGET [--binds] [--json]               dyld fixup format, imports, bind sites
  demangle  SYMBOL...                               Demangle Swift symbols (or read stdin)

  Common: --binary B   pick a binary inside an app ("main", a path, or e.g. Flutter.framework/Flutter)
          --arch A     pick a slice of a fat binary (default arm64e, then arm64)

DEVICE (libimobiledevice; devices paired with this computer)
  device list
  device info    [--udid U] [--full] [--json]
  device apps    [--udid U] [--type user|system|all] [--json]
  device syslog  [--udid U] [--seconds N] [--process P] [--match RE] [--json]
  device crashes --out DIR [--udid U] [--filter NAME] [--json]
  device screenshot --out FILE [--udid U]

FRIDA (runtime observation; frida-tools here, frida-server on a device you control)
  frida script MODE [--pattern P]... [--out FILE] [--backtrace] [--no-redact]
  frida run    MODE (--bundle ID [--attach] | --name N | --pid P | --frontmost)
               [--pattern P]... [--seconds N] [--device-id D | --host H] [--json]
  Modes: ${MODES.join(", ")}

AGENTS
  mcp                         Run the MCP server on stdio
  setup                       Print MCP registration commands for common agents

Lawful use only: analyze apps and devices you own or are authorized to examine.
FairPlay-encrypted App Store binaries need a decrypted copy from a device you own
before strings, class-dump and Swift metadata in __TEXT are readable.
`;

// ------------------------------------------------------------ args

function parseArgs(argv) {
  const pos = [];
  const flags = {};
  const multi = new Set(["pattern"]);
  const bool = new Set(["json", "deep", "all", "imports", "exports", "defined", "binds", "full", "attach", "frontmost", "backtrace", "no-redact", "no-demangle", "help"]);
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "-h") { flags.help = true; continue; }
    if (!a.startsWith("--")) { pos.push(a); continue; }
    const [k, inline] = a.slice(2).split(/=(.*)/s);
    if (bool.has(k) && inline === undefined) { flags[k] = true; continue; }
    const v = inline !== undefined ? inline : argv[++i];
    if (v === undefined) throw new Error(`--${k} needs a value`);
    if (multi.has(k)) (flags[k] ??= []).push(v);
    else flags[k] = v;
  }
  return { pos, flags };
}

const out = (s) => process.stdout.write(s.endsWith("\n") ? s : `${s}\n`);
const json = (o) => out(JSON.stringify(o, null, 2));
const re = (f) => (f ? new RegExp(f, "i") : null);

function image(target, flags) {
  if (!target) throw new Error("missing TARGET");
  const { buf, binary } = loadBinary(target, flags.binary);
  const { images } = openMachO(buf);
  const im = selectImage(images, flags.arch);
  if (!im) throw new Error(`architecture ${flags.arch} not present (have: ${images.map((i) => i.arch).join(", ")})`);
  return { im, binary: binary.path };
}

function deviceResult(r, flags, render) {
  if (!r.ok) throw new Error(`${r.error}${r.hint ? `\n${r.hint}` : ""}`);
  if (flags.json) json(r);
  else out(render(r));
}

// ------------------------------------------------------------ commands

const commands = {
  analyze({ pos, flags }) {
    const r = analyze(pos[0] ?? (() => { throw new Error("missing TARGET"); })(), { deep: !!flags.deep, arch: flags.arch });
    flags.json ? json(r) : out(renderText(r));
  },

  classdump({ pos, flags }) {
    const { im, binary } = image(pos[0], flags);
    const d = dumpObjC(im);
    const f = re(flags.filter);
    if (f) {
      d.classes = d.classes.filter((c) => f.test(c.name) || f.test(c.swiftName ?? ""));
      d.categories = d.categories.filter((c) => f.test(c.name) || f.test(c.class ?? ""));
      d.protocols = d.protocols.filter((p) => f.test(p.name));
    }
    if (flags.json) return json({ binary, arch: im.arch, ...d });
    out(renderObjCHeader(d));
    for (const l of d.limitations) process.stderr.write(`! ${l}\n`);
  },

  swift({ pos, flags }) {
    const { im, binary } = image(pos[0], flags);
    const d = dumpSwift(im);
    const f = re(flags.filter);
    if (f) {
      d.types = d.types.filter((t) => f.test(t.fullName ?? ""));
      d.protocols = d.protocols.filter((p) => f.test(p.fullName ?? ""));
      d.conformances = d.conformances.filter((c) => f.test(c.type ?? "") || f.test(c.protocol ?? ""));
    }
    if (flags.json) return json({ binary, arch: im.arch, ...d });
    out(renderSwiftInterface(d));
    for (const l of d.limitations) process.stderr.write(`! ${l}\n`);
  },

  strings({ pos, flags }) {
    const { im, binary } = image(pos[0], flags);
    const s = extractStrings(im, { minLength: Number(flags.min ?? 4) });
    const f = re(flags.filter);
    if (flags.json) {
      const o = { binary, arch: im.arch, counts: s.counts, findings: flags.category ? { [flags.category]: s.findings[flags.category] ?? [] } : s.findings, limitations: s.limitations };
      if (flags.all) o.strings = s.strings.filter((x) => !f || f.test(x.value)).map((x) => ({ value: x.value, source: x.source, address: `0x${x.vm.toString(16)}` }));
      return json(o);
    }
    if (flags.all) {
      for (const x of s.strings) if (!f || f.test(x.value)) out(`0x${x.vm.toString(16)}  ${x.source.padEnd(18)} ${x.value}`);
      return;
    }
    const cats = flags.category ? [flags.category] : Object.keys(s.findings);
    out(`Strings: ${Object.entries(s.counts).map(([k, v]) => `${k}=${v}`).join(", ") || "none"}`);
    for (const c of cats) {
      const items = s.findings[c] ?? [];
      if (!items.length) continue;
      out(`\n${c} (${items.length})`);
      for (const it of items) out(`  ${it.value}    [${it.rule}, ${it.source} @ ${it.address}]`);
    }
    for (const l of s.limitations) process.stderr.write(`! ${l}\n`);
  },

  symbols({ pos, flags }) {
    const { im, binary } = image(pos[0], flags);
    const f = re(flags.filter);
    const dm = !flags["no-demangle"];
    const show = (n) => (dm && demangleSymbol(n) ? `${n}\n      -> ${demangleSymbol(n)}` : n);
    if (flags.exports) {
      const ex = readExports(im).exports.filter((e) => !f || f.test(e.name));
      if (flags.json) return json({ binary, arch: im.arch, exports: ex.map((e) => ({ ...e, demangled: dm ? demangleSymbol(e.name) : undefined })) });
      for (const e of ex) out(`${e.address != null ? `0x${e.address.toString(16)}` : "reexport".padEnd(11)}  ${show(e.name)}`);
      return;
    }
    const syms = readSymbols(im).symbols;
    if (flags.defined || flags.all) {
      const list = syms.filter((s) => (flags.all || s.kind === "defined") && (!f || f.test(s.name)));
      if (flags.json) return json({ binary, arch: im.arch, symbols: list.map((s) => ({ ...s, demangled: dm ? demangleSymbol(s.name) : undefined })) });
      for (const s of list) out(`${s.address != null ? `0x${s.address.toString(16)}` : "-".padEnd(11)}  ${s.kind.padEnd(9)} ${show(s.name)}`);
      return;
    }
    const groups = groupImports(syms).map((g) => ({ ...g, symbols: g.symbols.filter((s) => !f || f.test(s)) })).filter((g) => g.symbols.length);
    if (flags.json) return json({ binary, arch: im.arch, imports: groups });
    for (const g of groups) {
      out(`${g.library} (${g.symbols.length})`);
      for (const s of g.symbols) out(`  ${show(s)}`);
    }
  },

  fixups({ pos, flags }) {
    const { im, binary } = image(pos[0], flags);
    const r = createPointerResolver(im);
    const o = { binary, arch: im.arch, mode: r.mode, formats: r.formats, imports: r.imports, limitations: r.limitations };
    if (flags.binds) o.binds = r.enumerate().filter((l) => l.kind === "bind").map((l) => ({ address: `0x${l.vm.toString(16)}`, symbol: l.symbol, library: l.library }));
    if (flags.json) return json(o);
    out(`Fixups: ${o.mode}${o.formats.length ? ` (${o.formats.join(", ")})` : ""}`);
    if (o.imports) for (const i of o.imports) out(`  import ${i.symbol}  [${i.library}${i.weak ? ", weak" : ""}]`);
    if (o.binds) for (const b of o.binds) out(`  bind ${b.address}  ${b.symbol}  [${b.library}]`);
    for (const l of o.limitations) process.stderr.write(`! ${l}\n`);
  },

  demangle({ pos }) {
    const inputs = pos.length ? pos : readFileSync(0, "utf8").split(/\s+/).filter(Boolean);
    for (const s of inputs) out(`${s}\n  -> ${demangleSymbol(s) ?? "(not demangled: unsupported or not a Swift symbol)"}`);
  },

  async device({ pos, flags }) {
    const sub = pos[0];
    const udid = flags.udid;
    if (sub === "list") {
      return deviceResult(await device.listDevices(), flags, (r) => (r.devices.length ? r.devices.map((d) => `${d.udid}  ${d.transport.padEnd(7)}  ${d.name ?? "?"}  ${d.product ?? ""}  iOS ${d.ios ?? "?"}`).join("\n") : "No paired devices found. Connect the device, unlock it, and tap Trust."));
    }
    if (sub === "info") {
      const r = await device.deviceInfo(udid);
      if (r.ok && !flags.full) delete r.properties;
      return deviceResult(r, flags, (x) => Object.entries(x.properties ?? x.summary).map(([k, v]) => `${k}: ${typeof v === "object" ? JSON.stringify(v) : v}`).join("\n"));
    }
    if (sub === "apps") {
      return deviceResult(await device.listApps(udid, { type: flags.type ?? "user" }), flags, (r) => r.apps.map((a) => `${(a.bundle_id ?? "?").padEnd(45)} ${(a.version ?? "").padEnd(10)} ${a.name ?? ""}`).join("\n") || "No apps.");
    }
    if (sub === "syslog") {
      return deviceResult(await device.captureSyslog(udid, { seconds: flags.seconds, process: flags.process, match: flags.match }), flags, (r) => r.lines.map((l) => (l.raw ?? `${l.time} ${l.process}[${l.pid}] <${l.level}>: ${l.message}`)).join("\n") || `(no matching lines in ${r.seconds}s)`);
    }
    if (sub === "crashes") {
      if (!flags.out) throw new Error("device crashes needs --out DIR");
      return deviceResult(await device.pullCrashReports(udid, flags.out, { filter: flags.filter }), flags, (r) => [`${r.count} report(s) in ${r.outDir}`, ...r.reports.map((c) => `- ${c.timestamp ?? "?"}  ${c.app_name ?? "?"} ${c.app_version ?? ""}  ${c.exception?.type ?? c.termination?.indicator ?? ""}\n    ${c.top_frames.slice(0, 4).join("\n    ")}`)].join("\n"));
    }
    if (sub === "screenshot") {
      if (!flags.out) throw new Error("device screenshot needs --out FILE");
      return deviceResult(await device.screenshot(udid, flags.out), flags, (r) => `Saved ${r.file}`);
    }
    throw new Error(`unknown device command: ${sub ?? "(none)"}`);
  },

  async frida({ pos, flags }) {
    const sub = pos[0];
    const mode = pos[1];
    const scriptOptions = { maxEvents: flags["max-events"], backtrace: !!flags.backtrace, redact: !flags["no-redact"] };
    if (sub === "script") {
      const s = generateScript(mode, { patterns: flags.pattern, ...scriptOptions });
      if (flags.out) { writeFileSync(flags.out, s); out(`Wrote ${flags.out}`); } else out(s);
      return;
    }
    if (sub === "run") {
      const target = flags.bundle ? { bundleId: flags.bundle, spawn: !flags.attach } : flags.name ? { name: flags.name } : flags.pid ? { pid: Number(flags.pid) } : flags.frontmost ? { frontmost: true } : null;
      if (!target) throw new Error("frida run needs --bundle, --name, --pid, or --frontmost");
      const dev = flags["device-id"] ? { id: flags["device-id"] } : flags.host ? { host: flags.host } : "usb";
      const r = await runFridaSession({ mode, patterns: flags.pattern, device: dev, target, seconds: flags.seconds, scriptOptions });
      if (flags.json) return json(r);
      if (!r.ok && r.error) throw new Error(r.error);
      out(`Frida ${r.mode}: ${Object.entries(r.counts ?? {}).map(([k, v]) => `${k}=${v}`).join(", ") || "no events"} in ${r.seconds}s`);
      for (const e of r.events ?? []) out(`  ${JSON.stringify(e)}`);
      if (r.stderr) process.stderr.write(`${r.stderr}\n`);
      return;
    }
    throw new Error(`unknown frida command: ${sub ?? "(none)"}`);
  },

  mcp() {
    startServer();
  },

  setup() {
    const bin = resolve(HERE, "rea-iphone.js");
    out(`Register REA-iPhone as an MCP server (stdio):

Claude Code:
  claude mcp add rea-iphone -- node ${bin} mcp

Codex CLI (~/.codex/config.toml):
  [mcp_servers.rea-iphone]
  command = "node"
  args = ["${bin}", "mcp"]

Cursor / Claude Desktop / generic (mcp.json):
  { "mcpServers": { "rea-iphone": { "command": "node", "args": ["${bin}", "mcp"] } } }

Optional tools for the device and Frida layers:
  libimobiledevice + ideviceinstaller   (macOS: brew install libimobiledevice ideviceinstaller)
  frida-tools                           (pip install frida-tools; frida-server on the device)
`);
  },
};

// Exit quietly when piped into a pager/head that closes early.
process.stdout.on("error", (err) => {
  if (err.code === "EPIPE") process.exit(0);
  throw err;
});

async function main() {
  const argv = process.argv.slice(2);
  if (argv.length === 0 || argv[0] === "--help" || argv[0] === "-h" || argv[0] === "help") {
    out(USAGE);
    process.exit(argv.length === 0 ? 1 : 0);
  }
  if (argv[0] === "--version" || argv[0] === "-v") return out(VERSION);
  const cmd = argv[0];
  const fn = commands[cmd];
  if (!fn) {
    process.stderr.write(`unknown command: ${cmd}\n\n${USAGE}`);
    process.exit(2);
  }
  try {
    await fn(parseArgs(argv.slice(1)));
  } catch (err) {
    process.stderr.write(`error: ${err.message}\n`);
    process.exit(1);
  }
}

main();
