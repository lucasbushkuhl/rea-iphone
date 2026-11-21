// MCP server: protocol handling and every static tool, plus a live stdio session.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { handleMessage, TOOLS } from "../src/mcp/server.js";
import { FIXTURE_BIN } from "./makeFixture.js";

const BIN = `${FIXTURE_BIN}WalletKit-chained`;
let nextId = 1;
const call = async (name, args) => {
  const r = await handleMessage({ jsonrpc: "2.0", id: nextId++, method: "tools/call", params: { name, arguments: args } });
  const text = r.result.content[0].text;
  return { isError: r.result.isError, text, json: (() => { try { return JSON.parse(text); } catch { return null; } })() };
};

test("initialize negotiates the protocol version", async () => {
  const a = await handleMessage({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "t", version: "1" } } });
  assert.equal(a.result.protocolVersion, "2025-03-26");
  assert.deepEqual(a.result.capabilities, { tools: { listChanged: false } });
  assert.equal(a.result.serverInfo.name, "rea-iphone");
  const b = await handleMessage({ jsonrpc: "2.0", id: 2, method: "initialize", params: { protocolVersion: "1999-01-01" } });
  assert.equal(b.result.protocolVersion, "2025-06-18", "unknown version -> latest supported");
  assert.equal(await handleMessage({ jsonrpc: "2.0", method: "notifications/initialized" }), null);
  assert.deepEqual((await handleMessage({ jsonrpc: "2.0", id: 3, method: "ping" })).result, {});
});

test("tools/list: unique names, object schemas, annotations", async () => {
  const r = await handleMessage({ jsonrpc: "2.0", id: 1, method: "tools/list" });
  const tools = r.result.tools;
  assert.equal(tools.length, TOOLS.length);
  assert.equal(new Set(tools.map((t) => t.name)).size, tools.length);
  for (const t of tools) {
    assert.equal(t.inputSchema.type, "object", t.name);
    assert.ok(t.description.length > 20, t.name);
    assert.ok(t.annotations, t.name);
    assert.equal(t.handler, undefined, "handlers are not serialized");
    for (const req of t.inputSchema.required ?? []) assert.ok(t.inputSchema.properties[req], `${t.name}.${req}`);
  }
});

test("protocol errors", async () => {
  assert.equal((await handleMessage({ jsonrpc: "2.0", id: 1, method: "nope" })).error.code, -32601);
  assert.equal((await handleMessage({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "nope" } })).error.code, -32602);
  assert.equal((await handleMessage({ id: 1, method: "ping" })).error.code, -32600);
  assert.equal((await handleMessage("str")).error.code, -32600);
  assert.equal((await handleMessage(null)).error.code, -32600);
});

test("argument validation is reported as a tool error", async () => {
  let r = await call("dump_objc_classes", {});
  assert.equal(r.isError, true);
  assert.match(r.text, /missing required argument "path"/);
  r = await call("dump_objc_classes", { path: BIN, format: "xml" });
  assert.match(r.text, /must be one of header, json/);
  r = await call("list_symbols", { path: BIN, limit: 0 });
  assert.match(r.text, /must be >= 1/);
  r = await call("analyze_ios_application", { path: "/does/not/exist.ipa" });
  assert.equal(r.isError, true);
  assert.match(r.text, /^Error: /);
});

test("static tools", async () => {
  let r = await call("analyze_ios_application", { path: BIN, deep: true });
  assert.equal(r.isError, false);
  assert.equal(r.json.apps[0].deep.objc.classes, 3);

  r = await call("dump_objc_classes", { path: BIN, filter: "^Wallet$" });
  assert.match(r.json.header, /@interface Wallet : NSObject <Greeter>/);
  assert.doesNotMatch(r.json.header, /RelativeClass/);

  r = await call("dump_objc_classes", { path: BIN, format: "json", filter: "Relative" });
  assert.deepEqual(r.json.classes.map((c) => c.name), ["RelativeClass"]);

  r = await call("dump_swift_types", { path: BIN, format: "json", filter: "Premium" });
  assert.equal(r.json.types[0].superclass, "WalletKit.TransferService");

  r = await call("extract_strings", { path: BIN, category: "credential_candidates" });
  assert.equal(r.json.findings.credential_candidates[0].rule, "stripe-secret-key");

  r = await call("extract_strings", { path: BIN, include_all: true, filter: "^nick", limit: 5 });
  assert.deepEqual(r.json.strings.items.map((s) => s.value), ["nickname"]);

  r = await call("list_symbols", { path: BIN, kind: "exports", filter: "Account.*Mn" });
  assert.equal(r.json.exports.items[0].demangled, "nominal type descriptor for WalletKit.Account");

  r = await call("list_symbols", { path: BIN, kind: "imports" });
  assert.equal(r.json.imports[0].library, "flat-lookup");

  r = await call("inspect_fixups", { path: BIN, include_locations: true });
  assert.equal(r.json.mode, "chained");
  assert.deepEqual(r.json.formats, ["DYLD_CHAINED_PTR_64"]);
  assert.ok(r.json.binds.items.some((b) => b.symbol === "_OBJC_CLASS_$_NSObject"));

  r = await call("demangle_swift", { symbols: ["_$sSHMp", "nope"] });
  assert.deepEqual(r.json.results.map((x) => x.demangled), ["protocol descriptor for Swift.Hashable", null]);

  r = await call("generate_frida_script", { mode: "objc-trace", patterns: ["-[Wallet *]"] });
  assert.match(r.json.script, /mode: objc-trace/);
});

test("device tool failure is surfaced as isError with the reason", async () => {
  const saved = { dir: process.env.REA_IPHONE_TOOLS_DIR, path: process.env.PATH };
  process.env.REA_IPHONE_TOOLS_DIR = "/nonexistent";
  process.env.PATH = "/nonexistent";
  try {
    const r = await call("list_ios_devices", {});
    assert.equal(r.isError, true);
    assert.match(r.json.error, /idevice_id: not found/);
  } finally {
    process.env.REA_IPHONE_TOOLS_DIR = saved.dir;
    process.env.PATH = saved.path;
  }
});

test("live stdio session", async () => {
  const cli = fileURLToPath(new URL("../bin/rea-iphone.js", import.meta.url));
  const child = spawn(process.execPath, [cli, "mcp"], { stdio: ["pipe", "pipe", "pipe"] });
  const lines = [];
  let buf = "";
  child.stdout.on("data", (c) => {
    buf += c;
    const parts = buf.split("\n");
    buf = parts.pop();
    lines.push(...parts.filter(Boolean).map((l) => JSON.parse(l)));
  });
  const send = (m) => child.stdin.write(`${JSON.stringify(m)}\n`);
  send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "1" } } });
  send({ jsonrpc: "2.0", method: "notifications/initialized" });
  send({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "demangle_swift", arguments: { symbols: ["$s4main3fooyyF"] } } });
  child.stdin.write("not json\n");
  send("a json string, not an object");
  child.stdin.end();
  await new Promise((r) => child.on("close", r));
  const byId = Object.fromEntries(lines.filter((l) => l.id != null).map((l) => [l.id, l]));
  assert.equal(byId[1].result.serverInfo.name, "rea-iphone");
  assert.match(byId[2].result.content[0].text, /main\.foo\(\) -> \(\)/);
  assert.ok(lines.some((l) => l.error?.code === -32700), "parse error reported");
  assert.ok(lines.some((l) => l.error?.code === -32600 && l.id === null), "non-object reported as Invalid Request");
});
