// Frida agent scripts executed against a mock Frida runtime, plus the CLI
// runner against a shim `frida` executable.
import { test } from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { mkdtempSync, writeFileSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { generateScript, MODES } from "../src/frida/scripts.js";
import { buildFridaArgs, parseEvents, runFridaSession } from "../src/frida/runner.js";

// ---- a minimal mock of the Frida JavaScript runtime

function P(value, extra = {}) {
  return {
    v: BigInt(value),
    isNull() { return this.v === 0n; },
    toString(radix = 16) { return radix === 16 ? `0x${this.v.toString(16)}` : this.v.toString(radix); },
    toInt32() { return Number(BigInt.asIntN(32, this.v)); },
    readUtf8String() { return extra.str ?? null; },
    ...extra,
  };
}

function mockRuntime({ objects = {}, encodings = {}, matches = [], exports = {} }) {
  const logs = [];
  const hooks = [];
  const NSURLRequest = { kind: "NSURLRequest" };
  const NSURL = { kind: "NSURL" };
  const ctx = {
    console: { log: (s) => logs.push(s) },
    BigInt,
    ObjC: {
      available: true,
      classes: new Proxy({ NSURLRequest, NSURL }, {
        get(t, cls) {
          if (cls in t) return t[cls];
          return new Proxy({}, { get: (_, key) => ({ handle: { cls, key } }) });
        },
      }),
      api: { method_getTypeEncoding: (h) => ({ readUtf8String: () => encodings[`${h.cls} ${h.key}`] }) },
      selectorAsString: (p) => `sel_${p.toString()}`,
      Object: function MockObject(p) {
        const o = objects[p.toString()];
        if (!o) throw new Error("not an object");
        return o;
      },
    },
    ApiResolver: function ApiResolver(kind) {
      this.enumerateMatches = (pattern) => matches.filter((m) => m.kind === kind && m.pattern === pattern);
    },
    Interceptor: { attach: (address, callbacks) => hooks.push({ address, callbacks }) },
    Process: { getCurrentThreadId: () => 7, enumerateModules: () => [{ name: "Demo", base: P(0x100000000), size: 4096, path: "/var/containers/Bundle/Application/X/Demo.app/Demo" }] },
    Module: { getGlobalExportByName: (n) => { if (exports[n]) return exports[n]; throw new Error("not found"); } },
    Thread: { backtrace: () => [] },
    Backtracer: { ACCURATE: 1 },
    DebugSymbol: { fromAddress: (a) => a },
    ModuleMap: function ModuleMap(f) { this.f = f; },
  };
  ctx.ObjC.enumerateLoadedClassesSync = () => ({ "/var/containers/Bundle/Application/X/Demo.app/Demo": ["Wallet", "RelativeClass"] });
  return { ctx, logs, hooks, NSURLRequest, NSURL };
}

const events = (logs) => logs.filter((l) => l.startsWith("REA_EVT ")).map((l) => JSON.parse(l.slice(8)));

test("every mode generates syntactically valid JavaScript", () => {
  for (const mode of MODES) {
    const src = generateScript(mode, { patterns: ["-[Wallet *]"] });
    assert.doesNotThrow(() => new vm.Script(src), mode);
    assert.match(src, new RegExp(`mode: ${mode}`));
  }
  assert.throws(() => generateScript("objc-trace"), /needs at least one pattern/);
  assert.throws(() => generateScript("bogus"), /unknown mode/);
  assert.throws(() => generateScript("objc-trace", { patterns: ["x".repeat(600)] }), /at most 512/);
});

test("objc-trace decodes arguments from the method's real type encoding", () => {
  const rt = mockRuntime({
    matches: [
      { kind: "objc", pattern: "-[Wallet *]", name: "-[Wallet deposit:]", address: P(0x100004048) },
      { kind: "objc", pattern: "-[Wallet *]", name: "-[Wallet transferTo:amount:error:]", address: P(0x100004074) },
    ],
    encodings: { "Wallet - deposit:": "v24@0:8q16", "Wallet - transferTo:amount:error:": "B40@0:8@16d24^@32" },
    objects: {
      "0x1000": { $className: "Wallet", toString: () => "<Wallet: 0x1000>" },
      "0x2000": { $className: "__NSCFString", toString: () => "alice" },
    },
  });
  vm.runInNewContext(generateScript("objc-trace", { patterns: ["-[Wallet *]"], perHook: 1 }), rt.ctx);
  assert.equal(rt.hooks.length, 2);
  const ready = events(rt.logs).find((e) => e.type === "ready");
  assert.equal(ready.hooks, 2);

  const [deposit, transfer] = rt.hooks;
  const self = {};
  deposit.callbacks.onEnter.call(self, [P(0x1000), P(0x99), P((1n << 64n) - 42n)]);
  deposit.callbacks.onLeave.call(self, P(0));
  const t = {};
  transfer.callbacks.onEnter.call(t, [P(0x1000), P(0x98), P(0x2000), P(0), P(0x3000)]);
  transfer.callbacks.onLeave.call(t, P(1));
  // perHook=1: a second call to deposit is dropped
  deposit.callbacks.onEnter.call({}, [P(0x1000), P(0x99), P(7)]);

  const evs = events(rt.logs).filter((e) => e.type !== "ready");
  assert.deepEqual(evs.map((e) => [e.type, e.method]), [
    ["call", "-[Wallet deposit:]"],
    ["call", "-[Wallet transferTo:amount:error:]"],
    ["return", "-[Wallet transferTo:amount:error:]"],
  ]);
  assert.deepEqual(evs[0].args, ["-42"], "signed 64-bit argument decoded exactly");
  assert.equal(evs[0].receiver, "<Wallet: 0x1000> <Wallet>");
  assert.deepEqual(evs[1].args, ["alice <__NSCFString>", "<floating-point register>", "0x3000"]);
  assert.equal(evs[2].value, 1, "BOOL return");
});

test("network mode: HTTP requests with credential headers redacted, DNS lookups", () => {
  const rt = mockRuntime({
    matches: [{ kind: "objc", pattern: "-[NSURLSession *TaskWithRequest:*]", name: "-[NSURLSession dataTaskWithRequest:completionHandler:]", address: P(0x5000) }],
    exports: { getaddrinfo: P(0x6000) },
  });
  const str = (s) => ({ toString: () => s, isNull: () => false });
  const headers = { Authorization: "Bearer s3cr3t", "Content-Type": "application/json" };
  rt.ctx.ObjC.Object = function (p) {
    if (p.toString() !== "0x7000") throw new Error("nope");
    return {
      isKindOfClass_: (c) => c === rt.NSURLRequest,
      URL: () => ({ absoluteString: () => str("https://api.example.com/v2/transfer") }),
      HTTPMethod: () => str("POST"),
      HTTPBody: () => ({ isNull: () => false, length: () => 42 }),
      allHTTPHeaderFields: () => ({
        isNull: () => false,
        allKeys: () => ({ count: () => 2, objectAtIndex_: (i) => str(Object.keys(headers)[i]) }),
        objectForKey_: (k) => str(headers[k]),
      }),
    };
  };
  vm.runInNewContext(generateScript("network"), rt.ctx);
  assert.equal(rt.hooks.length, 2);
  rt.hooks[0].callbacks.onEnter.call({}, [P(0x1), P(0x2), P(0x7000)]);
  rt.hooks[1].callbacks.onEnter.call({}, [P(0x8000, { str: "api.example.com" }), P(0x8100, { str: "443" })]);
  const evs = events(rt.logs);
  const http = evs.find((e) => e.type === "http");
  assert.equal(http.url, "https://api.example.com/v2/transfer");
  assert.equal(http.method, "POST");
  assert.equal(http.body_bytes, 42);
  assert.deepEqual(http.headers, { Authorization: "<redacted>", "Content-Type": "application/json" });
  assert.deepEqual(evs.find((e) => e.type === "dns"), { type: "dns", host: "api.example.com", service: "443", t: evs.find((e) => e.type === "dns").t });

  // redact:false shows values (for your own test accounts)
  const rt2 = mockRuntime({ matches: [{ kind: "objc", pattern: "-[NSURLSession *TaskWithRequest:*]", name: "-[NSURLSession dataTaskWithRequest:]", address: P(0x5000) }] });
  rt2.ctx.ObjC.Object = rt.ctx.ObjC.Object;
  rt2.NSURLRequest = rt.NSURLRequest;
  rt2.ctx.ObjC.classes = rt.ctx.ObjC.classes;
  vm.runInNewContext(generateScript("network", { redact: false }), rt2.ctx);
  rt2.hooks[0].callbacks.onEnter.call({}, [P(1), P(2), P(0x7000)]);
  assert.equal(events(rt2.logs).find((e) => e.type === "http").headers.Authorization, "Bearer s3cr3t");
});

test("classes and modules modes", () => {
  const rt = mockRuntime({});
  rt.ctx.ObjC.classes = new Proxy({}, { get: (_, n) => ({ $ownMethods: [`- ${String(n).toLowerCase()}Method`] }) });
  vm.runInNewContext(generateScript("classes"), rt.ctx);
  const evs = events(rt.logs);
  assert.deepEqual(evs.filter((e) => e.type === "class").map((e) => [e.module, e.name, e.methods[0]]), [["Demo", "Wallet", "- walletMethod"], ["Demo", "RelativeClass", "- relativeclassMethod"]]);
  const rt2 = mockRuntime({});
  vm.runInNewContext(generateScript("modules"), rt2.ctx);
  assert.equal(events(rt2.logs)[0].name, "Demo");
});

test("event cap is enforced", () => {
  const rt = mockRuntime({});
  rt.ctx.Process.enumerateModules = () => Array.from({ length: 10 }, (_, i) => ({ name: `m${i}`, base: P(i), size: 1, path: `/m${i}` }));
  vm.runInNewContext(generateScript("modules", { maxEvents: 3 }), rt.ctx);
  const evs = events(rt.logs);
  assert.deepEqual(evs.map((e) => e.type), ["module", "module", "module", "limit"]);
});

test("buildFridaArgs", () => {
  assert.deepEqual(buildFridaArgs({ target: { bundleId: "com.example.wallet" }, scriptPath: "/s.js", seconds: 5 }).args, ["-U", "-f", "com.example.wallet", "-l", "/s.js", "-q", "-t", "5"]);
  assert.deepEqual(buildFridaArgs({ device: { id: "abc" }, target: { bundleId: "com.example.wallet", spawn: false }, scriptPath: "/s.js" }).args, ["-D", "abc", "-N", "com.example.wallet", "-l", "/s.js", "-q", "-t", "20"]);
  assert.deepEqual(buildFridaArgs({ device: { host: "10.0.0.5:27042" }, target: { pid: 812 }, scriptPath: "/s.js", seconds: 9999 }).args, ["-H", "10.0.0.5:27042", "-p", "812", "-l", "/s.js", "-q", "-t", "600"]);
  assert.deepEqual(buildFridaArgs({ target: { frontmost: true }, scriptPath: "/s.js" }).args.slice(0, 2), ["-U", "-F"]);
  assert.throws(() => buildFridaArgs({ target: { bundleId: "bad id; rm -rf /" }, scriptPath: "/s.js" }), /invalid bundle identifier/);
  assert.throws(() => buildFridaArgs({ target: {}, scriptPath: "/s.js" }), /needs bundleId/);
});

test("parseEvents tolerates noise", () => {
  const p = parseEvents('Spawned `com.example.wallet`. Resuming main thread!\nREA_EVT {"type":"ready","hooks":1}\nREA_EVT {broken\n[iPhone::Demo ]-> REA_EVT {"type":"call","method":"-[A b]"}\n');
  assert.deepEqual(p.counts, { ready: 1, call: 1 });
  assert.equal(p.logs.length, 2);
});

test("runFridaSession drives the frida CLI and parses events", async () => {
  const dir = mkdtempSync(join(tmpdir(), "rea-frida-shim-"));
  const shim = join(dir, "frida");
  writeFileSync(shim, `#!/bin/sh
script=""
while [ $# -gt 0 ]; do [ "$1" = "-l" ] && script="$2"; shift; done
grep -q "REA_EVT" "$script" || { echo "bad script" >&2; exit 3; }
echo "Spawned \\\`com.example.wallet\\\`. Resuming main thread!"
echo 'REA_EVT {"type":"ready","mode":"network","hooks":4}'
echo 'REA_EVT {"type":"http","url":"https://api.example.com/v2/transfer","method":"POST"}'
`);
  chmodSync(shim, 0o755);
  const saved = process.env.REA_IPHONE_TOOLS_DIR;
  process.env.REA_IPHONE_TOOLS_DIR = dir;
  try {
    const r = await runFridaSession({ mode: "network", target: { bundleId: "com.example.wallet" }, seconds: 3 });
    assert.equal(r.ok, true);
    assert.deepEqual(r.counts, { ready: 1, http: 1 });
    assert.equal(r.events[1].url, "https://api.example.com/v2/transfer");
    assert.deepEqual(r.command.slice(1), ["-U", "-f", "com.example.wallet", "-l", "<agent.js>", "-q", "-t", "3"]);
  } finally {
    process.env.REA_IPHONE_TOOLS_DIR = saved;
  }
});
