// Device layer against shim executables that reproduce libimobiledevice's
// output formats (no physical device is needed to run the suite).
import { test, before } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, chmodSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import * as device from "../src/device/idevice.js";
import { summarizeCrashReport } from "../src/ips.js";

const UDID = "00008110-001A2B3C4D5E6F70";
let shims;

const INFO_XML = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>DeviceName</key><string>Test iPhone</string>
<key>ProductType</key><string>iPhone15,2</string>
<key>ProductVersion</key><string>17.4.1</string>
<key>BuildVersion</key><string>21E236</string>
<key>CPUArchitecture</key><string>arm64e</string>
<key>UniqueDeviceID</key><string>${UDID}</string>
<key>SerialNumber</key><string>XYZ</string>
</dict></plist>`;

const APPS_XML = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><array>
<dict><key>CFBundleIdentifier</key><string>com.example.wallet</string><key>CFBundleDisplayName</key><string>Wallet Demo</string>
<key>CFBundleShortVersionString</key><string>2.4.1</string><key>CFBundleVersion</key><string>2041</string>
<key>ApplicationType</key><string>User</string><key>CFBundleExecutable</key><string>Demo</string>
<key>Entitlements</key><dict><key>get-task-allow</key><true/><key>application-identifier</key><string>T.com.example.wallet</string></dict></dict>
<dict><key>CFBundleIdentifier</key><string>com.example.alpha</string><key>CFBundleName</key><string>Alpha</string>
<key>CFBundleShortVersionString</key><string>1.0</string><key>ApplicationType</key><string>User</string></dict>
</array></plist>`;

const IPS = `{"app_name":"Demo","timestamp":"2026-11-20 10:00:00.00 -0800","app_version":"2.4.1","slice_uuid":"4c4c44fc","build_version":"2041","bundleID":"com.example.wallet","bug_type":"309","os_version":"iPhone OS 17.4.1 (21E236)","incident_id":"ABC-123","name":"Demo"}
{"procName":"Demo","exception":{"type":"EXC_BAD_ACCESS","signal":"SIGSEGV","subtype":"KERN_INVALID_ADDRESS at 0x0000000000000010"},"termination":{"namespace":"SIGNAL","code":11,"indicator":"Segmentation fault: 11"},"faultingThread":0,"threads":[{"triggered":true,"queue":"com.apple.main-thread","frames":[{"imageOffset":16456,"symbol":"-[Wallet deposit:]","symbolLocation":20,"imageIndex":0},{"imageOffset":4096,"imageIndex":1}]}],"usedImages":[{"name":"Demo"},{"name":"UIKitCore"}]}`;

function shim(name, body) {
  const p = join(shims, name);
  writeFileSync(p, `#!/bin/sh\n${body}\n`);
  chmodSync(p, 0o755);
}

before(() => {
  shims = mkdtempSync(join(tmpdir(), "rea-shims-"));
  writeFileSync(join(shims, "info.xml"), INFO_XML);
  writeFileSync(join(shims, "apps.xml"), APPS_XML);
  writeFileSync(join(shims, "report.ips"), IPS);
  shim("idevice_id", `case "$1" in -l) echo "${UDID}";; -n) ;; esac`);
  shim("ideviceinfo", `case "$*" in *-x*) cat "${shims}/info.xml";; *) exit 1;; esac`);
  shim("idevicepair", `echo "SUCCESS: Validated pairing with device $2"`);
  // Legacy syntax unless SHIM_NEW_SYNTAX is set, which rejects -l like newer builds.
  shim("ideviceinstaller", `
if [ -n "$SHIM_NEW_SYNTAX" ]; then
  case "$*" in *" list "*|*" list") cat "${shims}/apps.xml"; exit 0;; *) echo "ERROR: unrecognized option -l" >&2; exit 1;; esac
fi
case "$*" in *-l*) cat "${shims}/apps.xml";; *) exit 1;; esac`);
  shim("idevicesyslog", `
echo "Nov 21 10:00:01 Test-iPhone SpringBoard(FrontBoard)[57] <Notice>: scene update"
echo "Nov 21 10:00:02 Test-iPhone Demo(CFNetwork)[812] <Error>: Task <1> HTTP load failed"
echo "Nov 21 10:00:03 Test-iPhone Demo[812] <Notice>: deposit amount=42"
sleep 30`);
  shim("idevicecrashreport", `for last; do :; done; mkdir -p "$last"; cp "${shims}/report.ips" "$last/Demo-2026-11-20.ips"; echo "Copy: Demo-2026-11-20.ips"`);
  process.env.REA_IPHONE_TOOLS_DIR = shims;
});

test("listDevices + deviceInfo", async () => {
  const r = await device.listDevices();
  assert.equal(r.ok, true);
  assert.deepEqual(r.devices, [{ udid: UDID, transport: "usb", name: "Test iPhone", product: "iPhone15,2", ios: "17.4.1" }]);
  const info = await device.deviceInfo(UDID);
  assert.equal(info.summary.CPUArchitecture, "arm64e");
  assert.deepEqual(info.command.slice(1), ["-u", UDID, "-x"]);
  assert.equal(info.properties.SerialNumber, "XYZ");
});

test("validatePairing", async () => {
  const r = await device.validatePairing(UDID);
  assert.equal(r.paired, true);
});

test("listApps: legacy ideviceinstaller syntax", async () => {
  delete process.env.SHIM_NEW_SYNTAX;
  const r = await device.listApps(UDID);
  assert.equal(r.ok, true);
  assert.deepEqual(r.apps.map((a) => a.bundle_id), ["com.example.alpha", "com.example.wallet"]);
  const w = r.apps[1];
  assert.equal(w.name, "Wallet Demo");
  assert.deepEqual(w.entitlement_keys, ["get-task-allow", "application-identifier"]);
  assert.deepEqual(r.command.slice(1), ["-u", UDID, "-l", "-o", "list_user", "-o", "xml"]);
});

test("listApps: falls back to the newer subcommand syntax", async () => {
  process.env.SHIM_NEW_SYNTAX = "1";
  try {
    const r = await device.listApps(UDID, { type: "all" });
    assert.equal(r.ok, true);
    assert.equal(r.count, 2);
    assert.deepEqual(r.command.slice(1), ["-u", UDID, "list", "--all", "--xml"]);
  } finally {
    delete process.env.SHIM_NEW_SYNTAX;
  }
});

test("captureSyslog: bounded capture, parsed, filtered by process", async () => {
  const t0 = Date.now();
  const r = await device.captureSyslog(UDID, { seconds: 1, process: "Demo" });
  assert.ok(Date.now() - t0 < 10000, "stream is stopped at the time limit");
  assert.equal(r.ok, true);
  assert.equal(r.count, 2);
  assert.deepEqual(r.lines[0], { time: "Nov 21 10:00:02", device: "Test-iPhone", process: "Demo", library: "CFNetwork", pid: 812, level: "Error", message: "Task <1> HTTP load failed" });
  const m = await device.captureSyslog(UDID, { seconds: 1, match: "amount=\\d+" });
  assert.equal(m.count, 1);
});

test("pullCrashReports copies and summarizes .ips", async () => {
  const out = mkdtempSync(join(tmpdir(), "rea-crash-"));
  const r = await device.pullCrashReports(UDID, out, { filter: "Demo" });
  assert.equal(r.ok, true);
  assert.equal(r.count, 1);
  const c = r.reports[0];
  assert.equal(c.bundle_id, "com.example.wallet");
  assert.equal(c.exception.type, "EXC_BAD_ACCESS");
  assert.equal(c.termination.indicator, "Segmentation fault: 11");
  assert.deepEqual(c.top_frames, ["Demo -[Wallet deposit:] + 20", "UIKitCore +0x1000"]);
  assert.deepEqual(r.command.slice(1), ["-u", UDID, "-k", "-e", "-f", "Demo", out]);
});

test("missing tools produce a clear error, not a crash", async () => {
  const saved = { dir: process.env.REA_IPHONE_TOOLS_DIR, path: process.env.PATH };
  process.env.REA_IPHONE_TOOLS_DIR = join(tmpdir(), "definitely-missing");
  process.env.PATH = "/nonexistent";
  try {
    const r = await device.listDevices();
    assert.equal(r.ok, false);
    assert.match(r.error, /idevice_id: not found/);
  } finally {
    process.env.REA_IPHONE_TOOLS_DIR = saved.dir;
    process.env.PATH = saved.path;
  }
});

test("legacy text crash log summary", () => {
  const txt = `Incident Identifier: X-1
Process:             Demo [812]
Identifier:          com.example.wallet
Version:             2041 (2.4.1)
Date/Time:           2026-11-20 10:00:00.000 -0800
OS Version:          iPhone OS 16.0 (20A362)
Exception Type:  EXC_CRASH (SIGABRT)

Thread 0 Crashed:
0   libsystem_kernel.dylib        	0x00000001e0a0b1c4 __pthread_kill + 8
1   Demo                          	0x0000000100004048 -[Wallet deposit:] + 20

Thread 1:
`;
  const s = summarizeCrashReport(txt, "a.crash");
  assert.equal(s.format, "crash-text");
  assert.equal(s.app_name, "Demo");
  assert.equal(s.exception.type, "EXC_CRASH (SIGABRT)");
  assert.equal(s.top_frames.length, 2);
  assert.match(s.top_frames[1], /-\[Wallet deposit:\] \+ 20/);
});

test("read the raw ips fixture back unchanged", () => {
  assert.ok(readFileSync(join(shims, "report.ips"), "utf8").startsWith('{"app_name":"Demo"'));
});
