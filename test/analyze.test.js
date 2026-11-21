import { test } from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { mkdtempSync, readFileSync } from "node:fs";
import { buildMachO, writeAppDir, writeIpa, FIXTURE_BIN } from "./makeFixture.js";
import { parseMachO, isMachO } from "../src/macho.js";
import { analyze } from "../src/analyze.js";
import { loadBinary } from "../src/target.js";
import { renderText } from "../src/report.js";

test("Mach-O parser reads crafted arm64 iOS image", () => {
  const buf = buildMachO();
  assert.ok(isMachO(buf));
  const macho = parseMachO(buf);
  assert.equal(macho.kind, "thin");
  const im = macho.images[0];
  assert.equal(im.arch, "arm64");
  assert.equal(im.bits, 64);
  assert.equal(im.filetype, "MH_EXECUTE");
  assert.equal(im.platform, "iOS");
  assert.equal(im.minOS, "14.0.0");
  assert.equal(im.sdk, "17.0.0");
  assert.equal(im.encryption.present, true);
  assert.equal(im.encryption.encrypted, true);
  assert.equal(im.encryption.cryptId, 1);
  assert.equal(im.codeSignature, true);
  assert.ok(im.dylibs.some((d) => d.includes("libSystem")));
  assert.ok(im.languageHints.includes("Swift"));
  assert.ok(im.uuid && im.uuid.length === 32);
});

test("analyze() on .app directory extracts full report", () => {
  const dir = mkdtempSync(join(tmpdir(), "rea-ios-"));
  writeAppDir(dir);
  const r = analyze(join(dir, "Payload", "Demo.app"));
  assert.equal(r.apps.length, 1);
  const app = r.apps[0];
  assert.equal(app.bundle.identifier, "com.example.demo");
  assert.equal(app.bundle.shortVersion, "2.4.1");
  assert.equal(app.bundle.minimumOS, "14.0");
  assert.deepEqual(app.bundle.urlSchemes, ["demoapp", "example"]);
  assert.deepEqual(app.bundle.queriedSchemes, ["venmo"]);
  assert.deepEqual(app.bundle.privacyUsageDescriptions, { NSCameraUsageDescription: "Scan receipts" });
  assert.equal(app.bundle.atsAllowsArbitraryLoads, true);
  assert.equal(app.executable.slices[0].fairplay_encrypted, true);
  assert.ok(app.entitlements);
  assert.equal(app.entitlements["get-task-allow"], true);
  assert.equal(app.provisioning.parsed, true);
  assert.equal(app.provisioning.distribution, "development");
  assert.equal(app.provisioning.teamName, "Example Inc.");
  assert.equal(app.provisioning.expired, false);
  assert.equal(app.provisioning.provisionedDeviceCount, 2);
  assert.deepEqual(app.embedded_frameworks, ["FirebaseCore.framework", "Flutter.framework"]);
  assert.deepEqual(app.app_extensions, ["DemoWidget.appex"]);
  assert.ok(r.runtime_families.some((f) => f.family === "Flutter"));
  assert.ok(r.third_party_sdks.some((s) => s.sdk === "Firebase"));
  assert.deepEqual(r.binaries.map((b) => b.role), ["main", "framework", "framework", "extension"]);
  assert.equal(r.binaries.find((b) => b.role === "extension").path, "Payload/Demo.app/PlugIns/DemoWidget.appex/DemoWidget");
});

test("analyze() on packed .ipa matches directory analysis", () => {
  const dir = mkdtempSync(join(tmpdir(), "rea-ios-ipa-"));
  writeAppDir(dir);
  const ipa = writeIpa(dir, join(dir, "Demo.ipa"));
  const r = analyze(ipa);
  assert.equal(r.container, "ipa");
  assert.equal(r.apps.length, 1);
  assert.equal(r.apps[0].bundle.identifier, "com.example.demo");
  assert.equal(r.apps[0].executable.slices[0].arch, "arm64");
  assert.equal(r.apps[0].provisioning.distribution, "development");
  assert.equal(r.binaries.length, 4);
});

test("deep analysis of an IPA whose executable is a real linked binary", () => {
  const dir = mkdtempSync(join(tmpdir(), "rea-ios-deep-"));
  writeAppDir(dir, { executable: readFileSync(`${FIXTURE_BIN}WalletKit-fat`) });
  const ipa = writeIpa(dir, join(dir, "Demo.ipa"));
  const r = analyze(ipa, { deep: true });
  const d = r.apps[0].deep;
  assert.equal(d.arch, "arm64");
  assert.equal(d.fixups.mode, "chained");
  assert.equal(d.objc.classes, 3);
  assert.equal(d.objc.categories, 2);
  assert.equal(d.swift.types, 4);
  assert.equal(d.swift.conformances, 3);
  assert.equal(d.swift.demangled_symbols, "13/13");
  assert.deepEqual(d.strings.findings.credential_candidates, ["sk_live_51HxExampleExampleExampleExample00"]);
  assert.equal(r.apps[0].executable.kind, "fat");
  assert.ok(r.evidence.some((e) => e.kind === "deep_static_analysis"));
  assert.doesNotThrow(() => JSON.stringify(r));
  assert.match(renderText(r), /Deep static analysis \(arm64, chained fixups: DYLD_CHAINED_PTR_64\)/);
  // A framework inside the IPA can be selected directly.
  const fw = loadBinary(ipa, "Flutter.framework/Flutter");
  assert.equal(fw.binary.role, "framework");
});

test("bare Mach-O target", () => {
  const r = analyze(`${FIXTURE_BIN}WalletKit-classic`, { deep: true });
  assert.equal(r.container, "macho");
  assert.equal(r.apps[0].deep.fixups.mode, "dyld-info");
  assert.equal(r.apps[0].deep.objc.classes, 3);
});
