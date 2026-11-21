import { test } from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { mkdtempSync } from "node:fs";
import { buildMachO, writeAppDir, writeIpa } from "./makeFixture.js";
import { parseMachO, isMachO } from "../src/macho.js";
import { analyze } from "../src/analyze.js";

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
  assert.equal(app.bundle.atsAllowsArbitraryLoads, true);
  assert.equal(app.executable.slices[0].fairplay_encrypted, true);
  assert.ok(app.entitlements);
  assert.equal(app.entitlements["get-task-allow"], true);
  assert.equal(app.provisioning.parsed, true);
  assert.equal(app.provisioning.distribution, "development");
  assert.equal(app.provisioning.teamName, "Example Inc.");
  assert.equal(app.provisioning.expired, false);
  assert.equal(app.provisioning.provisionedDeviceCount, 2);
  assert.ok(app.embedded_frameworks.includes("Flutter.framework"));
  assert.ok(r.runtime_families.some((f) => f.family === "Flutter"));
});

test("analyze() on packed .ipa matches directory analysis", () => {
  const dir = mkdtempSync(join(tmpdir(), "rea-ios-ipa-"));
  const appRoot = writeAppDir(dir); // Payload/Demo.app
  // zip the Payload/ tree so paths are Payload/Demo.app/...
  const payloadRoot = join(dir, "Payload");
  const ipa = writeIpa(join(dir), join(dir, "Demo.ipa")); // zip from dir root -> Payload/...
  void appRoot; void payloadRoot;
  const r = analyze(ipa);
  assert.equal(r.container, "ipa");
  assert.equal(r.apps.length, 1);
  assert.equal(r.apps[0].bundle.identifier, "com.example.demo");
  assert.equal(r.apps[0].executable.slices[0].arch, "arm64");
  assert.equal(r.apps[0].provisioning.distribution, "development");
});
