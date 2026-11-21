// String extraction and classification.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { openMachO, selectImage, MachOImage } from "../src/macho.js";
import { extractStrings } from "../src/strings.js";
import { FIXTURE_BIN } from "./makeFixture.js";
import { dumpObjC } from "../src/objc.js";
import { dumpSwift } from "../src/swift/metadata.js";

test("extracts and classifies strings from a real binary", () => {
  const im = selectImage(openMachO(readFileSync(`${FIXTURE_BIN}WalletKit-chained`)).images);
  const s = extractStrings(im);
  assert.deepEqual(s.limitations, []);
  assert.ok(s.counts["c-string"] > 0 && s.counts["objc-selector"] > 0 && s.counts["swift-reflection"] > 0);
  assert.equal(s.counts.cfstring, 1);
  const v = (cat) => (s.findings[cat] ?? []).map((f) => f.value).sort();
  assert.deepEqual(v("urls"), ["https://api.example.com/v2/transfer", "https://telemetry.example.com/collect"]);
  assert.deepEqual(v("credential_candidates"), ["sk_live_51HxExampleExampleExampleExample00"]);
  assert.equal(s.findings.credential_candidates[0].rule, "stripe-secret-key");
  assert.deepEqual(v("integrity_checks"), ["/Applications/Cydia.app"]);
  assert.deepEqual(v("emails"), ["support@example.com"]);
  const cf = s.strings.find((x) => x.source === "cfstring");
  assert.equal(cf.value, "https://telemetry.example.com/collect");
  assert.ok(s.strings.some((x) => x.source === "swift-reflection" && x.value === "nickname"));
});

test("FairPlay-encrypted binary: __TEXT reported unreadable, __DATA structure still recovered", () => {
  // Patch a copy of the real binary to cryptid=1 (the linker already set
  // cryptoff/cryptsize to cover __TEXT), simulating an App Store binary.
  const buf = Buffer.from(readFileSync(`${FIXTURE_BIN}WalletKit-chained`));
  const probe = new MachOImage(buf, 0);
  const lc = probe.loadCommands.find((c) => c.cmd === 0x2c);
  buf.writeUInt32LE(1, lc.offset + 16);
  const im = new MachOImage(buf, 0);
  assert.equal(im.encryption.encrypted, true);
  assert.ok(im.encryption.cryptSize > 0);

  const s = extractStrings(im);
  assert.equal(s.counts["c-string"], undefined, "no plaintext C strings from encrypted __TEXT");
  assert.ok(s.limitations.some((l) => l.includes("__cstring") && l.includes("encrypted")));

  const d = dumpObjC(im);
  assert.equal(d.classes.length, 3, "class structures live in __DATA and are still recovered");
  assert.ok(d.classes.every((c) => c.name === "<encrypted>"));
  assert.ok(d.limitations.some((l) => l.includes("FairPlay")));

  const sw = dumpSwift(im);
  assert.equal(sw.types.length, 0);
  assert.ok(sw.limitations.some((l) => l.includes("encrypted")));
});
