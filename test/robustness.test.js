// Robustness: rea-iphone opens untrusted binaries, so malformed input must
// produce limitations — never crashes, hangs, or unbounded work.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { openMachO, selectImage } from "../src/macho.js";
import { deepAnalyze } from "../src/deep.js";
import { demangleSymbol, demangleType } from "../src/swift/demangle.js";
import { FIXTURE_BIN } from "./makeFixture.js";

function lcg(seed) {
  let s = seed;
  return () => (s = (s * 1103515245 + 12345) % 2147483648) / 2147483648;
}

for (const [name, seed] of [["WalletKit-chained", 777], ["WalletKit-classic", 4242]]) {
  test(`mutation fuzz (${name}): no crash, bounded time`, () => {
    const orig = readFileSync(FIXTURE_BIN + name);
    const rnd = lcg(seed);
    let analyzed = 0;
    let slowest = 0;
    for (let i = 0; i < 150; i++) {
      const b = Buffer.from(orig);
      const n = 1 + Math.floor(rnd() * 24);
      for (let k = 0; k < n; k++) {
        const off = rnd() < 0.3 ? Math.floor(rnd() * 2048) : Math.floor(rnd() * b.length);
        const v = rnd();
        b[off] = v < 0.33 ? 0xff : v < 0.5 ? 0 : Math.floor(rnd() * 256);
      }
      let im;
      try {
        im = selectImage(openMachO(b).images);
      } catch (err) {
        assert.ok(!(err instanceof TypeError), `header parse threw TypeError: ${err.message}`);
        continue;
      }
      if (!im) continue;
      const t0 = performance.now();
      const d = deepAnalyze(im); // must not throw
      assert.doesNotThrow(() => JSON.stringify(d));
      slowest = Math.max(slowest, performance.now() - t0);
      analyzed++;
    }
    assert.ok(analyzed > 100, `analyzed ${analyzed} mutants`);
    assert.ok(slowest < 1000, `slowest mutant took ${slowest.toFixed(0)} ms`);
  });
}

test("truncated binaries fail cleanly", () => {
  const orig = readFileSync(`${FIXTURE_BIN}WalletKit-fat`);
  for (const len of [0, 3, 7, 8, 27, 31, 64, 1000, 4096, 20000]) {
    const b = orig.subarray(0, len);
    try {
      const { images } = openMachO(b);
      for (const im of images) deepAnalyze(im);
    } catch (err) {
      assert.ok(err instanceof Error && !(err instanceof TypeError), `len ${len}: ${err}`);
    }
  }
});

test("demangler: hostile symbols return null quickly", () => {
  const hostile = [
    "$s" + "A9999999999a",
    "$s" + "S99999999i",
    "$s" + "1a".repeat(5000),
    "$s" + "y".repeat(20000),
    "$s" + "0".repeat(100),
    "$s" + "_".repeat(5000) + "t",
    "$s4main" + "Say".repeat(3000) + "Si" + "G".repeat(3000),
    "$s99999999999999999999x",
  ];
  const t0 = performance.now();
  for (const h of hostile) {
    const r = demangleSymbol(h);
    assert.ok(r === null || typeof r === "string");
  }
  const rnd = lcg(99);
  const alphabet = "0123456789ACVOPSaGtyc_fFvgMNKYsT";
  for (let i = 0; i < 5000; i++) {
    let s = "$s";
    const len = 1 + Math.floor(rnd() * 40);
    for (let k = 0; k < len; k++) s += alphabet[Math.floor(rnd() * alphabet.length)];
    demangleSymbol(s);
    demangleType([...s.slice(2)].map((c) => c.charCodeAt(0)));
  }
  assert.ok(performance.now() - t0 < 3000, "bounded time");
});
